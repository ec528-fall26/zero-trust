// Replay recorded experiment results as OpenTelemetry traces, using the
// timestamps stored in each results file.  This visualizes runs that already
// happened; it does not contact AWS or re-run anything.
//
// Usage:
//   OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
//     node experiments/trace_replay.mjs [results/<file>.json ...]
//
// Each file becomes one trace: a root span covering the run, one child span
// per scenario, and the run's timeline steps as timestamped events.
import { context, trace } from '@opentelemetry/api';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { initTelemetry, recordedSpan, shutdownTelemetry } from './telemetry.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_FILES = ['results/demo2-end-to-end.json', 'results/ima-tamper.json'];

function times(result) {
  const values = [];
  for (const step of result.timeline || []) values.push(Date.parse(step.at));
  for (const scenario of result.scenarios || []) {
    values.push(Date.parse(scenario.started_at), Date.parse(scenario.completed_at));
  }
  const finite = values.filter(Number.isFinite);
  if (finite.length === 0) throw new Error(`${result.experiment}: no timestamps to replay`);
  return { start: Math.min(...finite), end: Math.max(...finite) };
}

function replay(result, source) {
  const { start, end } = times(result);
  const root = recordedSpan(`run.${result.experiment}`, start, end, {
    'ec528.replayed': true,
    'ec528.source_file': source,
    'ec528.status': result.status,
    'ec528.repository_revision': result.repository_revision,
    'ec528.repository_dirty': result.repository_dirty,
    'ec528.tpm_type': result.tpm_type,
    'ec528.instance_id': result.instance_id,
    'ec528.scenarios_passed': (result.scenarios || []).filter((s) => s.passed).length,
    'ec528.scenarios_total': (result.scenarios || []).length,
  });
  for (const step of result.timeline || []) {
    root.span.addEvent(step.step, { outcome: step.outcome }, new Date(step.at));
  }
  const parent = trace.setSpan(context.active(), root.span);
  for (const scenario of result.scenarios || []) {
    const observed = scenario.observed || {};
    const child = recordedSpan(
      `scenario.${scenario.name}`,
      Date.parse(scenario.started_at),
      Date.parse(scenario.completed_at),
      {
        'ec528.expected': scenario.expected,
        'ec528.passed': scenario.passed,
        'http.response.status_code': observed.status,
        'ec528.refusal_reason': observed.reason,
        'keylime.verdict': observed.attestation_verdict,
        'workload.executed': observed.workload_executed,
        'keylime.attestation_status': observed.keylime?.attestation_status,
        'keylime.last_event_id': observed.keylime?.last_event_id,
        'ima.detection_seconds_upper_bound': observed.detection_seconds_upper_bound,
      },
      parent,
    );
    child.end(scenario.passed);
  }
  root.end(result.status === 'pass');
}

async function main() {
  if (!(await initTelemetry('ec528-recorded-runs'))) {
    throw new Error('set OTEL_EXPORTER_OTLP_ENDPOINT, e.g. http://127.0.0.1:4318');
  }
  try {
    const files = process.argv.length > 2 ? process.argv.slice(2) : DEFAULT_FILES;
    for (const file of files) {
      const source = path.relative(repositoryRoot, path.resolve(repositoryRoot, file));
      const result = JSON.parse(await readFile(path.resolve(repositoryRoot, file), 'utf8'));
      replay(result, source);
      process.stdout.write(`replayed ${source} (${result.experiment}, ${result.status})\n`);
    }
  } finally {
    await shutdownTelemetry();
  }
}

main().catch((error) => {
  process.stderr.write(`trace replay failed: ${error.message}\n`);
  process.exitCode = 1;
});
