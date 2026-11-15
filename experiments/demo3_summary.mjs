// Prints the Demo 3 results table (Markdown) from the files in results/, for
// the design document and slides.  Missing results are shown as "not run".
//
//   node experiments/demo3_summary.mjs
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const results = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'results');

async function load(name) {
  try {
    return JSON.parse(await readFile(path.join(results, name), 'utf8'));
  } catch {
    return null;
  }
}

function status(result) {
  if (!result) return 'not run';
  const dirty = result.repository_dirty ? ', dirty tree' : '';
  const revision = result.repository_revision ? ` at \`${result.repository_revision.slice(0, 7)}\`` : '';
  return `**${result.status}**${revision}${dirty}`;
}

function passed(result) {
  if (!result?.scenarios) return '';
  const ran = result.scenarios.filter((entry) => entry.passed !== null && entry.observed !== 'not_run');
  return `${ran.filter((entry) => entry.passed).length}/${ran.length} scenarios`;
}

const [bridge, bridgeAws, trials, trialsAws, human, model, e2eHuman, attestation] = await Promise.all([
  'demo3-bridge.json', 'demo3-bridge-aws.json', 'demo3-trials.json', 'demo3-trials-aws.json',
  'demo3-human-approval.json', 'demo3-model-agent.json', 'demo3-end-to-end-human.json', 'demo2-attestation.json',
].map(load));

const rows = [
  ['Bound handoff, local (Exp. 8)', status(bridge), passed(bridge)],
  ['Bound handoff, AWS (Exp. 8)', status(bridgeAws), passed(bridgeAws)],
  ['Repeated trials, local (Exp. 10)', status(trials), trials
    ? `${trials.totals.scenario_runs_passed}/${trials.totals.scenario_runs} runs, ${trials.totals.unauthorized_or_duplicate_launches} unauthorized or duplicate launches` : ''],
  ['Repeated trials, AWS (Exp. 10)', status(trialsAws), trialsAws
    ? `${trialsAws.totals.scenario_runs_passed}/${trialsAws.totals.scenario_runs} runs, ${trialsAws.totals.unauthorized_or_duplicate_launches} unauthorized or duplicate launches` : ''],
  ['Two people approve (Exp. 9)', status(human), human
    ? `${passed(human)}, ${human.approver_mode}, ${human.human_wait_seconds} s human wait` : ''],
  ['Live model agent (Exp. 11)', status(model), model
    ? `${passed(model)}, ${model.scenarios.find((entry) => entry.name === 'model_request_published')?.model || ''}` : ''],
  ['End to end, people + model on AWS (Exp. 4)', status(e2eHuman), e2eHuman
    ? `${passed(e2eHuman)}, tpm ${e2eHuman.tpm_type}, agent ${e2eHuman.agent_mode}` : ''],
  ['Cloud attestation (Exp. 3)', status(attestation), attestation
    ? `${passed(attestation)}${attestation.tpm_type ? `, tpm ${attestation.tpm_type}` : ''}` : ''],
];

const lines = [
  '| Experiment | Result | Detail |',
  '| --- | --- | --- |',
  ...rows.map((row) => `| ${row.join(' | ')} |`),
];

if (trials?.latency) {
  lines.push('', '| Measurement | Demo 2 | Demo 3 |', '| --- | --- | --- |');
  lines.push(`| Runs per scenario | 1 | ${trials.totals.trials} |`);
  const tokenOnly = trials.scenarios.find((entry) => entry.name === 'bearer_token_without_permit');
  if (tokenOnly) {
    lines.push(`| Launches from a caller holding only the bearer token | possible (node checked the token only) | ${tokenOnly.launches} in ${tokenOnly.trials} attempts |`);
  }
  lines.push(`| Gated launch latency, median / p95 | not measured | ${trials.latency.gated.median_ms} / ${trials.latency.gated.p95_ms} ms |`);
  lines.push(`| Overhead of the gate over a direct permitted call, median | not measured | ${trials.latency.overhead_median_ms} ms |`);
  for (const entry of trials.workload_scaling?.sizes || []) {
    lines.push(`| Input ${entry.input}: gated / baseline median | 32-byte input only | ${entry.gated.median_ms} / ${entry.baseline.median_ms} ms |`);
  }
  if (trials.workload_scaling?.over_limit) {
    lines.push(`| Input over the 64 MiB node limit | not tested | ${trials.workload_scaling.over_limit.outcome}, ${trials.workload_scaling.over_limit.launches} launches |`);
  }
}

process.stdout.write(`${lines.join('\n')}\n`);
