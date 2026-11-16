// Demo 3 measurement: repeated trials instead of one run per scenario.
//
// 1. Runs every demo3-bridge scenario (valid launch, forged/expired/old-epoch
//    permits, token without permit, substitutions, stale attestation, replay,
//    10-client race, restart, lost response) --trials times and counts
//    unauthorized and duplicate launches from the workload's own records.
// 2. Measures --latency-runs paired launches: the full gated path (EMILIA
//    receipt gate, controller, permit, node) against a baseline that calls the
//    same node with a valid permit directly, with no quorum receipt or
//    controller gate.  Reports median and p95 for both and the overhead.
//
// 3. Local mode only: repeats the paired measurement with realistic input sizes
//    (--sizes, default 1KB,1MB,16MB,64MB; --size-runs per size), because the
//    Demo 2 workload hashed a 32-byte file.  The node hashes the input itself
//    before launching, and the workload hashes it again.  The node reads at
//    most 64 MiB of workload material, so one input just over that limit must
//    be refused with no launch.
//
//   node experiments/demo3_trials.mjs [--trials 20] [--latency-runs 50] [--aws] [out.json]
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { awsBackend, localBackend, runScenarios } from './demo3_bridge.mjs';
import { createDemoController } from '../src/demo/demo_controller.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const mode = argv.includes('--aws') ? 'aws' : 'local';
const integerOption = (name, fallback) => {
  const index = argv.indexOf(name);
  const value = index >= 0 ? Number.parseInt(argv[index + 1], 10) : fallback;
  if (!Number.isSafeInteger(value) || value < 1 || value > 1000) throw new Error(`${name} must be 1-1000`);
  return value;
};
const trials = integerOption('--trials', 20);
const latencyRuns = integerOption('--latency-runs', 50);
const sizeRuns = integerOption('--size-runs', 5);
const SIZE_UNITS = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3 };
const sizes = (() => {
  const index = argv.indexOf('--sizes');
  const text = index >= 0 ? argv[index + 1] : '1KB,1MB,16MB,64MB';
  if (text === 'none') return [];
  return text.split(',').map((entry) => {
    const match = /^(\d+)(B|KB|MB|GB)$/.exec(entry.trim().toUpperCase());
    if (!match) throw new Error(`invalid size: ${entry}`);
    return { label: entry.trim(), bytes: Number(match[1]) * SIZE_UNITS[match[2]] };
  });
})();
const outputPath = path.resolve(
  argv.find((argument, index) => !argument.startsWith('--')
    && !['--trials', '--latency-runs', '--sizes', '--size-runs'].includes(argv[index - 1]))
    || path.join(repositoryRoot, 'results', mode === 'aws' ? 'demo3-trials-aws.json' : 'demo3-trials.json'),
);

async function commandOutput(command, args) {
  try {
    const { stdout } = await execFileAsync(command, args, { cwd: repositoryRoot, timeout: 10_000 });
    return stdout.trim();
  } catch {
    return null;
  }
}

function percentile(values, fraction) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.min(sorted.length - 1, Math.max(0, Math.ceil(fraction * sorted.length) - 1));
  return Math.round(sorted[rank] * 10) / 10;
}

function stats(values) {
  return { runs: values.length, median_ms: percentile(values, 0.5), p95_ms: percentile(values, 0.95) };
}

async function measureLatency(backend, workRoot, manifest, { runs = latencyRuns, changes = {}, label = 'latency' } = {}) {
  const gated = [];
  const baseline = [];
  const failures = [];
  for (let run = 0; run < runs; run += 1) {
    // Paired and alternated so drift on the node affects both paths equally.
    const direct = backend.action(changes);
    let started = performance.now();
    const directOutcome = await backend.call({ ...direct, permit: backend.kit.sign(direct) });
    if (directOutcome === 'accepted') baseline.push(performance.now() - started);
    else failures.push({ run, path: 'baseline', outcome: directOutcome });

    const controller = await createDemoController({
      action: backend.action(changes),
      artifactPath: backend.artifactPath,
      inputPath: backend.inputPath,
      manifest,
      stateDirectory: path.join(workRoot, `${label}-${run}`),
      keylimeHandler: backend.keylimeHandler(),
    });
    controller.approve('operator');
    controller.approve('security');
    started = performance.now();
    const response = (await controller.execute('approved')).last_response;
    if (response.status === 200) gated.push(performance.now() - started);
    else failures.push({ run, path: 'gated', status: response.status, reason: response.body?.rejected?.reason || null });
  }
  const gatedStats = stats(gated);
  const baselineStats = stats(baseline);
  return {
    gated: gatedStats,
    baseline: baselineStats,
    overhead_median_ms: gatedStats.median_ms === null || baselineStats.median_ms === null
      ? null : Math.round((gatedStats.median_ms - baselineStats.median_ms) * 10) / 10,
    failures,
  };
}

// Writes `bytes` of pseudo-random data to `file` and returns its sha256 digest.
async function writeInput(file, bytes) {
  const chunk = crypto.randomBytes(1024 * 1024);
  let remaining = bytes;
  async function* chunks() {
    while (remaining > 0) {
      const size = Math.min(remaining, chunk.length);
      remaining -= size;
      yield chunk.subarray(0, size);
    }
  }
  await pipeline(chunks, createWriteStream(file, { mode: 0o600 }));
  const hash = crypto.createHash('sha256');
  await pipeline(createReadStream(file), hash);
  return `sha256:${hash.digest('hex')}`;
}

// Same paired measurement at realistic input sizes (local node only: the AWS
// node's input is a root-owned pinned file).
const NODE_MATERIAL_LIMIT_BYTES = 64 * 1024 * 1024;

async function measureScaling(backend, workRoot, manifest) {
  if (backend.mode !== 'local' || sizes.length === 0) return { sizes: [], over_limit: null };
  const original = await readFile(backend.inputPath);
  const results = [];
  let overLimit = null;
  try {
    for (const size of sizes) {
      const inputSha256 = await writeInput(backend.inputPath, size.bytes);
      const measured = await measureLatency(backend, workRoot, manifest, {
        runs: sizeRuns,
        changes: { input_sha256: inputSha256 },
        label: `size-${size.label}`,
      });
      process.stdout.write(`input ${size.label}: gated median ${measured.gated.median_ms} ms, `
        + `baseline median ${measured.baseline.median_ms} ms\n`);
      results.push({ input: size.label, bytes: size.bytes, ...measured });
    }
    // One byte-megabyte past the node's limit: must be refused, never launched.
    const overSize = NODE_MATERIAL_LIMIT_BYTES + 1024 * 1024;
    const inputSha256 = await writeInput(backend.inputPath, overSize);
    const action = backend.action({ input_sha256: inputSha256 });
    const before = await backend.processLaunches();
    const outcome = await backend.call({ ...action, permit: backend.kit.sign(action) });
    const after = await backend.processLaunches();
    overLimit = {
      bytes: overSize,
      outcome,
      launches: after - before,
      passed: outcome === 'refused' && after === before,
    };
  } finally {
    await writeFile(backend.inputPath, original, { mode: 0o600 });
  }
  return { sizes: results, over_limit: overLimit };
}

function aggregate(allTrials) {
  const byName = new Map();
  for (const records of allTrials) {
    for (const record of records) {
      if (record.passed === null) continue;
      const entry = byName.get(record.name) || {
        name: record.name,
        expected: record.expected,
        expected_launches_per_trial: record.expected_launches,
        trials: 0,
        passed: 0,
        launches: 0,
        excess_launches: 0,
      };
      entry.trials += 1;
      entry.passed += record.passed ? 1 : 0;
      entry.launches += record.launches;
      entry.excess_launches += Math.max(0, record.launches - record.expected_launches);
      byName.set(record.name, entry);
    }
  }
  return [...byName.values()];
}

async function main() {
  const runs = path.join(repositoryRoot, 'build', 'runs');
  await mkdir(runs, { recursive: true, mode: 0o700 });
  const workRoot = await mkdtemp(path.join(runs, 'demo3-trials-'));
  let backend;
  try {
    backend = mode === 'aws' ? await awsBackend(workRoot) : await localBackend(workRoot);
    const manifest = JSON.parse(await readFile(
      path.join(repositoryRoot, 'public', '.well-known', 'agent-actions.json'),
      'utf8',
    ));
    const allTrials = [];
    const startedAt = Date.now();
    for (let trial = 0; trial < trials; trial += 1) {
      const { records } = await runScenarios(backend, path.join(workRoot, `trial-${trial}`));
      allTrials.push(records);
      const passed = records.filter((record) => record.passed).length;
      const ran = records.filter((record) => record.passed !== null).length;
      process.stdout.write(`trial ${trial + 1}/${trials}: ${passed}/${ran}\n`);
    }
    const scenarios = aggregate(allTrials);
    const latency = await measureLatency(backend, workRoot, manifest);
    const scaling = await measureScaling(backend, workRoot, manifest);
    const scalingFailures = scaling.sizes.reduce((sum, entry) => sum + entry.failures.length, 0)
      + (scaling.over_limit && !scaling.over_limit.passed ? 1 : 0);
    const totals = {
      trials,
      scenario_runs: scenarios.reduce((sum, entry) => sum + entry.trials, 0),
      scenario_runs_passed: scenarios.reduce((sum, entry) => sum + entry.passed, 0),
      launches_observed: scenarios.reduce((sum, entry) => sum + entry.launches, 0),
      launches_expected: scenarios.reduce((sum, entry) => sum + entry.trials * entry.expected_launches_per_trial, 0),
      unauthorized_or_duplicate_launches: scenarios.reduce((sum, entry) => sum + entry.excess_launches, 0),
      duration_seconds: Math.round((Date.now() - startedAt) / 1000),
    };
    const status = totals.scenario_runs_passed === totals.scenario_runs
      && totals.unauthorized_or_duplicate_launches === 0
      && latency.failures.length === 0 && scalingFailures === 0 ? 'pass' : 'fail';
    const gitStatus = await commandOutput('git', ['status', '--porcelain', '--untracked-files=no']);
    const result = {
      schema_version: 1,
      experiment: 'demo3-trials',
      mode,
      status,
      generated_at: new Date().toISOString(),
      repository_revision: await commandOutput('git', ['rev-parse', 'HEAD']),
      repository_dirty: gitStatus === null ? null : gitStatus.length > 0,
      versions: { node: process.version },
      launch_evidence: backend.launchEvidence,
      ...backend.details,
      demo2_baseline: {
        runs_per_scenario: 1,
        node_side_checks: 'none: the node launched for any holder of the MCP bearer token',
        latency: 'not measured',
      },
      totals,
      scenarios,
      latency: {
        definition: 'gated = EMILIA receipt gate + controller + permit + node; baseline = the same node called directly with a valid permit (no quorum receipt, no controller gate). Approval time is excluded.',
        ...latency,
      },
      workload_scaling: {
        definition: 'Same paired measurement with the input replaced by pseudo-random data of each size. The node hashes the input before launch and the workload hashes it again. Demo 2 used a 32-byte input. The node reads at most 64 MiB of workload material and must refuse anything larger without launching.',
        runs_per_size: sizeRuns,
        node_material_limit_bytes: NODE_MATERIAL_LIMIT_BYTES,
        sizes: scaling.sizes,
        over_limit: scaling.over_limit,
      },
      limitations: [
        mode === 'local'
          ? 'Local mode: Keylime status is a stand-in socket; MCP, permits, ledger and execution are the real node code on this machine.'
          : 'AWS mode: launches are counted from the node ledger and accepted responses.',
        'Approver keys are fixture keys (automation); human approval is measured separately by demo3_human_approval.',
        'The baseline still includes the node\'s own permit and attestation checks, so overhead covers the controller-side gate only.',
      ],
    };
    await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
    const temporary = `${outputPath}.${crypto.randomBytes(8).toString('hex')}.tmp`;
    await writeFile(temporary, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, outputPath);
    process.stdout.write(`${outputPath}\n`);
    process.stdout.write(`${status}: ${totals.scenario_runs_passed}/${totals.scenario_runs} scenario runs, `
      + `${totals.unauthorized_or_duplicate_launches} unauthorized or duplicate launches; `
      + `gated median ${latency.gated.median_ms} ms (p95 ${latency.gated.p95_ms}), `
      + `baseline median ${latency.baseline.median_ms} ms\n`);
    if (status !== 'pass') process.exitCode = 1;
  } finally {
    if (backend) await backend.close();
    await rm(workRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`demo3-trials failed: ${error.message}\n`);
  process.exitCode = 1;
});
