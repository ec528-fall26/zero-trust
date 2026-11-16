// Experiment: time drift.
//
// Claims:
//  1. A receipt is only good for its max age (120 s by default), so one that
//     sat around is refused even though its signatures are valid.
//  2. Attestation freshness is judged on the node's own clock, and the node
//     clock is bounded against the controller's, so a skewed clock is refused
//     instead of silently making the freshness check meaningless.
//
// Real components: the 2-of-3 demo controller with real receipts, and the
// node's attest-and-deploy handler.  Stand-in: the Keylime status it reads is a
// fixed PASS document whose timestamp the experiment controls.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { createDemoController } from '../src/demo/demo_controller.mjs';
import { manifestWithReceiptMaxAge } from '../src/controller/receipt_required_mcp.mjs';
import { clockSkewSeconds, validateKeylimeResult } from '../src/controller/keylime_mcp_client.mjs';
import { createAttestAndDeploy } from '../src/keylime_mcp/attest_and_deploy.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputPath = path.resolve(
  process.argv[2] || path.join(repositoryRoot, 'results', 'drift-time.json'),
);
const TARGET = 'aws-keylime-demo-01';
const AGENT_ID = 'agent-drift-time';
const POLICY_VERSION = 'demo-2.1';
const LIMITATIONS = Object.freeze([
  'The node handler is the real attest-and-deploy code, but the Keylime status it reads is a fixed PASS document and the clock offsets are injected. No TPM, Keylime service or second machine is involved.',
  'Receipt age is checked by the EMILIA gate against the controller clock. A skewed controller clock is not detected by this experiment.',
  'The controller trusts the node to report its own age and clock honestly. A compromised node can lie about both, which is why the age is only checked for consistency, not trusted for security.',
  'Approver and issuer keys are ephemeral local demo keys on one machine.',
]);

function digest(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

async function commandOutput(command, args) {
  try {
    const { stdout } = await execFileAsync(command, args, {
      cwd: repositoryRoot,
      timeout: 5_000,
      windowsHide: true,
    });
    return stdout.trim();
  } catch {
    return null;
  }
}

async function requiredCommandOutput(command, args) {
  const { stdout } = await execFileAsync(command, args, {
    cwd: repositoryRoot,
    timeout: 30_000,
    windowsHide: true,
  });
  return stdout.trim();
}

async function writeResult(result) {
  await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  const temporary = `${outputPath}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  await writeFile(temporary, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, outputPath);
}

async function main() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-drift-time-'));
  const scenarios = [];
  try {
    const artifactPath = path.join(root, 'approved-workload.sh');
    const inputPath = path.join(root, 'approved-input.txt');
    const artifact = Buffer.from('#!/bin/sh\nsha256sum "$1"\n', 'utf8');
    const input = Buffer.from('EC528 approved input\n', 'utf8');
    await Promise.all([
      writeFile(artifactPath, artifact, { mode: 0o700 }),
      writeFile(inputPath, input, { mode: 0o600 }),
    ]);
    await chmod(artifactPath, 0o700);
    await chmod(root, 0o700);
    const manifest = JSON.parse(await readFile(
      path.join(repositoryRoot, 'public', '.well-known', 'agent-actions.json'),
      'utf8',
    ));
    const packageMetadata = JSON.parse(await readFile(
      path.join(repositoryRoot, 'package.json'),
      'utf8',
    ));
    const receiptMaxAge = manifest.actions.find((entry) => entry.receipt_required).max_age_sec;
    const action = () => ({
      action_type: 'workload.execute',
      operation: 'checksum.sha256',
      target: TARGET,
      artifact_sha256: digest(artifact),
      input_sha256: digest(input),
      occurrence_id: crypto.randomUUID(),
      policy_version: POLICY_VERSION,
    });

    // ---- receipt lifetime ---------------------------------------------------
    async function executeWithReceiptAge(ageSeconds, usedManifest = manifest) {
      const stateDirectory = path.join(root, `receipt-${crypto.randomUUID()}`);
      await mkdir(stateDirectory, { mode: 0o700 });
      const controller = await createDemoController({
        action: action(),
        artifactPath,
        inputPath,
        manifest: usedManifest,
        stateDirectory,
        receiptCreatedAt: new Date(Date.now() - ageSeconds * 1_000).toISOString(),
      });
      controller.approve('operator');
      controller.approve('security');
      return (await controller.execute('approved')).last_response;
    }

    const young = await executeWithReceiptAge(30);
    assert.equal(young.status, 200);
    scenarios.push({
      name: 'receipt_30s_old_executes',
      passed: true,
      observed: 'executed_once',
      max_age_sec: receiptMaxAge,
    });

    const old = await executeWithReceiptAge(150);
    assert.equal(old.status, 428);
    assert.equal(old.body.rejected.reason, 'receipt_expired');
    scenarios.push({
      name: 'receipt_150s_old_refused',
      passed: true,
      observed: old.body.rejected.reason,
      max_age_sec: receiptMaxAge,
    });

    const slow = await executeWithReceiptAge(150, manifestWithReceiptMaxAge(manifest, 900));
    assert.equal(slow.status, 200);
    scenarios.push({
      name: 'slow_approver_setting_accepts_150s',
      passed: true,
      observed: 'executed_once',
      max_age_sec: 900,
    });

    // ---- attestation age and clock skew ------------------------------------
    // Build the real node handler on a clock `clockOffsetMs` away from this
    // machine's, over a Keylime status whose last attestation is
    // `attestationAgeSeconds` old on that same node clock.
    function nodeHandler({ clockOffsetMs = 0, attestationAgeSeconds = 5 }) {
      const nodeNow = () => Date.now() + clockOffsetMs;
      let workloadRuns = 0;
      const handler = createAttestAndDeploy({
        statusCommand: '/fixed/status',
        artifactPath,
        inputPath,
        target: TARGET,
        agentId: AGENT_ID,
        policyVersion: POLICY_VERSION,
        requiredOwnerUid: process.getuid(),
        now: nodeNow,
        commandRunner: async (command) => {
          if (command === '/fixed/status') {
            return {
              stdout: JSON.stringify({
                agent_id: AGENT_ID,
                results: {
                  attestation_status: 'PASS',
                  last_successful_attestation:
                    Math.floor(nodeNow() / 1_000) - attestationAgeSeconds,
                },
              }),
              stderr: '',
            };
          }
          workloadRuns += 1;
          return { stdout: `${digest(input).slice(7)}  input.txt\n`, stderr: '' };
        },
      });
      return { handler, runs: () => workloadRuns };
    }

    async function controllerView(node, mutate = (result) => result) {
      const approved = action();
      const requestedAt = Date.now();
      const result = mutate(await node.handler(approved));
      const receivedAt = Date.now();
      const nodeTime = Date.parse(result.attestation.node_time);
      return {
        approved,
        result,
        skew: clockSkewSeconds(nodeTime, requestedAt, receivedAt),
        validate: () => validateKeylimeResult(result, approved, { requestedAt, receivedAt }),
      };
    }

    {
      const node = nodeHandler({ attestationAgeSeconds: 5 });
      const view = await controllerView(node);
      view.validate();
      assert.ok(view.result.attestation.age_seconds >= 5 && view.result.attestation.age_seconds < 7);
      scenarios.push({
        name: 'fresh_attestation_accepted',
        passed: true,
        observed: 'accepted',
        reported_age_seconds: view.result.attestation.age_seconds,
        measured_skew_seconds: view.skew,
      });
    }

    {
      const node = nodeHandler({ attestationAgeSeconds: 45 });
      await assert.rejects(node.handler(action()), /stale/);
      assert.equal(node.runs(), 0);
      scenarios.push({
        name: 'stale_attestation_refused_by_node',
        passed: true,
        observed: 'node_refused_workload_not_run',
        attestation_age_seconds: 45,
      });
    }

    {
      const node = nodeHandler({ attestationAgeSeconds: 5 });
      const view = await controllerView(node, (result) => ({
        ...result,
        attestation: { ...result.attestation, age_seconds: 0 },
      }));
      assert.throws(view.validate, /inconsistent/);
      scenarios.push({
        name: 'age_not_supported_by_timestamps_refused',
        passed: true,
        observed: 'age_inconsistent_with_timestamps',
      });
    }

    for (const [name, offsetSeconds] of [
      ['node_clock_ahead_60s_refused', 60],
      ['node_clock_behind_60s_refused', -60],
    ]) {
      const node = nodeHandler({ clockOffsetMs: offsetSeconds * 1_000, attestationAgeSeconds: 5 });
      const view = await controllerView(node);
      // The node is internally consistent: it accepted its own attestation.
      assert.equal(node.runs(), 1);
      assert.ok(Math.abs(view.skew - 60) < 2, `measured skew ${view.skew}`);
      assert.throws(view.validate, /allowed skew/);
      scenarios.push({
        name,
        passed: true,
        observed: 'clock_skew_refused',
        injected_offset_seconds: offsetSeconds,
        measured_skew_seconds: Math.round(view.skew * 10) / 10,
      });
    }

    {
      // A workload that takes 12 s is not clock skew: the node's clock reading
      // (8 s in) lies inside the interval the controller waited.
      const t0 = Date.now();
      const approved = action();
      const result = {
        attestation: {
          provider: 'keylime',
          verdict: 'trusted',
          target: TARGET,
          policy_version: POLICY_VERSION,
          occurrence_id: approved.occurrence_id,
          attested_at: new Date(t0 + 3_000).toISOString(),
          age_seconds: 5,
          node_time: new Date(t0 + 8_000).toISOString(),
          evidence_digest: `sha256:${'c'.repeat(64)}`,
        },
        workload: {
          executed: true,
          operation: approved.operation,
          artifact_sha256: approved.artifact_sha256,
          input_sha256: approved.input_sha256,
        },
      };
      result.attestation.attested_at = new Date(t0 + 3_000).toISOString();
      validateKeylimeResult(result, approved, { requestedAt: t0, receivedAt: t0 + 12_000 });
      scenarios.push({
        name: 'slow_workload_not_flagged_as_skew',
        passed: true,
        observed: 'accepted',
        measured_skew_seconds: 0,
      });
    }

    const gitStatus = await requiredCommandOutput(
      'git', ['status', '--porcelain', '--untracked-files=all'],
    );
    await writeResult({
      schema_version: 1,
      experiment: 'drift-time',
      status: 'pass',
      generated_at: new Date().toISOString(),
      repository_revision: await requiredCommandOutput('git', ['rev-parse', 'HEAD']),
      repository_dirty: gitStatus.length > 0,
      versions: {
        nono: await commandOutput('nono', ['--version']),
        node: process.version,
        emilia_require_receipt: packageMetadata.dependencies['@emilia-protocol/require-receipt'],
      },
      receipt_max_age_sec: receiptMaxAge,
      scenarios,
      limitations: [...LIMITATIONS],
    });
    process.stdout.write(`${outputPath}\n`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

main().catch(async (error) => {
  await writeResult({
    schema_version: 1,
    experiment: 'drift-time',
    status: 'fail',
    generated_at: new Date().toISOString(),
    error: error instanceof Error ? error.message : 'unknown error',
  });
  process.stderr.write(`drift time failed: ${error.stack || error.message}\n`);
  process.exitCode = 1;
});
