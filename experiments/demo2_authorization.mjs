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
import { DurableReceiptStore } from '../src/controller/receipt_required_mcp.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputPath = path.resolve(
  process.argv[2] || path.join(repositoryRoot, 'results', 'demo2-authorization.json'),
);
const LIMITATIONS = Object.freeze([
  'swtpm is not a hardware root of trust.',
  'The Keylime verifier, registrar, agent, swtpm and MCP all run on the same instance they are checking. This proves the protocol works, not independent attestation.',
  'The three EMILIA signer keys are on one machine. This proves the protocol works, not independent human approval.',
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
  const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), 'ec528-demo2-auth-'));
  const scenarios = [];
  let verifiedReceipt = null;
  try {
    const artifactPath = path.join(temporaryRoot, 'approved-workload.sh');
    const inputPath = path.join(temporaryRoot, 'approved-input.txt');
    const artifact = Buffer.from('#!/bin/sh\nsha256sum "$1"\n', 'utf8');
    const input = Buffer.from('EC528 approved input\n', 'utf8');
    await Promise.all([
      writeFile(artifactPath, artifact, { mode: 0o700 }),
      writeFile(inputPath, input, { mode: 0o600 }),
    ]);
    await chmod(artifactPath, 0o700);
    const manifest = JSON.parse(await readFile(
      path.join(repositoryRoot, 'public', '.well-known', 'agent-actions.json'),
      'utf8',
    ));
    const packageMetadata = JSON.parse(await readFile(
      path.join(repositoryRoot, 'package.json'),
      'utf8',
    ));
    const action = {
      action_type: 'workload.execute',
      operation: 'checksum.sha256',
      target: 'aws-keylime-demo-01',
      artifact_sha256: digest(artifact),
      input_sha256: digest(input),
      occurrence_id: crypto.randomUUID(),
      policy_version: 'demo-2.1',
    };
    const controller = await createDemoController({
      action,
      artifactPath,
      inputPath,
      manifest,
      stateDirectory: temporaryRoot,
    });

    const missing = await controller.execute('missing');
    assert.equal(missing.last_response.status, 428);
    scenarios.push({ name: 'missing_receipt', passed: true, observed: 'refused' });

    controller.approve('operator');
    assert.equal(controller.snapshot().receipt_ready, false);
    scenarios.push({ name: 'one_signer_pending', passed: true, observed: 'pending' });

    controller.approve('operator');
    assert.equal(controller.snapshot().approvals.length, 1);
    scenarios.push({ name: 'duplicate_signer', passed: true, observed: 'not_counted_twice' });

    assert.throws(() => controller.approve('untrusted'), /unknown demo approver role/);
    assert.equal(controller.snapshot().approvals.length, 1);
    scenarios.push({ name: 'untrusted_signer', passed: true, observed: 'refused' });

    controller.approve('security');
    assert.equal(controller.snapshot().receipt_ready, true);
    verifiedReceipt = controller.evidence();
    scenarios.push({ name: 'two_distinct_signers', passed: true, observed: 'receipt_issued' });

    const tampered = await controller.execute('tampered');
    assert.equal(tampered.last_response.status, 428);
    assert.equal(tampered.last_response.body.rejected.reason, 'action_hash_mismatch');
    scenarios.push({ name: 'receipt_target_binding', passed: true, observed: 'action_hash_mismatch' });

    const approved = await controller.execute('approved');
    assert.equal(approved.last_response.status, 200);
    scenarios.push({ name: 'exact_action', passed: true, observed: 'executed_once' });

    const replay = await controller.execute('replay');
    assert.equal(replay.last_response.status, 428);
    assert.equal(replay.last_response.body.rejected.reason, 'replay_refused');
    scenarios.push({ name: 'immediate_replay', passed: true, observed: 'replay_refused' });

    const restartedStore = await new DurableReceiptStore(
      path.join(temporaryRoot, 'receipt-store'),
    ).initialize();
    const reservedAfterRestart = await restartedStore.reserve(
      verifiedReceipt.payload.receipt_id,
    );
    assert.equal(reservedAfterRestart, false);
    scenarios.push({ name: 'replay_after_restart', passed: true, observed: 'durably_unavailable' });

    const expiredRoot = path.join(temporaryRoot, 'expired');
    const expiredController = await createDemoController({
      action: { ...action, occurrence_id: crypto.randomUUID() },
      artifactPath,
      inputPath,
      manifest,
      stateDirectory: expiredRoot,
      receiptCreatedAt: new Date(Date.now() - 20 * 60 * 1_000).toISOString(),
    });
    expiredController.approve('operator');
    expiredController.approve('security');
    const expired = await expiredController.execute('approved');
    assert.equal(expired.last_response.status, 428);
    scenarios.push({
      name: 'expired_evidence',
      passed: true,
      observed: expired.last_response.body.rejected.reason,
    });

    let simulatedNow = Date.now();
    const pendingController = await createDemoController({
      action: { ...action, occurrence_id: crypto.randomUUID() },
      artifactPath,
      inputPath,
      manifest,
      stateDirectory: path.join(temporaryRoot, 'pending'),
      approvalWindowMs: 1_000,
      now: () => simulatedNow,
    });
    pendingController.approve('operator');
    simulatedNow += 1_001;
    assert.equal(pendingController.snapshot().approval_status, 'expired');
    assert.throws(() => pendingController.approve('security'), /approval window expired/);
    scenarios.push({ name: 'one_signer_expiry', passed: true, observed: 'expired_without_execution' });

    const gitStatus = await requiredCommandOutput(
      'git', ['status', '--porcelain', '--untracked-files=all'],
    );
    const result = {
      schema_version: 1,
      experiment: 'demo2-authorization',
      status: 'pass',
      generated_at: new Date().toISOString(),
      repository_revision: await requiredCommandOutput('git', ['rev-parse', 'HEAD']),
      repository_dirty: gitStatus.length > 0,
      versions: {
        nono: await commandOutput('nono', ['--version']),
        node: process.version,
        emilia_require_receipt: packageMetadata.dependencies['@emilia-protocol/require-receipt'],
      },
      action,
      scenarios,
      verified_receipts: [verifiedReceipt],
      limitations: [...LIMITATIONS],
    };
    await writeResult(result);
    process.stdout.write(`${outputPath}\n`);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

main().catch(async (error) => {
  await writeResult({
    schema_version: 1,
    experiment: 'demo2-authorization',
    status: 'fail',
    generated_at: new Date().toISOString(),
    error: error instanceof Error ? error.message : 'unknown error',
  });
  process.stderr.write(`demo2 authorization failed: ${error.message}\n`);
  process.exitCode = 1;
});
