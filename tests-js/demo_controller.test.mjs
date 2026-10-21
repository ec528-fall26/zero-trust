import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createDemoController } from '../src/demo/demo_controller.mjs';

function digest(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

test('live demo enforces quorum, exact action binding, and single use', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-live-demo-'));
  try {
    const artifactPath = path.join(root, 'artifact.sh');
    const inputPath = path.join(root, 'input.txt');
    const artifact = Buffer.from('#!/bin/sh\nexit 0\n', 'utf8');
    const input = Buffer.from('approved input\n', 'utf8');
    await Promise.all([
      writeFile(artifactPath, artifact, { mode: 0o700 }),
      writeFile(inputPath, input, { mode: 0o600 }),
    ]);
    const manifest = JSON.parse(await readFile(
      new URL('../public/.well-known/agent-actions.json', import.meta.url),
      'utf8',
    ));
    const action = {
      action_type: 'workload.execute',
      operation: 'checksum.sha256',
      target: 'azure-vm-demo-01',
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
      stateDirectory: root,
    });

    const missing = await controller.execute('missing');
    assert.equal(missing.last_response.status, 428);
    controller.approve('operator');
    assert.equal(controller.snapshot().receipt_ready, false);
    controller.approve('security');
    assert.equal(controller.snapshot().receipt_ready, true);

    const tampered = await controller.execute('tampered');
    assert.equal(tampered.last_response.status, 428);
    assert.equal(tampered.last_response.body.rejected.reason, 'action_hash_mismatch');

    const approved = await controller.execute('approved');
    assert.equal(approved.last_response.status, 200);
    assert.equal(approved.last_response.body.result.attestation.verdict, 'trusted');
    assert.equal(approved.last_response.body.result.workload.executed, true);

    const replay = await controller.execute('replay');
    assert.equal(replay.last_response.status, 428);
    assert.equal(replay.last_response.body.rejected.reason, 'replay_refused');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
