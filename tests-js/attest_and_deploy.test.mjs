import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createAttestAndDeploy } from '../src/keylime_mcp/attest_and_deploy.mjs';

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

test('Keylime handler requires fresh PASS status and protected approved material', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-keylime-handler-'));
  try {
    const artifact = Buffer.from('#!/bin/sh\nexit 0\n', 'utf8');
    const input = Buffer.from('approved payload\n', 'utf8');
    const artifactPath = path.join(root, 'workload.sh');
    const inputPath = path.join(root, 'input.txt');
    await Promise.all([
      writeFile(artifactPath, artifact, { mode: 0o700 }),
      writeFile(inputPath, input, { mode: 0o600 }),
    ]);
    await chmod(root, 0o700);
    const now = Date.now();
    const calls = [];
    const runner = async (command, args, options) => {
      calls.push({ command, args, options });
      if (command === '/fixed/status') {
        return {
          stdout: JSON.stringify({
            agent_id: 'agent-test',
            results: {
              attestation_status: 'PASS',
              last_successful_attestation: Math.floor(now / 1_000),
            },
          }),
          stderr: '',
        };
      }
      return { stdout: `${digest(input).slice(7)}  input.txt\n`, stderr: '' };
    };
    const handler = createAttestAndDeploy({
      statusCommand: '/fixed/status',
      artifactPath,
      inputPath,
      target: 'azure-vm-demo-01',
      agentId: 'agent-test',
      policyVersion: 'demo-2.1',
      requiredOwnerUid: process.getuid(),
      now: () => now,
      commandRunner: runner,
    });
    const action = {
      action_type: 'workload.execute',
      operation: 'checksum.sha256',
      target: 'azure-vm-demo-01',
      artifact_sha256: digest(artifact),
      input_sha256: digest(input),
      occurrence_id: crypto.randomUUID(),
      policy_version: 'demo-2.1',
    };
    const result = await handler(action);
    assert.equal(result.attestation.verdict, 'trusted');
    assert.equal(result.attestation.occurrence_id, action.occurrence_id);
    assert.equal(result.workload.executed, true);
    assert.equal(result.workload.artifact_sha256, action.artifact_sha256);
    assert.equal(calls[1].command, '/proc/self/fd/3');
    assert.deepEqual(calls[1].args, ['/proc/self/fd/4']);
    assert.equal(calls[1].options.stdio.length, 5);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('Keylime handler rejects status for another agent before execution', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-keylime-agent-binding-'));
  try {
    const artifact = Buffer.from('#!/bin/sh\nexit 0\n', 'utf8');
    const input = Buffer.from('approved payload\n', 'utf8');
    const artifactPath = path.join(root, 'workload.sh');
    const inputPath = path.join(root, 'input.txt');
    await Promise.all([
      writeFile(artifactPath, artifact, { mode: 0o700 }),
      writeFile(inputPath, input, { mode: 0o600 }),
    ]);
    const now = Date.now();
    let executions = 0;
    const handler = createAttestAndDeploy({
      statusCommand: '/fixed/status',
      artifactPath,
      inputPath,
      target: 'azure-vm-demo-01',
      agentId: 'agent-expected',
      policyVersion: 'demo-2.1',
      requiredOwnerUid: process.getuid(),
      now: () => now,
      commandRunner: async (command) => {
        if (command !== '/fixed/status') executions += 1;
        return {
          stdout: JSON.stringify({
            agent_id: 'agent-attacker',
            results: {
              attestation_status: 'PASS',
              last_successful_attestation: Math.floor(now / 1_000),
            },
          }),
          stderr: '',
        };
      },
    });
    await assert.rejects(handler({
      action_type: 'workload.execute',
      operation: 'checksum.sha256',
      target: 'azure-vm-demo-01',
      artifact_sha256: digest(artifact),
      input_sha256: digest(input),
      occurrence_id: crypto.randomUUID(),
      policy_version: 'demo-2.1',
    }), /another agent/);
    assert.equal(executions, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('Keylime handler rejects ambiguous status output', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-keylime-ambiguous-'));
  try {
    const artifactPath = path.join(root, 'workload.sh');
    const inputPath = path.join(root, 'input.txt');
    await Promise.all([
      writeFile(artifactPath, '#!/bin/sh\nexit 0\n', { mode: 0o700 }),
      writeFile(inputPath, 'payload\n', { mode: 0o600 }),
    ]);
    const handler = createAttestAndDeploy({
      statusCommand: '/fixed/status',
      artifactPath,
      inputPath,
      target: 'azure-vm-demo-01',
      agentId: 'agent-test',
      policyVersion: 'demo-2.1',
      requiredOwnerUid: process.getuid(),
      commandRunner: async () => ({ stdout: '{}\n{}', stderr: '' }),
    });
    await assert.rejects(handler({
      action_type: 'workload.execute',
      operation: 'checksum.sha256',
      target: 'azure-vm-demo-01',
      artifact_sha256: digest('#!/bin/sh\nexit 0\n'),
      input_sha256: digest('payload\n'),
      occurrence_id: crypto.randomUUID(),
      policy_version: 'demo-2.1',
    }), /ambiguous JSON/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
