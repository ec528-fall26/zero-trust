import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { chmod, mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  createAttestAndDeploy,
  readStatusSocket,
  runCommand,
} from '../src/keylime_mcp/attest_and_deploy.mjs';

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

test('the default runner passes verified descriptors to the child', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-runner-fd-'));
  try {
    const filePath = path.join(root, 'payload.txt');
    await writeFile(filePath, 'descriptor-bound\n', { mode: 0o600 });
    const handle = await open(filePath, 'r');
    try {
      const { stdout } = await runCommand('/bin/sh', ['-c', 'cat <&3'], {
        stdio: ['ignore', 'pipe', 'pipe', handle.fd],
      });
      assert.equal(stdout, 'descriptor-bound\n');
    } finally {
      await handle.close();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('the default runner fails closed on exit status, timeout, and output bound', async () => {
  await assert.rejects(runCommand('/bin/sh', ['-c', 'exit 3']), /unsuccessfully \(3\)/);
  const started = Date.now();
  await assert.rejects(
    runCommand('/bin/sh', ['-c', 'sleep 5; true'], { timeout: 200 }),
    /timed out/,
  );
  // The forked sleep must die with the shell, not hold the pipe open.
  assert.ok(Date.now() - started < 2_000);
  await assert.rejects(
    runCommand('/bin/sh', ['-c', 'head -c 4096 /dev/zero'], { maxBuffer: 1024 }),
    /exceeded the bound/,
  );
});

async function statusServer(socketPath, payload) {
  const server = net.createServer((connection) => connection.end(payload));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, resolve);
  });
  return server;
}

test('the status socket is read once and bounded', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-status-'));
  const socketPath = path.join(root, 's.sock');
  const server = await statusServer(socketPath, '{"agent_id":"a"}\n');
  try {
    const { stdout } = await readStatusSocket(socketPath);
    assert.equal(stdout, '{"agent_id":"a"}\n');
    await assert.rejects(readStatusSocket(socketPath, { maxBytes: 4 }), /response bound/);
    await assert.rejects(readStatusSocket(path.join(root, 'missing.sock')));
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});

test('exactly one Keylime status source must be configured', () => {
  const base = {
    artifactPath: '/a', inputPath: '/b', target: 't', agentId: 'x', policyVersion: 'p',
  };
  assert.throws(() => createAttestAndDeploy(base), /exactly one/);
  assert.throws(
    () => createAttestAndDeploy({ ...base, statusCommand: '/c', statusSocket: '/s' }),
    /exactly one/,
  );
});

test('on Linux the real runner executes the verified workload by descriptor', {
  skip: process.platform !== 'linux',
}, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-linux-exec-'));
  const socketPath = path.join(root, 's.sock');
  const now = Date.now();
  const server = await statusServer(socketPath, JSON.stringify({
    agent_id: 'agent-linux',
    results: {
      attestation_status: 'PASS',
      last_successful_attestation: Math.floor(now / 1_000),
    },
  }));
  try {
    const artifact = Buffer.from('#!/bin/sh\nset -eu\n[ "$#" -eq 1 ] || exit 64\nexec sha256sum "$1"\n');
    const input = Buffer.from('EC528 approved workload payload\n');
    const artifactPath = path.join(root, 'checksum.sh');
    const inputPath = path.join(root, 'input.txt');
    await writeFile(artifactPath, artifact, { mode: 0o755 });
    await writeFile(inputPath, input, { mode: 0o644 });
    await chmod(artifactPath, 0o755);
    const handler = createAttestAndDeploy({
      statusSocket: socketPath,
      artifactPath,
      inputPath,
      target: 'aws-keylime-demo-01',
      agentId: 'agent-linux',
      policyVersion: 'demo-2.1',
      requiredOwnerUid: process.getuid(),
      now: () => now,
    });
    const result = await handler({
      action_type: 'workload.execute',
      operation: 'checksum.sha256',
      target: 'aws-keylime-demo-01',
      artifact_sha256: digest(artifact),
      input_sha256: digest(input),
      occurrence_id: crypto.randomUUID(),
      policy_version: 'demo-2.1',
    });
    assert.equal(result.workload.executed, true);
    assert.ok(result.workload.stdout.startsWith(digest(input).slice(7)));
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});
