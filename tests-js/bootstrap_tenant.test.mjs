import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { createDemoController } from '../src/demo/demo_controller.mjs';
import { createBootstrapTenant } from '../src/keylime_mcp/bootstrap_tenant.mjs';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function action() {
  return {
    action_type: 'tenant.bootstrap',
    target: 'aws-keylime-demo-01',
    agent_uuid: 'd432fbb3-d2f1-4a97-9ef7-75bd81c00000',
    runtime_policy_sha256: `sha256:${'a'.repeat(64)}`,
    payload_sha256: `sha256:${'b'.repeat(64)}`,
    occurrence_id: crypto.randomUUID(),
    policy_version: 'demo-2.1',
  };
}

test('tenant bootstrap needs two approvals and is bound to the exact digests', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-bootstrap-test-'));
  try {
    const manifest = JSON.parse(await readFile(
      path.join(repository, 'public', '.well-known', 'agent-actions.json'),
      'utf8',
    ));
    const approved = action();
    let calls = 0;
    const controller = await createDemoController({
      action: approved,
      artifactPath: path.join(root, 'unused-artifact'),
      inputPath: path.join(root, 'unused-input'),
      manifest,
      stateDirectory: root,
      toolName: 'bootstrap_keylime_tenant',
      keylimeHandler: async (observed) => {
        calls += 1;
        assert.deepEqual(observed, approved);
        return {
          status: 'enrolled',
          agent_uuid: observed.agent_uuid,
          runtime_policy_sha256: observed.runtime_policy_sha256,
          payload_sha256: observed.payload_sha256,
          occurrence_id: observed.occurrence_id,
          measured_boot: false,
        };
      },
    });
    assert.equal((await controller.execute('missing')).last_response.status, 428);
    controller.approve('operator');
    assert.equal(controller.evidence(), null);
    controller.approve('security');
    const result = await controller.execute('approved');
    assert.equal(result.last_response.status, 200, JSON.stringify(result.last_response));
    assert.equal(calls, 1);
    assert.equal((await controller.execute('replay')).last_response.status, 428);
    assert.equal(calls, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('node bootstrap helper client refuses a result bound to other material', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-bootstrap-socket-'));
  const socketPath = path.join(root, 'bootstrap.sock');
  const approved = action();
  const server = net.createServer((socket) => {
    socket.once('data', () => socket.end(JSON.stringify({
      status: 'enrolled',
      agent_uuid: approved.agent_uuid,
      runtime_policy_sha256: `sha256:${'c'.repeat(64)}`,
      payload_sha256: approved.payload_sha256,
      occurrence_id: approved.occurrence_id,
      measured_boot: false,
    })));
  });
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(socketPath, resolve);
    });
    const bootstrap = createBootstrapTenant({ socketPath, timeoutMilliseconds: 2_000 });
    await assert.rejects(bootstrap(approved), /not bound/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});
