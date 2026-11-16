// Attacks against the node, sent over the real path: HTTP, bearer token, MCP
// protocol, tool schema, node handler, and real process execution.  Keylime's
// status comes from a local socket.  The workload appends a line to a file each
// time it runs, so every assertion counts launches rather than trusting an
// error code.  See experiments/local_node.mjs.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { digest, LOCAL_AGENT, LOCAL_TARGET, startLocalNode } from '../experiments/local_node.mjs';
import { createPermitFixture } from '../experiments/permit_fixture.mjs';
import { createKeylimeMcpHandler } from '../src/controller/keylime_mcp_client.mjs';
import { createDemoController } from '../src/demo/demo_controller.mjs';
import { PRE_ENROLLMENT_EPOCH } from '../src/keylime_mcp/permit.mjs';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TARGET = LOCAL_TARGET;
const AGENT = LOCAL_AGENT;
const linuxOnly = { skip: process.platform !== 'linux' };

async function withNode(run) {
  const node = await startLocalNode();
  try {
    await run(node);
  } finally {
    await node.stop();
  }
}

test('a valid permit launches the workload exactly once', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = node.action();
    assert.equal(await node.call({ ...action, permit: node.permits.sign(action) }), 'accepted');
    assert.equal(await node.launches(), 1);
    assert.equal((await node.ledger.read(action.occurrence_id)).state, 'succeeded');
  });
});

test('holding the bearer token is not enough to launch', linuxOnly, async () => {
  await withNode(async (node) => {
    assert.equal(await node.call(node.action()), 'refused');
    assert.equal(await node.launches(), 0);
  });
});

test('a wrong bearer token is refused even with a valid permit', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = node.action();
    const outcome = await node.call(
      { ...action, permit: node.permits.sign(action) },
      { token: 'x'.repeat(64) },
    );
    assert.equal(outcome, 'refused');
    assert.equal(await node.launches(), 0);
  });
});

test('forged, expired, and misdirected permits launch nothing', linuxOnly, async () => {
  await withNode(async (node) => {
    const now = Date.now();
    const attacker = createPermitFixture({
      target: TARGET,
      agentId: AGENT,
      enrollmentEpoch: node.permits.enrollmentEpoch,
    });
    const attempts = [
      (action) => attacker.sign(action),
      (action) => node.permits.signWith(action, { issued_at: now - 60_000, expires_at: now - 50_000 }),
      (action) => node.permits.signWith(action, { issued_at: now + 60_000, expires_at: now + 65_000 }),
      (action) => node.permits.signWith(action, { target: 'other-node' }),
      (action) => node.permits.signWith(action, { agent_uuid: 'a0000000-0000-4000-8000-000000000000' }),
      (action) => node.permits.sign(action, 'receipt', 'bootstrap_keylime_tenant'),
    ];
    for (const makePermit of attempts) {
      const action = node.action();
      assert.equal(await node.call({ ...action, permit: makePermit(action) }), 'refused');
      assert.equal(await node.ledger.read(action.occurrence_id), null);
    }
    assert.equal(await node.launches(), 0);
  });
});

test('a permit for one action cannot launch a different one', linuxOnly, async () => {
  await withNode(async (node) => {
    const approved = node.action();
    const permit = node.permits.sign(approved);
    for (const changed of [
      { ...approved, occurrence_id: crypto.randomUUID() },
      { ...approved, policy_version: 'demo-2.2' },
      { ...approved, input_sha256: digest('other input') },
      { ...approved, artifact_sha256: digest('other artifact') },
    ]) {
      assert.equal(await node.call({ ...changed, permit }), 'refused');
    }
    assert.equal(await node.launches(), 0);
  });
});

test('a permit from an old enrollment epoch launches nothing', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = node.action();
    const permit = node.permits.signWith(action, { enrollment_epoch: crypto.randomUUID() });
    assert.equal(await node.call({ ...action, permit }), 'refused');
    assert.equal(await node.launches(), 0);
  });
});

test('after re-enrollment, permits for the previous epoch stop working', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = node.action();
    const permit = node.permits.sign(action);
    node.keylime.epoch = crypto.randomUUID();
    assert.equal(await node.call({ ...action, permit }), 'refused');
    assert.equal(await node.launches(), 0);
  });
});

test('a node that has not been bootstrapped launches nothing', linuxOnly, async () => {
  await withNode(async (node) => {
    for (const epoch of [null, 'malformed']) {
      node.keylime.epoch = epoch;
      const action = node.action();
      assert.equal(await node.call({ ...action, permit: node.permits.sign(action) }), 'refused');
    }
    assert.equal(await node.launches(), 0);
  });
});

test('a workload permit carrying the bootstrap epoch launches nothing', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = node.action();
    const permit = node.permits.signWith(action, { enrollment_epoch: PRE_ENROLLMENT_EPOCH });
    assert.equal(await node.call({ ...action, permit }), 'refused');
    assert.equal(await node.launches(), 0);
  });
});

test('replaying a used permit does not launch again', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = node.action();
    const permit = node.permits.sign(action);
    assert.equal(await node.call({ ...action, permit }), 'accepted');
    assert.equal(await node.call({ ...action, permit }), 'refused');
    assert.equal(await node.launches(), 1);
  });
});

test('a new permit for an occurrence that already launched is refused', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = node.action();
    assert.equal(await node.call({ ...action, permit: node.permits.sign(action, 'one') }), 'accepted');
    assert.equal(await node.call({ ...action, permit: node.permits.sign(action, 'two') }), 'refused');
    assert.equal(await node.launches(), 1);
  });
});

test('ten simultaneous deliveries launch exactly once', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = node.action();
    const permit = node.permits.sign(action);
    const outcomes = await Promise.all(Array.from({ length: 10 }, () => (
      node.call({ ...action, permit })
    )));
    assert.equal(outcomes.filter((outcome) => outcome === 'accepted').length, 1);
    assert.equal(await node.launches(), 1);
  });
});

test('a repeat delivery after a service restart does not launch again', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = node.action();
    const permit = node.permits.sign(action);
    assert.equal(await node.call({ ...action, permit }), 'accepted');
    await node.restart();
    assert.equal(await node.call({ ...action, permit }), 'refused');
    assert.equal(await node.call({ ...action, permit: node.permits.sign(action, 'two') }), 'refused');
    assert.equal(await node.launches(), 1);
  });
});

test('failed or stale attestation blocks a valid permit without consuming it', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = node.action();
    node.keylime.status = 'FAIL';
    assert.equal(await node.call({ ...action, permit: node.permits.sign(action) }), 'refused');
    node.keylime.status = 'PASS';
    node.keylime.ageSeconds = 60;
    assert.equal(await node.call({ ...action, permit: node.permits.sign(action) }), 'refused');
    assert.equal(await node.launches(), 0);
    assert.equal(await node.ledger.read(action.occurrence_id), null);

    node.keylime.ageSeconds = 0;
    assert.equal(await node.call({ ...action, permit: node.permits.sign(action) }), 'accepted');
    assert.equal(await node.launches(), 1);
  });
});

test('changed workload bytes block a valid permit without consuming it', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = node.action();
    await writeFile(node.inputPath, 'substituted input\n');
    assert.equal(await node.call({ ...action, permit: node.permits.sign(action) }), 'refused');
    assert.equal(await node.launches(), 0);
    assert.equal(await node.ledger.read(action.occurrence_id), null);
  });
});

test('a failed launch stays consumed and is recorded as failed', linuxOnly, async () => {
  await withNode(async (node) => {
    let attempts = 0;
    await node.restart({
      commandRunner: async () => {
        attempts += 1;
        throw new Error('simulated spawn failure');
      },
    });
    const action = node.action();
    assert.equal(await node.call({ ...action, permit: node.permits.sign(action) }), 'refused');
    assert.equal((await node.ledger.read(action.occurrence_id)).state, 'failed');
    assert.equal(await node.call({ ...action, permit: node.permits.sign(action) }), 'refused');
    assert.equal(attempts, 1);
  });
});

test('a claim left by a crash prevents the launch', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = node.action();
    assert.equal(await node.ledger.reserve(action.occurrence_id), true);
    assert.equal(await node.call({ ...action, permit: node.permits.sign(action) }), 'refused');
    assert.equal(await node.launches(), 0);
    assert.equal((await node.ledger.read(action.occurrence_id)).state, 'reserved');
  });
});

test('the bootstrap tool needs its own valid permit', linuxOnly, async () => {
  await withNode(async (node) => {
    const action = {
      action_type: 'tenant.bootstrap',
      target: TARGET,
      agent_uuid: AGENT,
      runtime_policy_sha256: digest('runtime policy'),
      payload_sha256: digest('payload'),
      occurrence_id: crypto.randomUUID(),
      policy_version: 'demo-2.1',
    };
    const name = 'bootstrap_keylime_tenant';
    const refusedPermits = [
      node.permits.sign(action, 'receipt', name),
      node.bootstrapPermits.sign(action, 'receipt', 'attest_and_deploy'),
      node.bootstrapPermits.signWith(action, { enrollment_epoch: crypto.randomUUID() }, name),
    ];
    assert.equal(await node.call(action, { name }), 'refused');
    for (const permit of refusedPermits) {
      assert.equal(await node.call({ ...action, permit }, { name }), 'refused');
    }
    assert.equal(node.bootstrapCalls, 0);

    const permit = node.bootstrapPermits.sign(action, 'receipt', name);
    assert.equal(await node.call({ ...action, permit }, { name }), 'accepted');
    assert.equal(node.bootstrapCalls, 1);
  });
});

test('a real 2-of-3 receipt reaches the node as a permit and launches once', linuxOnly, async () => {
  await withNode(async (node) => {
    const manifest = JSON.parse(await readFile(
      path.join(repository, 'public', '.well-known', 'agent-actions.json'),
      'utf8',
    ));
    const controller = await createDemoController({
      action: node.action(),
      artifactPath: node.artifactPath,
      inputPath: node.inputPath,
      manifest,
      stateDirectory: path.join(node.root, 'controller'),
      keylimeHandler: createKeylimeMcpHandler({
        endpoint: node.endpoint.href,
        token: node.token,
        allowInsecureLoopback: true,
        timeoutMilliseconds: 10_000,
        permitSigner: node.permits.signer,
      }),
    });

    assert.equal((await controller.execute('missing')).last_response.status, 428);
    controller.approve('operator');
    assert.equal(controller.snapshot().receipt_ready, false);
    assert.equal(await node.launches(), 0);

    controller.approve('security');
    const approved = await controller.execute('approved');
    assert.equal(approved.last_response.status, 200, JSON.stringify(approved.last_response));
    assert.equal(approved.last_response.body.result.workload.executed, true);
    assert.equal(await node.launches(), 1);

    assert.equal((await controller.execute('replay')).last_response.status, 428);
    assert.equal(await node.launches(), 1);
  });
});
