import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  clockSkewSeconds,
  createKeylimeMcpHandler,
  validateKeylimeResult,
} from '../src/controller/keylime_mcp_client.mjs';
import { createPermitFixture } from '../experiments/permit_fixture.mjs';

const action = Object.freeze({
  action_type: 'workload.execute',
  operation: 'checksum.sha256',
  target: 'azure-vm-demo-01',
  artifact_sha256: `sha256:${'a'.repeat(64)}`,
  input_sha256: `sha256:${'b'.repeat(64)}`,
  occurrence_id: 'd24f4f93-e555-4d48-93aa-a2c16c53a24f',
  policy_version: 'demo-2.1',
});

function acceptedResult(changes = {}) {
  return {
    attestation: {
      provider: 'keylime',
      verdict: 'trusted',
      target: action.target,
      policy_version: action.policy_version,
      occurrence_id: action.occurrence_id,
      attested_at: new Date().toISOString(),
      age_seconds: 0,
      node_time: new Date().toISOString(),
      evidence_digest: `sha256:${'c'.repeat(64)}`,
      ...changes,
    },
    workload: {
      executed: true,
      operation: action.operation,
      artifact_sha256: action.artifact_sha256,
      input_sha256: action.input_sha256,
    },
  };
}

test('Keylime contract accepts fresh evidence bound to the exact action', () => {
  const result = acceptedResult();
  assert.equal(validateKeylimeResult(result, action), result);
});

test('Keylime contract fails closed on a different occurrence', () => {
  assert.throws(
    () => validateKeylimeResult(acceptedResult({ occurrence_id: crypto.randomUUID() }), action),
    /another action/,
  );
});

test('Keylime contract refuses an attestation timestamp from the future', () => {
  const now = Date.now();
  assert.throws(
    () => validateKeylimeResult(
      acceptedResult({ attested_at: new Date(now + 6_000).toISOString() }),
      action,
      { now },
    ),
    /invalid timestamp/,
  );
});

test('Keylime contract judges freshness on the age the node measured', () => {
  const now = Date.now();
  const node = (ageSeconds) => ({
    attested_at: new Date(now - ageSeconds * 1_000).toISOString(),
    age_seconds: ageSeconds,
    node_time: new Date(now).toISOString(),
  });
  assert.doesNotThrow(() => validateKeylimeResult(acceptedResult(node(29)), action, { now }));
  assert.throws(
    () => validateKeylimeResult(acceptedResult(node(31)), action, { now }),
    /stale/,
  );
});

test('Keylime contract refuses an age that its own timestamps do not support', () => {
  const now = Date.now();
  assert.throws(
    () => validateKeylimeResult(
      acceptedResult({
        attested_at: new Date(now - 60_000).toISOString(),
        age_seconds: 0,
        node_time: new Date(now).toISOString(),
      }),
      action,
      { now },
    ),
    /inconsistent/,
  );
});

test('Keylime contract refuses a result from a node that does not report its age', () => {
  const result = acceptedResult();
  delete result.attestation.age_seconds;
  assert.throws(() => validateKeylimeResult(result, action), /stale or has an invalid/);
  const withoutClock = acceptedResult();
  delete withoutClock.attestation.node_time;
  assert.throws(() => validateKeylimeResult(withoutClock, action), /stale or has an invalid/);
  assert.throws(
    () => validateKeylimeResult(acceptedResult({ age_seconds: -1 }), action),
    /stale or has an invalid/,
  );
});

test('Keylime contract bounds the node clock against the controller clock', () => {
  const now = Date.now();
  const atNode = (offsetMs) => acceptedResult({
    attested_at: new Date(now + offsetMs).toISOString(),
    age_seconds: 0,
    node_time: new Date(now + offsetMs).toISOString(),
  });
  assert.throws(
    () => validateKeylimeResult(atNode(60_000), action, { now }),
    /allowed skew/,
  );
  assert.throws(
    () => validateKeylimeResult(atNode(-60_000), action, { now }),
    /allowed skew/,
  );
  assert.doesNotThrow(() => validateKeylimeResult(atNode(3_000), action, { now }));
  // A slow workload is not skew: the node clock reading falls inside the
  // interval in which the controller was waiting.
  assert.doesNotThrow(() => validateKeylimeResult(atNode(8_000), action, {
    requestedAt: now,
    receivedAt: now + 12_000,
  }));
});

test('clock skew is zero inside the wait window and grows outside it', () => {
  assert.equal(clockSkewSeconds(5_000, 0, 10_000), 0);
  assert.equal(clockSkewSeconds(-4_000, 0, 10_000), 4);
  assert.equal(clockSkewSeconds(70_000, 0, 10_000), 60);
});

test('invalid timing policy fails closed before a Keylime call', () => {
  for (const options of [
    { maximumAgeSeconds: Number.NaN },
    { maximumAgeSeconds: 0 },
    { maximumSkewSeconds: Number.NaN },
    { maximumSkewSeconds: -1 },
    { requestedAt: 2, receivedAt: 1 },
  ]) {
    assert.throws(
      () => validateKeylimeResult(acceptedResult(), action, options),
      /invalid (maximum|controller timing)/,
    );
  }
  assert.throws(
    () => createKeylimeMcpHandler({
      endpoint: 'https://keylime.example.test/mcp',
      token: 'a'.repeat(64),
      maximumAttestationAgeSeconds: Number.NaN,
    }),
    /invalid maximum attestation age/,
  );
});

test('Keylime MCP handler closes its client and returns validated structured output', async () => {
  let closed = false;
  let sent;
  const permits = createPermitFixture({ target: action.target, agentId: 'agent-test' });
  const handler = createKeylimeMcpHandler({
    endpoint: 'https://keylime.example.test/mcp',
    token: 'a'.repeat(64),
    permitSigner: permits.signer,
    clientFactory: async () => ({
      callTool: async ({ arguments: toolArguments }) => {
        sent = toolArguments;
        return { structuredContent: acceptedResult() };
      },
      close: async () => { closed = true; },
    }),
  });
  const result = await handler(action, { receiptId: 'receipt-1' });
  assert.equal(result.attestation.verdict, 'trusted');
  assert.equal(closed, true);
  const { permit, ...sentAction } = sent;
  assert.deepEqual(sentAction, action);
  assert.equal(permits.verifier.verify(permit, { tool: 'attest_and_deploy', action }).target, action.target);
});

test('the Keylime MCP client cannot be built without a permit signer', () => {
  assert.throws(
    () => createKeylimeMcpHandler({
      endpoint: 'https://keylime.example.test/mcp',
      token: 'a'.repeat(64),
    }),
    /permit signer is required/,
  );
});

test('the Keylime MCP client sends nothing without a verified receipt', async () => {
  let calls = 0;
  const permits = createPermitFixture({ target: action.target, agentId: 'agent-test' });
  const handler = createKeylimeMcpHandler({
    endpoint: 'https://keylime.example.test/mcp',
    token: 'a'.repeat(64),
    permitSigner: permits.signer,
    clientFactory: async () => ({
      callTool: async () => { calls += 1; return { structuredContent: acceptedResult() }; },
      close: async () => {},
    }),
  });
  await assert.rejects(handler(action), /failed closed/);
  assert.equal(calls, 0);
});

test('plain HTTP is refused for a non-loopback Keylime MCP server', () => {
  assert.throws(
    () => createKeylimeMcpHandler({
      endpoint: 'http://keylime.example.test/mcp',
      token: 'a'.repeat(64),
    }),
    /requires HTTPS/,
  );
});

test('Keylime MCP transport failure is converted to a fail-closed decision', async () => {
  const permits = createPermitFixture({ target: action.target, agentId: 'agent-test' });
  const handler = createKeylimeMcpHandler({
    endpoint: 'https://keylime.example.test/mcp',
    token: 'a'.repeat(64),
    permitSigner: permits.signer,
    clientFactory: async () => ({
      callTool: async () => { throw new Error('verifier unavailable'); },
      close: async () => {},
    }),
  });
  await assert.rejects(handler(action, { receiptId: 'receipt-1' }), /failed closed/);
});
