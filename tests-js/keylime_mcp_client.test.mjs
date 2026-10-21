import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  createKeylimeMcpHandler,
  validateKeylimeResult,
} from '../src/controller/keylime_mcp_client.mjs';

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

test('Keylime MCP handler closes its client and returns validated structured output', async () => {
  let closed = false;
  const handler = createKeylimeMcpHandler({
    endpoint: 'https://keylime.example.test/mcp',
    token: 'a'.repeat(64),
    clientFactory: async () => ({
      callTool: async () => ({ structuredContent: acceptedResult() }),
      close: async () => { closed = true; },
    }),
  });
  const result = await handler(action);
  assert.equal(result.attestation.verdict, 'trusted');
  assert.equal(closed, true);
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
  const handler = createKeylimeMcpHandler({
    endpoint: 'https://keylime.example.test/mcp',
    token: 'a'.repeat(64),
    clientFactory: async () => ({
      callTool: async () => { throw new Error('verifier unavailable'); },
      close: async () => {},
    }),
  });
  await assert.rejects(handler(action), /failed closed/);
});
