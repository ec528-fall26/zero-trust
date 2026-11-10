import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { createPermitSigner } from '../src/controller/permit_signer.mjs';
import { PERMIT_VERSION, PermitRefused, createPermitVerifier } from '../src/keylime_mcp/permit.mjs';
import { SECURITY_PARAMETERS } from '../src/security_parameters.mjs';
import { createPermitFixture } from '../experiments/permit_fixture.mjs';

const TARGET = 'aws-keylime-demo-01';
const AGENT = 'd432fbb3-d2f1-4a97-9ef7-75bd81c00000';
const TOOL = 'attest_and_deploy';
const NOW = 1_800_000_000_000;

const action = Object.freeze({
  action_type: 'workload.execute',
  operation: 'checksum.sha256',
  target: TARGET,
  artifact_sha256: `sha256:${'a'.repeat(64)}`,
  input_sha256: `sha256:${'b'.repeat(64)}`,
  occurrence_id: '6f52be12-785e-43ff-85f0-351ea797373b',
  policy_version: 'demo-2.1',
});

function fixture() {
  return createPermitFixture({ target: TARGET, agentId: AGENT, now: () => NOW });
}

function refusedWith(permits, permit, reason, context = { tool: TOOL, action }) {
  assert.throws(
    () => permits.verifier.verify(permit, context),
    (error) => error instanceof PermitRefused && error.reason === reason,
    `expected ${reason}`,
  );
}

test('a permit from the controller verifies and reports its binding', () => {
  const permits = fixture();
  const payload = permits.verifier.verify(permits.sign(action, 'receipt-1'), { tool: TOOL, action });
  assert.equal(payload.version, PERMIT_VERSION);
  assert.equal(payload.target, TARGET);
  assert.equal(payload.agent_uuid, AGENT);
  assert.equal(payload.enrollment_epoch, permits.enrollmentEpoch);
  assert.equal(payload.expires_at - payload.issued_at, SECURITY_PARAMETERS.permit_max_lifetime_sec * 1_000);
  assert.ok(Object.isFrozen(payload));
});

test('changing any signed field after signing breaks the signature', () => {
  const permits = fixture();
  const original = permits.sign(action);
  const changes = {
    tool: 'bootstrap_keylime_tenant',
    action_sha256: `sha256:${'c'.repeat(64)}`,
    target: 'other-node',
    agent_uuid: 'a0000000-0000-4000-8000-000000000000',
    enrollment_epoch: crypto.randomUUID(),
    receipt_sha256: `sha256:${'d'.repeat(64)}`,
    issued_at: original.payload.issued_at + 1,
    expires_at: original.payload.expires_at + 1,
  };
  for (const [field, value] of Object.entries(changes)) {
    refusedWith(
      permits,
      { payload: { ...original.payload, [field]: value }, signature: original.signature },
      'signature_invalid',
    );
  }
});

test('a permit signed by another key is refused even with a perfect payload', () => {
  const permits = fixture();
  const attacker = createPermitFixture({
    target: TARGET,
    agentId: AGENT,
    enrollmentEpoch: permits.enrollmentEpoch,
    now: () => NOW,
  });
  refusedWith(permits, attacker.sign(action), 'signature_invalid');
});

test('correctly signed permits are still refused when bound to something else', () => {
  const permits = fixture();
  const cases = [
    [{ target: 'other-node' }, 'target_mismatch'],
    [{ agent_uuid: 'a0000000-0000-4000-8000-000000000000' }, 'agent_mismatch'],
    [{ action_sha256: `sha256:${'c'.repeat(64)}` }, 'action_mismatch'],
  ];
  for (const [overrides, reason] of cases) {
    refusedWith(permits, permits.signWith(action, overrides), reason);
  }
  refusedWith(permits, permits.sign(action, 'r', 'bootstrap_keylime_tenant'), 'tool_mismatch');
});

test('a permit for one action cannot be used for a changed action', () => {
  const permits = fixture();
  const permit = permits.sign(action);
  for (const changed of [
    { ...action, occurrence_id: crypto.randomUUID() },
    { ...action, artifact_sha256: `sha256:${'e'.repeat(64)}` },
    { ...action, input_sha256: `sha256:${'e'.repeat(64)}` },
    { ...action, policy_version: 'demo-9' },
  ]) {
    refusedWith(permits, permit, 'action_mismatch', { tool: TOOL, action: changed });
  }
});

test('permit time limits include exactly the configured clock skew', () => {
  const permits = fixture();
  const skew = SECURITY_PARAMETERS.clock_skew_tolerance_sec * 1_000;
  const lifetime = SECURITY_PARAMETERS.permit_max_lifetime_sec * 1_000;
  const at = (issuedAt) => ({ issued_at: issuedAt, expires_at: issuedAt + lifetime });

  assert.ok(permits.verifier.verify(permits.signWith(action, at(NOW + skew)), { tool: TOOL, action }));
  refusedWith(permits, permits.signWith(action, at(NOW + skew + 1)), 'not_yet_valid');

  assert.ok(permits.verifier.verify(
    permits.signWith(action, at(NOW - lifetime - skew)),
    { tool: TOOL, action },
  ));
  refusedWith(permits, permits.signWith(action, at(NOW - lifetime - skew - 1)), 'expired');
});

test('a controller cannot grant itself a longer or backwards lifetime', () => {
  const permits = fixture();
  const lifetime = SECURITY_PARAMETERS.permit_max_lifetime_sec * 1_000;
  refusedWith(permits, permits.signWith(action, { issued_at: NOW, expires_at: NOW + lifetime + 1 }), 'lifetime_invalid');
  refusedWith(permits, permits.signWith(action, { issued_at: NOW, expires_at: NOW }), 'lifetime_invalid');
  refusedWith(permits, permits.signWith(action, { issued_at: NOW, expires_at: NOW - 1 }), 'lifetime_invalid');
});

test('missing and malformed permits are refused before any signature work', () => {
  const permits = fixture();
  const valid = permits.sign(action);
  refusedWith(permits, undefined, 'permit_missing');
  refusedWith(permits, null, 'permit_missing');
  const { tool, ...withoutTool } = valid.payload;
  assert.equal(tool, TOOL);
  for (const malformed of [
    'not-a-permit',
    [],
    {},
    { payload: valid.payload },
    { signature: valid.signature },
    { ...valid, extra: true },
    { payload: withoutTool, signature: valid.signature },
    { payload: { ...valid.payload, extra: 'x' }, signature: valid.signature },
    { payload: { ...valid.payload, version: 'EC528-PERMIT-v0' }, signature: valid.signature },
    { payload: { ...valid.payload, issued_at: '1' }, signature: valid.signature },
    { payload: { ...valid.payload, enrollment_epoch: 'not-an-epoch' }, signature: valid.signature },
    { payload: valid.payload, signature: 'short' },
  ]) {
    refusedWith(permits, malformed, 'permit_malformed');
  }
});

test('verifier and signer refuse unusable keys and settings', () => {
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const permits = fixture();
  assert.throws(() => createPermitVerifier({ target: TARGET, agentId: AGENT }), /public key is required/);
  assert.throws(
    () => createPermitVerifier({
      publicKeyPem: rsa.publicKey.export({ type: 'spki', format: 'pem' }),
      target: TARGET,
      agentId: AGENT,
    }),
    /must be Ed25519/,
  );
  assert.throws(() => createPermitVerifier({ publicKeyPem: permits.publicKeyPem, agentId: AGENT }), /target/);
  const signing = {
    privateKeyPem: permits.privateKeyPem,
    agentUuid: AGENT,
    enrollmentEpoch: permits.enrollmentEpoch,
  };
  assert.throws(() => createPermitSigner({ ...signing, privateKeyPem: undefined }), /signing key is required/);
  assert.throws(() => createPermitSigner({ ...signing, enrollmentEpoch: 'nope' }), /enrollment epoch/);
  assert.throws(
    () => createPermitSigner({ ...signing, lifetimeSeconds: SECURITY_PARAMETERS.permit_max_lifetime_sec + 1 }),
    /invalid permit lifetime/,
  );
});

test('the signer refuses to sign without a verified receipt', () => {
  const permits = fixture();
  for (const receiptId of [undefined, null, '']) {
    assert.throws(
      () => permits.signer.sign({ tool: TOOL, action, receiptId }),
      /verified receipt/,
    );
  }
});
