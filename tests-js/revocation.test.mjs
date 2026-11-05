import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  createRevocationChecker,
  receiptSignerKeyIds,
  signRevocationList,
} from '../src/controller/revocation.mjs';
import { createDemoController } from '../src/demo/demo_controller.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function authority() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey,
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

function receiptSignedBy(...keyIds) {
  return {
    payload: {
      assurance_proof: {
        signoffs: keyIds.map((approver_key_id) => ({ approver_key_id })),
      },
    },
  };
}

function listFor(signer, { sequence = 1, issuedAt = new Date(), revoked = [] } = {}) {
  return signRevocationList({
    privateKey: signer.privateKey,
    sequence,
    issuedAt: issuedAt.toISOString(),
    revoked: revoked.map((id) => ({
      approver_key_id: id,
      revoked_at: new Date().toISOString(),
    })),
  });
}

test('a list that names none of the signers lets the receipt through', async () => {
  const signer = authority();
  const checker = createRevocationChecker({
    authorityPublicKey: signer.publicKey,
    load: async () => listFor(signer, { revoked: ['someone-else'] }),
  });
  assert.deepEqual(
    await checker.check(receiptSignedBy('key-a', 'key-b')),
    { ok: true, sequence: 1 },
  );
});

test('a revoked signer refuses the receipt, even if they signed before the revocation', async () => {
  const signer = authority();
  const checker = createRevocationChecker({
    authorityPublicKey: signer.publicKey,
    load: async () => listFor(signer, { revoked: ['key-b'] }),
  });
  assert.deepEqual(
    await checker.check(receiptSignedBy('key-a', 'key-b')),
    { ok: false, reason: 'approver_key_revoked' },
  );
});

test('a missing, failing or unsigned list fails closed', async () => {
  const signer = authority();
  const receipt = receiptSignedBy('key-a');
  const make = (load, extra = {}) => createRevocationChecker({
    authorityPublicKey: signer.publicKey,
    load,
    ...extra,
  });
  assert.equal((await make(async () => null).check(receipt)).reason, 'revocation_unavailable');
  assert.equal(
    (await make(async () => { throw new Error('network'); }).check(receipt)).reason,
    'revocation_unavailable',
  );
  assert.equal((await make(async () => ({})).check(receipt)).reason, 'revocation_list_invalid');

  const forged = listFor(authority());
  assert.equal((await make(async () => forged).check(receipt)).reason, 'revocation_list_invalid');

  const tampered = listFor(signer, { revoked: ['key-z'] });
  tampered.payload.revoked = [];
  assert.equal((await make(async () => tampered).check(receipt)).reason, 'revocation_list_invalid');
});

test('an old list is stale and a future-dated list is invalid', async () => {
  const signer = authority();
  const receipt = receiptSignedBy('key-a');
  const now = Date.now();
  const check = (issuedAt) => createRevocationChecker({
    authorityPublicKey: signer.publicKey,
    maximumAgeSeconds: 300,
    now: () => now,
    load: async () => listFor(signer, { issuedAt: new Date(issuedAt) }),
  }).check(receipt);
  assert.equal((await check(now - 299_000)).ok, true);
  assert.equal((await check(now - 301_000)).reason, 'revocation_list_stale');
  assert.equal((await check(now + 60_000)).reason, 'revocation_list_invalid');
});

test('an older list than one already seen is a rollback', async () => {
  const signer = authority();
  const receipt = receiptSignedBy('key-a');
  const current = listFor(signer, { sequence: 7, revoked: ['key-a'] });
  const lists = [
    current,
    // A replayed earlier list that predates the revocation.
    listFor(signer, { sequence: 6, revoked: [] }),
    current,
  ];
  const checker = createRevocationChecker({
    authorityPublicKey: signer.publicKey,
    load: async () => lists.shift(),
  });
  assert.equal((await checker.check(receipt)).reason, 'approver_key_revoked');
  assert.equal((await checker.check(receipt)).reason, 'revocation_list_rollback');
  assert.equal((await checker.check(receipt)).reason, 'approver_key_revoked');
});

test('a different list at the same sequence is a rollback', async () => {
  const signer = authority();
  const receipt = receiptSignedBy('key-a');
  const issuedAt = new Date();
  const lists = [
    listFor(signer, { sequence: 7, issuedAt, revoked: ['key-a'] }),
    listFor(signer, { sequence: 7, issuedAt, revoked: [] }),
  ];
  const checker = createRevocationChecker({
    authorityPublicKey: signer.publicKey,
    load: async () => lists.shift(),
  });
  assert.equal((await checker.check(receipt)).reason, 'approver_key_revoked');
  assert.equal((await checker.check(receipt)).reason, 'revocation_list_rollback');
});

test('revocation entries require unique keys and valid non-future timestamps', async () => {
  const signer = authority();
  const receipt = receiptSignedBy('key-a');
  const check = async (revoked) => createRevocationChecker({
    authorityPublicKey: signer.publicKey,
    load: async () => signRevocationList({
      privateKey: signer.privateKey,
      sequence: 1,
      issuedAt: new Date().toISOString(),
      revoked,
    }),
  }).check(receipt);
  assert.equal((await check([
    { approver_key_id: 'key-a', revoked_at: 'not-a-date' },
  ])).reason, 'revocation_list_invalid');
  assert.equal((await check([
    { approver_key_id: 'key-a', revoked_at: new Date(Date.now() + 60_000).toISOString() },
  ])).reason, 'revocation_list_invalid');
  assert.equal((await check([
    { approver_key_id: 'key-a', revoked_at: new Date().toISOString() },
    { approver_key_id: 'key-a', revoked_at: new Date().toISOString() },
  ])).reason, 'revocation_list_invalid');
});

test('receipts without sign-offs have nothing to look up', async () => {
  assert.deepEqual(receiptSignerKeyIds({ payload: {} }), []);
  assert.deepEqual(receiptSignerKeyIds(null), []);
  assert.deepEqual(receiptSignerKeyIds(receiptSignedBy('a', 'b')), ['a', 'b']);
});

test('constructor rejects a missing loader or authority key', () => {
  const signer = authority();
  assert.throws(
    () => createRevocationChecker({ authorityPublicKey: signer.publicKey }),
    /loader is required/,
  );
  assert.throws(
    () => createRevocationChecker({ load: async () => null }),
    /authority public key is required/,
  );
});

// ---- real quorum receipts through the dispatcher ---------------------------

async function quorumFixture(revocation) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-revocation-'));
  const artifactPath = path.join(root, 'workload.sh');
  const inputPath = path.join(root, 'input.txt');
  const artifact = Buffer.from('#!/bin/sh\nsha256sum "$1"\n', 'utf8');
  const input = Buffer.from('revocation input\n', 'utf8');
  await writeFile(artifactPath, artifact, { mode: 0o700 });
  await writeFile(inputPath, input, { mode: 0o600 });
  await chmod(artifactPath, 0o700);
  const manifest = JSON.parse(await readFile(
    path.join(repositoryRoot, 'public', '.well-known', 'agent-actions.json'),
    'utf8',
  ));
  const digest = (bytes) => `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
  const controller = await createDemoController({
    action: {
      action_type: 'workload.execute',
      operation: 'checksum.sha256',
      target: 'azure-vm-01',
      artifact_sha256: digest(artifact),
      input_sha256: digest(input),
      occurrence_id: crypto.randomUUID(),
      policy_version: 'demo-2.1',
    },
    artifactPath,
    inputPath,
    manifest,
    stateDirectory: root,
    revocation,
  });
  controller.approve('operator');
  controller.approve('security');
  return { controller, cleanup: () => rm(root, { recursive: true, force: true }) };
}

test('a signer revoked after approval blocks execution without burning the receipt', async () => {
  const signer = authority();
  let current = listFor(signer, { sequence: 1, revoked: ['demo-security-key'] });
  const fixture = await quorumFixture(createRevocationChecker({
    authorityPublicKey: signer.publicKey,
    load: async () => current,
  }));
  try {
    const refused = await fixture.controller.execute('approved');
    assert.equal(refused.last_response.status, 428);
    assert.equal(refused.last_response.body.rejected.reason, 'approver_key_revoked');

    // The refusal happened before the receipt was reserved, so once the list
    // no longer names the key the same receipt still works, exactly once.
    current = listFor(signer, { sequence: 2, revoked: [] });
    const allowed = await fixture.controller.execute('approved');
    assert.equal(allowed.last_response.status, 200);
    const replay = await fixture.controller.execute('replay');
    assert.equal(replay.last_response.body.rejected.reason, 'replay_refused');
  } finally {
    await fixture.cleanup();
  }
});

test('an unavailable revocation list blocks a valid quorum receipt', async () => {
  const signer = authority();
  const fixture = await quorumFixture(createRevocationChecker({
    authorityPublicKey: signer.publicKey,
    load: async () => { throw new Error('list server down'); },
  }));
  try {
    const refused = await fixture.controller.execute('approved');
    assert.equal(refused.last_response.status, 428);
    assert.equal(refused.last_response.body.rejected.reason, 'revocation_unavailable');
  } finally {
    await fixture.cleanup();
  }
});
