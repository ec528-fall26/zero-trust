import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  APPROVER_RECORD_SCHEMA,
  createSignoff,
  publicKeyFingerprint,
  reviewApprovalRequest,
  validateRoster,
} from '../src/controller/approver_signoff.mjs';
import { createDemoController } from '../src/demo/demo_controller.mjs';

function digest(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

// Each "person" makes their own key; the controller only ever sees `record`.
function person(role) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKeyText = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    privateKey,
    record: {
      schema: APPROVER_RECORD_SCHEMA,
      role,
      name: `Test ${role}`,
      approver_id: `ep:approver:${role}`,
      key_id: `${role}-${publicKeyFingerprint(publicKeyText).slice(7, 15)}`,
      public_key: publicKeyText,
    },
  };
}

function sign(request, signer) {
  return createSignoff(request, { privateKey: signer.privateKey, keyId: signer.record.key_id });
}

async function fixture(t, options = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-human-approval-'));
  t.after(() => rm(root, { recursive: true, force: true }));
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
  const people = {
    operator: person('operator'),
    security: person('security'),
    reviewer: person('reviewer'),
  };
  const controller = await createDemoController({
    action: {
      action_type: 'workload.execute',
      operation: 'checksum.sha256',
      target: 'aws-node-demo-01',
      artifact_sha256: digest(artifact),
      input_sha256: digest(input),
      occurrence_id: crypto.randomUUID(),
      policy_version: 'demo-3.0',
    },
    artifactPath,
    inputPath,
    manifest,
    stateDirectory: root,
    approverRoster: Object.values(people).map((entry) => entry.record),
    ...options,
  });
  return { controller, people };
}

test('two enrolled people approve from their own keys; one approval stays pending', async (t) => {
  const { controller, people } = await fixture(t);
  assert.throws(() => controller.approve('operator'), /tools\/approver\.mjs/);
  const request = controller.approvalRequest();
  assert.equal(reviewApprovalRequest(request).action.target, 'aws-node-demo-01');

  assert.equal((await controller.execute('missing')).last_response.status, 428);
  assert.equal(controller.submitSignoff(sign(request, people.operator)).accepted, true);
  const pending = await controller.execute('missing');
  assert.equal(pending.approval_status, 'pending');
  assert.equal(pending.receipt_ready, false);
  assert.equal(pending.last_response.status, 428);

  const duplicate = controller.submitSignoff(sign(request, people.operator));
  assert.equal(duplicate.reason, 'duplicate_approver');
  assert.equal(controller.snapshot().receipt_ready, false);

  assert.equal(controller.submitSignoff(sign(request, people.security)).accepted, true);
  assert.equal(controller.snapshot().receipt_ready, true);
  const approved = await controller.execute('approved');
  assert.equal(approved.last_response.status, 200);
  assert.equal(approved.last_response.body.result.workload.executed, true);
  assert.equal((await controller.execute('replay')).last_response.body.rejected.reason, 'replay_refused');
});

test('signoffs from unenrolled keys, other requests, or forged signatures are refused', async (t) => {
  const { controller, people } = await fixture(t);
  const request = controller.approvalRequest();

  const outsider = person('outsider');
  assert.equal(controller.submitSignoff(sign(request, outsider)).reason, 'approver_not_enrolled');

  // An outsider using an enrolled key id still cannot produce a valid signature.
  const impostor = createSignoff(request, { privateKey: outsider.privateKey, keyId: people.reviewer.record.key_id });
  assert.equal(controller.submitSignoff(impostor).reason, 'signoff_signature_invalid');

  // A signoff for a different action does not count toward this one.
  const other = await fixture(t);
  const foreign = sign(other.controller.approvalRequest(), other.people.operator);
  assert.equal(controller.submitSignoff(foreign).reason, 'approver_not_enrolled');
  const crossRequest = { ...sign(request, people.operator), context_hash: foreign.context_hash };
  assert.equal(controller.submitSignoff(crossRequest).reason, 'signoff_for_different_request');

  assert.equal(controller.snapshot().approvals.length, 0);
  assert.equal(controller.snapshot().receipt_ready, false);
});

test('a tampered approval request cannot be signed', async (t) => {
  const { controller } = await fixture(t);
  const request = structuredClone(controller.approvalRequest());
  request.claim.canonical_action.target = 'attacker-node';
  assert.throws(() => reviewApprovalRequest(request), /action_hash does not match/);
});

test('signoffs after the approval window are refused', async (t) => {
  let clock = Date.parse('2026-11-16T12:00:00Z');
  const { controller, people } = await fixture(t, { now: () => clock, approvalWindowMs: 60_000 });
  const request = controller.approvalRequest();
  assert.equal(controller.submitSignoff(sign(request, people.operator)).accepted, true);
  clock += 61_000;
  assert.equal(controller.submitSignoff(sign(request, people.security)).reason, 'approval_window_expired');
  assert.equal(controller.snapshot().receipt_ready, false);
});

test('rosters reject shared keys and too few people', () => {
  const a = person('operator');
  const b = person('security');
  assert.throws(() => validateRoster([a.record, b.record]), /at least 3/);
  const shared = { ...person('reviewer').record, public_key: a.record.public_key };
  assert.throws(() => validateRoster([a.record, b.record, shared]), /distinct key/);
});
