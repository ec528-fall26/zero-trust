import assert from 'node:assert/strict';
import test from 'node:test';

import {
  STATIONS,
  boundaryNote,
  describeEvent,
  describeResponse,
} from '../src/demo/demo_view.mjs';

const remote = { keylime_mode: 'remote-mcp', limitations: ['Approver keys are demo keys.'] };
const local = {
  keylime_mode: 'local-stand-in',
  limitations: ['Approver keys are demo keys.', 'Keylime is a local stand-in.'],
};

test('a successful run reaches the workload and names the real provider', () => {
  const view = describeResponse({
    status: 200,
    body: { result: { attestation: { provider: 'keylime', verdict: 'trusted' }, workload: { executed: true } } },
  }, remote);
  assert.equal(view.stopAt, STATIONS.length - 1);
  assert.equal(view.tone, 'ok');
  assert.match(view.detail, /Keylime vouched for the AWS node/);
});

test('the local stand-in is never described as AWS', () => {
  const view = describeResponse({
    status: 200,
    body: { result: { attestation: { provider: 'local-keylime-stand-in' }, workload: { executed: true } } },
  }, local);
  assert.doesNotMatch(view.detail, /AWS/);
  assert.match(view.detail, /local Keylime stand-in/);
});

test('refusals stop at the gate with a plain reason', () => {
  const cases = {
    action_hash_mismatch: /changed after it was approved/,
    replay_refused: /already used/,
    receipt_expired: /expired/,
  };
  for (const [reason, pattern] of Object.entries(cases)) {
    const view = describeResponse({ status: 428, body: { rejected: { reason } } }, remote);
    assert.equal(view.stopAt, 2, reason);
    assert.equal(view.tone, 'bad', reason);
    assert.match(view.detail, pattern, reason);
  }
  const missing = describeResponse({ status: 428, body: { type: 'receipt_required' } }, remote);
  assert.equal(missing.stopAt, 2);
  assert.equal(missing.title, 'No receipt');
  const unknown = describeResponse({ status: 428, body: { rejected: { reason: 'something_new' } } }, remote);
  assert.match(unknown.detail, /something_new/);
});

test('a node failure stops at Keylime and says the receipt is used up', () => {
  const view = describeResponse({ status: 500, body: { rejected: { reason: 'effect_indeterminate' } } }, remote);
  assert.equal(view.stopAt, 3);
  assert.equal(view.tone, 'bad');
  assert.match(view.detail, /used up/);
  assert.equal(describeResponse(null, remote), null);
});

test('the boundary note only claims real Keylime in AWS mode', () => {
  assert.match(boundaryNote(remote).real, /Keylime attestation on AWS/);
  assert.doesNotMatch(boundaryNote(local).real, /Keylime/);
  assert.deepEqual(boundaryNote(local).simulated, local.limitations);
  assert.deepEqual(boundaryNote({}).simulated, []);
});

test('audit events become short sentences and unknown ones are hidden', () => {
  assert.match(describeEvent({ stage: 'emilia', outcome: 'approved', role: 'security' }), /^Security approved/);
  assert.match(describeEvent({ stage: 'emilia', outcome: 'receipt-issued' }), /two different people/);
  assert.match(describeEvent({ stage: 'receipt-guard', decision: 'deny', reason: 'replay_refused' }), /already used/);
  assert.match(describeEvent({ stage: 'receipt-guard', decision: 'invoke' }), /only be used once/);
  assert.match(describeEvent({ stage: 'receipt-guard', decision: 'deny', reason: 'receipt_required' }), /No receipt was presented/);
  assert.equal(describeEvent({ stage: 'demo', outcome: 'executed' }), null);
  assert.equal(describeEvent(null), null);
});
