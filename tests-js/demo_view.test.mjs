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

test('request events become a trace with gate and Keylime spans', async () => {
  const { traceFromEvents, stoppedBy } = await import('../src/demo/demo_view.mjs');
  const t = (ms) => new Date(Date.UTC(2026, 9, 21, 12, 0, 0, ms)).toISOString();
  const events = [
    { stage: 'emilia', outcome: 'approved', role: 'operator', at: t(0) },
    { stage: 'demo', outcome: 'request-received', scenario: 'missing', at: t(100) },
    { stage: 'receipt-guard', decision: 'deny', reason: 'receipt_required', at: t(101) },
    { stage: 'demo', outcome: 'refused', scenario: 'missing', at: t(102) },
    { stage: 'demo', outcome: 'request-received', scenario: 'approved', at: t(200) },
    { stage: 'receipt-guard', decision: 'invoke', at: t(203) },
    { stage: 'receipt-guard', decision: 'allow', at: t(1400) },
    { stage: 'demo', outcome: 'executed', scenario: 'approved', at: t(1402) },
  ];
  const [refused, ran] = traceFromEvents(events, { remote: true });
  assert.equal(refused.spans.length, 2);
  assert.equal(refused.spans[1].tone, 'bad');
  assert.match(refused.spans[1].note, /No receipt/);
  assert.deepEqual(ran.spans.map((span) => span.name),
    ['request approved workload', 'emilia.receipt_gate', 'keylime.attest_and_deploy', 'emilia.receipt_commit']);
  assert.equal(ran.spans[2].service, 'keylime (AWS)');
  assert.equal(ran.spans[2].end - ran.spans[2].start, 1197);
  assert.equal(ran.end - ran.start, 1202);
  assert.equal(stoppedBy({ tone: 'bad', stopAt: 2, reason: 'replay_refused' }).label, 'Durable receipt store');
  assert.equal(stoppedBy({ tone: 'bad', stopAt: 3 }).tech, 'keylime');
  assert.equal(stoppedBy({ tone: 'ok' }), null);
});

test('a recorded Jaeger export converts with nesting and errors', async () => {
  const { traceFromJaeger } = await import('../src/demo/demo_view.mjs');
  const { readFile } = await import('node:fs/promises');
  const recorded = JSON.parse(await readFile(
    new URL('../results/traces/otel-demo2-end-to-end.trace.json', import.meta.url), 'utf8',
  ));
  const trace = traceFromJaeger(recorded);
  assert.equal(trace.spans.length, 17);
  assert.equal(trace.spans[0].depth, 0);
  assert.ok(trace.spans.some((span) => span.depth === 2));
  assert.ok(trace.spans.some((span) => span.tone === 'bad'));
  assert.ok(Math.round((trace.end - trace.start) / 1000) >= 150);
  assert.equal(traceFromJaeger({}), null);
});
