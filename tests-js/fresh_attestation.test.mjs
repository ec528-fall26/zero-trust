import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createAttestAndDeploy } from '../src/keylime_mcp/attest_and_deploy.mjs';
import { LaunchLedger } from '../src/keylime_mcp/launch_ledger.mjs';
import { createPermitFixture } from '../experiments/permit_fixture.mjs';
import { validateKeylimeResult } from '../src/controller/keylime_mcp_client.mjs';

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

async function fixture({ statuses, ...options }) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-fresh-attestation-'));
  const artifact = Buffer.from('#!/bin/sh\nexit 0\n', 'utf8');
  const input = Buffer.from('approved payload\n', 'utf8');
  const artifactPath = path.join(root, 'workload.sh');
  const inputPath = path.join(root, 'input.txt');
  await writeFile(artifactPath, artifact, { mode: 0o700 });
  await writeFile(inputPath, input, { mode: 0o600 });
  await chmod(root, 0o700);

  // Fake clock: sleeping advances it, so timeouts need no real waiting.
  let clock = Date.now();
  const state = { statusReads: 0, workloadRuns: 0, sleeps: [] };
  const permits = createPermitFixture({
    target: 'azure-vm-demo-01',
    agentId: 'agent-test',
    now: () => clock,
  });
  const nodeHandler = createAttestAndDeploy({
    permitVerifier: permits.verifier,
    launchLedger: new LaunchLedger(path.join(root, 'launch-ledger')),
    statusCommand: '/fixed/status',
    artifactPath,
    inputPath,
    target: 'azure-vm-demo-01',
    agentId: 'agent-test',
    policyVersion: 'demo-2.1',
    requiredOwnerUid: process.getuid(),
    now: () => clock,
    sleep: async (milliseconds) => {
      state.sleeps.push(milliseconds);
      clock += milliseconds;
    },
    commandRunner: async (command) => {
      if (command === '/fixed/status') {
        const index = Math.min(state.statusReads, statuses.length - 1);
        state.statusReads += 1;
        const entry = statuses[index];
        return {
          stdout: JSON.stringify({
            agent_id: 'agent-test',
            enrollment_epoch: permits.enrollmentEpoch,
            results: {
              attestation_status: entry.status ?? 'PASS',
              last_successful_attestation: Math.floor(clock / 1_000),
              ...('count' in entry ? { attestation_count: entry.count } : {}),
            },
          }),
          stderr: '',
        };
      }
      state.workloadRuns += 1;
      return { stdout: `${digest(input).slice(7)}  input.txt\n`, stderr: '' };
    },
    ...options,
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
  const handler = (requested) => nodeHandler(requested, permits.sign(requested));
  return { handler, action, state, cleanup: () => rm(root, { recursive: true, force: true }) };
}

const counts = (...values) => values.map((count) => ({ count }));

test('waits for two more attestations, then runs the workload', async () => {
  const context = await fixture({
    statuses: counts(5, 5, 6, 7),
    requireFreshAttestation: true,
  });
  try {
    const result = await context.handler(context.action);
    assert.equal(context.state.statusReads, 4);
    assert.equal(context.state.workloadRuns, 1);
    assert.equal(result.attestation.fresh_after_request, true);
    assert.equal(result.attestation.attestation_count_before, 5);
    assert.equal(result.attestation.attestation_count_after, 7);
    assert.deepEqual(context.state.sleeps, [500, 500, 500]);
  } finally {
    await context.cleanup();
  }
});

test('an attestation that was already in flight is not enough on its own', async () => {
  // Count 5 -> 6 could be a quote requested before the call arrived.
  const context = await fixture({
    statuses: counts(5, 6),
    requireFreshAttestation: true,
    freshAttestationTimeoutSeconds: 2,
  });
  try {
    await assert.rejects(context.handler(context.action), /in time/);
    assert.equal(context.state.workloadRuns, 0);
  } finally {
    await context.cleanup();
  }
});

test('times out and fails closed when Keylime stops attesting', async () => {
  const context = await fixture({
    statuses: counts(5),
    requireFreshAttestation: true,
    freshAttestationTimeoutSeconds: 3,
  });
  try {
    await assert.rejects(context.handler(context.action), /did not attest again/);
    assert.equal(context.state.workloadRuns, 0);
    // About three seconds of polling at 500 ms, never unbounded.
    assert.ok(context.state.sleeps.length >= 5 && context.state.sleeps.length <= 7);
  } finally {
    await context.cleanup();
  }
});

test('a status that fails during the wait stops the request', async () => {
  const context = await fixture({
    statuses: [{ count: 5 }, { count: 6 }, { count: 6, status: 'FAIL' }],
    requireFreshAttestation: true,
  });
  try {
    await assert.rejects(context.handler(context.action), /did not pass/);
    assert.equal(context.state.workloadRuns, 0);
  } finally {
    await context.cleanup();
  }
});

test('a missing, malformed or backwards count fails closed', async () => {
  for (const [statuses, pattern] of [
    [[{}], /no usable attestation count/],
    [[{ count: null }], /no usable attestation count/],
    [[{ count: -1 }], /no usable attestation count/],
    [[{ count: 1.5 }], /no usable attestation count/],
    [[{ count: 'abc' }], /no usable attestation count/],
    [[{ count: 9 }, { count: 4 }], /went backwards/],
  ]) {
    const context = await fixture({ statuses, requireFreshAttestation: true });
    try {
      await assert.rejects(context.handler(context.action), pattern);
      assert.equal(context.state.workloadRuns, 0);
    } finally {
      await context.cleanup();
    }
  }
});

test('a count reported as a string of digits is accepted', async () => {
  const context = await fixture({
    statuses: [{ count: '10' }, { count: '12' }],
    requireFreshAttestation: true,
  });
  try {
    const result = await context.handler(context.action);
    assert.equal(result.attestation.attestation_count_after, 12);
  } finally {
    await context.cleanup();
  }
});

test('without the option nothing waits and no count is needed', async () => {
  const context = await fixture({ statuses: [{}] });
  try {
    const result = await context.handler(context.action);
    assert.equal(context.state.statusReads, 1);
    assert.deepEqual(context.state.sleeps, []);
    assert.equal('fresh_after_request' in result.attestation, false);
  } finally {
    await context.cleanup();
  }
});

test('absurd timing options are rejected when the handler is created', async () => {
  for (const options of [
    { freshAttestationTimeoutSeconds: 0 },
    { freshAttestationTimeoutSeconds: 3_600 },
    { freshAttestationPollMilliseconds: 1 },
    { freshAttestationPollMilliseconds: 60_000 },
    { maximumAttestationAgeSeconds: Number.NaN },
    { maximumAttestationAgeSeconds: 0 },
    { maximumAttestationAgeSeconds: 86_401 },
  ]) {
    await assert.rejects(
      fixture({ statuses: counts(1), ...options }),
      /invalid (fresh attestation timing|maximum attestation age)/,
    );
  }
});

test('the controller can insist that the attestation came after the request', async () => {
  const now = Date.now();
  const action = {
    action_type: 'workload.execute',
    operation: 'checksum.sha256',
    target: 'azure-vm-demo-01',
    artifact_sha256: `sha256:${'a'.repeat(64)}`,
    input_sha256: `sha256:${'b'.repeat(64)}`,
    occurrence_id: crypto.randomUUID(),
    policy_version: 'demo-2.1',
  };
  const result = (extra = {}) => ({
    attestation: {
      provider: 'keylime',
      verdict: 'trusted',
      target: action.target,
      policy_version: action.policy_version,
      occurrence_id: action.occurrence_id,
      attested_at: new Date(now).toISOString(),
      age_seconds: 0,
      node_time: new Date(now).toISOString(),
      evidence_digest: `sha256:${'c'.repeat(64)}`,
      ...extra,
    },
    workload: {
      executed: true,
      operation: action.operation,
      artifact_sha256: action.artifact_sha256,
      input_sha256: action.input_sha256,
    },
  });
  assert.doesNotThrow(() => validateKeylimeResult(result(), action, { now }));
  assert.throws(
    () => validateKeylimeResult(result(), action, { now, requireFreshAttestation: true }),
    /not taken after the request/,
  );
  assert.throws(
    () => validateKeylimeResult(
      result({ fresh_after_request: 'yes' }),
      action,
      { now, requireFreshAttestation: true },
    ),
    /not taken after the request/,
  );
  assert.doesNotThrow(() => validateKeylimeResult(
    result({ fresh_after_request: true }),
    action,
    { now, requireFreshAttestation: true },
  ));
});
