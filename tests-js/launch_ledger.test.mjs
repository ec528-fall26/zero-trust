import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { LaunchLedger } from '../src/keylime_mcp/launch_ledger.mjs';

async function withLedger(run) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-launch-ledger-'));
  try {
    await run(path.join(root, 'ledger'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('the first reservation wins and a duplicate is refused', async () => {
  await withLedger(async (directory) => {
    const ledger = await new LaunchLedger(directory).initialize();
    const occurrence = crypto.randomUUID();
    assert.equal(await ledger.reserve(occurrence), true);
    assert.equal(await ledger.reserve(occurrence), false);
    assert.equal(await ledger.reserve(crypto.randomUUID()), true);
  });
});

test('a reservation survives a restart', async () => {
  await withLedger(async (directory) => {
    const occurrence = crypto.randomUUID();
    await new LaunchLedger(directory).reserve(occurrence);
    const restarted = await new LaunchLedger(directory).initialize();
    assert.equal(await restarted.reserve(occurrence), false);
    assert.equal((await restarted.read(occurrence)).state, 'reserved');
  });
});

test('ten concurrent reservations across ledger instances have one winner', async () => {
  await withLedger(async (directory) => {
    const occurrence = crypto.randomUUID();
    const outcomes = await Promise.all(Array.from({ length: 10 }, () => (
      new LaunchLedger(directory).reserve(occurrence)
    )));
    assert.equal(outcomes.filter(Boolean).length, 1);
  });
});

test('entries record details and their final outcome, and stay used', async () => {
  await withLedger(async (directory) => {
    const ledger = new LaunchLedger(directory, { now: () => 1_800_000_000_000 });
    for (const outcome of ['succeeded', 'failed']) {
      const occurrence = crypto.randomUUID();
      await ledger.reserve(occurrence, { action_sha256: 'sha256:abc' });
      await ledger.record(occurrence, outcome);
      const entry = await ledger.read(occurrence);
      assert.equal(entry.state, outcome);
      assert.equal(entry.action_sha256, 'sha256:abc');
      assert.equal(entry.finished_at, '2027-01-15T08:00:00.000Z');
      assert.equal(await ledger.reserve(occurrence), false);
    }
  });
});

test('state is written to disk before reserve returns', async () => {
  await withLedger(async (directory) => {
    const ledger = new LaunchLedger(directory);
    const occurrence = crypto.randomUUID();
    await ledger.reserve(occurrence, { action_sha256: 'sha256:abc' });
    const stored = JSON.parse(await readFile(path.join(directory, occurrence, 'state.json'), 'utf8'));
    assert.equal(stored.state, 'reserved');
    assert.equal(stored.occurrence_id, occurrence);
    assert.equal((await stat(path.join(directory, occurrence))).mode & 0o077, 0);
  });
});

test('a crash between claiming and writing state still counts as used', async () => {
  await withLedger(async (directory) => {
    const ledger = await new LaunchLedger(directory).initialize();
    const occurrence = crypto.randomUUID();
    await mkdir(path.join(directory, occurrence));
    assert.equal(await ledger.reserve(occurrence), false);
    assert.equal((await ledger.read(occurrence)).state, 'reserved');
  });
});

test('an outcome can be recorded once, only for a reservation', async () => {
  await withLedger(async (directory) => {
    const ledger = await new LaunchLedger(directory).initialize();
    const occurrence = crypto.randomUUID();
    assert.equal(await ledger.read(occurrence), null);
    await assert.rejects(ledger.record(occurrence, 'succeeded'), /not reserved/);
    await ledger.reserve(occurrence);
    await assert.rejects(ledger.record(occurrence, 'unknown'), /invalid launch outcome/);
    await ledger.record(occurrence, 'succeeded');
    await assert.rejects(ledger.record(occurrence, 'failed'), /not reserved/);
  });
});

test('identifiers that are not UUIDs cannot reach the filesystem', async () => {
  await withLedger(async (directory) => {
    const ledger = await new LaunchLedger(directory).initialize();
    for (const identifier of ['../escape', 'x', '', null]) {
      await assert.rejects(ledger.reserve(identifier), /invalid occurrence identifier/);
    }
  });
});
