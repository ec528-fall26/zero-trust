// The node's durable record of what it has launched.
//
// A valid permit can be delivered twice, so proof of approval is not enough:
// the node must remember.  Claiming an occurrence is one atomic mkdir, fsynced
// before the workload starts.  If the node dies between the claim and the
// launch the occurrence stays used and nothing ran.  That is the deliberate
// cost of at-most-once launch attempts; another attempt needs a new approval.
import crypto from 'node:crypto';
import {
  mkdir,
  open,
  readFile,
  rename,
} from 'node:fs/promises';
import path from 'node:path';

const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const STATE_FILE = 'state.json';
const MAXIMUM_STATE_BYTES = 4 * 1024;
const OUTCOMES = new Set(['succeeded', 'failed']);

async function syncDirectory(directory) {
  const handle = await open(directory, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function writeNewFile(filePath, contents) {
  const handle = await open(filePath, 'wx', 0o600);
  try {
    await handle.writeFile(contents, { encoding: 'utf8' });
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export class LaunchLedger {
  constructor(root, { now = () => Date.now() } = {}) {
    if (typeof root !== 'string' || root.length === 0) {
      throw new TypeError('launch ledger directory is required');
    }
    this.root = path.resolve(root);
    this.now = now;
  }

  async initialize() {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    return this;
  }

  location(occurrenceId) {
    if (typeof occurrenceId !== 'string' || !UUID_PATTERN.test(occurrenceId)) {
      throw new TypeError('invalid occurrence identifier');
    }
    return path.join(this.root, occurrenceId);
  }

  // True for exactly one caller per occurrence, across processes and restarts.
  async reserve(occurrenceId, details = {}) {
    const directory = this.location(occurrenceId);
    await this.initialize();
    try {
      await mkdir(directory, { mode: 0o700 });
    } catch (error) {
      if (error?.code === 'EEXIST') return false;
      throw error;
    }
    await syncDirectory(this.root);
    await writeNewFile(path.join(directory, STATE_FILE), JSON.stringify({
      state: 'reserved',
      occurrence_id: occurrenceId,
      reserved_at: new Date(this.now()).toISOString(),
      ...details,
    }));
    await syncDirectory(directory);
    return true;
  }

  // A directory without a state file means the node died mid-reservation.  It
  // is still a claim, and is reported as reserved.
  async read(occurrenceId) {
    const directory = this.location(occurrenceId);
    let encoded;
    try {
      encoded = await readFile(path.join(directory, STATE_FILE), { encoding: 'utf8' });
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      try {
        await open(directory, 'r').then((handle) => handle.close());
      } catch (missing) {
        if (missing?.code === 'ENOENT') return null;
        throw missing;
      }
      return { state: 'reserved', occurrence_id: occurrenceId };
    }
    if (Buffer.byteLength(encoded, 'utf8') > MAXIMUM_STATE_BYTES) {
      throw new Error('launch ledger entry exceeded its bound');
    }
    return JSON.parse(encoded);
  }

  // Replaces `reserved` with the observed outcome.  An entry left at `reserved`
  // means the outcome is unknown and has to be reconciled, never retried.
  async record(occurrenceId, outcome) {
    if (!OUTCOMES.has(outcome)) throw new TypeError('invalid launch outcome');
    const directory = this.location(occurrenceId);
    const current = await this.read(occurrenceId);
    if (current?.state !== 'reserved') throw new Error('launch is not reserved');
    const temporary = path.join(directory, `state-${crypto.randomBytes(12).toString('hex')}.tmp`);
    await writeNewFile(temporary, JSON.stringify({
      ...current,
      state: outcome,
      finished_at: new Date(this.now()).toISOString(),
    }));
    await rename(temporary, path.join(directory, STATE_FILE));
    await syncDirectory(directory);
    return true;
  }
}
