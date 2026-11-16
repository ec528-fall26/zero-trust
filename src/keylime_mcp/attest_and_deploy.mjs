import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { open } from 'node:fs/promises';
import net from 'node:net';

import { SECURITY_PARAMETERS } from '../security_parameters.mjs';

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

async function openVerifiedProtectedFile(filePath, approvedDigest, executable, requiredOwnerUid) {
  const handle = await open(filePath, 'r');
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.uid !== requiredOwnerUid || (before.mode & 0o022) !== 0
        || before.size < 1 || before.size > 64 * 1024 * 1024) {
      throw new Error('workload material is not a protected regular file');
    }
    if (executable && (before.mode & 0o111) === 0) {
      throw new Error('approved workload is not executable');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
        || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
      throw new Error('workload material changed while being verified');
    }
    const digest = `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
    if (digest !== approvedDigest) throw new Error('workload material digest mismatch');
    return handle;
  } catch (error) {
    await handle.close();
    throw error;
  }
}

// Run a command without a shell and collect bounded output.  Unlike execFile,
// spawn honours the `stdio` array, which is how verified descriptors reach the
// child as fds 3 and 4.  Any non-zero exit, signal, timeout, or oversized
// output is a failure.
export function runCommand(file, args, options = {}) {
  const {
    timeout = 15_000,
    maxBuffer = 64 * 1024,
    stdio = ['ignore', 'pipe', 'pipe'],
  } = options;
  return new Promise((resolve, reject) => {
    let child;
    try {
      // detached puts the child in its own process group so a timeout can
      // kill anything it forked, not just the direct child.
      child = spawn(file, args, { shell: false, windowsHide: true, stdio, detached: true });
    } catch (error) {
      reject(error);
      return;
    }
    const chunks = { stdout: [], stderr: [] };
    let received = 0;
    let failure = null;
    const fail = (error) => {
      if (failure) return;
      failure = error;
      try {
        process.kill(-child.pid, 'SIGKILL');
      } catch {
        child.kill('SIGKILL');
      }
    };
    const timer = setTimeout(() => fail(new Error('command timed out')), timeout);
    for (const stream of ['stdout', 'stderr']) {
      child[stream].on('data', (chunk) => {
        received += chunk.length;
        if (received > maxBuffer) {
          fail(new Error('command output exceeded the bound'));
          return;
        }
        chunks[stream].push(chunk);
      });
    }
    child.once('error', fail);
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      if (failure) {
        reject(failure);
      } else if (code !== 0 || signal !== null) {
        reject(new Error(`command exited unsuccessfully (${signal ?? code})`));
      } else {
        resolve({
          stdout: Buffer.concat(chunks.stdout).toString('utf8'),
          stderr: Buffer.concat(chunks.stderr).toString('utf8'),
        });
      }
    });
  });
}

// Read the root-owned status helper through its systemd socket.  The helper
// writes one JSON document and closes the connection.
export function readStatusSocket(socketPath, { timeout = 15_000, maxBytes = 256 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else resolve(value);
    };
    const socket = net.createConnection({ path: socketPath });
    socket.setTimeout(timeout, () => finish(new Error('Keylime status socket timed out')));
    socket.on('data', (chunk) => {
      received += chunk.length;
      if (received > maxBytes) {
        finish(new Error('Keylime status exceeded the response bound'));
        return;
      }
      chunks.push(chunk);
    });
    socket.once('error', (error) => finish(error));
    socket.once('end', () => finish(null, { stdout: Buffer.concat(chunks).toString('utf8') }));
  });
}

function singleJsonObject(stdout) {
  const candidates = [];
  let start = -1;
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < stdout.length; index += 1) {
    const character = stdout[index];
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') quoted = false;
      continue;
    }
    if (character === '"' && depth > 0) {
      quoted = true;
    } else if (character === '{') {
      if (depth === 0) start = index;
      depth += 1;
    } else if (character === '}' && depth > 0) {
      depth -= 1;
      if (depth === 0) {
        candidates.push(stdout.slice(start, index + 1));
        start = -1;
      }
    }
  }
  if (depth !== 0 || quoted || candidates.length !== 1) {
    throw new Error('Keylime tenant returned ambiguous JSON status');
  }
  const status = JSON.parse(candidates[0]);
  if (status === null || typeof status !== 'object' || Array.isArray(status)) {
    throw new Error('Keylime tenant status is not an object');
  }
  return status;
}

function parseTenantStatus(stdout, expectedAgentId) {
  if (typeof stdout !== 'string') throw new Error('Keylime tenant returned invalid output');
  if (Buffer.byteLength(stdout, 'utf8') > 256 * 1024) {
    throw new Error('Keylime tenant status exceeded the response bound');
  }
  const status = singleJsonObject(stdout);
  if (status.agent_id !== expectedAgentId) {
    throw new Error('Keylime status belongs to another agent');
  }
  const results = status.results;
  if (results === null || typeof results !== 'object' || Array.isArray(results)) {
    throw new Error('Keylime tenant results are not an object');
  }
  if (results?.attestation_status !== 'PASS') {
    throw new Error('Keylime attestation did not pass');
  }
  const seconds = Number(results.last_successful_attestation);
  if (!Number.isFinite(seconds) || seconds <= 0) {
    throw new Error('Keylime returned no successful attestation timestamp');
  }
  return { results, attestedAt: new Date(seconds * 1_000) };
}

function attestationCount(results) {
  const value = results.attestation_count;
  const count = typeof value === 'string' && /^[0-9]{1,15}$/.test(value) ? Number(value) : value;
  if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 0) {
    throw new Error('Keylime returned no usable attestation count');
  }
  return count;
}

export function createAttestAndDeploy(options) {
  const {
    statusCommand,
    statusSocket,
    artifactPath,
    inputPath,
    target,
    agentId,
    policyVersion,
    maximumAttestationAgeSeconds = SECURITY_PARAMETERS.attestation_max_age_sec,
    requiredOwnerUid = 0,
    now = () => Date.now(),
    commandRunner = runCommand,
    // Require an attestation whose quote was requested after this call began.
    // The verifier picks a fresh nonce for every poll, so once the successful
    // attestation count has risen by two since our first read, the second quote
    // was requested after the request arrived (the first may already have been
    // in flight).  The caller cannot choose the nonce; the guarantee is about
    // when the quote was asked for, not who asked.
    requireFreshAttestation = false,
    freshAttestationTimeoutSeconds = SECURITY_PARAMETERS.fresh_attestation_timeout_sec,
    freshAttestationPollMilliseconds = 500,
    sleep = (milliseconds) => new Promise((resolve) => { setTimeout(resolve, milliseconds); }),
  } = options;
  if (!Number.isFinite(freshAttestationTimeoutSeconds) || freshAttestationTimeoutSeconds < 1
      || freshAttestationTimeoutSeconds > 120
      || !Number.isFinite(freshAttestationPollMilliseconds)
      || freshAttestationPollMilliseconds < 50 || freshAttestationPollMilliseconds > 10_000) {
    throw new TypeError('invalid fresh attestation timing');
  }
  if (!Number.isSafeInteger(maximumAttestationAgeSeconds)
      || maximumAttestationAgeSeconds < 1 || maximumAttestationAgeSeconds > 86_400) {
    throw new TypeError('invalid maximum attestation age');
  }
  if (Boolean(statusCommand) === Boolean(statusSocket)) {
    throw new TypeError('configure exactly one of statusCommand or statusSocket');
  }
  if (!artifactPath || !inputPath || !target || !agentId || !policyVersion) {
    throw new TypeError('Keylime MCP server configuration is incomplete');
  }

  return async function attestAndDeploy(action) {
    if (action?.action_type !== 'workload.execute'
        || action.operation !== 'checksum.sha256'
        || action.target !== target
        || action.policy_version !== policyVersion
        || !DIGEST_PATTERN.test(action.artifact_sha256)
        || !DIGEST_PATTERN.test(action.input_sha256)
        || !UUID_PATTERN.test(action.occurrence_id)) {
      throw new Error('action does not match the Keylime MCP policy');
    }
    const readStatus = async () => {
      const { stdout } = statusSocket
        ? await readStatusSocket(statusSocket)
        : await commandRunner(statusCommand, [], {
          timeout: 15_000,
          maxBuffer: 256 * 1024,
        });
      return parseTenantStatus(stdout, agentId);
    };
    let { results, attestedAt } = await readStatus();
    let freshness = null;
    if (requireFreshAttestation) {
      const before = attestationCount(results);
      const deadline = now() + freshAttestationTimeoutSeconds * 1_000;
      let count = before;
      while (count < before + 2) {
        if (now() >= deadline) {
          throw new Error('Keylime did not attest again after the request in time');
        }
        await sleep(freshAttestationPollMilliseconds);
        ({ results, attestedAt } = await readStatus());
        count = attestationCount(results);
        if (count < before) throw new Error('Keylime attestation count went backwards');
      }
      freshness = { before, after: count };
    }
    const current = now();
    if (attestedAt.getTime() > current + 5_000
        || current - attestedAt.getTime() > maximumAttestationAgeSeconds * 1_000) {
      throw new Error('Keylime attestation is stale');
    }
    const artifactHandle = await openVerifiedProtectedFile(
      artifactPath,
      action.artifact_sha256,
      true,
      requiredOwnerUid,
    );
    let inputHandle;
    try {
      inputHandle = await openVerifiedProtectedFile(
        inputPath,
        action.input_sha256,
        false,
        requiredOwnerUid,
      );
    } catch (error) {
      await artifactHandle.close();
      throw error;
    }
    let execution;
    try {
      if (process.platform !== 'linux' && commandRunner === runCommand) {
        throw new Error('descriptor-bound workload execution requires Linux');
      }
      // Duplicate the already-verified descriptors into fixed child FDs.  The
      // child executes and reads /proc/self/fd rather than reopening mutable
      // paths after verification.
      execution = await commandRunner('/proc/self/fd/3', ['/proc/self/fd/4'], {
        timeout: 15_000,
        maxBuffer: 64 * 1024,
        stdio: ['ignore', 'pipe', 'pipe', artifactHandle.fd, inputHandle.fd],
      });
    } finally {
      await Promise.allSettled([artifactHandle.close(), inputHandle.close()]);
    }
    const evidenceMaterial = JSON.stringify({
      agent_id: agentId,
      attestation_status: results.attestation_status,
      operational_state: results.operational_state ?? null,
      last_successful_attestation: results.last_successful_attestation,
      target,
      occurrence_id: action.occurrence_id,
    });
    return {
      attestation: {
        provider: 'keylime',
        verdict: 'trusted',
        target,
        policy_version: policyVersion,
        occurrence_id: action.occurrence_id,
        attested_at: attestedAt.toISOString(),
        // Age and clock reading come from the node's own clock, taken when the
        // freshness check ran, so the controller never has to subtract
        // timestamps that came from two different clocks.
        ...(freshness ? {
          fresh_after_request: true,
          attestation_count_before: freshness.before,
          attestation_count_after: freshness.after,
        } : {}),
        age_seconds: Math.round(Math.max(0, current - attestedAt.getTime())) / 1_000,
        node_time: new Date(current).toISOString(),
        evidence_digest: `sha256:${crypto.createHash('sha256').update(evidenceMaterial).digest('hex')}`,
      },
      workload: {
        executed: true,
        operation: action.operation,
        artifact_sha256: action.artifact_sha256,
        input_sha256: action.input_sha256,
        stdout: execution.stdout.trim().slice(0, 4096),
      },
    };
  };
}
