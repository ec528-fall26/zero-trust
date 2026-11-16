import net from 'node:net';

import { PRE_ENROLLMENT_EPOCH, PermitRefused } from './permit.mjs';

const MAX_RESPONSE_BYTES = 64 * 1024;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

function validAction(action) {
  return action?.action_type === 'tenant.bootstrap'
    && typeof action.target === 'string'
    && action.target.length >= 1
    && action.target.length <= 256
    && UUID_PATTERN.test(action.agent_uuid)
    && DIGEST_PATTERN.test(action.runtime_policy_sha256)
    && DIGEST_PATTERN.test(action.payload_sha256)
    && UUID_PATTERN.test(action.occurrence_id)
    && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(action.policy_version);
}

export function createBootstrapTenant({
  socketPath,
  permitVerifier,
  timeoutMilliseconds = 120_000,
} = {}) {
  if (typeof permitVerifier?.verify !== 'function') {
    throw new TypeError('a permit verifier is required');
  }
  if (typeof socketPath !== 'string' || !socketPath.startsWith('/')) {
    throw new TypeError('an absolute Keylime bootstrap socket path is required');
  }
  if (!Number.isSafeInteger(timeoutMilliseconds)
      || timeoutMilliseconds < 1_000 || timeoutMilliseconds > 300_000) {
    throw new TypeError('invalid Keylime bootstrap timeout');
  }
  return async function bootstrapTenant(action, permit) {
    if (!validAction(action)) throw new Error('bootstrap action is invalid');
    const verifiedPermit = permitVerifier.verify(permit, {
      tool: 'bootstrap_keylime_tenant',
      action,
    });
    if (verifiedPermit.enrollment_epoch !== PRE_ENROLLMENT_EPOCH) {
      throw new PermitRefused('enrollment_epoch_mismatch');
    }
    const request = Buffer.from(`${JSON.stringify(action)}\n`, 'utf8');
    const response = await new Promise((resolve, reject) => {
      const socket = net.createConnection({ path: socketPath });
      const chunks = [];
      let size = 0;
      socket.setTimeout(timeoutMilliseconds);
      socket.once('connect', () => socket.end(request));
      socket.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          socket.destroy(new Error('bootstrap response exceeded its bound'));
          return;
        }
        chunks.push(chunk);
      });
      socket.once('timeout', () => socket.destroy(new Error('bootstrap timed out')));
      socket.once('error', reject);
      socket.once('end', () => resolve(Buffer.concat(chunks, size).toString('utf8')));
    });
    let result;
    try {
      result = JSON.parse(response);
    } catch {
      throw new Error('bootstrap helper returned invalid JSON');
    }
    if (result?.status !== 'enrolled'
        || result.agent_uuid !== action.agent_uuid
        || result.runtime_policy_sha256 !== action.runtime_policy_sha256
        || result.payload_sha256 !== action.payload_sha256
        || result.occurrence_id !== action.occurrence_id) {
      throw new Error('bootstrap result is not bound to the approved action');
    }
    return result;
  };
}
