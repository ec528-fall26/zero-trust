// The controller's half of launch permits.  Only trusted controller code loads
// this module; deploy.sh does not ship it, so the private key stays off the node.
import crypto from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';

import {
  PERMIT_VERSION,
  PRE_ENROLLMENT_EPOCH,
  permitActionDigest,
  permitPayloadBytes,
  validEnrollmentEpoch,
} from '../keylime_mcp/permit.mjs';
import { sha256Digest } from '../keylime_mcp/policy_digest.mjs';
import { SECURITY_PARAMETERS } from '../security_parameters.mjs';

export function signPermitPayload(payload, privateKey) {
  return Object.freeze({
    payload,
    signature: crypto.sign(null, permitPayloadBytes(payload), privateKey).toString('base64url'),
  });
}

export function createPermitSigner(options = {}) {
  const {
    privateKeyPem,
    agentUuid,
    enrollmentEpoch,
    lifetimeSeconds = SECURITY_PARAMETERS.permit_max_lifetime_sec,
    now = () => Date.now(),
  } = options;
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(privateKeyPem);
  } catch (error) {
    throw new TypeError('a permit signing key is required', { cause: error });
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('the permit signing key must be Ed25519');
  }
  if (typeof agentUuid !== 'string' || agentUuid.length === 0) {
    throw new TypeError('the permit signer needs the node agent identity');
  }
  if (enrollmentEpoch !== PRE_ENROLLMENT_EPOCH && !validEnrollmentEpoch(enrollmentEpoch)) {
    throw new TypeError('the permit signer needs a valid enrollment epoch');
  }
  if (!Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1
      || lifetimeSeconds > SECURITY_PARAMETERS.permit_max_lifetime_sec) {
    throw new TypeError('invalid permit lifetime');
  }

  return Object.freeze({
    sign({ tool, action, receiptId }) {
      if (typeof tool !== 'string' || tool.length === 0) {
        throw new TypeError('a permit must name its tool');
      }
      if (typeof action?.target !== 'string') throw new TypeError('a permit needs an action');
      // No receipt reference means nothing was approved, so nothing is signed.
      if (typeof receiptId !== 'string' || receiptId.length === 0) {
        throw new TypeError('a permit needs the verified receipt');
      }
      const issuedAt = now();
      return signPermitPayload({
        version: PERMIT_VERSION,
        tool,
        action_sha256: permitActionDigest(action),
        target: action.target,
        agent_uuid: agentUuid,
        enrollment_epoch: enrollmentEpoch,
        receipt_sha256: sha256Digest(Buffer.from(receiptId, 'utf8')),
        issued_at: issuedAt,
        expires_at: issuedAt + lifetimeSeconds * 1_000,
      }, privateKey);
    },
  });
}

async function readPrivateKeyFile(keyPath) {
  const details = await stat(keyPath);
  if (!details.isFile() || (details.mode & 0o077) !== 0) {
    throw new Error('the permit signing key must be a file with mode 0600');
  }
  return readFile(keyPath, 'utf8');
}

function permitKeyPath(repositoryRoot, environment) {
  return path.resolve(environment.KEYLIME_PERMIT_KEY_FILE
    || path.join(repositoryRoot, 'build', 'aws-keylime', 'permit-key.pem'));
}

export function enrollmentRecordPath(repositoryRoot, environment = process.env) {
  return path.resolve(environment.KEYLIME_ENROLLMENT_FILE
    || path.join(repositoryRoot, 'build', 'aws-keylime', 'enrollment.json'));
}

// Signer for workloads, using the epoch recorded when this node was bootstrapped.
export async function permitSignerFromEnvironment(repositoryRoot, environment = process.env) {
  const privateKeyPem = await readPrivateKeyFile(permitKeyPath(repositoryRoot, environment));
  const enrollment = JSON.parse(
    await readFile(enrollmentRecordPath(repositoryRoot, environment), 'utf8'),
  );
  return createPermitSigner({
    privateKeyPem,
    agentUuid: enrollment.agent_uuid,
    enrollmentEpoch: enrollment.enrollment_epoch,
  });
}

export async function bootstrapPermitSignerFromEnvironment(
  repositoryRoot,
  agentUuid,
  environment = process.env,
) {
  return createPermitSigner({
    privateKeyPem: await readPrivateKeyFile(permitKeyPath(repositoryRoot, environment)),
    agentUuid,
    enrollmentEpoch: PRE_ENROLLMENT_EPOCH,
  });
}
