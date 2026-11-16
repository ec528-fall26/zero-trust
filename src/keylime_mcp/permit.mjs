// Launch permits: the node's own proof that a launch was approved.
//
// The bearer token only proves that a caller may talk to this server.  A permit
// is a short-lived Ed25519 signature from the controller, made after it has
// verified and reserved a 2-of-3 EMILIA receipt, and bound to one exact action
// on this enrolled node.  This module is the node's half; signing lives in
// src/controller/permit_signer.mjs so the private key never reaches the node.
import crypto from 'node:crypto';

import { canonicalPolicyJson, sha256Digest } from './policy_digest.mjs';
import { SECURITY_PARAMETERS } from '../security_parameters.mjs';

export const PERMIT_VERSION = 'EC528-PERMIT-v1';
// Workload permits carry the node's enrollment epoch.  Bootstrap happens before
// any epoch exists, so its permits carry this fixed value instead.
export const PRE_ENROLLMENT_EPOCH = 'pre-enrollment';

const PAYLOAD_FIELDS = Object.freeze([
  'action_sha256',
  'agent_uuid',
  'enrollment_epoch',
  'expires_at',
  'issued_at',
  'receipt_sha256',
  'target',
  'tool',
  'version',
]);
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const MAXIMUM_TEXT_LENGTH = 256;

// A refusal the operator can act on.  `reason` is a fixed code, safe to log.
export class PermitRefused extends Error {
  constructor(reason) {
    super(`permit refused: ${reason}`);
    this.name = 'PermitRefused';
    this.reason = reason;
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function boundedText(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= MAXIMUM_TEXT_LENGTH;
}

export function validEnrollmentEpoch(value) {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

function validPermitEpoch(value) {
  return value === PRE_ENROLLMENT_EPOCH || validEnrollmentEpoch(value);
}

export function permitActionDigest(action) {
  return sha256Digest(Buffer.from(canonicalPolicyJson(action), 'utf8'));
}

export function permitPayloadBytes(payload) {
  return Buffer.from(canonicalPolicyJson(payload), 'utf8');
}

function wellFormed(permit) {
  if (!isPlainObject(permit)
      || Object.keys(permit).sort().join('\n') !== 'payload\nsignature') return false;
  const { payload, signature } = permit;
  return isPlainObject(payload)
    && Object.keys(payload).sort().join('\n') === PAYLOAD_FIELDS.join('\n')
    && typeof signature === 'string'
    && SIGNATURE_PATTERN.test(signature)
    && payload.version === PERMIT_VERSION
    && boundedText(payload.tool)
    && boundedText(payload.target)
    && boundedText(payload.agent_uuid)
    && DIGEST_PATTERN.test(payload.action_sha256)
    && DIGEST_PATTERN.test(payload.receipt_sha256)
    && validPermitEpoch(payload.enrollment_epoch)
    && Number.isSafeInteger(payload.issued_at)
    && Number.isSafeInteger(payload.expires_at);
}

export function createPermitVerifier(options = {}) {
  const {
    publicKeyPem,
    target,
    agentId,
    maximumLifetimeSeconds = SECURITY_PARAMETERS.permit_max_lifetime_sec,
    clockSkewSeconds = SECURITY_PARAMETERS.clock_skew_tolerance_sec,
    now = () => Date.now(),
  } = options;
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(publicKeyPem);
  } catch (error) {
    throw new TypeError('a permit public key is required', { cause: error });
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('the permit public key must be Ed25519');
  }
  if (!boundedText(target) || !boundedText(agentId)) {
    throw new TypeError('the permit verifier needs the node target and agent identity');
  }
  if (!Number.isSafeInteger(maximumLifetimeSeconds) || maximumLifetimeSeconds < 1
      || !Number.isSafeInteger(clockSkewSeconds) || clockSkewSeconds < 0) {
    throw new TypeError('invalid permit timing');
  }

  return Object.freeze({
    // Checks everything that needs no I/O.  The enrollment epoch is compared by
    // the caller, against the value it reads from the node's status helper.
    verify(permit, { tool, action }) {
      if (permit === undefined || permit === null) throw new PermitRefused('permit_missing');
      if (!wellFormed(permit)) throw new PermitRefused('permit_malformed');
      const { payload, signature } = permit;
      // The signature comes first: nothing in an unauthenticated payload is
      // reported back or acted on.
      if (!crypto.verify(
        null,
        permitPayloadBytes(payload),
        publicKey,
        Buffer.from(signature, 'base64url'),
      )) {
        throw new PermitRefused('signature_invalid');
      }
      if (payload.tool !== tool) throw new PermitRefused('tool_mismatch');
      if (payload.action_sha256 !== permitActionDigest(action)) {
        throw new PermitRefused('action_mismatch');
      }
      if (payload.target !== target) throw new PermitRefused('target_mismatch');
      if (payload.agent_uuid !== agentId) throw new PermitRefused('agent_mismatch');
      if (payload.expires_at <= payload.issued_at
          || payload.expires_at - payload.issued_at > maximumLifetimeSeconds * 1_000) {
        throw new PermitRefused('lifetime_invalid');
      }
      const current = now();
      if (payload.issued_at > current + clockSkewSeconds * 1_000) {
        throw new PermitRefused('not_yet_valid');
      }
      if (current > payload.expires_at + clockSkewSeconds * 1_000) {
        throw new PermitRefused('expired');
      }
      return Object.freeze({ ...payload });
    },
  });
}
