// Revocation checking at verify time.
//
// An EMILIA receipt can be verified offline, so a receipt signed by an approver
// whose key was revoked afterwards still looks valid.  This module lets the
// dispatcher consult a signed revocation list at the moment of use:
//
//   { "@version": "EC528-REVOCATION-LIST-v1",
//     "payload": { "sequence": 7, "issued_at": "<ISO time>",
//                  "revoked": [ { "approver_key_id": "...", "revoked_at": "<ISO time>" } ] },
//     "signature": { "algorithm": "Ed25519", "value": "<base64url>" } }
//
// The signature covers the canonical JSON of `payload` and is made by a
// revocation authority whose public key the controller pins.  The check fails
// closed: no list, a list that does not verify, an old list, or a list older
// than one already seen all refuse the receipt, and any signer on the list
// refuses it regardless of when the receipt was signed.
//
// Limit: the highest sequence seen is kept in memory only, so an attacker who
// can restart the controller and replay an old list could roll it back.

import crypto from 'node:crypto';

import { canonicalPolicyJson } from '../keylime_mcp/policy_digest.mjs';
import { SECURITY_PARAMETERS } from '../security_parameters.mjs';

export const REVOCATION_LIST_VERSION = 'EC528-REVOCATION-LIST-v1';
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const FUTURE_TOLERANCE_MS = 5_000;

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function signRevocationList({ privateKey, sequence, issuedAt, revoked = [] }) {
  const payload = {
    sequence,
    issued_at: issuedAt,
    revoked: revoked.map((entry) => ({
      approver_key_id: entry.approver_key_id,
      revoked_at: entry.revoked_at,
    })),
  };
  const value = crypto.sign(
    null,
    Buffer.from(canonicalPolicyJson(payload), 'utf8'),
    privateKey,
  ).toString('base64url');
  return {
    '@version': REVOCATION_LIST_VERSION,
    payload,
    signature: { algorithm: 'Ed25519', value },
  };
}

function verifiedPayload(list, authorityPublicKey) {
  if (!isPlainObject(list) || list['@version'] !== REVOCATION_LIST_VERSION
      || !isPlainObject(list.payload) || !isPlainObject(list.signature)
      || list.signature.algorithm !== 'Ed25519'
      || typeof list.signature.value !== 'string') {
    return null;
  }
  try {
    const verified = crypto.verify(
      null,
      Buffer.from(canonicalPolicyJson(list.payload), 'utf8'),
      authorityPublicKey,
      Buffer.from(list.signature.value, 'base64url'),
    );
    return verified ? list.payload : null;
  } catch {
    return null;
  }
}

// Key ids of every approver whose sign-off is inside the receipt.
export function receiptSignerKeyIds(receipt) {
  const signoffs = receipt?.payload?.assurance_proof?.signoffs;
  if (!Array.isArray(signoffs)) return [];
  return signoffs
    .map((signoff) => signoff?.approver_key_id)
    .filter((id) => typeof id === 'string');
}

export function createRevocationChecker(options) {
  const {
    authorityPublicKey,
    load,
    maximumAgeSeconds = SECURITY_PARAMETERS.revocation_list_max_age_sec,
    now = () => Date.now(),
  } = options || {};
  if (typeof load !== 'function') throw new TypeError('a revocation list loader is required');
  if (!Number.isSafeInteger(maximumAgeSeconds) || maximumAgeSeconds < 1) {
    throw new TypeError('invalid maximum revocation list age');
  }
  const publicKey = typeof authorityPublicKey === 'string'
    ? crypto.createPublicKey({
      key: Buffer.from(authorityPublicKey, 'base64url'),
      format: 'der',
      type: 'spki',
    })
    : authorityPublicKey;
  if (!publicKey || publicKey.type !== 'public') {
    throw new TypeError('a revocation authority public key is required');
  }
  let highestSequence = -1;
  let highestPayloadDigest = null;

  async function check(receipt) {
    const signers = receiptSignerKeyIds(receipt);
    let list;
    try {
      list = await load();
    } catch {
      return { ok: false, reason: 'revocation_unavailable' };
    }
    if (list === null || list === undefined) {
      return { ok: false, reason: 'revocation_unavailable' };
    }
    const payload = verifiedPayload(list, publicKey);
    if (payload === null
        || !Number.isSafeInteger(payload.sequence) || payload.sequence < 0
        || !Array.isArray(payload.revoked)
        || payload.revoked.some((entry) => !isPlainObject(entry)
          || typeof entry.approver_key_id !== 'string'
          || !KEY_ID_PATTERN.test(entry.approver_key_id)
          || !Number.isFinite(Date.parse(entry.revoked_at)))) {
      return { ok: false, reason: 'revocation_list_invalid' };
    }
    const issuedAt = Date.parse(payload.issued_at);
    const current = now();
    if (!Number.isFinite(issuedAt) || issuedAt > current + FUTURE_TOLERANCE_MS) {
      return { ok: false, reason: 'revocation_list_invalid' };
    }
    if (current - issuedAt > maximumAgeSeconds * 1_000) {
      return { ok: false, reason: 'revocation_list_stale' };
    }
    const keyIds = payload.revoked.map((entry) => entry.approver_key_id);
    if (new Set(keyIds).size !== keyIds.length
        || payload.revoked.some((entry) => Date.parse(entry.revoked_at) > current + FUTURE_TOLERANCE_MS)) {
      return { ok: false, reason: 'revocation_list_invalid' };
    }
    const payloadDigest = crypto.createHash('sha256')
      .update(canonicalPolicyJson(payload), 'utf8')
      .digest('hex');
    if (payload.sequence < highestSequence) {
      return { ok: false, reason: 'revocation_list_rollback' };
    }
    if (payload.sequence === highestSequence && payloadDigest !== highestPayloadDigest) {
      return { ok: false, reason: 'revocation_list_rollback' };
    }
    highestSequence = payload.sequence;
    highestPayloadDigest = payloadDigest;
    const revoked = new Set(payload.revoked.map((entry) => entry.approver_key_id));
    if (signers.some((id) => revoked.has(id))) {
      return { ok: false, reason: 'approver_key_revoked' };
    }
    return { ok: true, sequence: payload.sequence };
  }

  return Object.freeze({ check });
}
