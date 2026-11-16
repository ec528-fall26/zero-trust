// Approver signoffs made with keys the controller never holds.
//
// Each approver keeps a P-256 private key on their own machine.  The controller
// is configured with the public half only (config/approvers/*.json).  For a
// pending action the controller publishes an approval request: the exact claim
// the receipt will carry, plus the EP-ASSURANCE-CONTEXT-v1 hash over it.  An
// approver reviews the material fields, signs that hash in the WebAuthn-shaped
// format the EMILIA gate verifies, and sends the signoff back.  The gate later
// checks every signoff against the pinned public keys and quorum policy, so the
// controller cannot forge or reuse one.
import crypto from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

import { approvalActionHash } from '@emilia-protocol/require-receipt';
import { canonicalizeStrictJson } from '@emilia-protocol/require-receipt/strict-json';

export const APPROVAL_REQUEST_SCHEMA = 'ec528.approval-request.v1';
export const SIGNOFF_SCHEMA = 'ec528.approver-signoff.v1';
export const APPROVER_RECORD_SCHEMA = 'ec528.approver.v1';

// Flags byte of WebAuthn authenticator data: user present (0x01) and user
// verified (0x04).  The gate requires both.  Here they mean "the approver ran
// the signing tool and confirmed the action", not a hardware authenticator.
const FLAGS_UP_UV = 0x05;
const APPROVER_ID = /^ep:approver:[a-z0-9][a-z0-9-]{0,62}$/;
const KEY_ID = /^[a-z0-9][a-z0-9-]{0,62}$/;

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest();
}

function sha256Hex(bytes) {
  return sha256(bytes).toString('hex');
}

export function contextHashFor(receiptId, claim) {
  const context = {
    '@version': 'EP-ASSURANCE-CONTEXT-v1',
    receipt_id: receiptId,
    claim_hash: `sha256:${sha256Hex(canonicalizeStrictJson(claim))}`,
  };
  return `sha256:${sha256Hex(canonicalizeStrictJson(context))}`;
}

function publicKeyFromRecord(publicKey) {
  const key = crypto.createPublicKey({
    key: Buffer.from(publicKey, 'base64url'),
    format: 'der',
    type: 'spki',
  });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new TypeError('approver keys must be P-256');
  }
  return key;
}

export function publicKeyFingerprint(publicKey) {
  return `sha256:${sha256Hex(publicKeyFromRecord(publicKey).export({ type: 'spki', format: 'der' }))}`;
}

export function validateApproverRecord(record) {
  const allowed = ['schema', 'role', 'name', 'approver_id', 'key_id', 'public_key'];
  if (record === null || typeof record !== 'object' || Array.isArray(record)
      || Object.keys(record).some((field) => !allowed.includes(field))) {
    throw new TypeError('approver record has unknown fields');
  }
  if (record.schema !== APPROVER_RECORD_SCHEMA) throw new TypeError('approver record schema is invalid');
  if (typeof record.role !== 'string' || !KEY_ID.test(record.role)) {
    throw new TypeError('approver role is invalid');
  }
  if (typeof record.name !== 'string' || record.name.length < 1 || record.name.length > 80) {
    throw new TypeError('approver name is invalid');
  }
  if (typeof record.approver_id !== 'string' || !APPROVER_ID.test(record.approver_id)) {
    throw new TypeError('approver_id is invalid');
  }
  if (typeof record.key_id !== 'string' || !KEY_ID.test(record.key_id)) {
    throw new TypeError('approver key_id is invalid');
  }
  publicKeyFromRecord(record.public_key);
  return Object.freeze({ ...record });
}

// A roster is the pinned list of humans who may approve.  Every approver must
// be a different person with a different key; a shared key would let one
// person satisfy a two-person rule.
export function validateRoster(records, { minimum = 3 } = {}) {
  const roster = records.map(validateApproverRecord);
  if (roster.length < minimum) {
    throw new TypeError(`an approver roster needs at least ${minimum} people`);
  }
  for (const field of ['role', 'approver_id', 'key_id']) {
    if (new Set(roster.map((entry) => entry[field])).size !== roster.length) {
      throw new TypeError(`approver ${field} values must be distinct`);
    }
  }
  if (new Set(roster.map((entry) => publicKeyFingerprint(entry.public_key))).size !== roster.length) {
    throw new TypeError('each approver must have a distinct key');
  }
  return Object.freeze(roster);
}

export async function loadRoster(directory, options) {
  const names = (await readdir(directory)).filter((name) => name.endsWith('.json')).sort();
  const records = await Promise.all(names.map(async (name) => (
    JSON.parse(await readFile(path.join(directory, name), 'utf8'))
  )));
  return validateRoster(records, options);
}

export function createApprovalRequest({ receiptId, subject, claim, rpId, origin, expiresAt }) {
  return Object.freeze({
    schema: APPROVAL_REQUEST_SCHEMA,
    receipt_id: receiptId,
    subject,
    claim: structuredClone(claim),
    context_hash: contextHashFor(receiptId, claim),
    rp_id: rpId,
    origin,
    expires_at: expiresAt,
  });
}

// Checks an approval request before anyone signs it: the hash an approver signs
// must be recomputed from the fields they are shown, never taken on trust.
export function reviewApprovalRequest(request) {
  if (request?.schema !== APPROVAL_REQUEST_SCHEMA) throw new TypeError('not an approval request');
  const action = request.claim?.canonical_action;
  if (!action || typeof action !== 'object') throw new TypeError('approval request has no action');
  if (request.claim.action_hash !== approvalActionHash(action)) {
    throw new TypeError('approval request action_hash does not match its action');
  }
  if (request.context_hash !== contextHashFor(request.receipt_id, request.claim)) {
    throw new TypeError('approval request context_hash does not match its claim');
  }
  return Object.freeze({
    receipt_id: request.receipt_id,
    expires_at: request.expires_at,
    action_hash: request.claim.action_hash,
    action: structuredClone(action),
    threshold: request.claim.quorum?.threshold,
    eligible: request.claim.quorum?.signers || [],
  });
}

export function createSignoff(request, { privateKey, keyId }) {
  reviewApprovalRequest(request);
  const challenge = Buffer.from(request.context_hash.slice('sha256:'.length), 'hex');
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge: challenge.toString('base64url'),
    origin: request.origin,
    crossOrigin: false,
  }), 'utf8');
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(1);
  const authenticatorData = Buffer.concat([sha256(request.rp_id), Buffer.from([FLAGS_UP_UV]), counter]);
  const signature = crypto.sign(
    'sha256',
    Buffer.concat([authenticatorData, sha256(clientData)]),
    privateKey,
  );
  return Object.freeze({
    schema: SIGNOFF_SCHEMA,
    receipt_id: request.receipt_id,
    context_hash: request.context_hash,
    signoff: Object.freeze({
      approver_key_id: keyId,
      key_class: 'A',
      webauthn: Object.freeze({
        authenticator_data: authenticatorData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature: signature.toString('base64url'),
      }),
    }),
  });
}

// Mirrors the gate's WebAuthn check so the controller can tell an approver at
// once that a signoff is wrong.  The gate still re-verifies everything.
export function verifySignoff(envelope, request, record) {
  try {
    if (envelope?.schema !== SIGNOFF_SCHEMA) return 'signoff_schema_invalid';
    if (envelope.receipt_id !== request.receipt_id || envelope.context_hash !== request.context_hash) {
      return 'signoff_for_different_request';
    }
    const signoff = envelope.signoff;
    if (signoff?.approver_key_id !== record.key_id) return 'signoff_key_mismatch';
    const authData = Buffer.from(signoff.webauthn.authenticator_data, 'base64url');
    const clientDataBytes = Buffer.from(signoff.webauthn.client_data_json, 'base64url');
    if (authData.length < 37 || !sha256(request.rp_id).equals(authData.subarray(0, 32))) {
      return 'signoff_rp_mismatch';
    }
    if ((authData[32] & FLAGS_UP_UV) !== FLAGS_UP_UV) return 'signoff_flags_invalid';
    const clientData = JSON.parse(clientDataBytes.toString('utf8'));
    const challenge = Buffer.from(request.context_hash.slice('sha256:'.length), 'hex').toString('base64url');
    if (clientData.type !== 'webauthn.get' || clientData.challenge !== challenge
        || clientData.origin !== request.origin || clientData.crossOrigin === true) {
      return 'signoff_client_data_invalid';
    }
    const ok = crypto.verify(
      'sha256',
      Buffer.concat([authData, sha256(clientDataBytes)]),
      publicKeyFromRecord(record.public_key),
      Buffer.from(signoff.webauthn.signature, 'base64url'),
    );
    return ok ? null : 'signoff_signature_invalid';
  } catch {
    return 'signoff_malformed';
  }
}
