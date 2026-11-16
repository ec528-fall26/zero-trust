// Policy digest pinning.
//
// The action that approvers sign carries `policy_version`.  Until now that was
// a hand-typed label, so the Keylime allowlist and the EMILIA approval policy
// could change without the label changing.  This module derives the label from
// the policies themselves:
//
//   policy_version = "pd1-" + first 60 hex characters of
//                    sha256(canonical JSON of
//                      { "@version": "EC528-POLICY-DIGEST-v1",
//                        "keylime_policy_sha256": <digest of the Keylime policy bytes>,
//                        "approval_policy": <approval policy bundle> })
//
// The result still matches the existing `policy_version` pattern
// (^[a-z0-9][a-z0-9._-]{0,63}$, 64 characters), so every component that
// already compares the field by equality now compares the real policies.
//
// This file lives under src/keylime_mcp/ because the node deployment ships only
// that directory.  src/controller/policy_digest.py implements the same
// algorithm; both are checked against the same test vector.

import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';

export const POLICY_DIGEST_VERSION = 'EC528-POLICY-DIGEST-v1';
export const APPROVAL_POLICY_VERSION = 'EC528-APPROVAL-POLICY-v1';
const PREFIX = 'pd1-';
const HEX_CHARACTERS = 60;
const MAXIMUM_DEPTH = 16;
const MAXIMUM_POLICY_BYTES = 1024 * 1024;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const KEY_PATTERN = /^[\x20-\x7e]*$/;

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

// Deterministic JSON for policy documents.  Objects have ASCII keys sorted in
// code order; numbers must be safe integers.  The Python implementation
// enforces the same limits, so both languages produce identical bytes.
export function canonicalPolicyJson(value, depth = 0) {
  if (depth > MAXIMUM_DEPTH) throw new TypeError('policy_too_deep');
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) throw new TypeError('policy_number_unsupported');
      return String(value);
    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalPolicyJson(item, depth + 1)).join(',')}]`;
      }
      if (!isPlainObject(value)) throw new TypeError('policy_object_unsupported');
      const keys = Object.keys(value).sort();
      const members = keys.map((key) => {
        if (!KEY_PATTERN.test(key)) throw new TypeError('policy_key_unsupported');
        return `${JSON.stringify(key)}:${canonicalPolicyJson(value[key], depth + 1)}`;
      });
      return `{${members.join(',')}}`;
    }
    default:
      throw new TypeError('policy_value_unsupported');
  }
}

export function sha256Digest(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

// The approver-facing half of the policy: who may issue receipts, who may
// approve, how many are needed, and where approvals are accepted from.
export function approvalPolicyBundle({
  trustedKeys,
  approverKeys,
  quorumPolicies,
  rpId,
  allowedOrigins,
}) {
  if (!Array.isArray(trustedKeys) || trustedKeys.length === 0) {
    throw new TypeError('trustedKeys is required');
  }
  if (!isPlainObject(approverKeys) || !isPlainObject(quorumPolicies)) {
    throw new TypeError('approverKeys and quorumPolicies are required');
  }
  return {
    '@version': APPROVAL_POLICY_VERSION,
    issuer_keys: [...trustedKeys].sort(),
    approver_keys: approverKeys,
    quorum_policies: quorumPolicies,
    rp_id: rpId ?? null,
    allowed_origins: [...(allowedOrigins || [])].sort(),
  };
}

export function policyDigest({ keylimePolicySha256, approvalPolicy }) {
  if (typeof keylimePolicySha256 !== 'string' || !DIGEST_PATTERN.test(keylimePolicySha256)) {
    throw new TypeError('keylimePolicySha256 must be a sha256: digest');
  }
  if (!isPlainObject(approvalPolicy)) throw new TypeError('approvalPolicy is required');
  const document = canonicalPolicyJson({
    '@version': POLICY_DIGEST_VERSION,
    keylime_policy_sha256: keylimePolicySha256,
    approval_policy: approvalPolicy,
  });
  const hex = crypto.createHash('sha256').update(document, 'utf8').digest('hex');
  return `${PREFIX}${hex.slice(0, HEX_CHARACTERS)}`;
}

async function readBounded(filePath) {
  const bytes = await readFile(filePath);
  if (bytes.length === 0 || bytes.length > MAXIMUM_POLICY_BYTES) {
    throw new Error('policy file is empty or too large');
  }
  return bytes;
}

// Used on the node and by the controller tooling: hash the Keylime policy file
// exactly as it is on disk, and canonicalize the approval policy bundle.
export async function policyVersionFromFiles({ keylimePolicyPath, approvalPolicyPath }) {
  const [keylimeBytes, approvalBytes] = await Promise.all([
    readBounded(keylimePolicyPath),
    readBounded(approvalPolicyPath),
  ]);
  let approvalPolicy;
  try {
    approvalPolicy = JSON.parse(approvalBytes.toString('utf8'));
  } catch {
    throw new Error('approval policy file is not valid JSON');
  }
  return policyDigest({
    keylimePolicySha256: sha256Digest(keylimeBytes),
    approvalPolicy,
  });
}
