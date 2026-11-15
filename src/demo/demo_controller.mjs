import crypto from 'node:crypto';
import { open, readFile } from 'node:fs/promises';
import path from 'node:path';

import { approvalActionHash } from '@emilia-protocol/require-receipt';
import { canonicalizeStrictJson } from '@emilia-protocol/require-receipt/strict-json';

import {
  createReceiptRequiredDispatcher,
  DurableReceiptStore,
} from '../controller/receipt_required_mcp.mjs';
import { approvalPolicyBundle } from '../keylime_mcp/policy_digest.mjs';
import {
  createApprovalRequest,
  createSignoff,
  validateRoster,
  verifySignoff,
} from '../controller/approver_signoff.mjs';
import { SECURITY_PARAMETERS } from '../security_parameters.mjs';

const APPROVER_DEFINITIONS = Object.freeze([
  Object.freeze({ role: 'operator', id: 'ep:approver:operator' }),
  Object.freeze({ role: 'security', id: 'ep:approver:security' }),
  Object.freeze({ role: 'reviewer', id: 'ep:approver:reviewer' }),
]);

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest();
}

async function digestRegularFile(filePath, maximumBytes = 64 * 1024 * 1024) {
  const handle = await open(filePath, 'r');
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size < 0 || before.size > maximumBytes) {
      throw new Error('demo material is not a bounded regular file');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (before.dev !== after.dev
        || before.ino !== after.ino
        || before.size !== after.size
        || before.mtimeMs !== after.mtimeMs
        || before.ctimeMs !== after.ctimeMs) {
      throw new Error('demo material changed while it was read');
    }
    return `sha256:${sha256(bytes).toString('hex')}`;
  } finally {
    await handle.close();
  }
}

function createApprover(definition) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync(
    'ec',
    { namedCurve: 'prime256v1' },
  );
  return Object.freeze({
    ...definition,
    privateKey,
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    keyId: `demo-${definition.role}-key`,
  });
}

function createIssuer() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return Object.freeze({
    privateKey,
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  });
}

function buildClaim(action, signerIds) {
  return {
    action_type: action.action_type,
    outcome: 'allow_with_signoff',
    canonical_action: action,
    action_hash: approvalActionHash(action),
    quorum: {
      threshold: 2,
      signers: signerIds,
    },
  };
}

// The issuer signs the whole payload once a quorum of signoffs exists.  The
// approvers signed only the receipt_id and claim (EP-ASSURANCE-CONTEXT-v1), so
// created_at is set at issuance and the receipt lifetime starts then.
function assembleReceipt({ request, signoffs, issuer, createdAt }) {
  const payload = {
    receipt_id: request.receipt_id,
    subject: request.subject,
    created_at: createdAt,
    claim: structuredClone(request.claim),
    assurance_proof: {
      '@version': 'EP-ASSURANCE-PROOF-v1',
      context_hash: request.context_hash,
      signoffs,
    },
  };
  const signature = crypto.sign(
    null,
    Buffer.from(canonicalizeStrictJson(payload), 'utf8'),
    issuer.privateKey,
  ).toString('base64url');
  return Object.freeze({
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: signature },
  });
}

function issueFixtureReceipt({ action, issuer, approvers, rpId, origin, createdAt }) {
  const request = createApprovalRequest({
    receiptId: `demo-${crypto.randomUUID()}`,
    subject: 'agent:ec528-demo',
    claim: buildClaim(action, approvers.map((approver) => approver.id)),
    rpId,
    origin,
    expiresAt: null,
  });
  const signoffs = approvers.map((approver) => (
    createSignoff(request, { privateKey: approver.privateKey, keyId: approver.keyId }).signoff
  ));
  return assembleReceipt({ request, signoffs, issuer, createdAt });
}

function publicResponse(response) {
  return {
    status: response.status,
    body: response.body,
  };
}

function toolArguments(action) {
  return Object.fromEntries(Object.entries(action).filter(([name]) => name !== 'action_type'));
}

export async function createDemoController(options) {
  const {
    action: initialAction,
    artifactPath,
    inputPath,
    keylimeHandler = null,
    manifest,
    stateDirectory,
    approvalWindowMs = SECURITY_PARAMETERS.approval_window_sec * 1_000,
    receiptCreatedAt = null,
    now = () => Date.now(),
    // Optional policy pinning.  With a Keylime policy digest the dispatcher only
    // accepts the policy_version derived from that digest and its own approval
    // policy.  bindPolicyVersion also rewrites the action's policy_version to
    // that derived value, because it depends on keys generated just below.
    keylimePolicySha256 = null,
    bindPolicyVersion = false,
    revocation = null,
    toolName = 'execute_approved_workload',
    // Real people: records from config/approvers/ (public keys only).  Without
    // a roster the controller generates labelled fixture keys for automation.
    approverRoster = null,
  } = options;
  let action = initialAction;
  const issuer = createIssuer();
  const roster = approverRoster === null ? null : validateRoster(approverRoster);
  const approvers = roster === null
    ? APPROVER_DEFINITIONS.map(createApprover)
    : roster.map((record) => Object.freeze({
      role: record.role,
      id: record.approver_id,
      keyId: record.key_id,
      publicKey: record.public_key,
      record,
    }));
  const approverByRole = new Map(approvers.map((approver) => [approver.role, approver]));
  const approverByKeyId = new Map(approvers.map((approver) => [approver.keyId, approver]));
  const approvals = new Set();
  const humanSignoffs = new Map();
  let approvalRequestRecord = null;
  const events = [];
  const rpId = '127.0.0.1';
  const origin = 'http://127.0.0.1';
  let receipt = null;
  let lastResponse = null;
  let approvalExpiresAt = null;

  if (!Number.isSafeInteger(approvalWindowMs) || approvalWindowMs < 1) {
    throw new TypeError('approval window must be a positive integer');
  }

  const approverKeys = Object.fromEntries(approvers.map((approver) => [
    approver.keyId,
    {
      public_key: approver.publicKey,
      key_class: 'A',
      approver_id: approver.id,
    },
  ]));
  const quorumPolicy = {
    mode: 'threshold',
    required: 2,
    distinct_humans: true,
    window_sec: SECURITY_PARAMETERS.approval_window_sec,
    approvers: approvers.map((approver) => ({
      role: approver.role,
      approver: approver.id,
    })),
  };
  const manifestAction = manifest.actions.find((entry) => entry?.match?.tool === toolName);
  if (!manifestAction?.receipt_required || manifestAction.action_type !== action.action_type) {
    throw new TypeError('tool is not bound to the requested receipt action');
  }
  const policyId = manifestAction.id;
  const activeManifest = {
    ...manifest,
    actions: manifest.actions.filter((entry) => (
      entry?.receipt_required !== true || entry?.match?.tool === toolName
    )),
  };
  const store = await new DurableReceiptStore(
    path.join(stateDirectory, 'receipt-store'),
  ).initialize();

  async function mockKeylimeHandler(observedAction) {
    const [artifactDigest, inputDigest] = await Promise.all([
      digestRegularFile(artifactPath),
      digestRegularFile(inputPath),
    ]);
    if (artifactDigest !== observedAction.artifact_sha256
        || inputDigest !== observedAction.input_sha256) {
      throw new Error('keylime mock refused changed workload material');
    }
    const input = await readFile(inputPath);
    const evidence = {
      provider: 'local-keylime-stand-in',
      verdict: 'trusted',
      target: observedAction.target,
      policy_version: observedAction.policy_version,
      evidence_digest: `sha256:${sha256(canonicalizeStrictJson({
        target: observedAction.target,
        artifact_sha256: artifactDigest,
        input_sha256: inputDigest,
        verdict: 'trusted',
      })).toString('hex')}`,
    };
    events.push({ stage: 'keylime', outcome: 'trusted', at: new Date().toISOString() });
    return {
      attestation: evidence,
      workload: {
        operation: observedAction.operation,
        executed: true,
        result_sha256: `sha256:${sha256(input).toString('hex')}`,
      },
    };
  }

  const activeKeylimeHandler = keylimeHandler || mockKeylimeHandler;
  const dispatch = await createReceiptRequiredDispatcher({
    manifest: activeManifest,
    handlers: {
      [toolName]: activeKeylimeHandler,
      get_request_status: async () => snapshot(),
    },
    trustedKeys: [issuer.publicKey],
    approverKeys,
    rpId,
    allowedOrigins: [origin],
    quorumPolicies: { [policyId]: quorumPolicy },
    keylimePolicySha256,
    revocation,
    store,
    audit: async (event) => {
      events.push({ stage: 'receipt-guard', ...event, at: new Date().toISOString() });
    },
  });

  if (bindPolicyVersion) {
    if (dispatch.expectedPolicyVersion === null) {
      throw new TypeError('bindPolicyVersion requires keylimePolicySha256');
    }
    action = { ...action, policy_version: dispatch.expectedPolicyVersion };
  }

  function policy() {
    return Object.freeze({
      expected_policy_version: dispatch.expectedPolicyVersion,
      approval_policy: approvalPolicyBundle({
        trustedKeys: [issuer.publicKey],
        approverKeys,
        quorumPolicies: { [policyId]: quorumPolicy },
        rpId,
        allowedOrigins: [origin],
      }),
    });
  }

  function snapshot() {
    const approvalExpired = approvalExpiresAt !== null
      && receipt === null
      && now() >= approvalExpiresAt;
    return {
      mode: 'local-integration-demo',
      approver_mode: roster ? 'human' : 'fixture',
      limitations: [
        roster
          ? 'Approvers sign on their own machines with their own P-256 keys; the controller holds only their public keys. The keys are software keys in files, not hardware authenticators.'
          : 'Approver keys are ephemeral local demo keys (automation), not enrolled human credentials.',
        ...(keylimeHandler ? [] : [
          'Keylime attestation is a digest-checking local stand-in until the team endpoint is available.',
        ]),
      ],
      keylime_mode: keylimeHandler ? 'remote-mcp' : 'local-stand-in',
      action,
      action_hash: approvalActionHash(action),
      approvals: [...approvals],
      required_approvals: 2,
      approval_status: approvalExpired ? 'expired' : (receipt ? 'approved' : 'pending'),
      approval_expires_at: approvalExpiresAt === null
        ? null
        : new Date(approvalExpiresAt).toISOString(),
      receipt_ready: receipt !== null,
      receipt_id: receipt?.payload.receipt_id || null,
      last_response: lastResponse,
      events: events.slice(-50),
    };
  }

  function approvalWindowExpired() {
    return approvalExpiresAt !== null && receipt === null && now() >= approvalExpiresAt;
  }

  // Human mode: the exact claim the receipt will carry, frozen on first use.
  // Every approver signs this same request; the window starts here.
  function approvalRequest() {
    if (roster === null) throw new Error('approval requests are only used with an approver roster');
    if (approvalRequestRecord === null) {
      approvalExpiresAt = now() + approvalWindowMs;
      approvalRequestRecord = createApprovalRequest({
        receiptId: `ep-${crypto.randomUUID()}`,
        subject: 'agent:ec528-demo',
        claim: buildClaim(action, approvers.map((approver) => approver.id)),
        rpId,
        origin,
        expiresAt: new Date(approvalExpiresAt).toISOString(),
      });
      events.push({ stage: 'emilia', outcome: 'approval-requested', at: new Date(now()).toISOString() });
    }
    return approvalRequestRecord;
  }

  function rejectSignoff(reason, details = {}) {
    events.push({ stage: 'emilia', outcome: 'signoff-rejected', reason, ...details, at: new Date(now()).toISOString() });
    return { accepted: false, reason, snapshot: snapshot() };
  }

  function submitSignoff(envelope) {
    if (roster === null) throw new Error('signoffs are only accepted with an approver roster');
    if (approvalRequestRecord === null) return rejectSignoff('no_pending_request');
    if (receipt !== null) return rejectSignoff('quorum_already_reached');
    if (approvalWindowExpired()) return rejectSignoff('approval_window_expired');
    const approver = approverByKeyId.get(envelope?.signoff?.approver_key_id);
    if (!approver) return rejectSignoff('approver_not_enrolled');
    const failure = verifySignoff(envelope, approvalRequestRecord, approver.record);
    if (failure) return rejectSignoff(failure, { role: approver.role });
    if (humanSignoffs.has(approver.id)) return rejectSignoff('duplicate_approver', { role: approver.role });
    humanSignoffs.set(approver.id, envelope.signoff);
    approvals.add(approver.role);
    events.push({ stage: 'emilia', outcome: 'approved', role: approver.role, at: new Date(now()).toISOString() });
    if (humanSignoffs.size >= 2) {
      receipt = assembleReceipt({
        request: approvalRequestRecord,
        signoffs: [...humanSignoffs.values()].slice(0, 2),
        issuer,
        createdAt: receiptCreatedAt || new Date(now()).toISOString(),
      });
      events.push({ stage: 'emilia', outcome: 'receipt-issued', at: new Date(now()).toISOString() });
    }
    return { accepted: true, reason: null, snapshot: snapshot() };
  }

  function approve(role) {
    if (roster !== null) {
      throw new Error('human approvers sign on their own machines with tools/approver.mjs');
    }
    if (approvalExpiresAt !== null && receipt === null && now() >= approvalExpiresAt) {
      events.push({ stage: 'emilia', outcome: 'expired', at: new Date(now()).toISOString() });
      throw new Error('approval window expired');
    }
    const approver = approverByRole.get(role);
    if (!approver) throw new TypeError('unknown demo approver role');
    if (approvalExpiresAt === null) approvalExpiresAt = now() + approvalWindowMs;
    approvals.add(role);
    events.push({ stage: 'emilia', outcome: 'approved', role, at: new Date(now()).toISOString() });
    if (approvals.size >= 2 && receipt === null) {
      const selected = [...approvals].slice(0, 2).map((name) => approverByRole.get(name));
      receipt = issueFixtureReceipt({
        action,
        issuer,
        approvers: selected,
        rpId,
        origin,
        createdAt: receiptCreatedAt || new Date(now()).toISOString(),
      });
      events.push({ stage: 'emilia', outcome: 'receipt-issued', at: new Date(now()).toISOString() });
    }
    return snapshot();
  }

  async function execute(mode) {
    const args = toolArguments(action);
    if (mode === 'approved' || mode === 'replay' || mode === 'tampered') {
      if (receipt === null) throw new Error('two approvals are required before this test');
      args.__ep = { receipt };
    }
    if (mode === 'tampered') args.target = `${action.target}-tampered`;
    if (!['approved', 'missing', 'replay', 'tampered'].includes(mode)) {
      throw new TypeError('unknown execution mode');
    }
    events.push({ stage: 'demo', outcome: 'request-received', scenario: mode, at: new Date().toISOString() });
    try {
      lastResponse = publicResponse(await dispatch(toolName, args));
    } catch {
      lastResponse = { status: 500, body: { rejected: { reason: 'effect_indeterminate' } } };
    }
    events.push({
      stage: 'demo',
      outcome: lastResponse.status === 200 ? 'executed' : 'refused',
      scenario: mode,
      at: new Date().toISOString(),
    });
    return snapshot();
  }

  events.push({ stage: 'nono-controller', outcome: 'action-ingested', at: new Date().toISOString() });
  function evidence() {
    return receipt === null ? null : structuredClone(receipt);
  }

  return Object.freeze({
    approvalRequest,
    approve,
    evidence,
    execute,
    policy,
    snapshot,
    submitSignoff,
  });
}
