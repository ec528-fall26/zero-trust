import crypto from 'node:crypto';
import { open, readFile } from 'node:fs/promises';
import path from 'node:path';

import { approvalActionHash } from '@emilia-protocol/require-receipt';
import { canonicalizeStrictJson } from '@emilia-protocol/require-receipt/strict-json';

import {
  createReceiptRequiredDispatcher,
  DurableReceiptStore,
} from '../controller/receipt_required_mcp.mjs';

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

function quorumSignoff(payload, approver, rpId, origin) {
  const context = {
    '@version': 'EP-ASSURANCE-CONTEXT-v1',
    receipt_id: payload.receipt_id,
    claim_hash: `sha256:${sha256(canonicalizeStrictJson(payload.claim)).toString('hex')}`,
  };
  const contextHash = `sha256:${sha256(canonicalizeStrictJson(context)).toString('hex')}`;
  const challenge = Buffer.from(contextHash.slice('sha256:'.length), 'hex');
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge: challenge.toString('base64url'),
    origin,
    crossOrigin: false,
  }), 'utf8');
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(1);
  const authenticatorData = Buffer.concat([
    sha256(rpId),
    Buffer.from([0x05]),
    counter,
  ]);
  const signature = crypto.sign(
    'sha256',
    Buffer.concat([authenticatorData, sha256(clientData)]),
    approver.privateKey,
  );
  return Object.freeze({
    contextHash,
    signoff: {
      approver_key_id: approver.keyId,
      key_class: 'A',
      webauthn: {
        authenticator_data: authenticatorData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature: signature.toString('base64url'),
      },
    },
  });
}

function issueReceipt({ action, issuer, approvers, rpId, origin, createdAt }) {
  const payload = {
    receipt_id: `demo-${crypto.randomUUID()}`,
    subject: 'agent:ec528-demo',
    created_at: createdAt,
    claim: {
      action_type: 'workload.execute',
      outcome: 'allow_with_signoff',
      canonical_action: action,
      action_hash: approvalActionHash(action),
      quorum: {
        threshold: 2,
        signers: approvers.map((approver) => approver.id),
      },
    },
  };
  const signed = approvers.map((approver) => (
    quorumSignoff(payload, approver, rpId, origin)
  ));
  payload.assurance_proof = {
    '@version': 'EP-ASSURANCE-PROOF-v1',
    context_hash: signed[0].contextHash,
    signoffs: signed.map((entry) => entry.signoff),
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

function publicResponse(response) {
  return {
    status: response.status,
    body: response.body,
  };
}

function toolArguments(action) {
  return {
    operation: action.operation,
    target: action.target,
    artifact_sha256: action.artifact_sha256,
    input_sha256: action.input_sha256,
    occurrence_id: action.occurrence_id,
    policy_version: action.policy_version,
  };
}

export async function createDemoController(options) {
  const {
    action,
    artifactPath,
    inputPath,
    keylimeHandler = null,
    manifest,
    stateDirectory,
    approvalWindowMs = 15 * 60 * 1_000,
    receiptCreatedAt = null,
    now = () => Date.now(),
  } = options;
  const issuer = createIssuer();
  const approvers = APPROVER_DEFINITIONS.map(createApprover);
  const approverByRole = new Map(approvers.map((approver) => [approver.role, approver]));
  const approvals = new Set();
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
    window_sec: 900,
    approvers: approvers.map((approver) => ({
      role: approver.role,
      approver: approver.id,
    })),
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
    manifest,
    handlers: {
      execute_approved_workload: activeKeylimeHandler,
      get_request_status: async () => snapshot(),
    },
    trustedKeys: [issuer.publicKey],
    approverKeys,
    rpId,
    allowedOrigins: [origin],
    quorumPolicies: { 'mcp.execute_approved_workload': quorumPolicy },
    store,
    audit: async (event) => {
      events.push({ stage: 'receipt-guard', ...event, at: new Date().toISOString() });
    },
  });

  function snapshot() {
    const approvalExpired = approvalExpiresAt !== null
      && receipt === null
      && now() >= approvalExpiresAt;
    return {
      mode: 'local-integration-demo',
      limitations: [
        'Approver keys are ephemeral local demo keys, not enrolled human credentials.',
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

  function approve(role) {
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
      receipt = issueReceipt({
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
      lastResponse = publicResponse(await dispatch('execute_approved_workload', args));
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

  return Object.freeze({ approve, evidence, execute, snapshot });
}
