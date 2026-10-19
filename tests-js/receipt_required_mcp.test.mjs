import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  approvalActionHash,
} from '@emilia-protocol/require-receipt';
import { canonicalizeStrictJson } from '@emilia-protocol/require-receipt/strict-json';

import {
  createReceiptRequiredDispatcher,
  DurableReceiptStore,
} from '../src/controller/receipt_required_mcp.mjs';

const manifest = {
  '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
  service: {
    name: 'test controller',
    manifest_url: 'https://controller.example.invalid/.well-known/agent-actions.json',
  },
  receipt_required: {
    status: 428,
    challenge_header: 'Receipt-Required',
    proof_header: 'X-EMILIA-Receipt',
    receipt_profile: 'EP-RECEIPT-v1',
  },
  defaults: {
    read_only: 'allow',
    missing_receipt: 'refuse',
    invalid_receipt: 'refuse',
    stale_receipt: 'refuse',
  },
  actions: [
    {
      id: 'mcp.execute_approved_workload',
      match: { protocol: 'mcp', tool: 'execute_approved_workload' },
      action_type: 'workload.execute',
      risk: 'high',
      receipt_required: true,
      assurance_class: 'software',
      max_age_sec: 900,
      execution_binding: {
        required_fields: [
          'action_type',
          'operation',
          'target',
          'artifact_sha256',
          'input_sha256',
          'occurrence_id',
          'policy_version',
        ],
      },
      quorum: { required: false },
    },
  ],
};

const actionArgs = Object.freeze({
  operation: 'checksum.sha256',
  target: 'azure-vm-01',
  artifact_sha256: `sha256:${'a'.repeat(64)}`,
  input_sha256: `sha256:${'b'.repeat(64)}`,
  occurrence_id: 'd24f4f93-e555-4d48-93aa-a2c16c53a24f',
  policy_version: 'demo-2.1',
});

function exactAction(args = actionArgs) {
  return {
    action_type: 'workload.execute',
    operation: args.operation,
    target: args.target,
    artifact_sha256: args.artifact_sha256,
    input_sha256: args.input_sha256,
    occurrence_id: args.occurrence_id,
    policy_version: args.policy_version,
  };
}

function issuer() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey,
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

function signReceipt(authority, action, receiptId) {
  const payload = {
    receipt_id: receiptId,
    subject: 'agent:test',
    created_at: new Date().toISOString(),
    claim: {
      action_type: 'workload.execute',
      outcome: 'allow',
      canonical_action: action,
      action_hash: approvalActionHash(action),
    },
  };
  const value = crypto.sign(
    null,
    Buffer.from(canonicalizeStrictJson(payload), 'utf8'),
    authority.privateKey,
  ).toString('base64url');
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value },
  };
}

function makeApprover(keyId, approverId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync(
    'ec',
    { namedCurve: 'prime256v1' },
  );
  return {
    keyId,
    approverId,
    privateKey,
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

// Test-only proof shape adapted from EMILIA Protocol examples/mcp/_kit.mts
// (Apache-2.0). Production uses separately enrolled human credentials.
function sha256(value) {
  return crypto.createHash('sha256').update(value).digest();
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
  return {
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
  };
}

function signQuorumReceipt(authority, action, receiptId, approvers, rpId, origin) {
  const payload = {
    receipt_id: receiptId,
    subject: 'agent:test',
    created_at: new Date().toISOString(),
    claim: {
      action_type: 'workload.execute',
      outcome: 'allow_with_signoff',
      canonical_action: action,
      action_hash: approvalActionHash(action),
      quorum: {
        threshold: 2,
        signers: approvers.map((approver) => approver.approverId),
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
  const value = crypto.sign(
    null,
    Buffer.from(canonicalizeStrictJson(payload), 'utf8'),
    authority.privateKey,
  ).toString('base64url');
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value },
  };
}

async function fixture(handler = async (action) => ({ executed: action.target })) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-receipts-'));
  const authority = issuer();
  const store = await new DurableReceiptStore(path.join(root, 'store')).initialize();
  const auditEvents = [];
  const dispatch = await createReceiptRequiredDispatcher({
    manifest,
    handlers: { execute_approved_workload: handler },
    trustedKeys: [authority.publicKey],
    store,
    audit: async (event) => auditEvents.push(event),
  });
  return {
    root,
    authority,
    dispatch,
    auditEvents,
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}

test('missing receipt returns a 428 challenge and does not invoke the handler', async () => {
  let invocations = 0;
  const context = await fixture(async () => { invocations += 1; });
  try {
    const response = await context.dispatch('execute_approved_workload', actionArgs);
    assert.equal(response.status, 428);
    assert.equal(invocations, 0);
    assert.match(response.headers['Receipt-Required'], /action_hash="sha256:[a-f0-9]{64}"/);
  } finally {
    await context.cleanup();
  }
});

test('a receipt bound to the exact action executes once', async () => {
  let invocations = 0;
  const context = await fixture(async (action) => {
    invocations += 1;
    assert.deepEqual(action, exactAction());
    return { executed: true };
  });
  try {
    const receipt = signReceipt(context.authority, exactAction(), 'rcpt_exact_action_001');
    const response = await context.dispatch(
      'execute_approved_workload',
      { ...actionArgs, __ep: { receipt } },
    );
    assert.equal(response.status, 200);
    assert.equal(response.body.evidence.receipt_id, 'rcpt_exact_action_001');
    assert.equal(invocations, 1);

    const replay = await context.dispatch(
      'execute_approved_workload',
      { ...actionArgs, __ep: { receipt } },
    );
    assert.equal(replay.status, 428);
    assert.equal(replay.body.rejected.reason, 'replay_refused');
    assert.equal(invocations, 1);
  } finally {
    await context.cleanup();
  }
});

test('the documented emiliaReceipt MCP carrier is accepted', async () => {
  let invocations = 0;
  const context = await fixture(async () => {
    invocations += 1;
    return { executed: true };
  });
  try {
    const receipt = signReceipt(context.authority, exactAction(), 'rcpt_camel_case_001');
    const response = await context.dispatch(
      'execute_approved_workload',
      { ...actionArgs, emiliaReceipt: receipt },
    );
    assert.equal(response.status, 200);
    assert.equal(invocations, 1);
  } finally {
    await context.cleanup();
  }
});

test('a receipt for target A is refused for target B', async () => {
  let invocations = 0;
  const context = await fixture(async () => { invocations += 1; });
  try {
    const receipt = signReceipt(context.authority, exactAction(), 'rcpt_exact_action_002');
    const response = await context.dispatch(
      'execute_approved_workload',
      { ...actionArgs, target: 'azure-vm-attacker', emilia_receipt: receipt },
    );
    assert.equal(response.status, 428);
    assert.equal(response.body.rejected.reason, 'action_hash_mismatch');
    assert.equal(invocations, 0);
  } finally {
    await context.cleanup();
  }
});

test('a receipt is refused when the approved input digest changes', async () => {
  let invocations = 0;
  const context = await fixture(async () => { invocations += 1; });
  try {
    const receipt = signReceipt(context.authority, exactAction(), 'rcpt_input_binding_001');
    const response = await context.dispatch(
      'execute_approved_workload',
      { ...actionArgs, input_sha256: `sha256:${'f'.repeat(64)}`, emiliaReceipt: receipt },
    );
    assert.equal(response.status, 428);
    assert.equal(response.body.rejected.reason, 'action_hash_mismatch');
    assert.equal(invocations, 0);
  } finally {
    await context.cleanup();
  }
});

test('an uncertain handler failure burns the receipt', async () => {
  const context = await fixture(async () => { throw new Error('simulated lost response'); });
  try {
    const receipt = signReceipt(context.authority, exactAction(), 'rcpt_exact_action_003');
    await assert.rejects(
      context.dispatch('execute_approved_workload', { ...actionArgs, __ep: { receipt } }),
      /simulated lost response/,
    );
    const replay = await context.dispatch(
      'execute_approved_workload',
      { ...actionArgs, __ep: { receipt } },
    );
    assert.equal(replay.status, 428);
    assert.equal(replay.body.rejected.reason, 'replay_refused');
  } finally {
    await context.cleanup();
  }
});

test('two store instances cannot reserve the same receipt', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-store-race-'));
  try {
    const first = await new DurableReceiptStore(root).initialize();
    const second = await new DurableReceiptStore(root).initialize();
    const outcomes = await Promise.all([
      first.reserve('rcpt_concurrent_001'),
      second.reserve('rcpt_concurrent_001'),
    ]);
    assert.deepEqual(outcomes.sort(), [false, true]);
    const directories = await readFile(
      path.join(root, crypto.createHash('sha256').update('rcpt_concurrent_001').digest('hex'), 'state.json'),
      'utf8',
    );
    assert.equal(JSON.parse(directories).state, 'reserved');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('unregistered tools fail closed', async () => {
  const context = await fixture();
  try {
    const response = await context.dispatch('shell_exec', { command: 'rm -rf /' });
    assert.equal(response.status, 428);
    assert.equal(response.body.rejected.reason, 'tool_not_registered');
  } finally {
    await context.cleanup();
  }
});

test('the production quorum profile refuses missing human trust pins at startup', async () => {
  const productionManifest = JSON.parse(
    await readFile(
      new URL('../public/.well-known/agent-actions.json', import.meta.url),
      'utf8',
    ),
  );
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-production-config-'));
  try {
    const authority = issuer();
    const store = await new DurableReceiptStore(path.join(root, 'store')).initialize();
    await assert.rejects(
      createReceiptRequiredDispatcher({
        manifest: productionManifest,
        handlers: {
          execute_approved_workload: async () => ({ executed: true }),
          get_request_status: async () => ({ status: 'pending' }),
        },
        trustedKeys: [authority.publicKey],
        store,
      }),
      /human-assurance trust pins are required/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('the production profile accepts a real 2-of-3 quorum receipt', async () => {
  const productionManifest = JSON.parse(
    await readFile(
      new URL('../public/.well-known/agent-actions.json', import.meta.url),
      'utf8',
    ),
  );
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-production-quorum-'));
  const authority = issuer();
  const rpId = 'controller.example.test';
  const origin = `https://${rpId}`;
  const approvers = [
    makeApprover('approver-key-1', 'ep:approver:operator'),
    makeApprover('approver-key-2', 'ep:approver:reviewer'),
    makeApprover('approver-key-3', 'ep:approver:security'),
  ];
  const approverKeys = Object.fromEntries(approvers.map((approver) => [
    approver.keyId,
    {
      public_key: approver.publicKey,
      key_class: 'A',
      approver_id: approver.approverId,
    },
  ]));
  const quorumPolicy = {
    mode: 'threshold',
    required: 2,
    distinct_humans: true,
    window_sec: 900,
    approvers: approvers.map((approver, index) => ({
      role: ['operator', 'reviewer', 'security'][index],
      approver: approver.approverId,
    })),
  };
  let invocations = 0;
  try {
    const store = await new DurableReceiptStore(path.join(root, 'store')).initialize();
    const dispatch = await createReceiptRequiredDispatcher({
      manifest: productionManifest,
      handlers: {
        execute_approved_workload: async () => {
          invocations += 1;
          return { executed: true };
        },
        get_request_status: async () => ({ status: 'pending' }),
      },
      trustedKeys: [authority.publicKey],
      approverKeys,
      rpId,
      allowedOrigins: [origin],
      quorumPolicies: { 'mcp.execute_approved_workload': quorumPolicy },
      store,
    });
    const receipt = signQuorumReceipt(
      authority,
      exactAction(),
      'rcpt_quorum_action_001',
      approvers.slice(0, 2),
      rpId,
      origin,
    );
    const response = await dispatch(
      'execute_approved_workload',
      { ...actionArgs, __ep: { receipt } },
    );
    assert.equal(response.status, 200);
    assert.equal(response.body.result.executed, true);
    assert.equal(response.body.evidence.receipt_id, 'rcpt_quorum_action_001');
    assert.equal(invocations, 1);

    const insufficient = signQuorumReceipt(
      authority,
      exactAction(),
      'rcpt_quorum_action_002',
      approvers.slice(0, 1),
      rpId,
      origin,
    );
    const refused = await dispatch(
      'execute_approved_workload',
      { ...actionArgs, __ep: { receipt: insufficient } },
    );
    assert.equal(refused.status, 428);
    assert.equal(invocations, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
