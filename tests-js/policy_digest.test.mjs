import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { approvalActionHash } from '@emilia-protocol/require-receipt';
import { canonicalizeStrictJson } from '@emilia-protocol/require-receipt/strict-json';

import {
  createReceiptRequiredDispatcher,
  DurableReceiptStore,
} from '../src/controller/receipt_required_mcp.mjs';
import {
  approvalPolicyBundle,
  canonicalPolicyJson,
  policyDigest,
  policyVersionFromFiles,
  sha256Digest,
} from '../src/keylime_mcp/policy_digest.mjs';

// The same inputs and expected value appear in tests/test_policy_digest.py.
// If either implementation changes, one of the two suites fails.
const VECTOR_KEYLIME = `sha256:${'ab'.repeat(32)}`;
const VECTOR_APPROVAL = Object.freeze({
  '@version': 'EC528-APPROVAL-POLICY-v1',
  issuer_keys: ['issuer-a'],
  approver_keys: {
    k2: { approver_id: 'ep:approver:café', key_class: 'A' },
    k1: { approver_id: 'ep:approver:ops', key_class: 'A' },
  },
  quorum_policies: {
    'mcp.execute_approved_workload': {
      distinct_humans: true,
      mode: 'threshold',
      required: 2,
      window_sec: 900,
    },
  },
  rp_id: '127.0.0.1',
  allowed_origins: ['http://127.0.0.1'],
});
const VECTOR_EXPECTED = 'pd1-1f60f071d37fe24373a5bbf0ed0497ab3fba7ec2ac5a9c15933c603562ad';

function derive(changes = {}, approvalChanges = {}) {
  return policyDigest({
    keylimePolicySha256: VECTOR_KEYLIME,
    approvalPolicy: structuredClone(VECTOR_APPROVAL),
    ...changes,
    ...(Object.keys(approvalChanges).length
      ? { approvalPolicy: { ...structuredClone(VECTOR_APPROVAL), ...approvalChanges } }
      : {}),
  });
}

test('policy digest matches the cross-language test vector', () => {
  assert.equal(derive(), VECTOR_EXPECTED);
});

test('policy digest fits the existing policy_version pattern', () => {
  assert.match(derive(), /^[a-z0-9][a-z0-9._-]{0,63}$/);
  assert.equal(derive().length, 64);
});

test('object key order does not change the digest', () => {
  const reordered = {
    allowed_origins: VECTOR_APPROVAL.allowed_origins,
    rp_id: VECTOR_APPROVAL.rp_id,
    quorum_policies: VECTOR_APPROVAL.quorum_policies,
    approver_keys: { k1: VECTOR_APPROVAL.approver_keys.k1, k2: VECTOR_APPROVAL.approver_keys.k2 },
    issuer_keys: VECTOR_APPROVAL.issuer_keys,
    '@version': VECTOR_APPROVAL['@version'],
  };
  assert.equal(derive({}, reordered), VECTOR_EXPECTED);
});

test('every policy component changes the digest', () => {
  const changed = new Map([
    ['keylime allowlist', derive({ keylimePolicySha256: `sha256:${'cd'.repeat(32)}` })],
    ['issuer key', derive({}, { issuer_keys: ['issuer-b'] })],
    ['added approver', derive({}, {
      approver_keys: {
        ...VECTOR_APPROVAL.approver_keys,
        k3: { approver_id: 'ep:approver:new', key_class: 'A' },
      },
    })],
    ['quorum threshold', derive({}, {
      quorum_policies: {
        'mcp.execute_approved_workload': {
          ...VECTOR_APPROVAL.quorum_policies['mcp.execute_approved_workload'],
          required: 1,
        },
      },
    })],
    ['approval window', derive({}, {
      quorum_policies: {
        'mcp.execute_approved_workload': {
          ...VECTOR_APPROVAL.quorum_policies['mcp.execute_approved_workload'],
          window_sec: 60,
        },
      },
    })],
    ['relying party', derive({}, { rp_id: 'example.invalid' })],
    ['allowed origin', derive({}, { allowed_origins: ['http://127.0.0.1:8080'] })],
  ]);
  for (const [name, value] of changed) {
    assert.notEqual(value, VECTOR_EXPECTED, `${name} must change the digest`);
  }
  assert.equal(new Set([...changed.values(), VECTOR_EXPECTED]).size, changed.size + 1);
});

test('unsupported policy content is refused instead of guessed at', () => {
  assert.throws(() => canonicalPolicyJson({ n: 1.5 }), /policy_number_unsupported/);
  assert.throws(() => canonicalPolicyJson({ n: undefined }), /policy_value_unsupported/);
  assert.throws(() => canonicalPolicyJson({ 'é': 1 }), /policy_key_unsupported/);
  assert.throws(() => canonicalPolicyJson(new Map()), /policy_object_unsupported/);
  assert.throws(() => derive({ keylimePolicySha256: 'not-a-digest' }), /sha256: digest/);
  let deep = {};
  for (let index = 0; index < 20; index += 1) deep = { deep };
  assert.throws(() => canonicalPolicyJson(deep), /policy_too_deep/);
});

test('policy version from files hashes the Keylime policy bytes exactly', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-policy-digest-'));
  try {
    const keylimePath = path.join(root, 'keylime-policy.json');
    const approvalPath = path.join(root, 'approval-policy.json');
    const keylimeBytes = Buffer.from('{"allowlist":["/usr/bin/sha256sum"]}\n', 'utf8');
    await writeFile(keylimePath, keylimeBytes);
    await writeFile(approvalPath, JSON.stringify(VECTOR_APPROVAL));
    const fromFiles = await policyVersionFromFiles({
      keylimePolicyPath: keylimePath,
      approvalPolicyPath: approvalPath,
    });
    assert.equal(fromFiles, derive({ keylimePolicySha256: sha256Digest(keylimeBytes) }));

    // One extra byte (a new allowlist entry, a trailing newline) is a new version.
    await writeFile(keylimePath, Buffer.concat([keylimeBytes, Buffer.from('\n')]));
    const afterEdit = await policyVersionFromFiles({
      keylimePolicyPath: keylimePath,
      approvalPolicyPath: approvalPath,
    });
    assert.notEqual(afterEdit, fromFiles);

    await writeFile(approvalPath, 'not json');
    await assert.rejects(
      policyVersionFromFiles({ keylimePolicyPath: keylimePath, approvalPolicyPath: approvalPath }),
      /not valid JSON/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---- dispatcher enforcement -------------------------------------------------

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

function actionWith(policyVersion) {
  return {
    action_type: 'workload.execute',
    operation: 'checksum.sha256',
    target: 'azure-vm-01',
    artifact_sha256: `sha256:${'a'.repeat(64)}`,
    input_sha256: `sha256:${'b'.repeat(64)}`,
    occurrence_id: crypto.randomUUID(),
    policy_version: policyVersion,
  };
}

function toolArguments(action) {
  const { action_type: _ignored, ...rest } = action;
  return rest;
}

function signedReceipt(authority, action) {
  const payload = {
    receipt_id: `rcpt_${crypto.randomUUID()}`,
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
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
}

async function dispatcherFixture({ keylimePolicySha256, trustedKeyOverride = null }) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-policy-gate-'));
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const authority = {
    privateKey,
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
  const store = await new DurableReceiptStore(path.join(root, 'receipts')).initialize();
  const invocations = [];
  const audit = [];
  const dispatch = await createReceiptRequiredDispatcher({
    manifest,
    handlers: {
      execute_approved_workload: async (action) => {
        invocations.push(action);
        return { executed: true };
      },
    },
    trustedKeys: [trustedKeyOverride ?? authority.publicKey],
    store,
    keylimePolicySha256,
    audit: async (event) => audit.push(event),
  });
  return { authority, dispatch, invocations, audit, cleanup: () => rm(root, { recursive: true, force: true }) };
}

test('dispatcher without a pinned Keylime policy keeps the old behaviour', async () => {
  const context = await dispatcherFixture({ keylimePolicySha256: null });
  try {
    assert.equal(context.dispatch.expectedPolicyVersion, null);
    const action = actionWith('demo-2.1');
    const response = await context.dispatch('execute_approved_workload', {
      ...toolArguments(action),
      __ep: { receipt: signedReceipt(context.authority, action) },
    });
    assert.equal(response.status, 200);
  } finally {
    await context.cleanup();
  }
});

test('dispatcher runs an action bound to the current policies and refuses a stale label', async () => {
  const context = await dispatcherFixture({ keylimePolicySha256: VECTOR_KEYLIME });
  try {
    const expected = context.dispatch.expectedPolicyVersion;
    assert.match(expected, /^pd1-[a-f0-9]{60}$/);

    const current = actionWith(expected);
    const ok = await context.dispatch('execute_approved_workload', {
      ...toolArguments(current),
      __ep: { receipt: signedReceipt(context.authority, current) },
    });
    assert.equal(ok.status, 200);

    // A perfectly valid receipt for a hand-typed label is no longer enough.
    const stale = actionWith('demo-2.1');
    const refused = await context.dispatch('execute_approved_workload', {
      ...toolArguments(stale),
      __ep: { receipt: signedReceipt(context.authority, stale) },
    });
    assert.equal(refused.status, 428);
    assert.equal(refused.body.rejected.reason, 'policy_version_mismatch');
    assert.equal(context.invocations.length, 1);
    assert.ok(context.audit.some((event) => event.reason === 'policy_version_mismatch'));
  } finally {
    await context.cleanup();
  }
});

test('changing the Keylime policy or the issuer roster changes the version the gate accepts', async () => {
  const first = await dispatcherFixture({ keylimePolicySha256: VECTOR_KEYLIME });
  const second = await dispatcherFixture({ keylimePolicySha256: `sha256:${'cd'.repeat(32)}` });
  try {
    // Different Keylime policy, otherwise identical shape: different version.
    assert.notEqual(first.dispatch.expectedPolicyVersion, second.dispatch.expectedPolicyVersion);

    // Action approved under the first policy, presented after the second took over.
    const action = actionWith(first.dispatch.expectedPolicyVersion);
    const response = await second.dispatch('execute_approved_workload', {
      ...toolArguments(action),
      __ep: { receipt: signedReceipt(second.authority, action) },
    });
    assert.equal(response.body.rejected.reason, 'policy_version_mismatch');
    assert.equal(second.invocations.length, 0);
  } finally {
    await Promise.all([first.cleanup(), second.cleanup()]);
  }
});

test('approval policy bundle sorts issuer keys and origins and defaults rp_id to null', () => {
  const bundle = approvalPolicyBundle({
    trustedKeys: ['b', 'a'],
    approverKeys: {},
    quorumPolicies: {},
    allowedOrigins: ['z', 'y'],
  });
  assert.deepEqual(bundle.issuer_keys, ['a', 'b']);
  assert.deepEqual(bundle.allowed_origins, ['y', 'z']);
  assert.equal(bundle.rp_id, null);
});
