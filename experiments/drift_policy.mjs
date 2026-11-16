// Experiment: policy digest pinning.
//
// Claim: policy_version is derived from the Keylime policy and the EMILIA
// approval policy, so changing either one makes the gate or the node refuse an
// action that was approved under the old policies.
//
// Real components: the 2-of-3 demo controller (real receipts and quorum
// checks), the receipt-required dispatcher, and the node's attest-and-deploy
// handler.  Stand-in: the Keylime status the node handler reads is a fixed PASS
// document, so no TPM or Keylime service is involved.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { createDemoController } from '../src/demo/demo_controller.mjs';
import {
  createReceiptRequiredDispatcher,
  DurableReceiptStore,
} from '../src/controller/receipt_required_mcp.mjs';
import { createPermitFixture } from './permit_fixture.mjs';
import { createAttestAndDeploy } from '../src/keylime_mcp/attest_and_deploy.mjs';
import { LaunchLedger } from '../src/keylime_mcp/launch_ledger.mjs';
import { policyVersionFromFiles, sha256Digest } from '../src/keylime_mcp/policy_digest.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputPath = path.resolve(
  process.argv[2] || path.join(repositoryRoot, 'results', 'drift-policy.json'),
);
const TARGET = 'aws-keylime-demo-01';
const AGENT_ID = 'agent-drift-policy';
const LIMITATIONS = Object.freeze([
  'The node handler is the real attest-and-deploy code, but the Keylime status it reads is a fixed PASS document. No TPM or Keylime service is involved.',
  'The approval policy bundle is exported by the controller and copied to the node as a file in this experiment. The AWS deployment scripts do not do this yet.',
  'Approver and issuer keys are ephemeral local demo keys on one machine.',
  'A node-side refusal happens after the receipt is reserved, so it burns the approval (effect_indeterminate). That is existing behaviour, recorded here as observed.',
]);

const KEYLIME_POLICY_A = Buffer.from(
  '{"allowlist":["/opt/ec528/workloads/checksum.sh"]}\n',
  'utf8',
);
const KEYLIME_POLICY_B = Buffer.from(
  '{"allowlist":["/opt/ec528/workloads/checksum.sh","/usr/bin/new-tool"]}\n',
  'utf8',
);

function digest(bytes) {
  return sha256Digest(bytes);
}

async function commandOutput(command, args) {
  try {
    const { stdout } = await execFileAsync(command, args, {
      cwd: repositoryRoot,
      timeout: 5_000,
      windowsHide: true,
    });
    return stdout.trim();
  } catch {
    return null;
  }
}

async function requiredCommandOutput(command, args) {
  const { stdout } = await execFileAsync(command, args, {
    cwd: repositoryRoot,
    timeout: 30_000,
    windowsHide: true,
  });
  return stdout.trim();
}

async function writeResult(result) {
  await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  const temporary = `${outputPath}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  await writeFile(temporary, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, outputPath);
}

async function main() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-drift-policy-'));
  const scenarios = [];
  try {
    const artifactPath = path.join(root, 'approved-workload.sh');
    const inputPath = path.join(root, 'approved-input.txt');
    const artifact = Buffer.from('#!/bin/sh\nsha256sum "$1"\n', 'utf8');
    const input = Buffer.from('EC528 approved input\n', 'utf8');
    await Promise.all([
      writeFile(artifactPath, artifact, { mode: 0o700 }),
      writeFile(inputPath, input, { mode: 0o600 }),
    ]);
    await chmod(artifactPath, 0o700);
    await chmod(root, 0o700);
    const manifest = JSON.parse(await readFile(
      path.join(repositoryRoot, 'public', '.well-known', 'agent-actions.json'),
      'utf8',
    ));
    const packageMetadata = JSON.parse(await readFile(
      path.join(repositoryRoot, 'package.json'),
      'utf8',
    ));
    const baseAction = () => ({
      action_type: 'workload.execute',
      operation: 'checksum.sha256',
      target: TARGET,
      artifact_sha256: digest(artifact),
      input_sha256: digest(input),
      occurrence_id: crypto.randomUUID(),
      policy_version: 'placeholder',
    });

    // A node whose Keylime policy file is `keylimeBytes`.  Its accepted
    // policy_version is derived from that file and the controller's bundle.
    let sequence = 0;
    async function buildNode(keylimeBytes, approvalPolicy) {
      sequence += 1;
      const directory = path.join(root, `node-${sequence}`);
      await mkdir(directory, { mode: 0o700 });
      const keylimePolicyPath = path.join(directory, 'keylime-policy.json');
      const approvalPolicyPath = path.join(directory, 'approval-policy.json');
      await writeFile(keylimePolicyPath, keylimeBytes);
      await writeFile(approvalPolicyPath, JSON.stringify(approvalPolicy));
      const policyVersion = await policyVersionFromFiles({ keylimePolicyPath, approvalPolicyPath });
      const state = { workloadRuns: 0 };
      const permits = createPermitFixture({ target: TARGET, agentId: AGENT_ID });
      const handler = createAttestAndDeploy({
        statusCommand: '/fixed/status',
        artifactPath,
        inputPath,
        target: TARGET,
        agentId: AGENT_ID,
        permitVerifier: permits.verifier,
        launchLedger: new LaunchLedger(path.join(directory, 'launch-ledger')),
        policyVersion,
        requiredOwnerUid: process.getuid(),
        commandRunner: async (command) => {
          if (command === '/fixed/status') {
            return {
              stdout: JSON.stringify({
                agent_id: AGENT_ID,
                enrollment_epoch: permits.enrollmentEpoch,
                results: {
                  attestation_status: 'PASS',
                  last_successful_attestation: Math.floor(Date.now() / 1_000),
                },
              }),
              stderr: '',
            };
          }
          state.workloadRuns += 1;
          return { stdout: `${digest(input).slice(7)}  input.txt\n`, stderr: '' };
        },
      });
      return {
        handler: (observed, extra) => handler(observed, permits.sign(observed, extra?.receiptId)),
        policyVersion,
        state,
      };
    }

    // A controller whose Keylime policy is `keylimeBytes`, with the node
    // attached later (the node needs the controller's approval policy first).
    async function buildController(keylimeBytes, { bindPolicyVersion = true, label = null } = {}) {
      const delegate = { handler: async () => { throw new Error('node not attached'); } };
      const action = baseAction();
      if (label) action.policy_version = label;
      const stateDirectory = path.join(root, `controller-${crypto.randomUUID()}`);
      await mkdir(stateDirectory, { mode: 0o700 });
      const controller = await createDemoController({
        action,
        artifactPath,
        inputPath,
        manifest,
        stateDirectory,
        keylimePolicySha256: digest(keylimeBytes),
        bindPolicyVersion,
        keylimeHandler: (observed, extra) => delegate.handler(observed, extra),
      });
      return { controller, delegate };
    }

    async function approved(controllerBundle) {
      controllerBundle.controller.approve('operator');
      controllerBundle.controller.approve('security');
      return controllerBundle.controller;
    }

    // ---- 1. consistent policies -------------------------------------------
    {
      const bundle = await buildController(KEYLIME_POLICY_A);
      const node = await buildNode(KEYLIME_POLICY_A, bundle.controller.policy().approval_policy);
      bundle.delegate.handler = node.handler;
      const controller = await approved(bundle);
      const snapshot = await controller.execute('approved');
      assert.equal(snapshot.last_response.status, 200);
      assert.equal(node.state.workloadRuns, 1);
      assert.equal(node.policyVersion, controller.snapshot().action.policy_version);
      assert.equal(
        snapshot.last_response.body.result.attestation.policy_version,
        node.policyVersion,
      );
      scenarios.push({
        name: 'consistent_policies_execute',
        passed: true,
        observed: 'executed_once',
        policy_version: node.policyVersion,
      });
    }

    // ---- 2. allowlist updated on the node only ------------------------------
    {
      const bundle = await buildController(KEYLIME_POLICY_A);
      const node = await buildNode(KEYLIME_POLICY_B, bundle.controller.policy().approval_policy);
      bundle.delegate.handler = node.handler;
      const controller = await approved(bundle);
      const snapshot = await controller.execute('approved');
      assert.notEqual(node.policyVersion, controller.snapshot().action.policy_version);
      assert.equal(snapshot.last_response.status, 500);
      assert.equal(snapshot.last_response.body.rejected.reason, 'effect_indeterminate');
      assert.equal(node.state.workloadRuns, 0);
      scenarios.push({
        name: 'keylime_allowlist_changed_on_node',
        passed: true,
        observed: 'node_refused_workload_not_run',
        http_status: 500,
        workload_runs: 0,
      });
    }

    // ---- 3. hand-typed label while pinning is on ---------------------------
    {
      const bundle = await buildController(KEYLIME_POLICY_A, {
        bindPolicyVersion: false,
        label: 'demo-2.1',
      });
      const controller = await approved(bundle);
      const snapshot = await controller.execute('approved');
      assert.equal(snapshot.last_response.status, 428);
      assert.equal(snapshot.last_response.body.rejected.reason, 'policy_version_mismatch');
      scenarios.push({
        name: 'hand_typed_label_refused',
        passed: true,
        observed: 'policy_version_mismatch',
        http_status: 428,
      });
    }

    // ---- 4 to 9. controller-side drift against one valid receipt ------------
    const reference = await buildController(KEYLIME_POLICY_A);
    const referenceController = await approved(reference);
    const referencePolicy = referenceController.policy();
    const referenceAction = referenceController.snapshot().action;
    const referenceReceipt = referenceController.evidence();
    const referenceArguments = {
      operation: referenceAction.operation,
      target: referenceAction.target,
      artifact_sha256: referenceAction.artifact_sha256,
      input_sha256: referenceAction.input_sha256,
      occurrence_id: referenceAction.occurrence_id,
      policy_version: referenceAction.policy_version,
    };

    async function gateWith(mutate = (options) => options, keylimeBytes = KEYLIME_POLICY_A) {
      const bundle = structuredClone(referencePolicy.approval_policy);
      const options = mutate({
        trustedKeys: bundle.issuer_keys,
        approverKeys: bundle.approver_keys,
        quorumPolicies: bundle.quorum_policies,
        rpId: bundle.rp_id,
        allowedOrigins: bundle.allowed_origins,
        keylimePolicySha256: digest(keylimeBytes),
      });
      const store = await new DurableReceiptStore(
        path.join(root, `gate-store-${crypto.randomUUID()}`),
      ).initialize();
      let invocations = 0;
      const dispatch = await createReceiptRequiredDispatcher({
        manifest: {
          ...manifest,
          actions: manifest.actions.filter((entry) => (
            entry.receipt_required !== true
            || entry.match?.tool === 'execute_approved_workload'
          )),
        },
        handlers: {
          execute_approved_workload: async () => {
            invocations += 1;
            return { executed: true };
          },
        },
        store,
        ...options,
      });
      const response = await dispatch('execute_approved_workload', {
        ...referenceArguments,
        __ep: { receipt: structuredClone(referenceReceipt) },
      });
      return { response, invocations, expected: dispatch.expectedPolicyVersion };
    }

    function refusedAsDrift(name, result) {
      assert.equal(result.response.status, 428);
      assert.equal(result.response.body.rejected.reason, 'policy_version_mismatch');
      assert.equal(result.invocations, 0);
      assert.notEqual(result.expected, referenceAction.policy_version);
      scenarios.push({
        name,
        passed: true,
        observed: 'policy_version_mismatch',
        http_status: 428,
        handler_invocations: 0,
      });
    }

    {
      const control = await gateWith();
      assert.equal(control.response.status, 200);
      assert.equal(control.invocations, 1);
      assert.equal(control.expected, referenceAction.policy_version);
      scenarios.push({
        name: 'control_gate_with_unchanged_policies',
        passed: true,
        observed: 'executed_once',
        http_status: 200,
      });
    }

    refusedAsDrift('approver_roster_changed', await gateWith((options) => ({
      ...options,
      approverKeys: {
        ...options.approverKeys,
        'demo-added-key': {
          public_key: 'AAAA',
          key_class: 'A',
          approver_id: 'ep:approver:added',
        },
      },
    })));

    refusedAsDrift('quorum_threshold_lowered', await gateWith((options) => {
      const policies = structuredClone(options.quorumPolicies);
      policies['mcp.execute_approved_workload'].required = 1;
      return { ...options, quorumPolicies: policies };
    }));

    refusedAsDrift('approval_window_changed', await gateWith((options) => {
      const policies = structuredClone(options.quorumPolicies);
      policies['mcp.execute_approved_workload'].window_sec = 3_600;
      return { ...options, quorumPolicies: policies };
    }));

    refusedAsDrift('issuer_key_rotated', await gateWith((options) => ({
      ...options,
      trustedKeys: [crypto.generateKeyPairSync('ed25519').publicKey
        .export({ type: 'spki', format: 'der' }).toString('base64url')],
    })));

    refusedAsDrift(
      'keylime_allowlist_changed_on_controller',
      await gateWith((options) => options, KEYLIME_POLICY_B),
    );

    const gitStatus = await requiredCommandOutput(
      'git', ['status', '--porcelain', '--untracked-files=all'],
    );
    await writeResult({
      schema_version: 1,
      experiment: 'drift-policy',
      status: 'pass',
      generated_at: new Date().toISOString(),
      repository_revision: await requiredCommandOutput('git', ['rev-parse', 'HEAD']),
      repository_dirty: gitStatus.length > 0,
      versions: {
        nono: await commandOutput('nono', ['--version']),
        node: process.version,
        emilia_require_receipt: packageMetadata.dependencies['@emilia-protocol/require-receipt'],
      },
      reference_policy_version: referenceAction.policy_version,
      scenarios,
      limitations: [...LIMITATIONS],
    });
    process.stdout.write(`${outputPath}\n`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

main().catch(async (error) => {
  await writeResult({
    schema_version: 1,
    experiment: 'drift-policy',
    status: 'fail',
    generated_at: new Date().toISOString(),
    error: error instanceof Error ? error.message : 'unknown error',
  });
  process.stderr.write(`drift policy failed: ${error.stack || error.message}\n`);
  process.exitCode = 1;
});
