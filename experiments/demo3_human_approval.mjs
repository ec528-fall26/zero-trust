// Demo 3: two real people approve from separate credentials.
//
// The controller holds only the approvers' public keys (config/approvers/).
// It writes an approval request, each person reviews and signs it on their own
// machine with tools/approver.mjs, and their signoff files are dropped back into
// the exchange folder.  The approved action then goes through the real node
// code (MCP over HTTP, launch permit, launch ledger) with a local Keylime
// stand-in, and launches are counted from process-start records.
//
//   node experiments/demo3_human_approval.mjs              # real people
//   node experiments/demo3_human_approval.mjs --fixture    # automation, labelled
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { startLocalNode } from './local_node.mjs';
import { approvalInstructions, collectTwoApprovals, publishApprovalRequest } from './signoff_exchange.mjs';
import {
  APPROVER_RECORD_SCHEMA,
  createSignoff,
  loadRoster,
  publicKeyFingerprint,
} from '../src/controller/approver_signoff.mjs';
import { createKeylimeMcpHandler } from '../src/controller/keylime_mcp_client.mjs';
import { createDemoController } from '../src/demo/demo_controller.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const fixtureMode = argv.includes('--fixture');
const option = (name, fallback) => {
  const index = argv.indexOf(name);
  return index >= 0 && index + 1 < argv.length ? argv[index + 1] : fallback;
};
const rosterDirectory = path.resolve(option('--roster', path.join(repositoryRoot, 'config', 'approvers')));
const exchangeRoot = path.resolve(option('--exchange', path.join(repositoryRoot, 'build', 'approvals')));
const outputPath = path.resolve(option('--out', path.join(
  repositoryRoot,
  'results',
  fixtureMode ? 'demo3-human-approval-fixture.json' : 'demo3-human-approval.json',
)));

async function commandOutput(command, args) {
  try {
    const { stdout } = await execFileAsync(command, args, { cwd: repositoryRoot, timeout: 10_000 });
    return stdout.trim();
  } catch {
    return null;
  }
}

async function writeJson(file, value, mode = 0o600) {
  await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode });
  await rename(temporary, file);
}

function fixturePerson(role) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKeyText = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    privateKey,
    record: {
      schema: APPROVER_RECORD_SCHEMA,
      role,
      name: `Fixture ${role} (automation)`,
      approver_id: `ep:approver:${role}`,
      key_id: `${role}-${publicKeyFingerprint(publicKeyText).slice(7, 15)}`,
      public_key: publicKeyText,
    },
  };
}

async function main() {
  if (process.platform !== 'linux') throw new Error('needs Linux for descriptor-bound execution');
  const workRoot = await mkdtemp(path.join(os.tmpdir(), 'ec528-human-approval-'));
  const node = await startLocalNode({ rootDirectory: workRoot });
  const scenarios = [];
  const timeline = [];
  const mark = (stage, details = {}) => timeline.push({ stage, at: new Date().toISOString(), ...details });
  const record = async (name, expected, passed, details = {}) => {
    scenarios.push({ name, expected, passed, launches: await node.launches(), ...details });
  };
  try {
    const fixtures = fixtureMode
      ? Object.fromEntries(['operator', 'security', 'reviewer'].map((role) => [role, fixturePerson(role)]))
      : null;
    const roster = fixtureMode
      ? Object.values(fixtures).map((entry) => entry.record)
      : await loadRoster(rosterDirectory);
    const manifest = JSON.parse(await readFile(
      path.join(repositoryRoot, 'public', '.well-known', 'agent-actions.json'),
      'utf8',
    ));
    const action = node.action();
    const controller = await createDemoController({
      action,
      artifactPath: node.artifactPath,
      inputPath: node.inputPath,
      manifest,
      stateDirectory: path.join(workRoot, 'controller'),
      approverRoster: roster,
      keylimeHandler: createKeylimeMcpHandler({
        endpoint: node.endpoint.href,
        token: node.token,
        allowInsecureLoopback: true,
        timeoutMilliseconds: 20_000,
        permitSigner: node.permits.signer,
      }),
    });

    const missing = await controller.execute('missing');
    await record('no_receipt_before_approval', 'denied', missing.last_response.status === 428
      && (await node.launches()) === 0);

    const request = controller.approvalRequest();
    const exchange = await publishApprovalRequest(exchangeRoot, request);
    const { inbox } = exchange;
    mark('approval_requested', { receipt_id: request.receipt_id, expires_at: request.expires_at });

    const outsider = fixturePerson('outsider');
    const unenrolled = controller.submitSignoff(createSignoff(request, {
      privateKey: outsider.privateKey,
      keyId: outsider.record.key_id,
    }));
    await record('unenrolled_key_refused', 'refused', unenrolled.reason === 'approver_not_enrolled'
      && controller.snapshot().approvals.length === 0, { reason: unenrolled.reason });

    if (fixtureMode) {
      for (const role of ['operator', 'security']) {
        const envelope = createSignoff(request, {
          privateKey: fixtures[role].privateKey,
          keyId: fixtures[role].record.key_id,
        });
        await writeJson(path.join(inbox, `signoff-${role}.json`), envelope, 0o644);
      }
    } else {
      process.stdout.write(approvalInstructions(exchange, request.expires_at));
    }

    const { accepted, rejected } = await collectTwoApprovals(controller, inbox, Date.parse(request.expires_at), {
      log: (line) => process.stdout.write(line),
      afterFirst: async (envelope) => {
        mark('first_human_approval', { role: controller.snapshot().approvals[0] });
        const pending = await controller.execute('missing');
        await record('pending_after_one_approval', 'pending_and_denied', pending.approval_status === 'pending'
          && pending.receipt_ready === false && pending.last_response.status === 428
          && (await node.launches()) === 0, { approvals: pending.approvals });
        const again = controller.submitSignoff(envelope);
        await record('same_person_twice_counts_once', 'refused', again.reason === 'duplicate_approver'
          && controller.snapshot().receipt_ready === false, { reason: again.reason });
      },
    });
    mark('second_human_approval', { role: accepted[1].role });

    const receiptReady = controller.snapshot().receipt_ready;
    const tampered = await controller.execute('tampered');
    await record('changed_action_after_approval', 'denied', receiptReady
      && tampered.last_response.status === 428 && (await node.launches()) === 0,
    { reason: tampered.last_response.body?.rejected?.reason || null });

    const started = performance.now();
    const approved = await controller.execute('approved');
    const gateToLaunchMs = performance.now() - started;
    mark('approved_action_executed', { status: approved.last_response.status });
    await record('approved_action_launches_once', 'executed_once', approved.last_response.status === 200
      && (await node.launches()) === 1, { gate_to_launch_ms: Math.round(gateToLaunchMs) });

    const replay = await controller.execute('replay');
    await record('receipt_replay_refused', 'denied', replay.last_response.status === 428
      && (await node.launches()) === 1, { reason: replay.last_response.body?.rejected?.reason || null });

    const dirty = await commandOutput('git', ['status', '--porcelain', '--untracked-files=no']);
    const result = {
      experiment: 'demo3_human_approval',
      schema_version: 1,
      generated_at: new Date().toISOString(),
      repository_revision: await commandOutput('git', ['rev-parse', 'HEAD']),
      repository_dirty: dirty === null ? null : dirty.length > 0,
      approver_mode: fixtureMode ? 'fixture_automation' : 'human',
      status: scenarios.every((scenario) => scenario.passed) ? 'pass' : 'fail',
      approvers: roster.map((entry) => ({
        role: entry.role,
        name: entry.name,
        key_fingerprint: publicKeyFingerprint(entry.public_key),
      })),
      approvals: accepted,
      refused_signoffs: rejected,
      human_wait_seconds: accepted.at(-1).seconds_after_request,
      scenarios,
      timeline,
      limitations: [
        fixtureMode
          ? 'Automation: fixture keys generated in this process, not real people.'
          : 'Approvers hold software P-256 keys in files on their own machines, not hardware authenticators; the signoff uses the WebAuthn format but no browser ceremony.',
        'Keylime status is a local stand-in socket; the MCP, permit, ledger and execution path are the real node code.',
        'Signoff files travel over whatever channel the team uses; integrity comes from the signatures, not the channel.',
        'The node verifies the controller\'s permit, not the approvers\' signatures.',
      ],
    };
    await writeJson(outputPath, result);
    process.stdout.write(`\n${result.status}: ${scenarios.filter((s) => s.passed).length}/${scenarios.length} scenarios; wrote ${outputPath}\n`);
    if (result.status !== 'pass') process.exitCode = 1;
  } finally {
    await node.stop();
    await rm(workRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`demo3_human_approval: ${error.message}\n`);
  process.exitCode = 1;
});
