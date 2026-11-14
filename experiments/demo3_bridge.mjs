// Experiment: Demo 3 bound, restart-safe handoff.
//
// Claim: a launch happens only for the exact action a 2-of-3 quorum approved,
// on the enrolled node it was approved for, at most once.  Substituted
// artifacts, inputs and targets, stale attestation, forged, expired or
// old-epoch permits, replays, a 10-client race, a service restart and a lost
// response never produce an extra launch.
//
// Modes:
//   (default) local   The real node server on this machine (Linux only), with
//                     Keylime's status served from a local socket.  Launches
//                     are counted from process-start records.
//   --aws             The deployed AWS node, after `make demo2-bootstrap` and
//                     `infra/aws/prepare-demo.sh`.  Opens its own SSM tunnel.
//                     Launches are counted from the node's launch ledger.
import crypto from 'node:crypto';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { digest, startLocalNode } from './local_node.mjs';
import { callNodeTool } from './node_client.mjs';
import { createPermitFixture, permitKitFromPrivateKey } from './permit_fixture.mjs';
import { createKeylimeMcpHandler } from '../src/controller/keylime_mcp_client.mjs';
import {
  enrollmentRecordFromEnvironment,
  permitPrivateKeyFromEnvironment,
} from '../src/controller/permit_signer.mjs';
import { createDemoController } from '../src/demo/demo_controller.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const mode = argv.includes('--aws') ? 'aws' : 'local';
const outputPath = path.resolve(
  argv.find((argument) => !argument.startsWith('--'))
    || path.join(repositoryRoot, 'results', 'demo3-bridge.json'),
);
const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

const COMMON_LIMITATIONS = [
  'The three EMILIA approver keys are ephemeral demo keys on one machine.',
  'The node verifies the controller\'s permit signature, not the approvers\' signatures.',
  'The restart scenario restarts the MCP service; it does not reboot the node or roll back a snapshot.',
  'The workload runs as the same user as the MCP service, which could alter the launch ledger.',
];
const MODE_LIMITATIONS = {
  local: [
    'Keylime status is a local stand-in socket. The HTTP and MCP path, permit checks, launch ledger and descriptor-bound execution are the real node code.',
    'Launches are counted from records the workload process writes when it starts.',
  ],
  aws: [
    'Launches are counted from the node\'s launch ledger and accepted responses; the AWS node keeps no separate process-start record.',
    'Staged-input substitution and stale attestation are not run against AWS: the first needs root changes to the pinned files, and the second is covered by demo2_end_to_end (keylime_agent_stopped).',
  ],
};

async function commandOutput(command, args) {
  try {
    const { stdout } = await execFileAsync(command, args, { cwd: repositoryRoot, timeout: 10_000 });
    return stdout.trim();
  } catch {
    return null;
  }
}

async function writeResult(result) {
  await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  const temporary = `${outputPath}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  await writeFile(temporary, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, outputPath);
}

// ---- local backend ---------------------------------------------------------

async function localBackend(workRoot) {
  if (process.platform !== 'linux') {
    throw new Error('local mode needs Linux for descriptor-bound execution');
  }
  const node = await startLocalNode({ rootDirectory: workRoot });
  return {
    mode: 'local',
    launchEvidence: 'process_start_records',
    target: node.target,
    action: (changes) => node.action(changes),
    kit: node.permits,
    forger: createPermitFixture({
      target: node.target,
      agentId: node.agentId,
      enrollmentEpoch: node.permits.enrollmentEpoch,
    }),
    call: (toolArguments) => node.call(toolArguments),
    keylimeHandler: () => createKeylimeMcpHandler({
      endpoint: node.endpoint.href,
      token: node.token,
      allowInsecureLoopback: true,
      timeoutMilliseconds: 20_000,
      permitSigner: node.permits.signer,
    }),
    artifactPath: node.artifactPath,
    inputPath: node.inputPath,
    restart: () => node.restart(),
    processLaunches: () => node.launches(),
    readLedger: async (ids) => new Map(await Promise.all(
      ids.map(async (id) => [id, await node.ledger.read(id)]),
    )),
    setAttestationAge: (seconds) => { node.keylime.ageSeconds = seconds; },
    substituteInput: () => writeFile(node.inputPath, 'substituted input\n'),
    restoreInput: () => writeFile(node.inputPath, node.input),
    details: {},
    close: () => node.stop(),
  };
}

// ---- AWS backend -----------------------------------------------------------

// Some macOS AWS CLI installs need Homebrew's expat; elsewhere this is a no-op.
function awsEnvironment() {
  const environment = { ...process.env };
  if (process.platform !== 'darwin') return environment;
  try {
    const prefix = execFileSync('brew', ['--prefix', 'expat'], { encoding: 'utf8', timeout: 10_000 }).trim();
    if (prefix) environment.DYLD_LIBRARY_PATH = path.join(prefix, 'lib');
  } catch {
    // Let the AWS CLI produce the actionable error if Homebrew or expat is absent.
  }
  return environment;
}

async function awsBackend(workRoot) {
  const profile = process.env.AWS_PROFILE || 'ec528-deployer';
  const region = process.env.AWS_REGION || 'us-east-2';
  const stack = process.env.AWS_STACK_NAME || 'ec528-zero-trust-demo';
  const endpoint = process.env.KEYLIME_MCP_URL || 'http://127.0.0.1:3000/mcp';
  const buildDirectory = path.join(repositoryRoot, 'build', 'aws-keylime');
  const tokenPath = path.resolve(process.env.KEYLIME_MCP_TOKEN_FILE || path.join(buildDirectory, 'mcp-token'));
  const actionPath = path.resolve(process.env.KEYLIME_ACTION_FILE || path.join(buildDirectory, 'action.json'));
  const environment = awsEnvironment();

  async function aws(args) {
    const { stdout } = await execFileAsync('aws', [...args, '--profile', profile, '--region', region], {
      cwd: repositoryRoot,
      env: environment,
      timeout: 300_000,
      maxBuffer: 1024 * 1024,
    });
    return stdout.trim();
  }

  async function runSsm(instanceId, commands) {
    const commandId = await aws([
      'ssm', 'send-command', '--instance-ids', instanceId,
      '--document-name', 'AWS-RunShellScript',
      '--parameters', JSON.stringify({ commands }),
      '--query', 'Command.CommandId', '--output', 'text',
    ]);
    for (let attempt = 0; attempt < 90; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1_000));
      let invocation;
      try {
        invocation = JSON.parse(await aws([
          'ssm', 'get-command-invocation', '--command-id', commandId,
          '--instance-id', instanceId, '--output', 'json',
        ]));
      } catch (error) {
        if (String(error.stderr || error.message).includes('InvocationDoesNotExist')) continue;
        throw error;
      }
      if (invocation.Status === 'Success') return invocation.StandardOutputContent;
      if (['Failed', 'TimedOut', 'Cancelled'].includes(invocation.Status)) {
        throw new Error(`SSM command ${invocation.Status}`);
      }
    }
    throw new Error('SSM command did not finish in time');
  }

  async function waitForHealth(tunnel) {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      if (tunnel.exitCode !== null) throw new Error('SSM tunnel exited');
      try {
        const response = await fetch(new URL('/healthz', endpoint), { signal: AbortSignal.timeout(1_000) });
        if (response.ok) return;
      } catch {
        // The port forward is still starting, or the service is restarting.
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    throw new Error('Keylime MCP did not become healthy through the tunnel');
  }

  const tokenStat = await stat(tokenPath);
  if (!tokenStat.isFile() || (tokenStat.mode & 0o077) !== 0) throw new Error('MCP token file must be mode 0600');
  const token = (await readFile(tokenPath, 'utf8')).trim();
  const baseAction = JSON.parse(await readFile(actionPath, 'utf8'));
  const enrollment = await enrollmentRecordFromEnvironment(repositoryRoot);
  const kit = permitKitFromPrivateKey({
    privateKeyPem: await permitPrivateKeyFromEnvironment(repositoryRoot),
    target: baseAction.target,
    agentId: enrollment.agent_uuid,
    enrollmentEpoch: enrollment.enrollment_epoch,
  });
  const instanceId = await aws([
    'cloudformation', 'describe-stacks', '--stack-name', stack,
    '--query', "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue | [0]", '--output', 'text',
  ]);
  if (!/^i-[a-f0-9]+$/.test(instanceId)) throw new Error('could not resolve the demo instance');

  const tunnel = spawn(path.join(repositoryRoot, 'infra', 'aws', 'open-tunnel.sh'), [stack], {
    cwd: repositoryRoot,
    detached: true,
    env: environment,
    stdio: 'ignore',
  });
  await waitForHealth(tunnel);

  // Local copies of the node's pinned bytes.  The demo controller only uses them
  // for its local bookkeeping; the node checks its own files.
  const artifactPath = path.join(workRoot, 'checksum.sh');
  const inputPath = path.join(workRoot, 'demo-payload.txt');
  await writeFile(artifactPath, '#!/bin/sh\nset -eu\n[ "$#" -eq 1 ] || exit 64\nexec sha256sum "$1"\n', { mode: 0o700 });
  await writeFile(inputPath, 'EC528 approved workload payload\n', { mode: 0o600 });

  return {
    mode: 'aws',
    launchEvidence: 'node_launch_ledger',
    target: baseAction.target,
    action: (changes = {}) => ({ ...baseAction, occurrence_id: crypto.randomUUID(), ...changes }),
    kit,
    forger: createPermitFixture({
      target: baseAction.target,
      agentId: enrollment.agent_uuid,
      enrollmentEpoch: enrollment.enrollment_epoch,
    }),
    call: (toolArguments) => callNodeTool({ endpoint, token, toolArguments, timeoutMilliseconds: 25_000 }),
    keylimeHandler: () => createKeylimeMcpHandler({
      endpoint,
      token,
      allowInsecureLoopback: true,
      timeoutMilliseconds: 25_000,
      permitSigner: kit.signer,
    }),
    artifactPath,
    inputPath,
    restart: async () => {
      await runSsm(instanceId, [
        'systemctl restart ec528-keylime-mcp.service',
        'for i in $(seq 1 30); do curl -fsS http://127.0.0.1:3000/healthz >/dev/null && exit 0; sleep 1; done; exit 1',
      ]);
      await waitForHealth(tunnel);
    },
    processLaunches: async () => null,
    readLedger: async (ids) => {
      const safe = ids.filter((id) => UUID_PATTERN.test(id));
      const output = await runSsm(instanceId, [
        `for id in ${safe.join(' ')}; do d=/var/lib/ec528-launch-ledger/$id; `
          + 'if [ -f "$d/state.json" ]; then printf "%s\\t" "$id"; cat "$d/state.json"; echo; '
          + 'elif [ -d "$d" ]; then printf "%s\\t{\\"state\\":\\"reserved\\"}\\n" "$id"; fi; done',
      ]);
      const entries = new Map(safe.map((id) => [id, null]));
      for (const line of output.split('\n')) {
        const [id, json] = line.split('\t');
        if (entries.has(id) && json) entries.set(id, JSON.parse(json));
      }
      return entries;
    },
    setAttestationAge: null,
    substituteInput: null,
    restoreInput: null,
    details: { instance_id: instanceId, stack, enrollment_epoch: enrollment.enrollment_epoch },
    close: async () => {
      if (tunnel.exitCode === null) {
        try { process.kill(-tunnel.pid, 'SIGTERM'); } catch { /* already gone */ }
      }
    },
  };
}

// ---- scenarios -------------------------------------------------------------

async function runScenarios(backend, workRoot) {
  const manifest = JSON.parse(await readFile(
    path.join(repositoryRoot, 'public', '.well-known', 'agent-actions.json'),
    'utf8',
  ));
  let controllers = 0;
  const controllerFor = (action, keylimeHandler) => {
    controllers += 1;
    return createDemoController({
      action,
      artifactPath: backend.artifactPath,
      inputPath: backend.inputPath,
      manifest,
      stateDirectory: path.join(workRoot, `controller-${controllers}`),
      keylimeHandler,
    });
  };

  const definitions = [
    {
      name: 'quorum_approved_launch',
      expected: 'executed_once',
      launches: 1,
      run: async (fresh) => {
        const action = fresh();
        const controller = await controllerFor(action, backend.keylimeHandler());
        const missing = (await controller.execute('missing')).last_response.status;
        controller.approve('operator');
        const pendingAfterOne = controller.snapshot().receipt_ready === false;
        controller.approve('security');
        const approved = (await controller.execute('approved')).last_response;
        const replay = (await controller.execute('replay')).last_response.status;
        return {
          ok: missing === 428 && pendingAfterOne && approved.status === 200
            && approved.body?.result?.workload?.executed === true && replay === 428,
          observed: {
            without_receipt: missing,
            after_one_approval: pendingAfterOne ? 'pending' : 'issued',
            after_two_approvals: approved.status,
            receipt_replay: replay,
          },
        };
      },
    },
    {
      name: 'bearer_token_without_permit',
      expected: 'refused',
      launches: 0,
      run: async (fresh) => {
        const outcome = await backend.call(fresh());
        return { ok: outcome === 'refused', observed: outcome };
      },
    },
    {
      name: 'forged_permit',
      expected: 'refused',
      launches: 0,
      run: async (fresh) => {
        const action = fresh();
        const outcome = await backend.call({ ...action, permit: backend.forger.sign(action) });
        return { ok: outcome === 'refused', observed: outcome };
      },
    },
    {
      name: 'expired_permit',
      expected: 'refused',
      launches: 0,
      run: async (fresh) => {
        const action = fresh();
        const now = Date.now();
        const permit = backend.kit.signWith(action, { issued_at: now - 60_000, expires_at: now - 50_000 });
        const outcome = await backend.call({ ...action, permit });
        return { ok: outcome === 'refused', observed: outcome };
      },
    },
    {
      name: 'old_enrollment_epoch',
      expected: 'refused',
      launches: 0,
      run: async (fresh) => {
        const action = fresh();
        const permit = backend.kit.signWith(action, { enrollment_epoch: crypto.randomUUID() });
        const outcome = await backend.call({ ...action, permit });
        return { ok: outcome === 'refused', observed: outcome };
      },
    },
    {
      name: 'target_substitution',
      expected: 'refused',
      launches: 0,
      run: async (fresh) => {
        // A correctly signed permit, for an action naming another node.
        const action = fresh({ target: `${backend.target}-other` });
        const outcome = await backend.call({ ...action, permit: backend.kit.sign(action) });
        return { ok: outcome === 'refused', observed: outcome };
      },
    },
    {
      name: 'artifact_substitution',
      expected: 'refused',
      launches: 0,
      run: async (fresh) => {
        // Approved and permitted, but naming bytes the node does not hold.
        const action = fresh({ artifact_sha256: digest('substituted artifact') });
        const outcome = await backend.call({ ...action, permit: backend.kit.sign(action) });
        return { ok: outcome === 'refused', observed: outcome };
      },
    },
    {
      name: 'staged_input_substituted',
      expected: 'refused_then_executed_once',
      launches: 1,
      localOnly: true,
      run: async (fresh) => {
        const action = fresh();
        await backend.substituteInput();
        const substituted = await backend.call({ ...action, permit: backend.kit.sign(action) });
        await backend.restoreInput();
        const consumed = (await backend.readLedger([action.occurrence_id])).get(action.occurrence_id) !== null;
        const restored = await backend.call({ ...action, permit: backend.kit.sign(action) });
        return {
          ok: substituted === 'refused' && !consumed && restored === 'accepted',
          observed: { substituted, consumed_by_refusal: consumed, after_restore: restored },
        };
      },
    },
    {
      name: 'stale_attestation',
      expected: 'refused_then_executed_once',
      launches: 1,
      localOnly: true,
      run: async (fresh) => {
        const action = fresh();
        backend.setAttestationAge(60);
        const stale = await backend.call({ ...action, permit: backend.kit.sign(action) });
        backend.setAttestationAge(0);
        const consumed = (await backend.readLedger([action.occurrence_id])).get(action.occurrence_id) !== null;
        const fresh_ = await backend.call({ ...action, permit: backend.kit.sign(action) });
        return {
          ok: stale === 'refused' && !consumed && fresh_ === 'accepted',
          observed: { stale, consumed_by_refusal: consumed, after_fresh_attestation: fresh_ },
        };
      },
    },
    {
      name: 'permit_replay',
      expected: 'executed_once',
      launches: 1,
      run: async (fresh) => {
        const action = fresh();
        const permit = backend.kit.sign(action, 'receipt-one');
        const first = await backend.call({ ...action, permit });
        const samePermit = await backend.call({ ...action, permit });
        const newPermit = await backend.call({ ...action, permit: backend.kit.sign(action, 'receipt-two') });
        return {
          ok: first === 'accepted' && samePermit === 'refused' && newPermit === 'refused',
          observed: { first, same_permit_again: samePermit, new_permit_same_occurrence: newPermit },
        };
      },
    },
    {
      name: 'race_10_clients',
      expected: 'executed_once',
      launches: 1,
      run: async (fresh) => {
        const action = fresh();
        const permit = backend.kit.sign(action);
        const outcomes = await Promise.all(Array.from({ length: 10 }, () => (
          backend.call({ ...action, permit })
        )));
        const accepted = outcomes.filter((outcome) => outcome === 'accepted').length;
        return { ok: accepted === 1, observed: { deliveries: 10, accepted } };
      },
    },
    {
      name: 'redelivery_after_restart',
      expected: 'executed_once',
      launches: 1,
      run: async (fresh) => {
        const action = fresh();
        const permit = backend.kit.sign(action, 'receipt-one');
        const first = await backend.call({ ...action, permit });
        await backend.restart();
        // A new permit for the same occurrence, so that only the ledger can refuse it.
        const afterRestart = await backend.call({ ...action, permit: backend.kit.sign(action, 'receipt-two') });
        return {
          ok: first === 'accepted' && afterRestart === 'refused',
          observed: { before_restart: first, after_restart: afterRestart },
        };
      },
    },
    {
      name: 'lost_response_after_launch',
      expected: 'executed_once_and_receipt_burned',
      launches: 1,
      run: async (fresh) => {
        const action = fresh();
        const realHandler = backend.keylimeHandler();
        const lossy = async (observed, extra) => {
          await realHandler(observed, extra);
          throw new Error('simulated lost response');
        };
        const controller = await controllerFor(action, lossy);
        controller.approve('operator');
        controller.approve('security');
        const lost = (await controller.execute('approved')).last_response;
        const retry = (await controller.execute('replay')).last_response.status;
        return {
          ok: lost.status === 500 && lost.body?.rejected?.reason === 'effect_indeterminate' && retry === 428,
          observed: {
            lost_response: lost.status,
            reason: lost.body?.rejected?.reason ?? null,
            retry_with_same_receipt: retry,
          },
        };
      },
    },
  ];

  const records = [];
  for (const definition of definitions) {
    const record = {
      name: definition.name,
      expected: definition.expected,
      expected_launches: definition.launches,
    };
    if (definition.localOnly && backend.mode !== 'local') {
      records.push({ ...record, passed: null, observed: 'not_run' });
      continue;
    }
    const ids = [];
    const fresh = (changes) => {
      const action = backend.action(changes);
      ids.push(action.occurrence_id);
      return action;
    };
    const startedAt = new Date().toISOString();
    const before = await backend.processLaunches();
    let outcome;
    try {
      outcome = await definition.run(fresh);
    } catch (error) {
      outcome = { ok: false, observed: { error: error.message } };
    }
    const after = await backend.processLaunches();
    records.push({
      ...record,
      observed: outcome.observed,
      responses_as_expected: outcome.ok,
      occurrence_ids: ids,
      process_launches: before === null ? null : after - before,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
    });
  }

  // Reconciliation: what the node itself recorded for every occurrence used.
  const allIds = records.flatMap((record) => record.occurrence_ids || []);
  const ledger = await backend.readLedger(allIds);
  const reconciliation = [];
  for (const record of records) {
    if (record.observed === 'not_run') continue;
    const entries = record.occurrence_ids.map((id) => ({ id, entry: ledger.get(id) ?? null }));
    record.ledger_launches = entries.filter(({ entry }) => entry !== null).length;
    record.launches = record.process_launches ?? record.ledger_launches;
    record.passed = record.responses_as_expected
      && record.launches === record.expected_launches
      && record.ledger_launches === record.expected_launches;
    for (const { id, entry } of entries) {
      reconciliation.push({
        scenario: record.name,
        occurrence_id: id,
        state: entry?.state ?? 'never_reserved',
        reserved_at: entry?.reserved_at ?? null,
        finished_at: entry?.finished_at ?? null,
        action_sha256: entry?.action_sha256 ?? null,
        receipt_sha256: entry?.receipt_sha256 ?? null,
      });
    }
  }
  return { records, reconciliation };
}

async function main() {
  const runs = path.join(repositoryRoot, 'build', 'runs');
  await mkdir(runs, { recursive: true, mode: 0o700 });
  const workRoot = await mkdtemp(path.join(runs, 'demo3-bridge-'));
  let backend;
  try {
    backend = mode === 'aws' ? await awsBackend(workRoot) : await localBackend(workRoot);
    const { records, reconciliation } = await runScenarios(backend, workRoot);
    const ran = records.filter((record) => record.passed !== null);
    const status = ran.length > 0 && ran.every((record) => record.passed) ? 'pass' : 'fail';
    const gitStatus = await commandOutput('git', ['status', '--porcelain', '--untracked-files=all']);
    await writeResult({
      schema_version: 1,
      experiment: 'demo3-bridge',
      mode,
      status,
      generated_at: new Date().toISOString(),
      repository_revision: await commandOutput('git', ['rev-parse', 'HEAD']),
      repository_dirty: gitStatus === null ? null : gitStatus.length > 0,
      versions: { node: process.version },
      launch_evidence: backend.launchEvidence,
      ...backend.details,
      summary: {
        scenarios_passed: ran.filter((record) => record.passed).length,
        scenarios_run: ran.length,
        scenarios_not_run: records.length - ran.length,
      },
      scenarios: records,
      reconciliation,
      limitations: [...MODE_LIMITATIONS[mode], ...COMMON_LIMITATIONS],
    });
    process.stdout.write(`${outputPath}\n`);
    for (const record of records) {
      const verdict = record.passed === null ? 'not run' : (record.passed ? 'pass' : 'FAIL');
      process.stdout.write(`  ${verdict.padEnd(8)} ${record.name}\n`);
    }
    process.stdout.write(`demo3-bridge (${mode}): ${status}\n`);
    if (status !== 'pass') process.exitCode = 1;
  } finally {
    if (backend) await backend.close();
    await rm(workRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`demo3-bridge failed: ${error.message}\n`);
  process.exitCode = 1;
});
