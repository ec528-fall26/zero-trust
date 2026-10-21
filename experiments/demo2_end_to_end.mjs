import crypto from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { createKeylimeMcpHandler } from '../src/controller/keylime_mcp_client.mjs';
import { createDemoController } from '../src/demo/demo_controller.mjs';
import { assertSandboxCannotRead } from './sandbox_check.mjs';
import {
  addEvent,
  initTelemetry,
  markOutcome,
  scenarioSpan,
  shutdownTelemetry,
  tracedKeylimeHandler,
  withSpan,
} from './telemetry.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const LIMITATIONS = Object.freeze([
  'swtpm is not a hardware root of trust.',
  'The Keylime verifier, registrar, agent, swtpm and MCP all run on the same instance they are checking. This proves the protocol works, not independent attestation.',
  'The three EMILIA signer keys are on one machine. This proves the protocol works, not independent human approval.',
]);

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

async function requiredCommand(command, args, options = {}) {
  const { stdout } = await execFileAsync(command, args, {
    cwd: repositoryRoot,
    timeout: 60_000,
    maxBuffer: 2 * 1024 * 1024,
    windowsHide: true,
    ...options,
  });
  return stdout.trim();
}

async function writeResult(outputPath, result) {
  await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  const temporary = `${outputPath}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  await writeFile(temporary, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, outputPath);
}

function cleanResponse(response) {
  const reason = response?.body?.rejected?.reason;
  const result = response?.body?.result;
  return {
    status: response?.status ?? null,
    reason: typeof reason === 'string' ? reason : null,
    attestation_verdict: result?.attestation?.verdict ?? null,
    evidence_digest: result?.attestation?.evidence_digest ?? null,
    workload_executed: result?.workload?.executed ?? null,
    workload_stdout_sha256: typeof result?.workload?.stdout === 'string'
      ? digest(Buffer.from(result.workload.stdout, 'utf8'))
      : null,
  };
}

function responseDigest(response) {
  return digest(Buffer.from(JSON.stringify(response), 'utf8'));
}

async function awsEnvironment() {
  const environment = { ...process.env };
  if (process.platform === 'darwin') {
    try {
      const prefix = await requiredCommand('brew', ['--prefix', 'expat']);
      environment.DYLD_LIBRARY_PATH = path.join(prefix, 'lib');
    } catch {
      // The AWS CLI will fail loudly if its own runtime cannot load.
    }
  }
  return environment;
}

async function runAws(arguments_, environment, timeout = 60_000) {
  return requiredCommand('aws', arguments_, { env: environment, timeout });
}

async function runSsm(commands, context) {
  return withSpan('ssm.run_command', { 'ssm.command_count': commands.length }, () => (
    runSsmUntraced(commands, context)
  ));
}

async function runSsmUntraced(commands, context) {
  const parameters = JSON.stringify({ commands, executionTimeout: ['180'] });
  const commandId = await runAws([
    'ssm', 'send-command',
    '--profile', context.profile,
    '--region', context.region,
    '--instance-ids', context.instanceId,
    '--document-name', 'AWS-RunShellScript',
    '--parameters', parameters,
    '--query', 'Command.CommandId',
    '--output', 'text',
  ], context.awsEnv);
  const deadline = Date.now() + 210_000;
  while (Date.now() < deadline) {
    let invocation;
    try {
      invocation = JSON.parse(await runAws([
        'ssm', 'get-command-invocation',
        '--profile', context.profile,
        '--region', context.region,
        '--command-id', commandId,
        '--instance-id', context.instanceId,
        '--output', 'json',
      ], context.awsEnv));
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 1_000));
      continue;
    }
    if (invocation.Status === 'Success') return invocation.StandardOutputContent.trim();
    if (['Failed', 'TimedOut', 'Cancelled', 'Cancelling'].includes(invocation.Status)) {
      throw new Error(`SSM command failed: ${invocation.Status}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error('SSM command did not finish before its deadline');
}

function keylimeRecoveryCommands(agentUuid, waitSeconds = 15) {
  return [
    'systemctl stop keylime_agent.service',
    // Restarting swtpm also restarts ec528-ima-emulator (PartOf=), which
    // replays the IMA log into the fresh PCR 10 before the agent quotes.
    'systemctl restart swtpm-keylime.service',
    'sleep 5',
    'systemctl start keylime_agent.service',
    'sleep 5',
    `keylime_tenant -c delete -u ${agentUuid}`,
    'if [ -f /var/lib/ec528/runtime-policy.json ]; then '
      + `keylime_tenant -c add -u ${agentUuid} -t 127.0.0.1 -v 127.0.0.1 `
      + '--runtime-policy /var/lib/ec528/runtime-policy.json; '
      + `else keylime_tenant -c add -u ${agentUuid} -t 127.0.0.1 -v 127.0.0.1; fi`,
    `sleep ${waitSeconds}`,
    'systemctl is-active swtpm-keylime.service keylime_agent.service',
  ];
}

async function waitForHealth(url, tunnel) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (tunnel.exitCode !== null) throw new Error('SSM tunnel exited before becoming ready');
    try {
      const response = await fetch(new URL('/healthz', url), {
        signal: AbortSignal.timeout(1_000),
      });
      if (response.ok) return;
    } catch {
      // The port forward is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('SSM tunnel did not become healthy');
}

async function stopTunnel(tunnel) {
  if (!tunnel || tunnel.exitCode !== null) return;
  try {
    process.kill(-tunnel.pid, 'SIGINT');
  } catch {
    tunnel.kill('SIGINT');
  }
  await Promise.race([
    new Promise((resolve) => tunnel.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 5_000)),
  ]);
  if (tunnel.exitCode === null) tunnel.kill('SIGKILL');
}

function scenarioRecord(name, expected, snapshot, passed, startedAt) {
  const response = snapshot.last_response;
  return {
    name,
    expected,
    observed: cleanResponse(response),
    passed,
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    raw_response_sha256: responseDigest(response),
  };
}

async function runExperiment() {
  const outputPath = path.resolve(
    process.argv[2] || path.join(repositoryRoot, 'results', 'demo2-end-to-end.json'),
  );
  const python = process.env.PYTHON_BIN || 'python3';
  const nono = process.env.NONO_BIN || 'nono';
  const tokenPath = path.resolve(
    process.env.KEYLIME_MCP_TOKEN_FILE
      || path.join(repositoryRoot, 'build', 'aws-keylime', 'mcp-token'),
  );
  const endpoint = process.env.KEYLIME_MCP_URL || 'http://127.0.0.1:3000/mcp';
  const profile = process.env.AWS_PROFILE || 'ec528-deployer';
  const region = process.env.AWS_REGION || 'us-east-2';
  const stackName = process.env.AWS_STACK_NAME || 'ec528-zero-trust-demo';
  const agentUuid = 'd432fbb3-d2f1-4a97-9ef7-75bd81c00000';
  // Keep controller state out of os.tmpdir(): nono's default macOS groups let
  // the sandbox read /private/var, which holds the per-user temp folder.
  const runsRoot = path.join(repositoryRoot, 'build', 'runs');
  await mkdir(runsRoot, { recursive: true, mode: 0o700 });
  const temporaryRoot = await mkdtemp(path.join(runsRoot, 'ec528-e2e-'));
  const timeline = [];
  const scenarios = [];
  let tunnel = null;
  let agentStopped = false;
  let context;

  const mark = (step, outcome, details = {}) => {
    timeline.push({ step, outcome, at: new Date().toISOString(), ...details });
    addEvent(step, { outcome, ...details });
  };

  try {
    const awsEnv = await awsEnvironment();
    const instanceId = await runAws([
      'cloudformation', 'describe-stacks',
      '--profile', profile,
      '--region', region,
      '--stack-name', stackName,
      '--query', "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue | [0]",
      '--output', 'text',
    ], awsEnv);
    if (!/^i-[a-f0-9]+$/.test(instanceId)) throw new Error('demo instance was not resolved');
    context = { awsEnv, profile, region, instanceId };

    const directories = Object.fromEntries(
      ['outbox', 'inbox', 'storage', 'inputs', 'state', 'work']
        .map((name) => [name, path.join(temporaryRoot, name)]),
    );
    await Promise.all(Object.values(directories).map((directory) => (
      mkdir(directory, { mode: 0o700 })
    )));
    const artifactPath = path.join(temporaryRoot, 'checksum.sh');
    const inputPath = path.join(directories.inputs, 'demo-payload.txt');
    const artifact = Buffer.from(
      '#!/bin/sh\nset -eu\n[ "$#" -eq 1 ] || exit 64\nexec sha256sum "$1"\n',
      'utf8',
    );
    const input = Buffer.from('EC528 approved workload payload\n', 'utf8');
    await Promise.all([
      writeFile(artifactPath, artifact, { mode: 0o700 }),
      writeFile(inputPath, input, { mode: 0o600 }),
    ]);
    await chmod(artifactPath, 0o700);

    const requestId = crypto.randomUUID();
    const request = {
      schema_version: 'ec528.nono.request.v1',
      request_id: requestId,
      operation: 'checksum.sha256',
      target: 'aws-keylime-demo-01',
      input_name: path.basename(inputPath),
      expected_input_sha256: digest(input),
    };
    const profilePath = path.join(temporaryRoot, 'nono-profile.json');
    const generatedProfile = await requiredCommand(python, [
      path.join(repositoryRoot, 'src', 'agent_tool', 'nono_profile.py'),
      '--outbox', directories.outbox,
      '--inbox', directories.inbox,
    ], { env: { ...process.env, PYTHONPATH: path.join(repositoryRoot, 'src') } });
    await writeFile(profilePath, `${generatedProfile}\n`, { mode: 0o600 });
    mark('nono_profile_generated', 'success');

    // Prove, with nono's own policy evaluation, that the agent cannot read
    // anything the controller keeps private. Fails closed.
    const pathsChecked = await withSpan('sandbox.controller_state_unreadable', {}, () => (
      assertSandboxCannotRead({
        nono,
        profilePath,
        workdir: directories.work,
        paths: [
          directories.storage,
          directories.inputs,
          directories.state,
          path.join(temporaryRoot, 'stopped-state'),
          path.join(temporaryRoot, 'recovery-state'),
          artifactPath,
          tokenPath,
        ],
      })
    ));
    mark('controller_state_unreadable_by_sandbox', 'success', { paths_checked: pathsChecked });

    const requestPath = path.join(directories.outbox, `${requestId}.json`);
    const encodedRequest = Buffer.from(JSON.stringify(request), 'utf8').toString('base64');
    await withSpan('nono.agent_writes_request', { 'ec528.request_id': requestId }, () => (
      requiredCommand(nono, [
        'run', '--silent',
        '--profile', profilePath,
        '--workdir', directories.work,
        '--allow-cwd',
        '--strict-broker-path',
        '--audit-integrity',
        '--', '/bin/sh', '-c',
        `printf %s ${shellQuote(encodedRequest)} | /usr/bin/base64 -D > ${shellQuote(requestPath)}`,
      ], { timeout: 30_000 })
    ));
    mark('nono_agent_request_written', 'success', { request_id: requestId });

    await withSpan('watcher.build_trusted_action', {}, () => requiredCommand(python, [
      path.join(repositoryRoot, 'src', 'controller', 'outbox_watcher.py'),
      '--outbox', directories.outbox,
      '--inbox', directories.inbox,
      '--storage', directories.storage,
      '--input-root', directories.inputs,
      '--artifact', artifactPath,
      '--allowed-target', 'aws-keylime-demo-01',
      '--policy-version', 'demo-2.1',
    ], { env: { ...process.env, PYTHONPATH: path.join(repositoryRoot, 'src') } }));
    const action = JSON.parse(await readFile(
      path.join(directories.storage, `${requestId}.action.json`),
      'utf8',
    ));
    if (action.artifact_sha256 !== digest(artifact) || action.input_sha256 !== digest(input)) {
      throw new Error('watcher action did not bind the trusted material');
    }
    mark('watcher_action_constructed', 'success', {
      occurrence_id: action.occurrence_id,
      policy_version: action.policy_version,
    });

    const plugin = process.env.SESSION_MANAGER_PLUGIN_BIN;
    const tunnelEnvironment = { ...process.env };
    if (plugin) tunnelEnvironment.PATH = `${path.dirname(plugin)}:${tunnelEnvironment.PATH}`;
    tunnel = spawn(path.join(repositoryRoot, 'infra', 'aws', 'open-tunnel.sh'), [stackName], {
      cwd: repositoryRoot,
      detached: true,
      env: tunnelEnvironment,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    tunnel.stdout.resume();
    tunnel.stderr.resume();
    await withSpan('ssm.tunnel_open', {}, () => waitForHealth(endpoint, tunnel));
    mark('ssm_tunnel_ready', 'success', { instance_id: instanceId });

    const tokenBytes = await readFile(tokenPath);
    let token;
    try {
      token = tokenBytes.toString('utf8').trim();
    } finally {
      tokenBytes.fill(0);
    }
    const keylimeHandler = tracedKeylimeHandler(createKeylimeMcpHandler({
      endpoint,
      token,
      allowInsecureLoopback: true,
      timeoutMilliseconds: 25_000,
    }));
    const manifest = JSON.parse(await readFile(
      path.join(repositoryRoot, 'public', '.well-known', 'agent-actions.json'),
      'utf8',
    ));
    const controller = await createDemoController({
      action,
      artifactPath,
      inputPath,
      keylimeHandler,
      manifest,
      stateDirectory: directories.state,
    });

    let startedAt = new Date().toISOString();
    let snapshot = await scenarioSpan('no_receipt', 'denied', () => controller.execute('missing'));
    scenarios.push(scenarioRecord(
      'no_receipt', 'denied', snapshot, snapshot.last_response.status === 428, startedAt,
    ));

    controller.approve('operator');
    mark('emilia_first_distinct_signature', 'pending');
    startedAt = new Date().toISOString();
    snapshot = await scenarioSpan('one_of_three_signatures', 'pending_and_denied', () => controller.execute('missing'));
    scenarios.push(scenarioRecord(
      'one_of_three_signatures', 'pending_and_denied', snapshot,
      controller.snapshot().receipt_ready === false && snapshot.last_response.status === 428,
      startedAt,
    ));

    controller.approve('security');
    if (!controller.snapshot().receipt_ready) throw new Error('EMILIA did not issue a 2-of-3 receipt');
    mark('emilia_second_distinct_signature', 'receipt_issued');

    startedAt = new Date().toISOString();
    snapshot = await scenarioSpan('action_changed_after_approval', 'denied', () => controller.execute('tampered'));
    scenarios.push(scenarioRecord(
      'action_changed_after_approval', 'denied', snapshot,
      snapshot.last_response.status === 428
        && snapshot.last_response.body?.rejected?.reason === 'action_hash_mismatch',
      startedAt,
    ));

    startedAt = new Date().toISOString();
    snapshot = await scenarioSpan('exact_action_end_to_end', 'executed_once', () => controller.execute('approved'));
    scenarios.push(scenarioRecord(
      'exact_action_end_to_end', 'executed_once', snapshot,
      snapshot.last_response.status === 200
        && snapshot.last_response.body?.result?.workload?.executed === true,
      startedAt,
    ));

    startedAt = new Date().toISOString();
    snapshot = await scenarioSpan('used_receipt_replay', 'denied', () => controller.execute('replay'));
    scenarios.push(scenarioRecord(
      'used_receipt_replay', 'denied', snapshot,
      snapshot.last_response.status === 428
        && snapshot.last_response.body?.rejected?.reason === 'replay_refused',
      startedAt,
    ));

    const stoppedController = await createDemoController({
      action,
      artifactPath,
      inputPath,
      keylimeHandler,
      manifest,
      stateDirectory: path.join(temporaryRoot, 'stopped-state'),
    });
    stoppedController.approve('operator');
    stoppedController.approve('security');
    await runSsm(['systemctl stop keylime_agent.service'], context);
    agentStopped = true;
    mark('keylime_agent_stopped', 'success');
    await new Promise((resolve) => setTimeout(resolve, 35_000));
    startedAt = new Date().toISOString();
    snapshot = await scenarioSpan('keylime_agent_stopped', 'denied', () => stoppedController.execute('approved'));
    scenarios.push(scenarioRecord(
      'keylime_agent_stopped', 'denied', snapshot,
      snapshot.last_response.status !== 200,
      startedAt,
    ));

    mark('keylime_agent_recovery_started', 'started');
    await runSsm(keylimeRecoveryCommands(agentUuid), context);
    agentStopped = false;
    mark('keylime_agent_restarted', 'success');

    const recoveryController = await createDemoController({
      action,
      artifactPath,
      inputPath,
      keylimeHandler,
      manifest,
      stateDirectory: path.join(temporaryRoot, 'recovery-state'),
    });
    recoveryController.approve('operator');
    recoveryController.approve('security');
    startedAt = new Date().toISOString();
    snapshot = await scenarioSpan('keylime_agent_recovered', 'executed_once', () => recoveryController.execute('approved'));
    scenarios.push(scenarioRecord(
      'keylime_agent_recovered', 'executed_once', snapshot,
      snapshot.last_response.status === 200
        && snapshot.last_response.body?.result?.workload?.executed === true,
      startedAt,
    ));

    const finalStatus = {
      request_id: requestId,
      state: 'SUCCEEDED',
      action_hash: controller.snapshot().action_hash,
      completed_at: new Date().toISOString(),
    };
    const finalStatusPath = path.join(directories.inbox, `${requestId}.result.json`);
    await writeFile(finalStatusPath, `${JSON.stringify(finalStatus)}\n`, {
      mode: 0o600,
      flag: 'wx',
    });
    const agentStatus = await requiredCommand(nono, [
      'run', '--silent',
      '--profile', profilePath,
      '--workdir', directories.work,
      '--allow-cwd',
      '--strict-broker-path',
      '--audit-integrity',
      '--', '/bin/cat', finalStatusPath,
    ], { timeout: 30_000 });
    if (JSON.parse(agentStatus).state !== 'SUCCEEDED') {
      throw new Error('agent could not read its trusted final status');
    }
    mark('readonly_inbox_status_observed', 'success');

    const instance = JSON.parse(await runAws([
      'ec2', 'describe-instances',
      '--profile', profile,
      '--region', region,
      '--instance-ids', instanceId,
      '--query', 'Reservations[0].Instances[0]',
      '--output', 'json',
    ], awsEnv));
    const remoteVersions = (await runSsm([
      "printf 'keylime='; rpm -q --qf '%{VERSION}-%{RELEASE}\\n' keylime",
      "printf 'swtpm='; rpm -q --qf '%{VERSION}-%{RELEASE}\\n' swtpm",
    ], context)).split('\n').reduce((values, line) => {
      const separator = line.indexOf('=');
      if (separator > 0) values[line.slice(0, separator)] = line.slice(separator + 1);
      return values;
    }, {});
    const gitStatus = await requiredCommand('git', ['status', '--porcelain', '--untracked-files=all']);
    const result = {
      schema_version: 1,
      experiment: 'demo2-end-to-end',
      status: scenarios.every((scenario) => scenario.passed) ? 'pass' : 'fail',
      generated_at: new Date().toISOString(),
      repository_revision: await requiredCommand('git', ['rev-parse', 'HEAD']),
      repository_dirty: gitStatus.length > 0,
      versions: {
        nono: await requiredCommand(nono, ['--version']),
        node: process.version,
        keylime: remoteVersions.keylime,
        swtpm: remoteVersions.swtpm,
        ami_id: instance.ImageId,
        instance_type: instance.InstanceType,
      },
      tpm_type: 'swtpm',
      instance_id: instanceId,
      agent_uuid: agentUuid,
      action,
      scenarios,
      timeline,
      limitations: [...LIMITATIONS],
    };
    await writeResult(outputPath, result);
    process.stdout.write(`${outputPath}\n`);
    if (result.status !== 'pass') process.exitCode = 1;
  } catch (error) {
    let repositoryRevision = 'unavailable';
    let repositoryDirty = true;
    try {
      repositoryRevision = await requiredCommand('git', ['rev-parse', 'HEAD']);
      repositoryDirty = (await requiredCommand(
        'git', ['status', '--porcelain', '--untracked-files=all'],
      )).length > 0;
    } catch {
      // Preserve a conservative dirty value if Git itself is unavailable.
    }
    await writeResult(outputPath, {
      schema_version: 1,
      experiment: 'demo2-end-to-end',
      status: 'fail',
      generated_at: new Date().toISOString(),
      repository_revision: repositoryRevision,
      repository_dirty: repositoryDirty,
      versions: { node: process.version },
      tpm_type: 'swtpm',
      failed_after: timeline.at(-1)?.step || 'initialization',
      error: error instanceof Error ? error.message : 'unknown error',
      scenarios,
      timeline,
      limitations: [...LIMITATIONS],
    });
    process.stderr.write(`demo2 end-to-end failed: ${error.message}\n`);
    process.exitCode = 1;
  } finally {
    if (agentStopped && context) {
      try {
        await runSsm(keylimeRecoveryCommands(agentUuid, 5), context);
      } catch {
        process.stderr.write('warning: failed to restart Keylime agent during cleanup\n');
      }
    }
    await stopTunnel(tunnel);
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

async function main() {
  const traced = await initTelemetry('ec528-demo2-end-to-end');
  try {
    await withSpan('demo2.end_to_end', {}, async (span) => {
      await runExperiment();
      markOutcome(span, !process.exitCode);
    });
  } finally {
    if (traced) await shutdownTelemetry();
  }
}

main().catch((error) => {
  process.stderr.write(`demo2 end-to-end failed: ${error.message}\n`);
  process.exitCode = 1;
});
