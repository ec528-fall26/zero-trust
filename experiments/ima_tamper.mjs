// IMA tamper experiment: a clean node runs the approved workload, then an
// unapproved program is executed on the node, Keylime's IMA runtime policy
// must mark the node failed, and the next fully approved request must be
// denied.  Requires the AWS stack from infra/aws and leaves the node in the
// failed state (the IMA log keeps the probe until reboot), so tear the stack
// down afterwards.
import crypto from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { createKeylimeMcpHandler } from '../src/controller/keylime_mcp_client.mjs';
import { createDemoController } from '../src/demo/demo_controller.mjs';
import {
  addEvent,
  initTelemetry,
  markOutcome,
  scenarioSpan,
  setAttributes,
  shutdownTelemetry,
  tracedKeylimeHandler,
  withSpan,
} from './telemetry.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const AGENT_UUID = 'd432fbb3-d2f1-4a97-9ef7-75bd81c00000';
const DETECTION_TIMEOUT_MS = 120_000;
const LIMITATIONS = Object.freeze([
  'swtpm is not a hardware root of trust.',
  'IMA measurements are recorded by the real kernel but copied into the swtpm PCR 10 by a userspace emulator (keylime_ima_emulator); root on the node could forge them.',
  'The runtime policy was generated on the node from its own filesystem at boot (trust on first use).',
  'Only executed and executable-mapped files are measured. tmpfs and other in-memory filesystems are not measured, and the SSM per-command script directory is excluded.',
  'The Keylime verifier, registrar, agent, swtpm and MCP all run on the same instance they are checking. This proves the protocol works, not independent attestation.',
  'The three EMILIA signer keys are on one machine. This proves the protocol works, not independent human approval.',
]);

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
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

function keyValues(text) {
  const values = {};
  for (const line of text.split('\n')) {
    const separator = line.indexOf('=');
    if (separator > 0) values[line.slice(0, separator).trim()] = line.slice(separator + 1).trim();
  }
  return values;
}

// Keep only the fields needed to reconstruct the decision; never store the
// raw verifier response in Git.
async function keylimeStatus(context) {
  const output = await runSsm(['/usr/local/libexec/ec528-keylime-status'], context);
  const parsed = JSON.parse(output);
  if (parsed.agent_id !== AGENT_UUID) throw new Error('status belongs to another agent');
  const results = parsed.results || {};
  return {
    sanitized: {
      attestation_status: results.attestation_status ?? null,
      operational_state: results.operational_state ?? null,
      last_successful_attestation: results.last_successful_attestation ?? null,
      severity_level: results.severity_level ?? null,
      last_event_id: results.last_event_id ?? null,
      has_runtime_policy: results.has_runtime_policy ?? null,
    },
    raw_sha256: digest(Buffer.from(output, 'utf8')),
  };
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

function responseSummary(response) {
  const result = response?.body?.result;
  return {
    status: response?.status ?? null,
    reason: response?.body?.rejected?.reason ?? null,
    attestation_verdict: result?.attestation?.verdict ?? null,
    workload_executed: result?.workload?.executed ?? null,
  };
}

async function runExperiment() {
  const outputPath = path.resolve(
    process.argv[2] || path.join(repositoryRoot, 'results', 'ima-tamper.json'),
  );
  const tokenPath = path.resolve(
    process.env.KEYLIME_MCP_TOKEN_FILE
      || path.join(repositoryRoot, 'build', 'aws-keylime', 'mcp-token'),
  );
  const endpoint = process.env.KEYLIME_MCP_URL || 'http://127.0.0.1:3000/mcp';
  const profile = process.env.AWS_PROFILE || 'ec528-deployer';
  const region = process.env.AWS_REGION || 'us-east-2';
  const stackName = process.env.AWS_STACK_NAME || 'ec528-zero-trust-demo';
  // Same layout rule as the end-to-end experiment: never under os.tmpdir().
  const runsRoot = path.join(repositoryRoot, 'build', 'runs');
  await mkdir(runsRoot, { recursive: true, mode: 0o700 });
  const temporaryRoot = await mkdtemp(path.join(runsRoot, 'ec528-ima-'));
  const scenarios = [];
  const timeline = [];
  let tunnel = null;

  const mark = (step, outcome, details = {}) => {
    timeline.push({ step, outcome, at: new Date().toISOString(), ...details });
    addEvent(step, { outcome, ...details });
  };
  const record = (name, expected, observed, passed, startedAt) => {
    scenarios.push({
      name,
      expected,
      observed,
      passed: Boolean(passed),
      started_at: startedAt,
      completed_at: new Date().toISOString(),
    });
  };

  let remote = {};
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
    const context = { awsEnv, profile, region, instanceId };

    remote = keyValues(await runSsm([
      "printf 'keylime=%s\\n' \"$(rpm -q --qf '%{VERSION}-%{RELEASE}' keylime)\"",
      "printf 'swtpm=%s\\n' \"$(rpm -q --qf '%{VERSION}-%{RELEASE}' swtpm)\"",
      "printf 'kernel=%s\\n' \"$(uname -r)\"",
      "printf 'emulator=%s\\n' \"$(systemctl is-active ec528-ima-emulator.service || true)\"",
      "printf 'ima_policy_rules=%s\\n' \"$(grep -c . /sys/kernel/security/ima/policy || true)\"",
      "printf 'ima_measurements=%s\\n' \"$(wc -l < /sys/kernel/security/ima/ascii_runtime_measurements)\"",
      "printf 'runtime_policy_sha256=sha256:%s\\n' \"$(sha256sum /var/lib/ec528/runtime-policy.json | cut -d' ' -f1)\"",
    ], context));
    let startedAt = new Date().toISOString();
    const before = await keylimeStatus(context);
    record('ima_active_before_tamper', 'pass', {
      emulator: remote.emulator,
      ima_policy_rules: Number(remote.ima_policy_rules),
      ima_measurements: Number(remote.ima_measurements),
      keylime: before.sanitized,
      raw_status_sha256: before.raw_sha256,
    }, remote.emulator === 'active'
      && Number(remote.ima_policy_rules) > 0
      && Number(remote.ima_measurements) > 1
      && before.sanitized.attestation_status === 'PASS', startedAt);
    mark('ima_precheck', before.sanitized.attestation_status === 'PASS' ? 'success' : 'failure');

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
    // Same bytes as /opt/ec528/workloads/checksum.sh and the input on the node.
    const artifact = Buffer.from(
      '#!/bin/sh\nset -eu\n[ "$#" -eq 1 ] || exit 64\nexec sha256sum "$1"\n',
      'utf8',
    );
    const input = Buffer.from('EC528 approved workload payload\n', 'utf8');
    const artifactPath = path.join(temporaryRoot, 'checksum.sh');
    const inputPath = path.join(temporaryRoot, 'demo-payload.txt');
    await writeFile(artifactPath, artifact, { mode: 0o700 });
    await writeFile(inputPath, input, { mode: 0o600 });
    const approvedController = async (name) => {
      const controller = await createDemoController({
        action: {
          action_type: 'workload.execute',
          operation: 'checksum.sha256',
          target: 'aws-keylime-demo-01',
          artifact_sha256: digest(artifact),
          input_sha256: digest(input),
          occurrence_id: crypto.randomUUID(),
          policy_version: 'demo-2.1',
        },
        artifactPath,
        inputPath,
        keylimeHandler,
        manifest,
        stateDirectory: path.join(temporaryRoot, name),
      });
      controller.approve('operator');
      controller.approve('security');
      if (!controller.snapshot().receipt_ready) throw new Error('2-of-3 receipt was not issued');
      return controller;
    };

    startedAt = new Date().toISOString();
    let snapshot = await scenarioSpan('clean_node_allows_exact_workload', 'executed_once',
      async () => (await approvedController('clean')).execute('approved'));
    const clean = responseSummary(snapshot.last_response);
    record('clean_node_allows_exact_workload', 'executed_once', clean,
      clean.status === 200 && clean.workload_executed === true, startedAt);

    startedAt = new Date().toISOString();
    const probe = keyValues(await withSpan('node.run_unapproved_program', {}, () => runSsm([
      'set -eu',
      'probe=/root/ec528-unapproved-probe.sh',
      // Unique content so the digest cannot already be in any policy.
      "printf '#!/bin/sh\\necho ec528-unapproved-%s\\n' \"$(date +%s%N)\" > \"$probe\"",
      'chmod 0700 "$probe"',
      '"$probe" >/dev/null',
      "printf 'probe_sha256=sha256:%s\\n' \"$(sha256sum \"$probe\" | cut -d' ' -f1)\"",
      "printf 'probe_measured=%s\\n' \"$(grep -c ec528-unapproved-probe /sys/kernel/security/ima/ascii_runtime_measurements || true)\"",
    ], context)));
    const tamperedAt = Date.now();
    mark('unapproved_program_executed', 'success');
    record('unapproved_program_measured', 'measured', {
      probe_sha256: probe.probe_sha256,
      ima_entries: Number(probe.probe_measured),
    }, Number(probe.probe_measured) >= 1, startedAt);

    startedAt = new Date().toISOString();
    const after = await withSpan('keylime.wait_for_detection', {}, async (span) => {
      let status = await keylimeStatus(context);
      while (status.sanitized.attestation_status === 'PASS'
          && Date.now() - tamperedAt < DETECTION_TIMEOUT_MS) {
        await new Promise((resolve) => setTimeout(resolve, 3_000));
        status = await keylimeStatus(context);
      }
      setAttributes(span, {
        'keylime.attestation_status': status.sanitized.attestation_status,
        'keylime.last_event_id': status.sanitized.last_event_id,
      });
      return status;
    });
    const detectionSeconds = (Date.now() - tamperedAt) / 1_000;
    mark('verifier_status_after_tamper', after.sanitized.attestation_status === 'PASS' ? 'not_detected' : 'detected');
    record('verifier_detects_unapproved_program', 'not_pass', {
      keylime: after.sanitized,
      raw_status_sha256: after.raw_sha256,
      detection_seconds_upper_bound: Number(detectionSeconds.toFixed(1)),
    }, after.sanitized.attestation_status !== 'PASS', startedAt);

    startedAt = new Date().toISOString();
    snapshot = await scenarioSpan('approved_request_denied_after_tamper', 'denied',
      async () => (await approvedController('after-tamper')).execute('approved'));
    const denied = responseSummary(snapshot.last_response);
    record('approved_request_denied_after_tamper', 'denied', denied,
      denied.status !== 200 && denied.workload_executed !== true, startedAt);

    const instance = JSON.parse(await runAws([
      'ec2', 'describe-instances',
      '--profile', profile,
      '--region', region,
      '--instance-ids', instanceId,
      '--query', 'Reservations[0].Instances[0]',
      '--output', 'json',
    ], awsEnv));
    const gitStatus = await requiredCommand('git', ['status', '--porcelain', '--untracked-files=all']);
    const result = {
      schema_version: 1,
      experiment: 'ima-tamper',
      status: scenarios.every((scenario) => scenario.passed) ? 'pass' : 'fail',
      generated_at: new Date().toISOString(),
      repository_revision: await requiredCommand('git', ['rev-parse', 'HEAD']),
      repository_dirty: gitStatus.length > 0,
      versions: {
        node: process.version,
        keylime: remote.keylime,
        swtpm: remote.swtpm,
        kernel: remote.kernel,
        ami_id: instance.ImageId,
        instance_type: instance.InstanceType,
      },
      tpm_type: 'swtpm',
      ima_mode: 'kernel log replayed into swtpm PCR 10 by keylime_ima_emulator',
      runtime_policy_sha256: remote.runtime_policy_sha256,
      instance_id: instanceId,
      agent_uuid: AGENT_UUID,
      scenarios,
      timeline,
      node_left_failed: true,
      // Free-text operator note for anything done to the node outside this
      // script (for example a manual re-enrollment).
      run_notes: process.env.EXPERIMENT_NOTE ? [process.env.EXPERIMENT_NOTE] : [],
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
      // Keep the conservative dirty value if Git itself is unavailable.
    }
    await writeResult(outputPath, {
      schema_version: 1,
      experiment: 'ima-tamper',
      status: 'fail',
      generated_at: new Date().toISOString(),
      repository_revision: repositoryRevision,
      repository_dirty: repositoryDirty,
      versions: { node: process.version, ...remote },
      tpm_type: 'swtpm',
      failed_after: timeline.at(-1)?.step || 'initialization',
      error: error instanceof Error ? error.message : 'unknown error',
      scenarios,
      timeline,
      limitations: [...LIMITATIONS],
    });
    process.stderr.write(`ima tamper experiment failed: ${error.message}\n`);
    process.exitCode = 1;
  } finally {
    await stopTunnel(tunnel);
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

async function main() {
  const traced = await initTelemetry('ec528-ima-tamper');
  try {
    await withSpan('ima.tamper_experiment', {}, async (span) => {
      await runExperiment();
      markOutcome(span, !process.exitCode);
    });
  } finally {
    if (traced) await shutdownTelemetry();
  }
}

main().catch((error) => {
  process.stderr.write(`ima tamper experiment failed: ${error.message}\n`);
  process.exitCode = 1;
});
