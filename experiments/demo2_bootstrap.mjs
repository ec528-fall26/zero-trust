import crypto from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createKeylimeBootstrapHandler } from '../src/controller/keylime_bootstrap_client.mjs';
import {
  bootstrapPermitSignerFromEnvironment,
  enrollmentRecordPath,
} from '../src/controller/permit_signer.mjs';
import { createDemoController } from '../src/demo/demo_controller.mjs';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputPath = path.resolve(process.argv[2] || path.join(repository, 'results', 'demo2-bootstrap.json'));
const profile = process.env.AWS_PROFILE || 'ec528-deployer';
const region = process.env.AWS_REGION || 'us-east-2';
const stack = process.env.AWS_STACK_NAME || 'ec528-zero-trust-demo';
const endpoint = process.env.KEYLIME_MCP_URL || 'http://127.0.0.1:3000/mcp';
const tokenPath = path.resolve(process.env.KEYLIME_MCP_TOKEN_FILE
  || path.join(repository, 'build', 'aws-keylime', 'mcp-token'));

function awsEnvironment() {
  const environment = { ...process.env };
  if (process.platform !== 'darwin') return environment;
  try {
    const prefix = execFileSync('brew', ['--prefix', 'expat'], {
      encoding: 'utf8',
      timeout: 10_000,
    }).trim();
    if (prefix) environment.DYLD_LIBRARY_PATH = path.join(prefix, 'lib');
  } catch {
    // Let the AWS CLI produce the actionable error if Homebrew/expat is absent.
  }
  return environment;
}

const awsProcessEnvironment = awsEnvironment();

function aws(arguments_) {
  return execFileSync('aws', [...arguments_, '--profile', profile, '--region', region], {
    cwd: repository,
    encoding: 'utf8',
    env: awsProcessEnvironment,
    timeout: 300_000,
  }).trim();
}

function instanceId() {
  return aws(['cloudformation', 'describe-stacks', '--stack-name', stack,
    '--query', "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue | [0]", '--output', 'text']);
}

async function remotePolicyDigests(id) {
  const parameters = JSON.stringify({
    commands: [
      "printf 'runtime_policy_sha256=sha256:%s\\n' \"$(sha256sum /var/lib/ec528/runtime-policy.json | cut -d' ' -f1)\"",
      "printf 'payload_sha256=sha256:%s\\n' \"$(sha256sum /var/lib/ec528/bootstrap-payload/bootstrap.json | cut -d' ' -f1)\"",
      "test \"$(cat /var/lib/ec528-bootstrap-result)\" = keylime-bootstrap-pending",
    ],
  });
  const commandId = aws(['ssm', 'send-command', '--instance-ids', id,
    '--document-name', 'AWS-RunShellScript', '--parameters', parameters,
    '--query', 'Command.CommandId', '--output', 'text']);
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const invocation = JSON.parse(aws(['ssm', 'get-command-invocation',
        '--command-id', commandId, '--instance-id', id, '--output', 'json']));
      if (invocation.Status === 'Success') {
        return Object.fromEntries(invocation.StandardOutputContent.trim().split('\n')
          .map((line) => line.split('=', 2)));
      }
      if (['Failed', 'TimedOut', 'Cancelled'].includes(invocation.Status)) {
        throw new Error(`policy digest command failed: ${invocation.Status}`);
      }
    } catch (error) {
      if (!String(error.message).includes('InvocationDoesNotExist')) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error('policy digest command timed out');
}

async function waitForTunnel(tunnel) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (tunnel.exitCode !== null) throw new Error('SSM tunnel exited');
    try {
      const response = await fetch(new URL('/healthz', endpoint), { signal: AbortSignal.timeout(500) });
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('MCP tunnel did not become healthy');
}

async function main() {
  const tokenStat = await stat(tokenPath);
  if (!tokenStat.isFile() || (tokenStat.mode & 0o077) !== 0) throw new Error('MCP token file must be mode 0600');
  const token = (await readFile(tokenPath, 'utf8')).trim();
  const id = instanceId();
  const digests = await remotePolicyDigests(id);
  const tunnel = spawn(path.join(repository, 'infra', 'aws', 'open-tunnel.sh'), [stack], {
    cwd: repository,
    detached: true,
    stdio: 'ignore',
  });
  const runs = path.join(repository, 'build', 'runs');
  await mkdir(runs, { recursive: true, mode: 0o700 });
  const root = await mkdtemp(path.join(runs, 'bootstrap-'));
  try {
    await waitForTunnel(tunnel);
    const manifest = JSON.parse(await readFile(
      path.join(repository, 'public', '.well-known', 'agent-actions.json'), 'utf8',
    ));
    const action = {
      action_type: 'tenant.bootstrap',
      target: 'aws-keylime-demo-01',
      agent_uuid: 'd432fbb3-d2f1-4a97-9ef7-75bd81c00000',
      runtime_policy_sha256: digests.runtime_policy_sha256,
      payload_sha256: digests.payload_sha256,
      occurrence_id: crypto.randomUUID(),
      policy_version: 'demo-2.1',
    };
    const controller = await createDemoController({
      action,
      artifactPath: path.join(root, 'unused-artifact'),
      inputPath: path.join(root, 'unused-input'),
      manifest,
      stateDirectory: root,
      toolName: 'bootstrap_keylime_tenant',
      keylimeHandler: createKeylimeBootstrapHandler({
        permitSigner: await bootstrapPermitSignerFromEnvironment(repository, action.agent_uuid),
        endpoint,
        token,
        allowInsecureLoopback: true,
        timeoutMilliseconds: 240_000,
      }),
    });
    const missing = await controller.execute('missing');
    controller.approve('operator');
    const oneSigner = controller.snapshot();
    controller.approve('security');
    const enrolled = await controller.execute('approved');
    const evidence = {
      schema_version: 1,
      experiment: 'demo2-bootstrap',
      status: missing.last_response.status === 428
        && oneSigner.receipt_ready === false
        && enrolled.last_response.status === 200 ? 'pass' : 'fail',
      generated_at: new Date().toISOString(),
      repository_revision: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repository, encoding: 'utf8' }).trim(),
      repository_dirty: execFileSync('git', ['status', '--porcelain'], { cwd: repository, encoding: 'utf8' }).trim().length > 0,
      action,
      scenarios: [
        { name: 'missing_receipt', passed: missing.last_response.status === 428 },
        { name: 'one_signer_pending', passed: oneSigner.receipt_ready === false },
        { name: 'quorum_controlled_enrollment', passed: enrolled.last_response.status === 200 },
      ],
      result: enrolled.last_response.body,
      limitations: [
        'swtpm is not a hardware root of trust.',
        'The Keylime verifier, registrar, agent, swtpm and MCP run on the same instance in this demo. This proves the protocol flow, not independent attestation.',
        'The three demo signer keys are generated on one controller machine.',
        'This swtpm deployment has IMA runtime measurements but no measured-boot policy; measured boot requires a hardware TPM and a kernel UEFI event log.',
      ],
    };
    await mkdir(path.dirname(outputPath), { recursive: true });
    const temporary = `${outputPath}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
    await chmod(temporary, 0o600);
    await rename(temporary, outputPath);
    if (evidence.status === 'pass') {
      // The controller's record of this enrollment.  Workload permits carry this
      // epoch, so they stop working if the node is rebuilt and bootstrapped again.
      const enrollmentPath = enrollmentRecordPath(repository);
      await mkdir(path.dirname(enrollmentPath), { recursive: true, mode: 0o700 });
      const enrollmentTemporary = `${enrollmentPath}.${process.pid}.tmp`;
      await writeFile(enrollmentTemporary, `${JSON.stringify({
        schema_version: 1,
        agent_uuid: action.agent_uuid,
        enrollment_epoch: action.occurrence_id,
      }, null, 2)}\n`, { mode: 0o600 });
      await rename(enrollmentTemporary, enrollmentPath);
    }
    process.stdout.write(`${outputPath}\n`);
    if (evidence.status !== 'pass') process.exitCode = 1;
  } finally {
    if (tunnel.exitCode === null) {
      try {
        process.kill(-tunnel.pid, 'SIGTERM');
      } catch {}
    }
    await rm(root, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`demo2 bootstrap failed: ${error.message}\n`);
  process.exitCode = 1;
});
