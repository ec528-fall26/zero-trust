import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import {
  mkdir,
  readFile,
  rename,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { createKeylimeMcpHandler } from '../src/controller/keylime_mcp_client.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const LIMITATIONS = Object.freeze([
  'swtpm is not a hardware root of trust.',
  'The Keylime verifier, registrar, agent, swtpm and MCP all run on the same instance they are checking. This proves the protocol works, not independent attestation.',
  'The three EMILIA signer keys are on one machine. This proves the protocol works, not independent human approval.',
]);

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

async function writeResult(outputPath, result) {
  await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  const temporary = `${outputPath}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  await writeFile(temporary, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, outputPath);
}

function requireValue(value, name) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${name} is required`);
  }
  return value;
}

async function main() {
  const outputPath = path.resolve(
    process.argv[2] || path.join(repositoryRoot, 'results', 'demo2-attestation.json'),
  );
  const actionPath = path.resolve(requireValue(process.env.KEYLIME_ACTION_FILE, 'KEYLIME_ACTION_FILE'));
  const tokenPath = path.resolve(
    requireValue(process.env.KEYLIME_MCP_TOKEN_FILE, 'KEYLIME_MCP_TOKEN_FILE'),
  );
  const endpoint = requireValue(process.env.KEYLIME_MCP_URL, 'KEYLIME_MCP_URL');
  const mode = process.env.KEYLIME_EXPERIMENT_MODE || 'pass';
  if (!['pass', 'expect-deny'].includes(mode)) throw new Error('invalid experiment mode');

  const tokenBytes = await readFile(tokenPath);
  let token;
  try {
    token = tokenBytes.toString('utf8').trim();
  } finally {
    tokenBytes.fill(0);
  }
  const action = JSON.parse(await readFile(actionPath, 'utf8'));
  const scenarios = [];
  const handler = createKeylimeMcpHandler({
    endpoint,
    token,
    allowInsecureLoopback: true,
    timeoutMilliseconds: 20_000,
  });

  if (mode === 'expect-deny') {
    await handler(action).then(
      () => { throw new Error('Keylime unexpectedly allowed the workload'); },
      () => scenarios.push({
        name: 'failed_attestation_blocks_workload',
        passed: true,
        observed: 'denied',
      }),
    );
  } else {
    const accepted = await handler(action);
    scenarios.push({
      name: 'fresh_attestation_allows_exact_workload',
      passed: accepted.workload.executed === true,
      observed: 'executed',
      evidence: accepted.attestation,
      workload: accepted.workload,
    });

    await handler({ ...action, target: `${action.target}-other` }).then(
      () => { throw new Error('Keylime unexpectedly allowed another target'); },
      () => scenarios.push({
        name: 'mcp_target_binding',
        passed: true,
        observed: 'denied',
      }),
    );

    const unavailable = createKeylimeMcpHandler({
      endpoint: 'http://127.0.0.1:9/mcp',
      token,
      allowInsecureLoopback: true,
      timeoutMilliseconds: 2_000,
    });
    await unavailable(action).then(
      () => { throw new Error('unreachable Keylime unexpectedly allowed the workload'); },
      () => scenarios.push({
        name: 'keylime_unavailable_fails_closed',
        passed: true,
        observed: 'denied',
      }),
    );
  }

  const gitStatus = await requiredCommandOutput(
    'git', ['status', '--porcelain', '--untracked-files=all'],
  );
  const result = {
    schema_version: 1,
    experiment: 'demo2-attestation',
    status: scenarios.every((scenario) => scenario.passed) ? 'pass' : 'fail',
    generated_at: new Date().toISOString(),
    repository_revision: await requiredCommandOutput('git', ['rev-parse', 'HEAD']),
    repository_dirty: gitStatus.length > 0,
    versions: {
      keylime: process.env.KEYLIME_VERSION || 'not-reported',
      nono: await commandOutput('nono', ['--version']),
      tpm_type: requireValue(process.env.KEYLIME_TPM_TYPE, 'KEYLIME_TPM_TYPE'),
    },
    action,
    scenarios,
    limitations: [...LIMITATIONS],
  };
  await writeResult(outputPath, result);
  process.stdout.write(`${outputPath}\n`);
  if (result.status !== 'pass') process.exitCode = 1;
}

main().catch(async (error) => {
  const outputPath = path.resolve(
    process.argv[2] || path.join(repositoryRoot, 'results', 'demo2-attestation.json'),
  );
  await writeResult(outputPath, {
    schema_version: 1,
    experiment: 'demo2-attestation',
    status: 'fail',
    generated_at: new Date().toISOString(),
    error: error instanceof Error ? error.message : 'unknown error',
  });
  process.stderr.write(`demo2 attestation failed: ${error.message}\n`);
  process.exitCode = 1;
});
