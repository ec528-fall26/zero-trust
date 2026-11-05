import crypto from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const testFile = path.join(repository, 'tests-js', 'spiffe_mtls_proxy.test.mjs');

function git(...arguments_) {
  const completed = spawnSync('git', arguments_, { cwd: repository, encoding: 'utf8' });
  return completed.status === 0 ? completed.stdout.trim() : 'unavailable';
}

const startedAt = new Date().toISOString();
const completed = spawnSync(
  process.execPath,
  ['--test', '--test-reporter=tap', testFile],
  { cwd: repository, encoding: 'utf8' },
);
const finishedAt = new Date().toISOString();
const output = `${completed.stdout || ''}${completed.stderr || ''}`;
const scenarios = [...output.matchAll(/^ok \d+ - (.+)$/gm)].map((match) => ({
  scenario: match[1],
  expected: 'pass',
  observed: 'pass',
  passed: true,
}));
if (completed.status !== 0 || scenarios.length < 2) {
  scenarios.push({
    scenario: 'identity transport harness completed',
    expected: 'pass',
    observed: `exit_${completed.status ?? 'unknown'}`,
    passed: false,
  });
}

const evidence = {
  schema_version: 'ec528-drift-identity-v1',
  started_at: startedAt,
  finished_at: finishedAt,
  commit: git('rev-parse', 'HEAD'),
  repository_dirty: git('status', '--porcelain') !== '',
  implementation: {
    transport: 'TLS 1.3 mutual authentication',
    credential_source: 'SPIFFE Helper file interface',
    trust_domain: 'zt.demo',
  },
  scenarios,
  passed: completed.status === 0 && scenarios.every((scenario) => scenario.passed),
  raw_output_sha256: crypto.createHash('sha256').update(output).digest('hex'),
  limitations: [
    'This local harness uses an ephemeral test CA and does not claim that a SPIRE agent issued the certificates.',
    'A deployed run still requires Linux SPIRE server and agent services and AWS IID node attestation.',
    'SPIFFE authenticates workloads; Keylime and EMILIA remain separate attestation and authorization checks.',
  ],
};

await mkdir(path.join(repository, 'results'), { recursive: true });
const resultPath = path.join(repository, 'results', 'drift-identity.json');
await writeFile(resultPath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
if (!evidence.passed) process.exitCode = 1;
