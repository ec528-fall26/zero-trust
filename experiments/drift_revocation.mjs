// Experiment: revocation at verify time.
//
// Claim: a receipt that verifies offline is still refused if one of its
// approvers' keys has been revoked since, and the check fails closed when the
// revocation list is missing, stale, forged or rolled back.
//
// Real components: the 2-of-3 demo controller with real receipts and the
// receipt-required dispatcher.  Stand-in: the revocation list is served from
// memory by the experiment, signed by a local demo revocation authority.
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
import { createRevocationChecker, signRevocationList } from '../src/controller/revocation.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputPath = path.resolve(
  process.argv[2] || path.join(repositoryRoot, 'results', 'drift-revocation.json'),
);
const LIMITATIONS = Object.freeze([
  'The revocation list is served from memory and signed by a local demo authority. There is no real distribution channel, and nobody operates the authority.',
  'Receipts are refused if any signer is on the list, whether the key was revoked before or after signing. Time of signing is not consulted.',
  'The highest list sequence seen is kept in memory only, so a controller restart forgets it and an old list could be replayed after one.',
  'Approver keys are ephemeral local demo keys on one machine.',
]);

function digest(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
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

function newAuthority() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey,
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

async function main() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ec528-drift-revocation-'));
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
    const manifest = JSON.parse(await readFile(
      path.join(repositoryRoot, 'public', '.well-known', 'agent-actions.json'),
      'utf8',
    ));
    const packageMetadata = JSON.parse(await readFile(
      path.join(repositoryRoot, 'package.json'),
      'utf8',
    ));
    const authority = newAuthority();
    const list = ({ sequence = 1, issuedAt = new Date(), revoked = [], signer = authority }) =>
      signRevocationList({
        privateKey: signer.privateKey,
        sequence,
        issuedAt: issuedAt.toISOString(),
        revoked: revoked.map((id) => ({
          approver_key_id: id,
          revoked_at: new Date().toISOString(),
        })),
      });

    // A controller with two real approvals (operator and security), checking
    // `source.current` as its revocation list.
    async function approvedController(source) {
      const stateDirectory = path.join(root, `controller-${crypto.randomUUID()}`);
      await mkdir(stateDirectory, { mode: 0o700 });
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
        manifest,
        stateDirectory,
        revocation: createRevocationChecker({
          authorityPublicKey: authority.publicKey,
          maximumAgeSeconds: 300,
          load: async () => {
            if (source.error) throw source.error;
            return source.current;
          },
        }),
      });
      controller.approve('operator');
      controller.approve('security');
      return controller;
    }

    async function outcome(controller) {
      return (await controller.execute('approved')).last_response;
    }

    function record(name, response, expectedStatus, expectedReason, extra = {}) {
      assert.equal(response.status, expectedStatus);
      if (expectedReason) assert.equal(response.body.rejected.reason, expectedReason);
      scenarios.push({
        name,
        passed: true,
        observed: expectedReason || 'executed_once',
        http_status: response.status,
        ...extra,
      });
    }

    {
      const source = { current: list({ sequence: 1, revoked: [] }) };
      record('no_revocations_executes', await outcome(await approvedController(source)), 200, null);
    }

    {
      const source = { current: list({ sequence: 1, revoked: ['demo-reviewer-key'] }) };
      record(
        'unrelated_key_revoked_executes',
        await outcome(await approvedController(source)),
        200,
        null,
      );
    }

    {
      // The receipt was issued while the key was good, then the key is revoked.
      const source = { current: list({ sequence: 1, revoked: [] }) };
      const controller = await approvedController(source);
      source.current = list({ sequence: 2, revoked: ['demo-security-key'] });
      const first = await outcome(controller);
      record('approver_revoked_after_signing_refused', first, 428, 'approver_key_revoked');

      // Refused before reservation: the approval is not burned.
      source.current = list({ sequence: 3, revoked: [] });
      record('revocation_refusal_does_not_burn_receipt', await outcome(controller), 200, null);
    }

    {
      const source = { current: null, error: new Error('list server unreachable') };
      record(
        'revocation_list_unavailable_refused',
        await outcome(await approvedController(source)),
        428,
        'revocation_unavailable',
      );
    }

    {
      const source = { current: list({ issuedAt: new Date(Date.now() - 10 * 60 * 1_000) }) };
      record(
        'stale_revocation_list_refused',
        await outcome(await approvedController(source)),
        428,
        'revocation_list_stale',
      );
    }

    {
      const source = { current: list({ signer: newAuthority(), revoked: [] }) };
      record(
        'forged_revocation_list_refused',
        await outcome(await approvedController(source)),
        428,
        'revocation_list_invalid',
      );
    }

    {
      // The checker has seen list 9 naming the key.  Replaying the older list 4,
      // which predates the revocation, must not re-enable the receipt.
      const source = { current: list({ sequence: 9, revoked: ['demo-security-key'] }) };
      const controller = await approvedController(source);
      record(
        'revocation_seen_before_rollback',
        await outcome(controller),
        428,
        'approver_key_revoked',
        { sequence: 9 },
      );
      source.current = list({ sequence: 4, revoked: [] });
      record(
        'rolled_back_revocation_list_refused',
        await outcome(controller),
        428,
        'revocation_list_rollback',
        { sequence_seen: 9, sequence_replayed: 4 },
      );
    }

    const gitStatus = await requiredCommandOutput(
      'git', ['status', '--porcelain', '--untracked-files=all'],
    );
    await writeResult({
      schema_version: 1,
      experiment: 'drift-revocation',
      status: 'pass',
      generated_at: new Date().toISOString(),
      repository_revision: await requiredCommandOutput('git', ['rev-parse', 'HEAD']),
      repository_dirty: gitStatus.length > 0,
      versions: {
        nono: await commandOutput('nono', ['--version']),
        node: process.version,
        emilia_require_receipt: packageMetadata.dependencies['@emilia-protocol/require-receipt'],
      },
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
    experiment: 'drift-revocation',
    status: 'fail',
    generated_at: new Date().toISOString(),
    error: error instanceof Error ? error.message : 'unknown error',
  });
  process.stderr.write(`drift revocation failed: ${error.stack || error.message}\n`);
  process.exitCode = 1;
});
