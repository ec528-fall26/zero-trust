#!/usr/bin/env node
// Approver tool: each person runs this on their own machine.
//
//   node tools/approver.mjs keygen --role security --name "Kim Wong"
//       Creates a P-256 key in ~/.ec528-approver (private key never leaves it)
//       and writes the public record to add to config/approvers/.
//   node tools/approver.mjs review request.json
//       Shows exactly what would be approved, after recomputing its hashes.
//   node tools/approver.mjs sign request.json [--out signoff.json] [--yes]
//       Signs the request after you confirm the action hash.
import crypto from 'node:crypto';
import { chmod, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline/promises';

import {
  APPROVER_RECORD_SCHEMA,
  createSignoff,
  publicKeyFingerprint,
  reviewApprovalRequest,
  validateApproverRecord,
} from '../src/controller/approver_signoff.mjs';

const KEY_FILE = 'approver-key.pem';
const RECORD_FILE = 'approver.json';

function option(args, name, fallback = null) {
  const index = args.indexOf(name);
  return index >= 0 && index + 1 < args.length ? args[index + 1] : fallback;
}

function keyDirectory(args) {
  return path.resolve(option(args, '--dir', path.join(os.homedir(), '.ec528-approver')));
}

async function keygen(args) {
  const role = option(args, '--role');
  const name = option(args, '--name');
  if (!role || !name) throw new Error('usage: keygen --role <role> --name "<your name>" [--dir <dir>]');
  const directory = keyDirectory(args);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const keyPath = path.join(directory, KEY_FILE);
  try {
    await stat(keyPath);
    throw new Error(`${keyPath} already exists; refusing to replace an enrolled key`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  await writeFile(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
  const publicKeyText = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const record = validateApproverRecord({
    schema: APPROVER_RECORD_SCHEMA,
    role,
    name,
    approver_id: `ep:approver:${role}`,
    key_id: `${role}-${publicKeyFingerprint(publicKeyText).slice('sha256:'.length, 'sha256:'.length + 8)}`,
    public_key: publicKeyText,
  });
  const recordText = `${JSON.stringify(record, null, 2)}\n`;
  await writeFile(path.join(directory, RECORD_FILE), recordText, { mode: 0o644 });
  process.stdout.write(recordText);
  process.stderr.write(
    `\nPrivate key: ${keyPath} (mode 0600). Never share or commit it.\n`
    + `Public record: ${path.join(directory, RECORD_FILE)}\n`
    + `Enroll by committing that public record as config/approvers/${role}.json.\n`,
  );
}

async function readRequest(file) {
  if (!file) throw new Error('give the approval request file');
  return JSON.parse(await readFile(file, 'utf8'));
}

function describe(review) {
  const action = review.action;
  const lines = [
    `Receipt id:     ${review.receipt_id}`,
    `Expires:        ${review.expires_at}`,
    `Action type:    ${action.action_type}`,
    `Operation:      ${action.operation}`,
    `Target node:    ${action.target}`,
    `Artifact:       ${action.artifact_sha256}`,
    `Input:          ${action.input_sha256}`,
    `Policy version: ${action.policy_version}`,
    `Occurrence:     ${action.occurrence_id}`,
    `Quorum:         ${review.threshold} of ${review.eligible.join(', ')}`,
    `Action hash:    ${review.action_hash}`,
  ];
  return `${lines.join('\n')}\n`;
}

async function reviewCommand(args) {
  process.stdout.write(describe(reviewApprovalRequest(await readRequest(args[0]))));
}

async function sign(args) {
  const request = await readRequest(args[0]);
  const review = reviewApprovalRequest(request);
  const directory = keyDirectory(args);
  const record = validateApproverRecord(JSON.parse(await readFile(path.join(directory, RECORD_FILE), 'utf8')));
  if (!review.eligible.includes(record.approver_id)) {
    throw new Error(`${record.approver_id} is not an eligible approver for this request`);
  }
  if (review.expires_at && Date.parse(review.expires_at) <= Date.now()) {
    throw new Error('this approval request has expired');
  }
  process.stdout.write(`You are approving as ${record.name} (${record.approver_id}).\n\n${describe(review)}\n`);
  if (!args.includes('--yes')) {
    const prompt = createInterface({ input: process.stdin, output: process.stdout });
    const typed = (await prompt.question('To approve, type the first 8 hex characters of the action hash: ')).trim();
    prompt.close();
    if (typed !== review.action_hash.replace(/^sha256:/, '').slice(0, 8)) {
      throw new Error('not approved: the characters did not match');
    }
  }
  const privateKey = crypto.createPrivateKey(await readFile(path.join(directory, KEY_FILE), 'utf8'));
  const signoff = createSignoff(request, { privateKey, keyId: record.key_id });
  const output = path.resolve(option(args, '--out', `signoff-${record.role}.json`));
  await writeFile(output, `${JSON.stringify(signoff, null, 2)}\n`, { mode: 0o644 });
  await chmod(output, 0o644);
  process.stdout.write(`\nSigned. Send ${output} back to the operator.\n`);
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  const commands = { keygen, review: reviewCommand, sign };
  if (!commands[command]) {
    throw new Error('usage: approver.mjs keygen|review|sign ... (see the header of this file)');
  }
  await commands[command](args);
}

main().catch((error) => {
  process.stderr.write(`approver: ${error.message}\n`);
  process.exitCode = 1;
});
