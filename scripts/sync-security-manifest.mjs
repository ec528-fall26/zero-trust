import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const policyPath = path.join(repository, 'config', 'security-parameters.json');
const manifestPath = path.join(repository, 'public', '.well-known', 'agent-actions.json');
const check = process.argv.includes('--check');

const policy = JSON.parse(await readFile(policyPath, 'utf8'));
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
let changed = false;
for (const action of manifest.actions) {
  if (action.receipt_required === true && action.max_age_sec !== policy.receipt_max_age_sec) {
    action.max_age_sec = policy.receipt_max_age_sec;
    changed = true;
  }
}
if (check && changed) {
  throw new Error('agent action manifest is not synchronized with security-parameters.json');
}
if (!check && changed) {
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}
