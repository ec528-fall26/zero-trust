import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const POLICY_URL = new URL('../config/security-parameters.json', import.meta.url);
const BOUNDS = Object.freeze({
  receipt_max_age_sec: [1, 86_400],
  approval_window_sec: [1, 86_400],
  attestation_max_age_sec: [1, 86_400],
  clock_skew_tolerance_sec: [0, 300],
  fresh_attestation_timeout_sec: [1, 120],
  revocation_list_max_age_sec: [1, 86_400],
  permit_max_lifetime_sec: [1, 300],
});

function loadSecurityParameters() {
  let value;
  try {
    value = JSON.parse(readFileSync(fileURLToPath(POLICY_URL), 'utf8'));
  } catch (error) {
    throw new Error('security parameter policy is unavailable', { cause: error });
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\n') !== Object.keys(BOUNDS).sort().join('\n')) {
    throw new Error('security parameter policy fields are invalid');
  }
  for (const [name, [minimum, maximum]] of Object.entries(BOUNDS)) {
    if (!Number.isSafeInteger(value[name]) || value[name] < minimum || value[name] > maximum) {
      throw new Error(`security parameter is invalid: ${name}`);
    }
  }
  if (value.receipt_max_age_sec > value.approval_window_sec) {
    throw new Error('receipt lifetime must not exceed the approval window');
  }
  return Object.freeze({ ...value });
}

export const SECURITY_PARAMETERS = loadSecurityParameters();
