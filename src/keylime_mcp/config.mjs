// Strict parsing for security-sensitive environment settings.  A malformed
// value must stop startup instead of silently selecting a weaker default.

export function booleanSetting(value, name, defaultValue = false) {
  if (value === undefined) return defaultValue;
  if (value === '1') return true;
  if (value === '0') return false;
  throw new TypeError(`${name} must be 0 or 1`);
}

export function integerSetting(value, name, defaultValue, minimum, maximum) {
  const candidate = value === undefined ? String(defaultValue) : value;
  if (typeof candidate !== 'string' || !/^[0-9]+$/.test(candidate)) {
    throw new TypeError(`${name} must be an integer`);
  }
  const parsed = Number(candidate);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new TypeError(`${name} must be between ${minimum} and ${maximum}`);
  }
  return parsed;
}
