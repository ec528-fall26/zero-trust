import assert from 'node:assert/strict';
import test from 'node:test';

import { booleanSetting, integerSetting } from '../src/keylime_mcp/config.mjs';

test('security flags accept only explicit zero or one', () => {
  assert.equal(booleanSetting(undefined, 'FLAG', true), true);
  assert.equal(booleanSetting('0', 'FLAG'), false);
  assert.equal(booleanSetting('1', 'FLAG'), true);
  for (const value of ['', 'true', 'yes', '2']) {
    assert.throws(() => booleanSetting(value, 'FLAG'), /must be 0 or 1/);
  }
});

test('integer settings reject partial, negative and out-of-range values', () => {
  assert.equal(integerSetting(undefined, 'AGE', 30, 1, 60), 30);
  assert.equal(integerSetting('15', 'AGE', 30, 1, 60), 15);
  for (const value of ['', '-1', '15seconds', '1.5', '61']) {
    assert.throws(() => integerSetting(value, 'AGE', 30, 1, 60));
  }
});
