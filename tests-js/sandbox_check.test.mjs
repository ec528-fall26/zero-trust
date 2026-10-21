import assert from 'node:assert/strict';
import test from 'node:test';

import { assertSandboxCannotRead } from '../experiments/sandbox_check.mjs';

const base = { nono: 'nono', profilePath: '/p.json', workdir: '/w' };

function runnerFor(verdicts) {
  const calls = [];
  return {
    calls,
    runner: async (command, args) => {
      calls.push([command, ...args]);
      const target = args[args.indexOf('--path') + 1];
      const verdict = verdicts[target];
      if (verdict instanceof Error) throw verdict;
      return typeof verdict === 'string' ? verdict : JSON.stringify(verdict);
    },
  };
}

test('passes only when nono denies every controller path', async () => {
  const { runner, calls } = runnerFor({
    '/repo/build/run/state': { status: 'denied', reason: 'path_not_granted' },
    '/repo/build/run/storage': { status: 'denied', reason: 'path_not_granted' },
  });
  const checked = await assertSandboxCannotRead({
    ...base, paths: ['/repo/build/run/state', '/repo/build/run/storage'], runner,
  });
  assert.equal(checked, 2);
  assert.deepEqual(calls[0].slice(0, 3), ['nono', 'why', '--json']);
  assert.ok(calls[0].includes('--op') && calls[0].includes('read'));
});

test('refuses state inside a system location nono grants by default', async () => {
  const { runner } = runnerFor({
    '/var/folders/x/T/state': {
      status: 'allowed', granted_path: '/private/var', source: 'group:system_read_macos',
    },
  });
  await assert.rejects(
    assertSandboxCannotRead({ ...base, paths: ['/var/folders/x/T/state'], runner }),
    /could read controller state .*granted by \/private\/var via group:system_read_macos/,
  );
});

test('fails closed on unexpected output or a failing nono', async () => {
  const garbage = runnerFor({ '/s': 'not json' });
  await assert.rejects(
    assertSandboxCannotRead({ ...base, paths: ['/s'], runner: garbage.runner }),
    /could not confirm/,
  );
  const unknown = runnerFor({ '/s': { status: 'maybe' } });
  await assert.rejects(
    assertSandboxCannotRead({ ...base, paths: ['/s'], runner: unknown.runner }),
    /could read controller state/,
  );
  const crashed = runnerFor({ '/s': new Error('nono crashed') });
  await assert.rejects(
    assertSandboxCannotRead({ ...base, paths: ['/s'], runner: crashed.runner }),
    /could not confirm/,
  );
  await assert.rejects(assertSandboxCannotRead({ ...base, paths: [] }), TypeError);
});
