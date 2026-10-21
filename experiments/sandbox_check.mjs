// Ask nono itself whether the sandboxed agent could read controller-only
// paths, and refuse to continue if it could.
//
// nono's built-in macOS groups grant the sandbox read access to system
// locations such as /private/var (which holds the per-user temp folder) and
// read+write to /private/tmp. Controller state placed there would be visible
// to the agent even though our profile never grants it, so experiments must
// keep it elsewhere and prove it with this check.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

async function defaultRunner(command, args) {
  const { stdout } = await execFileAsync(command, args, {
    timeout: 30_000,
    maxBuffer: 256 * 1024,
    windowsHide: true,
  });
  return stdout;
}

// Fails closed: anything other than an explicit "denied" verdict throws.
export async function assertSandboxCannotRead({
  nono,
  profilePath,
  workdir,
  paths,
  runner = defaultRunner,
}) {
  if (!nono || !profilePath || !workdir || !Array.isArray(paths) || paths.length === 0) {
    throw new TypeError('nono, profilePath, workdir and at least one path are required');
  }
  for (const target of paths) {
    let verdict;
    try {
      verdict = JSON.parse(await runner(nono, [
        'why', '--json',
        '--profile', profilePath,
        '--workdir', workdir,
        '--path', target,
        '--op', 'read',
      ]));
    } catch (error) {
      throw new Error(`could not confirm the sandbox cannot read ${target}`, { cause: error });
    }
    if (verdict?.status !== 'denied') {
      const grantedBy = verdict?.granted_path
        ? ` (granted by ${verdict.granted_path} via ${verdict.source || 'unknown'})`
        : '';
      throw new Error(`the sandboxed agent could read controller state at ${target}${grantedBy}`);
    }
  }
  return paths.length;
}
