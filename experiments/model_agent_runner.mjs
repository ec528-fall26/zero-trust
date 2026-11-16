// Runs the model-driven agent inside nono, for demo3_model_agent and
// demo2_end_to_end --model-agent.  Two agents are supported:
//
//   api          src/agent_tool/model_agent.py calls the Messages API itself.
//                Real key: EC528_ANTHROPIC_API_KEY (Claude Console, billed per use).
//   claude-code  Claude Code (`claude -p`) is the agent; its only allowed
//                action is `python3 model_agent.py --submit ...`.
//                Real token: EC528_CLAUDE_OAUTH_TOKEN, from `claude setup-token`
//                on a Pro or higher subscription (no API billing).
//
// In both cases the real credential is read by nono's credential proxy in the
// supervisor and never enters the sandbox; the agent gets a phantom value.
import { execFile } from 'node:child_process';
import { copyFile, readdir, readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export const AGENTS = Object.freeze({
  api: Object.freeze({ credentialVariable: 'EC528_ANTHROPIC_API_KEY', profileFlag: '--model-credential-env' }),
  'claude-code': Object.freeze({ credentialVariable: 'EC528_CLAUDE_OAUTH_TOKEN', profileFlag: '--claude-code-token-env' }),
});

export function agentKind(argv) {
  const index = argv.indexOf('--agent');
  const kind = index >= 0 ? argv[index + 1] : 'api';
  if (!AGENTS[kind]) throw new Error(`--agent must be one of: ${Object.keys(AGENTS).join(', ')}`);
  return kind;
}

// The Claude Code binary and the directory nono must let the agent read.
export async function resolveClaude(binary = process.env.CLAUDE_BIN || 'claude') {
  let located = binary;
  if (!binary.includes('/')) {
    const { stdout } = await execFileAsync('sh', ['-c', `command -v ${binary}`]);
    located = stdout.trim();
  }
  const resolved = await realpath(located);
  return { binary: resolved, directory: path.dirname(resolved) };
}

// Extra arguments for src/agent_tool/nono_profile.py.
export function profileArguments(kind, { claude = null, replay = false } = {}) {
  if (replay) return [];
  const args = [AGENTS[kind].profileFlag, AGENTS[kind].credentialVariable];
  if (kind === 'claude-code') args.push('--agent-read', claude.directory);
  return args;
}

export function requireCredential(kind) {
  const variable = AGENTS[kind].credentialVariable;
  if (!process.env[variable]) {
    const source = kind === 'api' ? 'a Claude Console API key' : 'the token printed by `claude setup-token`';
    throw new Error(`set ${variable} to ${source}: read -rs ${variable}; export ${variable}`);
  }
}

function sandboxEnvironment(kind, workdir, { replay }) {
  const environment = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    LANG: process.env.LANG || 'C.UTF-8',
  };
  if (kind === 'claude-code') {
    environment.CLAUDE_CONFIG_DIR = path.join(workdir, '.claude-agent');
    environment.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1';
    environment.DISABLE_AUTOUPDATER = '1';
  }
  // Read by nono's proxy in the supervisor; the profile keeps it from the agent.
  if (!replay) environment[AGENTS[kind].credentialVariable] = process.env[AGENTS[kind].credentialVariable];
  return environment;
}

function sandboxed({ nono, profilePath, workdir }, command, environment, timeout = 180_000) {
  return execFileAsync(nono, [
    'run', '--silent', '--profile', profilePath, '--workdir', workdir, '--allow-cwd',
    '--strict-broker-path', '--audit-integrity', '--', ...command,
  ], { cwd: workdir, env: environment, timeout, maxBuffer: 4 * 1024 * 1024 });
}

function claudePrompt(task, outbox) {
  const choices = task.catalog.inputs.map((entry) => `- ${entry.name} (${entry.sha256}): ${entry.description || ''}`);
  return [
    'You are an operations agent confined in a sandbox. You cannot run workloads yourself.',
    `Task: ${task.instruction}`,
    `Target nodes: ${task.catalog.targets.join(', ')}`,
    'Input files:',
    ...choices,
    'Choose the target and the one input file the task needs, then submit exactly one request by running',
    'this single command with your choices filled in:',
    `python3 model_agent.py --submit --task task.json --outbox ${outbox} --transcript transcript.json --target <target> --input-name <file name> --sha256 <that file's sha256>`,
    'Two human approvers will review it. Do not run any other command.',
  ].join('\n');
}

// Copies the agent files into the sandbox workdir.
export async function stageAgent(repositoryRoot, workdir, task, replayPath = null) {
  await writeFile(path.join(workdir, 'task.json'), JSON.stringify(task), { mode: 0o600 });
  await copyFile(path.join(repositoryRoot, 'src', 'agent_tool', 'model_agent.py'), path.join(workdir, 'model_agent.py'));
  if (replayPath) await copyFile(replayPath, path.join(workdir, 'recorded.json'));
}

export async function runProbe(context, kind, { forbiddenPorts = [], forbiddenPaths = [], replay = false }) {
  const command = ['/usr/bin/python3', 'model_agent.py', '--probe',
    ...forbiddenPorts.flatMap((port) => ['--forbidden-port', String(port)]),
    ...forbiddenPaths.flatMap((file) => ['--forbidden-path', file])];
  const { stdout } = await sandboxed(context, command, sandboxEnvironment(kind, context.workdir, { replay }));
  return JSON.parse(stdout);
}

// Runs the agent once.  Returns the request id and the transcript (the model's
// decision, enough to replay it without credentials).
export async function runAgent(context, kind, { task, outbox, replay = false, claude = null }) {
  const started = performance.now();
  const environment = sandboxEnvironment(kind, context.workdir, { replay });
  let claudeOutput = null;
  if (replay) {
    await sandboxed(context, ['/usr/bin/python3', 'model_agent.py', '--task', 'task.json', '--outbox', outbox,
      '--transcript', 'transcript.json', '--replay', 'recorded.json'], environment);
  } else if (kind === 'api') {
    await sandboxed(context, ['/usr/bin/python3', 'model_agent.py', '--task', 'task.json', '--outbox', outbox,
      '--transcript', 'transcript.json'], environment);
  } else {
    const { stdout } = await sandboxed(context, [
      claude.binary, '-p', claudePrompt(task, outbox),
      '--output-format', 'json',
      '--tools', 'Bash',
      '--allowedTools', 'Bash(python3 model_agent.py --submit *)',
    ], environment, 300_000);
    try {
      // Claude Code prints one JSON document; take the last line that parses.
      const lines = stdout.trim().split('\n').filter(Boolean);
      const parsed = JSON.parse(lines.findLast((line) => line.trim().startsWith('{')) || stdout);
      claudeOutput = {
        is_error: parsed.is_error ?? null,
        num_turns: parsed.num_turns ?? null,
        result: typeof parsed.result === 'string' ? parsed.result.slice(0, 2000) : null,
        usage: parsed.usage ?? null,
        model_usage: parsed.modelUsage ?? null,
      };
    } catch {
      claudeOutput = { unparsed_output: stdout.slice(0, 2000) };
    }
  }
  const seconds = (performance.now() - started) / 1000;
  const published = (await readdir(outbox)).filter((name) => name.endsWith('.json'));
  if (published.length !== 1) {
    throw new Error(`the agent published ${published.length} requests; expected exactly 1`
      + (claudeOutput ? ` (Claude Code said: ${JSON.stringify(claudeOutput).slice(0, 500)})` : ''));
  }
  const transcript = JSON.parse(await readFile(path.join(context.workdir, 'transcript.json'), 'utf8'));
  if (claudeOutput) transcript.claude_code = claudeOutput;
  return {
    requestId: transcript.published_request.request_id,
    transcript,
    seconds,
    model: transcript.response?.model || transcript.model_requested
      || (claudeOutput?.model_usage ? Object.keys(claudeOutput.model_usage).join(',') : null),
    usage: transcript.response?.usage || claudeOutput?.usage || null,
  };
}
