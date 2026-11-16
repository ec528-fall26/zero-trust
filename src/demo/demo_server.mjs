import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createDemoController } from './demo_controller.mjs';
import { createKeylimeMcpHandler } from '../controller/keylime_mcp_client.mjs';

const MAX_BODY_BYTES = 4096;
// Recorded Jaeger exports the page may show. Fixed names only: no path from
// the request ever reaches the filesystem.
const RECORDED_TRACES = Object.freeze({
  'end-to-end': 'otel-demo2-end-to-end.trace.json',
  'ima-tamper': 'otel-ima-tamper.trace.json',
});
const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(moduleDirectory, '../..');

function argumentValue(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || index + 1 >= process.argv.length) return null;
  return process.argv[index + 1];
}

async function readJsonFile(filePath, maximumBytes = 64 * 1024) {
  const details = await stat(filePath);
  if (!details.isFile() || details.size > maximumBytes) throw new Error('invalid JSON file');
  return JSON.parse(await readFile(filePath, 'utf8'));
}

async function requestJson(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > MAX_BODY_BYTES) throw new Error('request body too large');
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function sendJson(response, status, body) {
  const encoded = Buffer.from(JSON.stringify(body), 'utf8');
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': encoded.length,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  });
  response.end(encoded);
}

// Only pages served by this loopback server may POST. Browsers treat
// localhost and 127.0.0.1 as different origins, so accept both spellings.
function sameOrigin(request, port) {
  const origin = request.headers.origin;
  return origin === undefined
    || origin === `http://127.0.0.1:${port}`
    || origin === `http://localhost:${port}`;
}

export async function startDemoServer(options) {
  const {
    action,
    artifactPath,
    inputPath,
    keylimeHandler = null,
    manifest,
    stateDirectory,
    port,
  } = options;
  const controller = await createDemoController({
    action,
    artifactPath,
    inputPath,
    keylimeHandler,
    manifest,
    stateDirectory,
  });
  const html = await readFile(path.join(repository, 'public', 'demo.html'));
  const viewModule = await readFile(path.join(moduleDirectory, 'demo_view.mjs'));
  const server = createServer(async (request, response) => {
    try {
      if (request.method === 'GET' && request.url === '/') {
        response.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Length': html.length,
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
          'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        });
        response.end(html);
        return;
      }
      if (request.method === 'GET' && request.url === '/demo-view.js') {
        response.writeHead(200, {
          'Content-Type': 'text/javascript; charset=utf-8',
          'Content-Length': viewModule.length,
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        });
        response.end(viewModule);
        return;
      }
      if (request.method === 'GET' && request.url.startsWith('/api/recorded-trace/')) {
        const file = RECORDED_TRACES[request.url.slice('/api/recorded-trace/'.length)];
        if (!file) {
          sendJson(response, 404, { error: 'not_found' });
          return;
        }
        try {
          sendJson(response, 200, await readJsonFile(path.join(repository, 'results', 'traces', file), 2 * 1024 * 1024));
        } catch {
          sendJson(response, 404, { error: 'recording_unavailable' });
        }
        return;
      }
      if (request.method === 'GET' && request.url === '/api/state') {
        sendJson(response, 200, controller.snapshot());
        return;
      }
      if (request.method !== 'POST' || !sameOrigin(request, port)) {
        sendJson(response, 404, { error: 'not_found' });
        return;
      }
      if (request.headers['content-type'] !== 'application/json') {
        sendJson(response, 415, { error: 'application_json_required' });
        return;
      }
      const body = await requestJson(request);
      if (request.url === '/api/approve') {
        sendJson(response, 200, controller.approve(body.role));
        return;
      }
      if (request.url === '/api/execute') {
        sendJson(response, 200, await controller.execute(body.mode));
        return;
      }
      sendJson(response, 404, { error: 'not_found' });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'request_failed';
      sendJson(response, 400, { error: message });
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return server;
}

function keylimeHandlerFromEnvironment() {
  const endpoint = process.env.KEYLIME_MCP_URL;
  if (!endpoint) return null;
  return createKeylimeMcpHandler({
    endpoint,
    token: process.env.KEYLIME_MCP_TOKEN,
    toolName: process.env.KEYLIME_MCP_TOOL || 'attest_and_deploy',
    timeoutMilliseconds: Number.parseInt(process.env.KEYLIME_MCP_TIMEOUT_MS || '30000', 10),
    maximumAttestationAgeSeconds: Number.parseInt(
      process.env.KEYLIME_MAX_ATTESTATION_AGE_SECONDS || '30',
      10,
    ),
    allowInsecureLoopback: process.env.KEYLIME_MCP_ALLOW_INSECURE_LOOPBACK === '1',
  });
}

async function main() {
  const actionPath = argumentValue('--action');
  const artifactPath = argumentValue('--artifact');
  const inputPath = argumentValue('--input');
  const stateDirectory = argumentValue('--state-dir');
  const portText = argumentValue('--port') || '8787';
  const port = Number.parseInt(portText, 10);
  if (!actionPath || !artifactPath || !inputPath || !stateDirectory
      || !Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error('required: --action --artifact --input --state-dir [--port 8787]');
  }
  const [action, manifest] = await Promise.all([
    readJsonFile(actionPath),
    readJsonFile(path.join(repository, 'public', '.well-known', 'agent-actions.json')),
  ]);
  await startDemoServer({
    action,
    artifactPath: path.resolve(artifactPath),
    inputPath: path.resolve(inputPath),
    keylimeHandler: keylimeHandlerFromEnvironment(),
    manifest,
    stateDirectory: path.resolve(stateDirectory),
    port,
  });
  process.stdout.write(`EC528 live demo: http://127.0.0.1:${port}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`demo-server: ${error.message}\n`);
    process.exitCode = 1;
  });
}
