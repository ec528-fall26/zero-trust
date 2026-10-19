import crypto from 'node:crypto';
import { createServer as createHttpServer } from 'node:http';
import { readFile } from 'node:fs/promises';

import { McpServer, createMcpHandler } from '@modelcontextprotocol/server';
import {
  localhostHostValidation,
  localhostOriginValidation,
  toNodeHandler,
} from '@modelcontextprotocol/node';
import * as z from 'zod/v4';

import { createAttestAndDeploy } from './attest_and_deploy.mjs';

const actionSchema = z.object({
  action_type: z.literal('workload.execute'),
  operation: z.literal('checksum.sha256'),
  target: z.string().min(1).max(256),
  artifact_sha256: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  input_sha256: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  occurrence_id: z.string().uuid(),
  policy_version: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/),
}).strict();

async function configuredToken() {
  const tokenFile = process.env.KEYLIME_MCP_TOKEN_FILE;
  if (!tokenFile) throw new Error('KEYLIME_MCP_TOKEN_FILE is required');
  const encoded = await readFile(tokenFile);
  try {
    const token = encoded.toString('utf8').trim();
    if (token.length < 32 || token.length > 4096) throw new Error('invalid bearer token');
    return crypto.createHash('sha256').update(token).digest();
  } finally {
    encoded.fill(0);
  }
}

function authorized(request, expectedDigest) {
  const header = request.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const actual = crypto.createHash('sha256').update(header.slice(7)).digest();
  return crypto.timingSafeEqual(actual, expectedDigest);
}

function createMcpServer(handler) {
  const server = new McpServer({ name: 'ec528-keylime', version: '0.1.0' });
  server.registerTool(
    'attest_and_deploy',
    {
      description: 'Require fresh Keylime attestation, then run the pinned workload once.',
      inputSchema: actionSchema,
    },
    async (action) => {
      try {
        const result = await handler(action);
        return {
          content: [{ type: 'text', text: JSON.stringify(result) }],
          structuredContent: result,
        };
      } catch {
        process.stderr.write('keylime-mcp: attest_and_deploy refused\n');
        return {
          content: [{ type: 'text', text: 'Keylime refused the workload.' }],
          isError: true,
        };
      }
    },
  );
  return server;
}

async function main() {
  const tokenDigest = await configuredToken();
  const port = Number.parseInt(process.env.KEYLIME_MCP_PORT || '3000', 10);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('invalid port');
  const handler = createAttestAndDeploy({
    statusCommand: process.env.KEYLIME_STATUS_COMMAND,
    statusSocket: process.env.KEYLIME_STATUS_SOCKET,
    artifactPath: process.env.KEYLIME_WORKLOAD_ARTIFACT,
    inputPath: process.env.KEYLIME_WORKLOAD_INPUT,
    target: process.env.KEYLIME_TARGET,
    agentId: process.env.KEYLIME_AGENT_ID,
    policyVersion: process.env.KEYLIME_POLICY_VERSION,
    maximumAttestationAgeSeconds: Number.parseInt(
      process.env.KEYLIME_MAX_ATTESTATION_AGE_SECONDS || '30',
      10,
    ),
  });
  const webHandler = createMcpHandler(() => createMcpServer(handler));
  const nodeHandler = toNodeHandler(webHandler, {
    maxRequestBodySize: 128 * 1024,
    onerror: () => {
      process.stderr.write('keylime-mcp: request adapter failed\n');
    },
  });
  const validateHost = localhostHostValidation();
  const validateOrigin = localhostOriginValidation();
  const server = createHttpServer((request, response) => {
    if (request.url === '/healthz' && request.method === 'GET') {
      response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      response.end('{"status":"ok"}');
      return;
    }
    if (request.url !== '/mcp' || !validateHost(request, response)
        || !validateOrigin(request, response)) {
      if (!response.headersSent) {
        response.writeHead(404, { 'Content-Type': 'application/json' });
        response.end('{"error":"not_found"}');
      }
      return;
    }
    if (!authorized(request, tokenDigest)) {
      response.writeHead(401, {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer realm="ec528-keylime"',
      });
      response.end('{"error":"unauthorized"}');
      return;
    }
    void nodeHandler(request, response);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  process.stderr.write(`Keylime MCP listening on 127.0.0.1:${port}\n`);
}

main().catch((error) => {
  process.stderr.write(`keylime-mcp: ${error.message}\n`);
  process.exitCode = 1;
});
