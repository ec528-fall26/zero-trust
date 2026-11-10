// The node's MCP tools and HTTP front end.  Separated from server.mjs, which
// only reads configuration, so tests can exercise the real request path.
import crypto from 'node:crypto';
import { createServer as createHttpServer } from 'node:http';

import { McpServer, createMcpHandler } from '@modelcontextprotocol/server';
import {
  localhostHostValidation,
  localhostOriginValidation,
  toNodeHandler,
} from '@modelcontextprotocol/node';
import * as z from 'zod/v4';

import { PermitRefused } from './permit.mjs';

// Only the envelope is described here.  permit.mjs validates the contents, so
// there is a single definition of what a well-formed permit is.
const permitSchema = z.object({
  payload: z.record(z.string(), z.unknown()),
  signature: z.string().max(256),
}).strict();

const actionSchema = z.object({
  action_type: z.literal('workload.execute'),
  operation: z.literal('checksum.sha256'),
  target: z.string().min(1).max(256),
  artifact_sha256: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  input_sha256: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  occurrence_id: z.string().uuid(),
  policy_version: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/),
  permit: permitSchema,
}).strict();

const bootstrapSchema = z.object({
  action_type: z.literal('tenant.bootstrap'),
  target: z.string().min(1).max(256),
  agent_uuid: z.string().uuid(),
  runtime_policy_sha256: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  payload_sha256: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  occurrence_id: z.string().uuid(),
  policy_version: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/),
  permit: permitSchema,
}).strict();

export function bearerTokenDigest(token) {
  return crypto.createHash('sha256').update(token).digest();
}

function authorized(request, expectedDigest) {
  const header = request.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  return crypto.timingSafeEqual(bearerTokenDigest(header.slice(7)), expectedDigest);
}

function logRefusal(tool, error) {
  const detail = error instanceof PermitRefused ? ` (${error.reason})` : '';
  process.stderr.write(`keylime-mcp: ${tool} refused${detail}\n`);
}

function createMcpServer(handler, bootstrapHandler) {
  const server = new McpServer({ name: 'ec528-keylime', version: '0.1.0' });
  server.registerTool(
    'attest_and_deploy',
    {
      description: 'Require a signed permit and fresh Keylime attestation, then run the pinned workload once.',
      inputSchema: actionSchema,
    },
    async ({ permit, ...action }) => {
      try {
        const result = await handler(action, permit);
        return {
          content: [{ type: 'text', text: JSON.stringify(result) }],
          structuredContent: result,
        };
      } catch (error) {
        logRefusal('attest_and_deploy', error);
        return {
          content: [{ type: 'text', text: 'Keylime refused the workload.' }],
          isError: true,
        };
      }
    },
  );
  server.registerTool(
    'bootstrap_keylime_tenant',
    {
      description: 'Enroll the pinned Keylime agent only with a permit for an exact-action quorum approval.',
      inputSchema: bootstrapSchema,
    },
    async ({ permit, ...action }) => {
      try {
        const result = await bootstrapHandler(action, permit);
        return {
          content: [{ type: 'text', text: JSON.stringify(result) }],
          structuredContent: result,
        };
      } catch (error) {
        logRefusal('bootstrap_keylime_tenant', error);
        return {
          content: [{ type: 'text', text: 'Keylime tenant bootstrap refused.' }],
          isError: true,
        };
      }
    },
  );
  return server;
}

// Returns an http.Server that has not started listening.
export function createKeylimeHttpServer({ handler, bootstrapHandler, tokenDigest }) {
  const webHandler = createMcpHandler(() => createMcpServer(handler, bootstrapHandler));
  const nodeHandler = toNodeHandler(webHandler, {
    maxRequestBodySize: 128 * 1024,
    onerror: () => {
      process.stderr.write('keylime-mcp: request adapter failed\n');
    },
  });
  const validateHost = localhostHostValidation();
  const validateOrigin = localhostOriginValidation();
  return createHttpServer((request, response) => {
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
}
