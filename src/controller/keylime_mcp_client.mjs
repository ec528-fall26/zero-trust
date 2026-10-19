import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const TOOL_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/;

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function checkedEndpoint(value, allowInsecureLoopback) {
  const endpoint = new URL(value);
  if (endpoint.username || endpoint.password || endpoint.hash) {
    throw new TypeError('Keylime MCP URL must not contain credentials or a fragment');
  }
  const loopback = ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(endpoint.hostname);
  if (endpoint.protocol !== 'https:' && !(allowInsecureLoopback && loopback)) {
    throw new TypeError('Keylime MCP requires HTTPS or an explicitly allowed loopback URL');
  }
  return endpoint;
}

function resultObject(result) {
  if (isPlainObject(result.structuredContent)) return result.structuredContent;
  const textBlocks = Array.isArray(result.content)
    ? result.content.filter((block) => block?.type === 'text' && typeof block.text === 'string')
    : [];
  if (textBlocks.length !== 1 || Buffer.byteLength(textBlocks[0].text, 'utf8') > 64 * 1024) {
    throw new Error('Keylime MCP returned no bounded structured result');
  }
  const parsed = JSON.parse(textBlocks[0].text);
  if (!isPlainObject(parsed)) throw new Error('Keylime MCP result is not an object');
  return parsed;
}

export function validateKeylimeResult(value, action, options = {}) {
  const { maximumAgeSeconds = 30, now = Date.now() } = options;
  if (!isPlainObject(value) || !isPlainObject(value.attestation)
      || !isPlainObject(value.workload)) {
    throw new Error('Keylime MCP result does not match the pinned contract');
  }
  const { attestation, workload } = value;
  if (attestation.verdict !== 'trusted'
      || attestation.target !== action.target
      || attestation.policy_version !== action.policy_version
      || attestation.occurrence_id !== action.occurrence_id
      || typeof attestation.provider !== 'string'
      || typeof attestation.evidence_digest !== 'string'
      || !DIGEST_PATTERN.test(attestation.evidence_digest)) {
    throw new Error('Keylime attestation is untrusted or bound to another action');
  }
  const attestedAt = Date.parse(attestation.attested_at);
  if (!Number.isFinite(attestedAt)
      || attestedAt > now + 5_000
      || now - attestedAt > maximumAgeSeconds * 1_000) {
    throw new Error('Keylime attestation is stale or has an invalid timestamp');
  }
  if (workload.executed !== true
      || workload.operation !== action.operation
      || workload.artifact_sha256 !== action.artifact_sha256
      || workload.input_sha256 !== action.input_sha256) {
    throw new Error('Keylime workload result is not bound to the approved material');
  }
  return value;
}

export function createKeylimeMcpHandler(options) {
  const {
    endpoint,
    token,
    toolName = 'attest_and_deploy',
    timeoutMilliseconds = 30_000,
    maximumAttestationAgeSeconds = 30,
    allowInsecureLoopback = false,
    clientFactory,
  } = options || {};
  const url = checkedEndpoint(endpoint, allowInsecureLoopback);
  if (typeof token !== 'string' || token.length < 32 || token.length > 4096) {
    throw new TypeError('a sufficiently strong Keylime MCP bearer token is required');
  }
  if (!TOOL_PATTERN.test(toolName)) throw new TypeError('invalid Keylime MCP tool name');
  if (!Number.isSafeInteger(timeoutMilliseconds) || timeoutMilliseconds < 1_000
      || timeoutMilliseconds > 300_000) {
    throw new TypeError('invalid Keylime MCP timeout');
  }

  return async function keylimeMcpHandler(action) {
    let client;
    try {
      if (typeof clientFactory === 'function') {
        client = await clientFactory();
      } else {
        const transport = new StreamableHTTPClientTransport(url, {
          authProvider: { token: async () => token },
          requestInit: { redirect: 'error' },
          redirectPolicy: 'same-origin',
          onInsufficientScope: 'throw',
        });
        client = new Client(
          { name: 'ec528-nono-controller', version: '0.1.0' },
          { versionNegotiation: { mode: 'auto', probe: { timeoutMs: 2_000, maxRetries: 0 } } },
        );
        await client.connect(transport, { timeout: timeoutMilliseconds });
      }
      const result = await client.callTool(
        { name: toolName, arguments: action },
        { timeout: timeoutMilliseconds, maxTotalTimeout: timeoutMilliseconds },
      );
      if (result.isError === true) throw new Error('Keylime MCP tool refused the action');
      return validateKeylimeResult(resultObject(result), action, {
        maximumAgeSeconds: maximumAttestationAgeSeconds,
      });
    } catch (error) {
      throw new Error('Keylime MCP call failed closed', { cause: error });
    } finally {
      if (client && typeof client.close === 'function') {
        try {
          await client.close();
        } catch {
          // The call already fails closed; a close error must not replace that decision.
        }
      }
    }
  };
}
