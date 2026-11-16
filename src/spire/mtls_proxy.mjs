import crypto, { X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';

const MAX_REQUEST_BYTES = 128 * 1024;
const MAX_CREDENTIAL_BYTES = 1024 * 1024;
const SPIFFE_ID_PATTERN = /^spiffe:\/\/[a-z0-9](?:[a-z0-9.-]{0,253}[a-z0-9])?(?:\/[a-zA-Z0-9._~-]+)+$/;
const FORWARDED_RESPONSE_HEADERS = new Set([
  'cache-control',
  'content-type',
  'mcp-session-id',
  'retry-after',
  'www-authenticate',
]);

function setting(value, name) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function portSetting(value, name) {
  if (!/^\d{1,5}$/.test(value || '')) throw new Error(`${name} must be a port`);
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
    throw new Error(`${name} must be between 1024 and 65535`);
  }
  return port;
}

export function validateSpiffeId(value, name = 'SPIFFE ID') {
  if (!SPIFFE_ID_PATTERN.test(value || '')) throw new Error(`${name} is invalid`);
  const parsed = new URL(value);
  if (parsed.username || parsed.password || parsed.port || parsed.search || parsed.hash) {
    throw new Error(`${name} is invalid`);
  }
  return parsed.href.replace(/\/$/, '');
}

function certificateSpiffeIds(rawCertificate) {
  if (!Buffer.isBuffer(rawCertificate) || rawCertificate.length === 0) return [];
  const certificate = new X509Certificate(rawCertificate);
  const subjectAltName = certificate.subjectAltName;
  if (typeof subjectAltName !== 'string') return [];
  return subjectAltName
    .split(', ')
    .filter((entry) => entry.startsWith('URI:'))
    .map((entry) => entry.slice(4));
}

export function certificateHasSpiffeId(rawCertificate, expectedId) {
  const validated = validateSpiffeId(expectedId, 'expected peer SPIFFE ID');
  return certificateSpiffeIds(rawCertificate).some((id) => id === validated);
}

function readBoundedFile(filePath, name, { privateFile = false } = {}) {
  const resolved = path.resolve(setting(filePath, name));
  const stat = fs.statSync(resolved);
  if (!stat.isFile() || stat.size < 1 || stat.size > MAX_CREDENTIAL_BYTES) {
    throw new Error(`${name} must be a non-empty bounded regular file`);
  }
  if (privateFile && (stat.mode & 0o077) !== 0) {
    throw new Error(`${name} must not be accessible by group or other users`);
  }
  return fs.readFileSync(resolved);
}

function readTlsCredentials(config) {
  const cert = readBoundedFile(config.certFile, 'SPIFFE_PROXY_CERT_FILE');
  const key = readBoundedFile(config.keyFile, 'SPIFFE_PROXY_KEY_FILE', { privateFile: true });
  const ca = readBoundedFile(config.bundleFile, 'SPIFFE_PROXY_BUNDLE_FILE');
  try {
    const leaf = new X509Certificate(cert);
    if (Date.parse(leaf.validTo) <= Date.now()) throw new Error('the workload SVID has expired');
    if (Date.parse(leaf.validFrom) > Date.now() + 5_000) {
      throw new Error('the workload SVID is not valid yet');
    }
    return { cert, key, ca, minVersion: 'TLSv1.3' };
  } catch (error) {
    key.fill(0);
    throw error;
  }
}

function tokenDigest(tokenFile, name) {
  const token = readBoundedFile(tokenFile, name, { privateFile: true });
  try {
    const trimmed = token.toString('utf8').trim();
    if (trimmed.length < 32 || trimmed.length > 4096) throw new Error(`${name} is invalid`);
    return crypto.createHash('sha256').update(trimmed).digest();
  } finally {
    token.fill(0);
  }
}

function bearerAuthorized(request, expectedDigest) {
  const header = request.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const actual = crypto.createHash('sha256').update(header.slice(7)).digest();
  return actual.length === expectedDigest.length && crypto.timingSafeEqual(actual, expectedDigest);
}

async function boundedBody(request) {
  const declared = Number(request.headers['content-length']);
  if (Number.isFinite(declared) && declared > MAX_REQUEST_BYTES) {
    throw new Error('request body is too large');
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_REQUEST_BYTES) throw new Error('request body is too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

function responseHeaders(headers) {
  const selected = {};
  for (const [name, value] of Object.entries(headers)) {
    if (FORWARDED_RESPONSE_HEADERS.has(name) && value !== undefined) selected[name] = value;
  }
  selected['cache-control'] ||= 'no-store';
  return selected;
}

function requestHeaders(request, target, authorization) {
  const selected = {
    accept: request.headers.accept || '*/*',
    'content-type': request.headers['content-type'] || 'application/octet-stream',
    host: target.host,
  };
  if (request.headers['mcp-protocol-version']) {
    selected['mcp-protocol-version'] = request.headers['mcp-protocol-version'];
  }
  if (request.headers['mcp-session-id']) selected['mcp-session-id'] = request.headers['mcp-session-id'];
  if (authorization) selected.authorization = authorization;
  return selected;
}

function allowedPath(request) {
  return request.url === '/mcp' || request.url === '/healthz';
}

function refuse(response, status, error) {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  response.end(JSON.stringify({ error }));
}

async function forward({ request, response, target, transport, tlsOptions, authorization }) {
  if (!allowedPath(request)) {
    refuse(response, 404, 'not_found');
    return;
  }
  let body;
  try {
    body = await boundedBody(request);
  } catch {
    refuse(response, 413, 'request_too_large');
    return;
  }
  await new Promise((resolve) => {
    const upstreamRequest = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port,
      method: request.method,
      path: request.url,
      headers: requestHeaders(request, target, authorization),
      timeout: 30_000,
      // Never share a TLS socket across proxy instances or credential
      // rotations. A pooled socket was authenticated under older policy.
      agent: false,
      ...tlsOptions,
    }, (upstreamResponse) => {
      response.writeHead(
        upstreamResponse.statusCode || 502,
        responseHeaders(upstreamResponse.headers),
      );
      upstreamResponse.pipe(response);
      resolve();
    });
    upstreamRequest.once('timeout', () => upstreamRequest.destroy(new Error('upstream timeout')));
    upstreamRequest.once('error', () => {
      if (!response.headersSent) refuse(response, 502, 'upstream_unavailable');
      else response.destroy();
      resolve();
    });
    upstreamRequest.end(body);
  });
}

function parseTarget(value, protocol, name) {
  const target = new URL(setting(value, name));
  if (target.protocol !== protocol || target.username || target.password || target.search
      || target.hash || target.pathname !== '/') {
    throw new Error(`${name} must be an origin using ${protocol}`);
  }
  return target;
}

export function clientProxyConfig(environment = process.env) {
  return {
    mode: 'client',
    listenHost: '127.0.0.1',
    listenPort: portSetting(environment.SPIFFE_PROXY_LISTEN_PORT || '3001', 'SPIFFE_PROXY_LISTEN_PORT'),
    upstream: parseTarget(environment.SPIFFE_PROXY_UPSTREAM, 'https:', 'SPIFFE_PROXY_UPSTREAM'),
    expectedPeerId: validateSpiffeId(environment.SPIFFE_PROXY_EXPECTED_PEER_ID),
    certFile: setting(environment.SPIFFE_PROXY_CERT_FILE, 'SPIFFE_PROXY_CERT_FILE'),
    keyFile: setting(environment.SPIFFE_PROXY_KEY_FILE, 'SPIFFE_PROXY_KEY_FILE'),
    bundleFile: setting(environment.SPIFFE_PROXY_BUNDLE_FILE, 'SPIFFE_PROXY_BUNDLE_FILE'),
    localTokenFile: setting(environment.SPIFFE_PROXY_LOCAL_TOKEN_FILE, 'SPIFFE_PROXY_LOCAL_TOKEN_FILE'),
  };
}

export function serverProxyConfig(environment = process.env) {
  return {
    mode: 'server',
    listenHost: '127.0.0.1',
    listenPort: portSetting(environment.SPIFFE_PROXY_LISTEN_PORT || '3443', 'SPIFFE_PROXY_LISTEN_PORT'),
    backend: parseTarget(environment.SPIFFE_PROXY_BACKEND || 'http://127.0.0.1:3000', 'http:', 'SPIFFE_PROXY_BACKEND'),
    expectedPeerId: validateSpiffeId(environment.SPIFFE_PROXY_EXPECTED_PEER_ID),
    certFile: setting(environment.SPIFFE_PROXY_CERT_FILE, 'SPIFFE_PROXY_CERT_FILE'),
    keyFile: setting(environment.SPIFFE_PROXY_KEY_FILE, 'SPIFFE_PROXY_KEY_FILE'),
    bundleFile: setting(environment.SPIFFE_PROXY_BUNDLE_FILE, 'SPIFFE_PROXY_BUNDLE_FILE'),
    backendTokenFile: setting(environment.SPIFFE_PROXY_BACKEND_TOKEN_FILE, 'SPIFFE_PROXY_BACKEND_TOKEN_FILE'),
  };
}

export async function startClientProxy(config) {
  const expectedToken = tokenDigest(config.localTokenFile, 'SPIFFE_PROXY_LOCAL_TOKEN_FILE');
  const server = http.createServer(async (request, response) => {
    if (!bearerAuthorized(request, expectedToken)) {
      refuse(response, 401, 'unauthorized');
      return;
    }
    let credentials;
    try {
      credentials = readTlsCredentials(config);
      await forward({
        request,
        response,
        target: config.upstream,
        transport: https,
        tlsOptions: {
          ...credentials,
          rejectUnauthorized: true,
          // Supplying an SNI name makes Node run checkServerIdentity even when
          // the transport target is an IP address. Authorization remains the
          // exact URI SAN comparison below, not DNS-name matching.
          servername: new URL(config.expectedPeerId).hostname,
          checkServerIdentity: (_hostname, certificate) => (
            certificateHasSpiffeId(certificate.raw, config.expectedPeerId)
              ? undefined
              : new Error('server SPIFFE ID does not match')
          ),
        },
      });
    } catch {
      if (!response.headersSent) refuse(response, 503, 'identity_unavailable');
    } finally {
      credentials?.key.fill(0);
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.listenPort, config.listenHost, resolve);
  });
  return server;
}

export async function startServerProxy(config) {
  const backendDigest = tokenDigest(config.backendTokenFile, 'SPIFFE_PROXY_BACKEND_TOKEN_FILE');
  const backendTokenBytes = readBoundedFile(
    config.backendTokenFile,
    'SPIFFE_PROXY_BACKEND_TOKEN_FILE',
    { privateFile: true },
  );
  const backendToken = backendTokenBytes.toString('utf8').trim();
  backendTokenBytes.fill(0);
  if (backendDigest.length !== 32) throw new Error('backend token digest failed');
  const credentials = readTlsCredentials(config);
  let credentialsHealthy = true;
  const server = https.createServer({
    ...credentials,
    requestCert: true,
    rejectUnauthorized: true,
  }, async (request, response) => {
    const peer = request.socket.getPeerCertificate(true);
    if (!credentialsHealthy || request.socket.authorized !== true
        || !certificateHasSpiffeId(peer.raw, config.expectedPeerId)) {
      refuse(response, 403, 'spiffe_identity_denied');
      return;
    }
    await forward({
      request,
      response,
      target: config.backend,
      transport: http,
      authorization: `Bearer ${backendToken}`,
    });
  });
  credentials.key.fill(0);

  const watched = [config.certFile, config.keyFile, config.bundleFile];
  const reload = () => {
    let next;
    try {
      next = readTlsCredentials(config);
      server.setSecureContext(next);
      credentialsHealthy = true;
    } catch {
      credentialsHealthy = false;
    } finally {
      next?.key.fill(0);
    }
  };
  for (const file of watched) fs.watchFile(file, { interval: 1_000, persistent: false }, reload);
  server.once('close', () => {
    for (const file of watched) fs.unwatchFile(file, reload);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.listenPort, config.listenHost, resolve);
  });
  return server;
}

async function main() {
  const mode = process.env.SPIFFE_PROXY_MODE;
  if (mode === 'client') {
    const config = clientProxyConfig();
    await startClientProxy(config);
    process.stderr.write(`SPIFFE client proxy listening on ${config.listenHost}:${config.listenPort}\n`);
    return;
  }
  if (mode === 'server') {
    const config = serverProxyConfig();
    await startServerProxy(config);
    process.stderr.write(`SPIFFE server proxy listening on ${config.listenHost}:${config.listenPort}\n`);
    return;
  }
  throw new Error('SPIFFE_PROXY_MODE must be client or server');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    process.stderr.write(`spiffe-mtls-proxy: ${error.message}\n`);
    process.exitCode = 1;
  });
}
