import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  certificateHasSpiffeId,
  startClientProxy,
  startServerProxy,
  validateSpiffeId,
} from '../src/spire/mtls_proxy.mjs';

function runOpenSsl(directory, ...arguments_) {
  execFileSync('openssl', arguments_, { cwd: directory, stdio: 'ignore' });
}

function issueCertificate(directory, name, spiffeId) {
  runOpenSsl(directory, 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${name}`);
  fs.chmodSync(path.join(directory, `${name}.key`), 0o600);
  fs.writeFileSync(path.join(directory, `${name}.ext`), [
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=critical,digitalSignature,keyEncipherment',
    'extendedKeyUsage=clientAuth,serverAuth',
    `subjectAltName=URI:${spiffeId}`,
    '',
  ].join('\n'));
  runOpenSsl(directory, 'x509', '-req', '-in', `${name}.csr`, '-CA', 'ca.pem',
    '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-sha256',
    '-extfile', `${name}.ext`, '-out', `${name}.pem`);
}

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ec528-spiffe-test-'));
  runOpenSsl(directory, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-sha256', '-subj', '/CN=test-ca');
  fs.chmodSync(path.join(directory, 'ca.key'), 0o600);
  issueCertificate(directory, 'controller', 'spiffe://zt.demo/controller');
  issueCertificate(directory, 'intruder', 'spiffe://zt.demo/intruder');
  issueCertificate(directory, 'server', 'spiffe://zt.demo/keylime-mcp');
  fs.writeFileSync(path.join(directory, 'local-token'), 'l'.repeat(64), { mode: 0o600 });
  fs.writeFileSync(path.join(directory, 'backend-token'), 'b'.repeat(64), { mode: 0o600 });
  return directory;
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

async function close(server) {
  if (!server) return;
  await new Promise((resolve) => server.close(resolve));
}

async function request(port, token, pathname = '/mcp') {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path: pathname,
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.once('end', () => resolve({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.once('error', reject);
    req.end('{"request":"test"}');
  });
}

test('SPIFFE IDs are validated and certificate matching is exact', () => {
  const directory = fixture();
  try {
    assert.equal(validateSpiffeId('spiffe://zt.demo/controller'), 'spiffe://zt.demo/controller');
    assert.throws(() => validateSpiffeId('https://zt.demo/controller'), /invalid/);
    assert.throws(() => validateSpiffeId('spiffe://zt.demo/controller?admin=true'), /invalid/);
    const certificate = fs.readFileSync(path.join(directory, 'controller.pem'));
    assert.equal(certificateHasSpiffeId(certificate, 'spiffe://zt.demo/controller'), true);
    assert.equal(certificateHasSpiffeId(certificate, 'spiffe://zt.demo/control'), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('mTLS proxies require both the local token and exact workload identities', async () => {
  const directory = fixture();
  let backend;
  let serverProxy;
  let clientProxy;
  let intruderProxy;
  let wrongServerProxy;
  try {
    backend = http.createServer((request_, response) => {
      if (request_.headers.authorization !== `Bearer ${'b'.repeat(64)}`) {
        response.writeHead(401).end();
        return;
      }
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{"status":"identity-accepted"}');
    });
    const backendPort = await listen(backend);

    serverProxy = await startServerProxy({
      listenHost: '127.0.0.1',
      listenPort: 0,
      backend: new URL(`http://127.0.0.1:${backendPort}`),
      expectedPeerId: 'spiffe://zt.demo/controller',
      certFile: path.join(directory, 'server.pem'),
      keyFile: path.join(directory, 'server.key'),
      bundleFile: path.join(directory, 'ca.pem'),
      backendTokenFile: path.join(directory, 'backend-token'),
    });
    const serverPort = serverProxy.address().port;

    clientProxy = await startClientProxy({
      listenHost: '127.0.0.1',
      listenPort: 0,
      upstream: new URL(`https://127.0.0.1:${serverPort}`),
      expectedPeerId: 'spiffe://zt.demo/keylime-mcp',
      certFile: path.join(directory, 'controller.pem'),
      keyFile: path.join(directory, 'controller.key'),
      bundleFile: path.join(directory, 'ca.pem'),
      localTokenFile: path.join(directory, 'local-token'),
    });
    const clientPort = clientProxy.address().port;

    assert.deepEqual(await request(clientPort, 'l'.repeat(64)), {
      status: 200,
      body: '{"status":"identity-accepted"}',
    });
    assert.equal((await request(clientPort, 'wrong-token')).status, 401);
    assert.equal((await request(clientPort, 'l'.repeat(64), '/not-mcp')).status, 404);

    intruderProxy = await startClientProxy({
      listenHost: '127.0.0.1',
      listenPort: 0,
      upstream: new URL(`https://127.0.0.1:${serverPort}`),
      expectedPeerId: 'spiffe://zt.demo/keylime-mcp',
      certFile: path.join(directory, 'intruder.pem'),
      keyFile: path.join(directory, 'intruder.key'),
      bundleFile: path.join(directory, 'ca.pem'),
      localTokenFile: path.join(directory, 'local-token'),
    });
    assert.equal((await request(intruderProxy.address().port, 'l'.repeat(64))).status, 403);

    wrongServerProxy = await startClientProxy({
      listenHost: '127.0.0.1',
      listenPort: 0,
      upstream: new URL(`https://127.0.0.1:${serverPort}`),
      expectedPeerId: 'spiffe://zt.demo/not-keylime',
      certFile: path.join(directory, 'controller.pem'),
      keyFile: path.join(directory, 'controller.key'),
      bundleFile: path.join(directory, 'ca.pem'),
      localTokenFile: path.join(directory, 'local-token'),
    });
    assert.equal((await request(wrongServerProxy.address().port, 'l'.repeat(64))).status, 502);
  } finally {
    await close(wrongServerProxy);
    await close(intruderProxy);
    await close(clientProxy);
    await close(serverProxy);
    await close(backend);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
