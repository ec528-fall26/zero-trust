// A complete Keylime node on this machine, for tests and local experiments.
//
// Real: the HTTP server, bearer token, MCP protocol and tool schemas, the
// attest-and-deploy handler, permit verification, the launch ledger, and
// descriptor-bound process execution.  Stand-in: Keylime's status, served from
// a local socket whose verdict, age and enrollment epoch the caller controls.
// The workload appends a line to a file every time it runs, so launches are
// counted from the processes themselves, not from responses.  Linux only.
import crypto from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

import { callNodeTool } from './node_client.mjs';
import { createPermitFixture } from './permit_fixture.mjs';
import { createAttestAndDeploy } from '../src/keylime_mcp/attest_and_deploy.mjs';
import { createBootstrapTenant } from '../src/keylime_mcp/bootstrap_tenant.mjs';
import { LaunchLedger } from '../src/keylime_mcp/launch_ledger.mjs';
import { bearerTokenDigest, createKeylimeHttpServer } from '../src/keylime_mcp/mcp_http.mjs';
import { PRE_ENROLLMENT_EPOCH } from '../src/keylime_mcp/permit.mjs';

export const LOCAL_TARGET = 'aws-keylime-demo-01';
export const LOCAL_AGENT = 'd432fbb3-d2f1-4a97-9ef7-75bd81c00000';

export function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

export function closeServer(server) {
  return new Promise((resolve) => {
    server.close(resolve);
    server.closeAllConnections?.();
  });
}

async function listenSocket(server, socketPath) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, resolve);
  });
}

export async function startLocalNode({ rootDirectory = os.tmpdir() } = {}) {
  const root = await mkdtemp(path.join(rootDirectory, 'ec528-local-node-'));
  await chmod(root, 0o700);
  const launchesPath = path.join(root, 'launches');
  const artifact = Buffer.from(`#!/bin/sh\necho launched >> '${launchesPath}'\nexec sha256sum "$1"\n`);
  const input = Buffer.from('EC528 approved workload payload\n');
  const permits = createPermitFixture({ target: LOCAL_TARGET, agentId: LOCAL_AGENT });
  const node = {
    root,
    target: LOCAL_TARGET,
    agentId: LOCAL_AGENT,
    token: crypto.randomBytes(32).toString('hex'),
    permits,
    bootstrapPermits: createPermitFixture({
      target: LOCAL_TARGET,
      agentId: LOCAL_AGENT,
      enrollmentEpoch: PRE_ENROLLMENT_EPOCH,
    }),
    artifact,
    input,
    artifactPath: path.join(root, 'checksum.sh'),
    inputPath: path.join(root, 'input.txt'),
    ledgerPath: path.join(root, 'launch-ledger'),
    statusPath: path.join(root, 'status.sock'),
    bootstrapPath: path.join(root, 'bootstrap.sock'),
    keylime: { status: 'PASS', ageSeconds: 0, epoch: permits.enrollmentEpoch },
    bootstrapCalls: 0,
    server: null,
    endpoint: null,
  };
  await writeFile(node.artifactPath, artifact, { mode: 0o755 });
  await chmod(node.artifactPath, 0o755);
  await writeFile(node.inputPath, input, { mode: 0o644 });

  const statusServer = net.createServer((connection) => {
    connection.end(JSON.stringify({
      agent_id: LOCAL_AGENT,
      enrollment_epoch: node.keylime.epoch,
      results: {
        attestation_status: node.keylime.status,
        last_successful_attestation: Math.floor(Date.now() / 1_000) - node.keylime.ageSeconds,
      },
    }));
  });
  const bootstrapServer = net.createServer((connection) => {
    connection.once('data', (data) => {
      node.bootstrapCalls += 1;
      const action = JSON.parse(data.toString('utf8'));
      connection.end(JSON.stringify({
        status: 'enrolled',
        agent_uuid: action.agent_uuid,
        runtime_policy_sha256: action.runtime_policy_sha256,
        payload_sha256: action.payload_sha256,
        occurrence_id: action.occurrence_id,
        measured_boot: false,
      }));
    });
  });
  await listenSocket(statusServer, node.statusPath);
  await listenSocket(bootstrapServer, node.bootstrapPath);

  // (Re)starts the MCP service.  The ledger directory persists across restarts,
  // exactly as /var/lib/ec528-launch-ledger does on the AWS node.
  async function start(overrides = {}) {
    const handler = createAttestAndDeploy({
      statusSocket: node.statusPath,
      artifactPath: node.artifactPath,
      inputPath: node.inputPath,
      target: LOCAL_TARGET,
      agentId: LOCAL_AGENT,
      policyVersion: 'demo-2.1',
      requiredOwnerUid: process.getuid(),
      permitVerifier: permits.verifier,
      launchLedger: new LaunchLedger(node.ledgerPath),
      ...overrides,
    });
    const bootstrapHandler = createBootstrapTenant({
      socketPath: node.bootstrapPath,
      permitVerifier: node.bootstrapPermits.verifier,
      timeoutMilliseconds: 2_000,
    });
    const server = createKeylimeHttpServer({
      handler,
      bootstrapHandler,
      tokenDigest: bearerTokenDigest(node.token),
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    node.server = server;
    node.endpoint = new URL(`http://127.0.0.1:${server.address().port}/mcp`);
  }
  await start();

  node.ledger = new LaunchLedger(node.ledgerPath);
  node.action = (changes = {}) => ({
    action_type: 'workload.execute',
    operation: 'checksum.sha256',
    target: LOCAL_TARGET,
    artifact_sha256: digest(artifact),
    input_sha256: digest(input),
    occurrence_id: crypto.randomUUID(),
    policy_version: 'demo-2.1',
    ...changes,
  });
  node.launches = async () => {
    try {
      return (await readFile(launchesPath, 'utf8')).trim().split('\n').length;
    } catch (error) {
      if (error.code === 'ENOENT') return 0;
      throw error;
    }
  };
  node.call = (toolArguments, { name = 'attest_and_deploy', token = node.token } = {}) => (
    callNodeTool({ endpoint: node.endpoint, token, name, toolArguments, timeoutMilliseconds: 10_000 })
  );
  node.restart = async (overrides = {}) => {
    await closeServer(node.server);
    await start(overrides);
  };
  node.stop = async () => {
    await closeServer(node.server);
    await closeServer(statusServer);
    await closeServer(bootstrapServer);
    await rm(root, { recursive: true, force: true });
  };
  return node;
}
