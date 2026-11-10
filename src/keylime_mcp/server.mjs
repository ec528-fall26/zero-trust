import { readFile } from 'node:fs/promises';

import { createAttestAndDeploy } from './attest_and_deploy.mjs';
import { createBootstrapTenant } from './bootstrap_tenant.mjs';
import { booleanSetting, integerSetting } from './config.mjs';
import { LaunchLedger } from './launch_ledger.mjs';
import { bearerTokenDigest, createKeylimeHttpServer } from './mcp_http.mjs';
import { createPermitVerifier } from './permit.mjs';
import { policyVersionFromFiles } from './policy_digest.mjs';
import { SECURITY_PARAMETERS } from '../security_parameters.mjs';

async function configuredToken() {
  const tokenFile = process.env.KEYLIME_MCP_TOKEN_FILE;
  if (!tokenFile) throw new Error('KEYLIME_MCP_TOKEN_FILE is required');
  const encoded = await readFile(tokenFile);
  try {
    const token = encoded.toString('utf8').trim();
    if (token.length < 32 || token.length > 4096) throw new Error('invalid bearer token');
    return bearerTokenDigest(token);
  } finally {
    encoded.fill(0);
  }
}

// The policy_version this node accepts.  Preferred: derive it from the Keylime
// policy file the node enforces plus the controller's approval policy bundle,
// so a change to either one changes the version.  The fixed label is kept for
// existing deployments.
async function configuredPolicyVersion() {
  const keylimePolicyPath = process.env.KEYLIME_POLICY_FILE;
  const approvalPolicyPath = process.env.KEYLIME_APPROVAL_POLICY_FILE;
  const label = process.env.KEYLIME_POLICY_VERSION;
  if (keylimePolicyPath || approvalPolicyPath) {
    if (!keylimePolicyPath || !approvalPolicyPath) {
      throw new Error('KEYLIME_POLICY_FILE and KEYLIME_APPROVAL_POLICY_FILE are both required');
    }
    if (label) {
      throw new Error('set KEYLIME_POLICY_VERSION or the policy files, not both');
    }
    return policyVersionFromFiles({ keylimePolicyPath, approvalPolicyPath });
  }
  return label;
}

function requiredSetting(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main() {
  const tokenDigest = await configuredToken();
  const port = Number.parseInt(process.env.KEYLIME_MCP_PORT || '3000', 10);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('invalid port');
  // There is deliberately no way to start this server without permit checks.
  const permitVerifier = createPermitVerifier({
    publicKeyPem: await readFile(requiredSetting('KEYLIME_PERMIT_PUBLIC_KEY_FILE'), 'utf8'),
    target: process.env.KEYLIME_TARGET,
    agentId: process.env.KEYLIME_AGENT_ID,
  });
  const launchLedger = await new LaunchLedger(
    requiredSetting('KEYLIME_LAUNCH_LEDGER_DIR'),
  ).initialize();
  const handler = createAttestAndDeploy({
    statusCommand: process.env.KEYLIME_STATUS_COMMAND,
    statusSocket: process.env.KEYLIME_STATUS_SOCKET,
    artifactPath: process.env.KEYLIME_WORKLOAD_ARTIFACT,
    inputPath: process.env.KEYLIME_WORKLOAD_INPUT,
    target: process.env.KEYLIME_TARGET,
    agentId: process.env.KEYLIME_AGENT_ID,
    policyVersion: await configuredPolicyVersion(),
    permitVerifier,
    launchLedger,
    requireFreshAttestation: booleanSetting(
      process.env.KEYLIME_REQUIRE_FRESH_ATTESTATION,
      'KEYLIME_REQUIRE_FRESH_ATTESTATION',
      false,
    ),
    freshAttestationTimeoutSeconds: integerSetting(
      process.env.KEYLIME_FRESH_ATTESTATION_TIMEOUT_SECONDS,
      'KEYLIME_FRESH_ATTESTATION_TIMEOUT_SECONDS',
      SECURITY_PARAMETERS.fresh_attestation_timeout_sec,
      1,
      120,
    ),
    maximumAttestationAgeSeconds: integerSetting(
      process.env.KEYLIME_MAX_ATTESTATION_AGE_SECONDS,
      'KEYLIME_MAX_ATTESTATION_AGE_SECONDS',
      SECURITY_PARAMETERS.attestation_max_age_sec,
      1,
      86_400,
    ),
  });
  const bootstrapHandler = createBootstrapTenant({
    socketPath: process.env.KEYLIME_BOOTSTRAP_SOCKET || '/run/ec528/keylime-bootstrap.sock',
    permitVerifier,
  });
  const server = createKeylimeHttpServer({ handler, bootstrapHandler, tokenDigest });
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
