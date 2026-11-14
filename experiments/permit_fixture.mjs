// Permit helpers for local experiments and tests.  A real deployment
// generates one key pair in infra/aws/deploy.sh and keeps the private half on
// the controller.
import crypto from 'node:crypto';

import { createPermitSigner, signPermitPayload } from '../src/controller/permit_signer.mjs';
import { createPermitVerifier } from '../src/keylime_mcp/permit.mjs';

// Signer, verifier and refusal helpers around one existing private key.
export function permitKitFromPrivateKey({
  privateKeyPem,
  target,
  agentId,
  enrollmentEpoch,
  now = () => Date.now(),
}) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKeyPem = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
  const signer = createPermitSigner({
    privateKeyPem,
    agentUuid: agentId,
    enrollmentEpoch,
    now,
  });
  const verifier = createPermitVerifier({ publicKeyPem, target, agentId, now });
  const sign = (action, receiptId = 'fixture-receipt', tool = 'attest_and_deploy') => (
    signer.sign({ tool, action, receiptId })
  );
  return Object.freeze({
    enrollmentEpoch,
    publicKeyPem,
    privateKeyPem,
    signer,
    verifier,
    sign,
    // A correctly signed permit with chosen fields, for testing refusals.
    signWith(action, overrides, tool = 'attest_and_deploy') {
      return signPermitPayload({ ...sign(action, 'fixture-receipt', tool).payload, ...overrides }, privateKey);
    },
  });
}

// The same helpers with a freshly generated, ephemeral key.
export function createPermitFixture({
  target,
  agentId,
  enrollmentEpoch = crypto.randomUUID(),
  now = () => Date.now(),
}) {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  return permitKitFromPrivateKey({
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    target,
    agentId,
    enrollmentEpoch,
    now,
  });
}
