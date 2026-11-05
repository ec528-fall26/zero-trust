import { createKeylimeMcpHandler } from './keylime_mcp_client.mjs';

export function validateBootstrapResult(value, action) {
  if (value?.status !== 'enrolled'
      || value.agent_uuid !== action.agent_uuid
      || value.runtime_policy_sha256 !== action.runtime_policy_sha256
      || value.payload_sha256 !== action.payload_sha256
      || value.occurrence_id !== action.occurrence_id
      || typeof value.measured_boot !== 'boolean') {
    throw new Error('Keylime bootstrap result is not bound to the approved action');
  }
  return value;
}

export function createKeylimeBootstrapHandler(options) {
  return createKeylimeMcpHandler({
    ...options,
    toolName: 'bootstrap_keylime_tenant',
    resultValidator: validateBootstrapResult,
  });
}
