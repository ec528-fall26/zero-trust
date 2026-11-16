// One raw MCP tool call to a Keylime node, the way any caller holding the
// bearer token could make it.  Used by the node-enforcement tests and the
// Demo 3 bridge experiment to send requests that the controller never would.
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

export async function callNodeTool({
  endpoint,
  token,
  name = 'attest_and_deploy',
  toolArguments,
  timeoutMilliseconds = 20_000,
}) {
  const transport = new StreamableHTTPClientTransport(new URL(endpoint), {
    authProvider: { token: async () => token },
    requestInit: { redirect: 'error' },
    onInsufficientScope: 'throw',
  });
  const client = new Client(
    { name: 'ec528-direct-caller', version: '0.1.0' },
    { versionNegotiation: { mode: 'auto', probe: { timeoutMs: 2_000, maxRetries: 0 } } },
  );
  try {
    await client.connect(transport, { timeout: timeoutMilliseconds });
    const result = await client.callTool(
      { name, arguments: toolArguments },
      { timeout: timeoutMilliseconds, maxTotalTimeout: timeoutMilliseconds },
    );
    return result.isError === true ? 'refused' : 'accepted';
  } catch {
    // A transport, protocol or schema failure is also a refusal: nothing ran.
    return 'refused';
  } finally {
    await client.close().catch(() => {});
  }
}
