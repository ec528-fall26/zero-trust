// Optional OpenTelemetry tracing for the experiments.
//
// Tracing is off unless OTEL_EXPORTER_OTLP_ENDPOINT is set (for example
// http://127.0.0.1:4318 for a local Jaeger).  When it is off, every helper
// here is a cheap no-op and the experiments behave exactly as before.
//
// Spans carry only step names, outcomes, HTTP statuses, refusal reasons and
// public identifiers (occurrence IDs, digests).  Never put tokens, receipts,
// signatures or raw Keylime responses into span attributes.
import { SpanStatusCode, trace } from '@opentelemetry/api';

const TRACER_NAME = 'ec528-zero-trust-experiments';
let provider = null;

export async function initTelemetry(serviceName) {
  if (!process.env.OTEL_EXPORTER_OTLP_ENDPOINT) return false;
  const [{ NodeTracerProvider }, { SimpleSpanProcessor }, { OTLPTraceExporter }, { resourceFromAttributes }] =
    await Promise.all([
      import('@opentelemetry/sdk-trace-node'),
      import('@opentelemetry/sdk-trace-base'),
      import('@opentelemetry/exporter-trace-otlp-http'),
      import('@opentelemetry/resources'),
    ]);
  // SimpleSpanProcessor exports each span as soon as it ends, so the trace
  // fills in while the run is still going.
  provider = new NodeTracerProvider({
    resource: resourceFromAttributes({ 'service.name': serviceName }),
    spanProcessors: [new SimpleSpanProcessor(new OTLPTraceExporter())],
  });
  provider.register();
  return true;
}

export async function shutdownTelemetry() {
  if (!provider) return;
  try {
    await provider.forceFlush();
    await provider.shutdown();
  } catch {
    process.stderr.write('warning: telemetry export failed; the experiment result is unaffected\n');
  }
}

function tracer() {
  return trace.getTracer(TRACER_NAME);
}

function cleanAttributes(attributes) {
  const clean = {};
  for (const [key, value] of Object.entries(attributes || {})) {
    if (value === null || value === undefined) continue;
    if (['string', 'number', 'boolean'].includes(typeof value)) clean[key] = value;
  }
  return clean;
}

// Run fn inside a span.  fn receives the span so it can add attributes or
// events.  A thrown error marks the span as failed and is rethrown.
export async function withSpan(name, attributes, fn) {
  return tracer().startActiveSpan(name, { attributes: cleanAttributes(attributes) }, async (span) => {
    try {
      const result = await fn(span);
      return result;
    } catch (error) {
      span.setStatus({ code: SpanStatusCode.ERROR, message: error instanceof Error ? error.message : 'error' });
      throw error;
    } finally {
      span.end();
    }
  });
}

export function setAttributes(span, attributes) {
  span.setAttributes(cleanAttributes(attributes));
}

// Mark a span as a failed security expectation without throwing.
export function markOutcome(span, passed, attributes = {}) {
  span.setAttributes(cleanAttributes({ ...attributes, 'ec528.passed': passed }));
  if (!passed) span.setStatus({ code: SpanStatusCode.ERROR, message: 'expectation not met' });
}

export function addEvent(name, attributes) {
  trace.getActiveSpan()?.addEvent(name, cleanAttributes(attributes));
}

// Build a span with explicit start and end times, for replaying a recorded
// run.  parentContext is optional.
export function recordedSpan(name, startTime, endTime, attributes, parentContext) {
  const span = tracer().startSpan(
    name,
    { startTime: new Date(startTime), attributes: cleanAttributes(attributes) },
    parentContext,
  );
  return {
    span,
    end(status) {
      if (status === false) span.setStatus({ code: SpanStatusCode.ERROR, message: 'expectation not met' });
      span.end(new Date(endTime));
    },
  };
}

// Wrap the Keylime MCP call so each attestation-and-run attempt is a span.
export function tracedKeylimeHandler(handler) {
  return (action) => withSpan('keylime.mcp.attest_and_deploy', {
    'ec528.target': action?.target,
    'ec528.occurrence_id': action?.occurrence_id,
  }, async (span) => {
    const result = await handler(action);
    setAttributes(span, {
      'keylime.verdict': result?.attestation?.verdict,
      'workload.executed': result?.workload?.executed,
    });
    return result;
  });
}

// Run one scenario's request inside a span and record what came back.
export async function scenarioSpan(name, expected, run) {
  return withSpan(`scenario.${name}`, { 'ec528.expected': expected }, async (span) => {
    const snapshot = await run();
    const response = snapshot.last_response;
    setAttributes(span, {
      'http.response.status_code': response?.status,
      'ec528.refusal_reason': response?.body?.rejected?.reason,
      'workload.executed': response?.body?.result?.workload?.executed === true,
    });
    return snapshot;
  });
}
