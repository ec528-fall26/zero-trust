// Plain-English view model for the demo dashboard. Pure functions shared by
// the browser page (served as /demo-view.js) and the unit tests. They only
// read the controller snapshot; they never decide anything security-relevant.

export const STATIONS = Object.freeze([
  { id: 'agent', title: 'Agent', subtitle: 'in nono sandbox' },
  { id: 'approvals', title: 'Approvals', subtitle: '2 of 3 needed' },
  { id: 'gate', title: 'Receipt gate', subtitle: '7 checks' },
  { id: 'keylime', title: 'Keylime', subtitle: 'node health' },
  { id: 'job', title: 'Workload', subtitle: 'not run' },
]);

const GATE_REASONS = Object.freeze({
  receipt_required: 'No receipt was presented.',
  action_hash_mismatch: 'The request was changed after it was approved.',
  replay_refused: 'This receipt was already used once.',
  receipt_expired: 'The approval has expired.',
  receipt_not_yet_valid: 'The receipt is dated in the future.',
  untrusted_or_invalid_signature: 'The receipt is not signed by a trusted issuer.',
  assurance_too_low: 'The receipt does not carry two valid human approvals.',
  action_mismatch: 'The receipt is for a different kind of action.',
  consumption_store_unavailable: 'The one-use receipt store is unavailable.',
});

const ROLE_NAMES = Object.freeze({
  operator: 'Operator',
  security: 'Security',
  reviewer: 'Reviewer',
});

function isRemote(snapshot) {
  return snapshot?.keylime_mode === 'remote-mcp';
}

// Where a request stopped, and why, in words a non-specialist can follow.
// stopAt is an index into STATIONS; tone is 'ok' or 'bad'.
export function describeResponse(response, snapshot) {
  if (!response) return null;
  const body = response.body || {};
  const reason = body.rejected?.reason;
  if (response.status === 200 && body.result?.workload?.executed === true) {
    const provider = body.result?.attestation?.provider;
    return {
      stopAt: 4,
      tone: 'ok',
      title: 'Workload ran once',
      detail: provider === 'keylime'
        ? 'Keylime vouched for the AWS node, so the approved job ran there exactly once.'
        : 'The local Keylime stand-in accepted the job material, so the approved job ran once.',
      gate: 'all checks passed',
      keylime: 'trusted',
      job: 'ran once',
    };
  }
  if (reason === 'effect_indeterminate' || response.status >= 500) {
    return {
      stopAt: 3,
      tone: 'bad',
      title: 'Keylime refused the node',
      detail: isRemote(snapshot)
        ? 'The receipt was valid, but the node did not pass attestation (or could not be reached). The job did not run, and the receipt is now used up.'
        : 'The receipt was valid, but the node check failed. The job did not run, and the receipt is now used up.',
      gate: 'all checks passed',
      keylime: 'untrusted',
      job: 'blocked',
    };
  }
  if (response.status === 428 && !reason) {
    return {
      stopAt: 2,
      tone: 'bad',
      title: 'No receipt',
      detail: 'Nothing runs without a receipt signed by two of the three approvers.',
      gate: 'refused',
    };
  }
  return {
    stopAt: 2,
    tone: 'bad',
    title: 'Receipt gate refused',
    detail: GATE_REASONS[reason] || `The receipt failed a check (${reason || 'unknown reason'}).`,
    gate: 'refused',
    reason: reason || null,
  };
}

// One audit event as a short sentence, or null to hide it.
export function describeEvent(event) {
  if (!event || typeof event !== 'object') return null;
  if (event.stage === 'nono-controller' && event.outcome === 'action-ingested') {
    return 'The agent\'s request left the sandbox and was rebuilt by the trusted watcher.';
  }
  if (event.stage === 'emilia') {
    if (event.outcome === 'approved') return `${ROLE_NAMES[event.role] || 'An approver'} approved.`;
    if (event.outcome === 'receipt-issued') return 'Receipt issued: two different people signed this exact request.';
    if (event.outcome === 'expired') return 'The approval window expired.';
  }
  if (event.stage === 'receipt-guard') {
    if (event.decision === 'invoke') return 'Receipt verified and reserved, so it can only be used once.';
    if (event.decision === 'allow') return 'Workload finished.';
    if (event.decision === 'deny') {
      if (event.reason === 'effect_indeterminate') return 'Job did not run; the receipt is used up.';
      return `Gate refused: ${GATE_REASONS[event.reason] || event.reason || 'receipt required'}`;
    }
  }
  if (event.stage === 'demo' && event.outcome === 'request-received') {
    return `Request sent: ${SCENARIO_NAMES[event.scenario] || event.scenario}.`;
  }
  if (event.stage === 'keylime' && event.outcome === 'trusted') {
    return 'Local Keylime stand-in: material matches.';
  }
  return null;
}

// What is real and what is simulated in this run.
export function boundaryNote(snapshot) {
  const real = ['receipt verification', 'quorum counting', 'replay protection'];
  if (isRemote(snapshot)) real.push('Keylime attestation on AWS (software TPM)');
  return {
    real: `Real: ${real.join(', ')}.`,
    simulated: Array.isArray(snapshot?.limitations) ? snapshot.limitations : [],
  };
}

// Which lock stopped a request, for the "stopped by" pill.
export function stoppedBy(view) {
  if (!view || view.tone === 'ok') return null;
  if (view.stopAt === 3) return { tech: 'keylime', label: 'Keylime, fails closed' };
  if (view.reason === 'action_hash_mismatch') return { tech: 'emilia', label: 'EMILIA action hash' };
  if (view.reason === 'replay_refused') return { tech: 'emilia', label: 'Durable receipt store' };
  return { tech: 'emilia', label: 'EMILIA quorum' };
}

const SCENARIO_NAMES = Object.freeze({
  missing: 'no receipt',
  tampered: 'altered target',
  approved: 'approved workload',
  replay: 'receipt replay',
});

function millis(value) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

// Turn the controller's audit events into one trace per request, using the
// timestamps the server recorded. Spans: the whole request, the receipt gate,
// the Keylime call (when the gate let it through), and the receipt commit.
export function traceFromEvents(events, { remote = false } = {}) {
  const traces = [];
  let current = null;
  for (const event of Array.isArray(events) ? events : []) {
    const at = millis(event?.at);
    if (at === null) continue;
    if (event.stage === 'demo' && event.outcome === 'request-received') {
      current = { scenario: event.scenario, start: at, marks: {} };
      continue;
    }
    if (!current) continue;
    if (event.stage === 'receipt-guard') {
      if (event.decision === 'invoke') current.marks.invoke = at;
      if (event.decision === 'allow') current.marks.allow = at;
      if (event.decision === 'deny') {
        current.marks.deny = at;
        current.marks.denyReason = event.reason || 'receipt_required';
      }
    }
    if (event.stage === 'demo' && (event.outcome === 'executed' || event.outcome === 'refused')) {
      current.end = at;
      current.outcome = event.outcome;
      traces.push(buildTrace(current, remote));
      current = null;
    }
  }
  return traces;
}

function buildTrace({ scenario, start, end, outcome, marks }, remote) {
  const keylimeService = remote ? 'keylime (AWS)' : 'keylime (stand-in)';
  const passedGate = marks.invoke !== undefined;
  const gateEnd = passedGate ? marks.invoke : (marks.deny ?? end);
  const spans = [
    { name: `request ${SCENARIO_NAMES[scenario] || scenario}`, service: 'controller', start, end, depth: 0, tone: outcome === 'executed' ? 'ok' : 'bad' },
    {
      name: 'emilia.receipt_gate',
      service: 'emilia',
      start,
      end: gateEnd,
      depth: 1,
      tone: passedGate ? 'ok' : 'bad',
      note: passedGate ? 'verified and reserved' : (GATE_REASONS[marks.denyReason] || marks.denyReason || 'refused'),
    },
  ];
  if (passedGate) {
    const keylimeEnd = marks.allow ?? marks.deny ?? end;
    spans.push({
      name: 'keylime.attest_and_deploy',
      service: keylimeService,
      start: marks.invoke,
      end: keylimeEnd,
      depth: 1,
      tone: marks.allow !== undefined ? 'ok' : 'bad',
      note: marks.allow !== undefined ? 'trusted, workload ran' : 'refused, did not run',
    });
    if (marks.allow !== undefined) {
      spans.push({ name: 'emilia.receipt_commit', service: 'emilia', start: marks.allow, end, depth: 1, tone: 'ok', note: 'marked used' });
    }
  }
  return { name: spans[0].name, scenario, start, end, outcome, spans };
}

// Convert a Jaeger JSON export (results/traces/*.trace.json) into the same
// shape: spans sorted by start time, with nesting depth from CHILD_OF links.
export function traceFromJaeger(document) {
  const trace = document?.data?.[0];
  if (!trace || !Array.isArray(trace.spans) || trace.spans.length === 0) return null;
  const byId = new Map(trace.spans.map((span) => [span.spanID, span]));
  const depthOf = (span, seen = new Set()) => {
    const parentId = span.references?.find((ref) => ref.refType === 'CHILD_OF')?.spanID;
    if (!parentId || !byId.has(parentId) || seen.has(parentId)) return 0;
    seen.add(parentId);
    return 1 + depthOf(byId.get(parentId), seen);
  };
  const tag = (span, key) => span.tags?.find((entry) => entry.key === key)?.value;
  const spans = trace.spans
    .map((span) => {
      const start = span.startTime / 1000;
      const errored = tag(span, 'error') === true || tag(span, 'otel.status_code') === 'ERROR';
      return {
        name: span.operationName,
        service: trace.processes?.[span.processID]?.serviceName || 'unknown',
        start,
        end: start + span.duration / 1000,
        depth: depthOf(span),
        tone: errored ? 'bad' : 'ok',
        note: tag(span, 'ec528.refusal_reason') || tag(span, 'keylime.attestation_status') || tag(span, 'otel.status_description') || '',
      };
    })
    .sort((left, right) => left.start - right.start || left.depth - right.depth);
  const start = Math.min(...spans.map((span) => span.start));
  const end = Math.max(...spans.map((span) => span.end));
  const root = spans.find((span) => span.depth === 0) || spans[0];
  return { name: root.name, start, end, outcome: 'recorded', spans };
}
