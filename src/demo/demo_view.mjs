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
