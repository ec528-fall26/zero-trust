// File-based exchange between the controller and human approvers.
//
// The controller publishes build/approvals/<receipt_id>/request.json.  Each
// approver signs it on their own machine (tools/approver.mjs sign) and the
// returned signoff-<role>.json goes into .../signoffs/.  The channel needs no
// trust: every signoff is verified against the pinned roster.
import crypto from 'node:crypto';
import { mkdir, readdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

const sleep = (milliseconds) => new Promise((resolve) => { setTimeout(resolve, milliseconds); });

export async function publishApprovalRequest(exchangeRoot, request) {
  const directory = path.join(exchangeRoot, request.receipt_id);
  const inbox = path.join(directory, 'signoffs');
  await mkdir(inbox, { recursive: true, mode: 0o700 });
  const requestPath = path.join(directory, 'request.json');
  const temporary = `${requestPath}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  await writeFile(temporary, `${JSON.stringify(request, null, 2)}\n`, { mode: 0o644 });
  await rename(temporary, requestPath);
  return { requestPath, inbox };
}

export function approvalInstructions({ requestPath, inbox }, expiresAt) {
  return [
    '',
    `Approval request: ${requestPath}`,
    'Send it to two approvers. Each runs, on their own machine:',
    '  node tools/approver.mjs sign request.json',
    `and sends back signoff-<role>.json. Put those files in:\n  ${inbox}`,
    `Waiting until ${expiresAt}...`,
    '',
  ].join('\n');
}

// Yields each new signoff file in arrival order until the deadline.
export async function* signoffFiles(inbox, deadline, pollMilliseconds = 1_000) {
  const seen = new Set();
  while (Date.now() < deadline) {
    const names = (await readdir(inbox)).filter((name) => name.endsWith('.json') && !seen.has(name)).sort();
    for (const name of names) {
      seen.add(name);
      try {
        yield { name, envelope: JSON.parse(await readFile(path.join(inbox, name), 'utf8')) };
      } catch {
        yield { name, envelope: null };
      }
    }
    await sleep(pollMilliseconds);
  }
}

// Feeds arriving signoffs to the controller until two distinct people have
// approved.  `afterFirst(envelope)` runs once, while the request is pending.
export async function collectTwoApprovals(controller, inbox, deadline, { afterFirst, log = () => {} } = {}) {
  const accepted = [];
  const rejected = [];
  const startedAt = Date.now();
  for await (const { name, envelope } of signoffFiles(inbox, deadline)) {
    const outcome = envelope === null
      ? { accepted: false, reason: 'signoff_unreadable' }
      : controller.submitSignoff(envelope);
    if (!outcome.accepted) {
      rejected.push({ file: name, reason: outcome.reason });
      log(`${name}: refused: ${outcome.reason}\n`);
      continue;
    }
    const role = controller.snapshot().approvals.at(-1);
    accepted.push({ file: name, role, seconds_after_request: (Date.now() - startedAt) / 1000 });
    log(`${name}: accepted (${role})\n`);
    if (accepted.length === 1 && afterFirst) await afterFirst(envelope);
    if (accepted.length === 2) return { accepted, rejected };
  }
  throw new Error('approval window ended without two distinct approvals');
}
