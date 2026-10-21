import crypto from 'node:crypto';
import {
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rmdir,
  unlink,
} from 'node:fs/promises';
import path from 'node:path';

import {
  findActionRequirement,
  makeReceiptGate,
  parseReceiptCarrier,
  receiptRequiredHeader,
  validateActionRiskManifest,
} from '@emilia-protocol/require-receipt';

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const POLICY_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const TARGET_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const OPERATIONS = new Set(['checksum.sha256']);
const MATERIAL_FIELDS = Object.freeze([
  'operation',
  'target',
  'artifact_sha256',
  'input_sha256',
  'occurrence_id',
  'policy_version',
]);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function dataValue(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
    throw new TypeError(`invalid_data_field:${key}`);
  }
  return descriptor.value;
}

function validateText(value, field, maximum = 256) {
  if (typeof value !== 'string'
      || value.length === 0
      || Buffer.byteLength(value, 'utf8') > maximum
      || value !== value.trim()
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TypeError(`invalid_${field}`);
  }
  return value;
}

function workloadSnapshot(args) {
  if (!isPlainObject(args)) throw new TypeError('workload_arguments_invalid');
  const keys = Reflect.ownKeys(args);
  const allowed = new Set([...MATERIAL_FIELDS, '__ep', 'emilia_receipt', 'emiliaReceipt']);
  if (keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    throw new TypeError('workload_arguments_invalid');
  }
  for (const field of MATERIAL_FIELDS) {
    if (!keys.includes(field)) throw new TypeError(`missing_${field}`);
  }

  const operation = dataValue(args, 'operation');
  if (typeof operation !== 'string' || !OPERATIONS.has(operation)) {
    throw new TypeError('invalid_operation');
  }
  const artifactSha256 = dataValue(args, 'artifact_sha256');
  const inputSha256 = dataValue(args, 'input_sha256');
  if (typeof artifactSha256 !== 'string' || !DIGEST_PATTERN.test(artifactSha256)) {
    throw new TypeError('invalid_artifact_sha256');
  }
  if (typeof inputSha256 !== 'string' || !DIGEST_PATTERN.test(inputSha256)) {
    throw new TypeError('invalid_input_sha256');
  }
  const occurrenceId = dataValue(args, 'occurrence_id');
  if (typeof occurrenceId !== 'string' || !UUID_PATTERN.test(occurrenceId)) {
    throw new TypeError('invalid_occurrence_id');
  }
  const policyVersion = dataValue(args, 'policy_version');
  if (typeof policyVersion !== 'string' || !POLICY_PATTERN.test(policyVersion)) {
    throw new TypeError('invalid_policy_version');
  }

  const target = validateText(dataValue(args, 'target'), 'target');
  if (!TARGET_PATTERN.test(target)) throw new TypeError('invalid_target');
  return Object.freeze({
    action_type: 'workload.execute',
    operation,
    target,
    artifact_sha256: artifactSha256,
    input_sha256: inputSha256,
    occurrence_id: occurrenceId,
    policy_version: policyVersion,
  });
}

function receiptFrom(args, extra) {
  if (isPlainObject(args)) {
    const ep = Object.getOwnPropertyDescriptor(args, '__ep');
    if (ep && 'value' in ep && isPlainObject(ep.value)) {
      const nested = Object.getOwnPropertyDescriptor(ep.value, 'receipt');
      if (nested && 'value' in nested) return normalizeReceipt(nested.value);
    }
    const direct = Object.getOwnPropertyDescriptor(args, 'emilia_receipt');
    if (direct && 'value' in direct) return normalizeReceipt(direct.value);
    const camelCase = Object.getOwnPropertyDescriptor(args, 'emiliaReceipt');
    if (camelCase && 'value' in camelCase) return normalizeReceipt(camelCase.value);
  }
  if (isPlainObject(extra)) {
    const meta = Object.getOwnPropertyDescriptor(extra, '_meta');
    if (!meta || !('value' in meta) || !isPlainObject(meta.value)) return null;
    const carried = Object.getOwnPropertyDescriptor(meta.value, 'emilia_receipt');
    if (carried && 'value' in carried) return normalizeReceipt(carried.value);
  }
  return null;
}

function stripReceiptControlArgs(args) {
  if (!isPlainObject(args)) throw new TypeError('tool_arguments_invalid');
  const clean = Object.create(null);
  for (const key of Reflect.ownKeys(args)) {
    if (typeof key !== 'string') throw new TypeError('tool_arguments_invalid');
    if (key === '__ep' || key === 'emilia_receipt' || key === 'emiliaReceipt') continue;
    clean[key] = dataValue(args, key);
  }
  return Object.freeze(clean);
}

function normalizeReceipt(value) {
  if (isPlainObject(value)) return value;
  if (typeof value === 'string') return parseReceiptCarrier(value);
  return null;
}

async function syncDirectory(directory) {
  const handle = await open(directory, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export class DurableReceiptStore {
  constructor(root) {
    if (typeof root !== 'string' || root.length === 0) {
      throw new TypeError('receipt store root is required');
    }
    this.root = path.resolve(root);
    this.ownership = new Map();
    this.durable = true;
    this.ownershipFenced = true;
  }

  async initialize() {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    return this;
  }

  location(receiptId) {
    if (typeof receiptId !== 'string' || receiptId.length === 0
        || Buffer.byteLength(receiptId, 'utf8') > 512) {
      throw new TypeError('invalid receipt identifier');
    }
    const digest = crypto.createHash('sha256').update(receiptId, 'utf8').digest('hex');
    return path.join(this.root, digest);
  }

  async reserve(receiptId) {
    const directory = this.location(receiptId);
    try {
      await mkdir(directory, { mode: 0o700 });
    } catch (error) {
      if (error && error.code === 'EEXIST') return false;
      throw error;
    }
    const token = crypto.randomBytes(32).toString('hex');
    const state = JSON.stringify({ state: 'reserved', owner_token: token });
    const handle = await open(path.join(directory, 'state.json'), 'wx', 0o600);
    try {
      await handle.writeFile(state, { encoding: 'utf8' });
      await handle.sync();
    } finally {
      await handle.close();
    }
    await syncDirectory(directory);
    await syncDirectory(this.root);
    this.ownership.set(receiptId, token);
    return true;
  }

  async ownedReservation(receiptId) {
    const token = this.ownership.get(receiptId);
    if (!token) throw new Error('consumption reservation not owned');
    const directory = this.location(receiptId);
    const encoded = await readFile(path.join(directory, 'state.json'), { encoding: 'utf8' });
    if (Buffer.byteLength(encoded, 'utf8') > 1024) throw new Error('invalid reservation state');
    const state = JSON.parse(encoded);
    const actual = Buffer.from(String(state.owner_token || ''), 'utf8');
    const expected = Buffer.from(token, 'utf8');
    if (state.state !== 'reserved'
        || actual.length !== expected.length
        || !crypto.timingSafeEqual(actual, expected)) {
      throw new Error('consumption reservation not owned');
    }
    return { directory, token };
  }

  async commit(receiptId) {
    const { directory, token } = await this.ownedReservation(receiptId);
    const temporary = path.join(directory, `state-${crypto.randomBytes(12).toString('hex')}.tmp`);
    const handle = await open(temporary, 'wx', 0o600);
    try {
      await handle.writeFile(
        JSON.stringify({ state: 'committed', owner_token: token }),
        { encoding: 'utf8' },
      );
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, path.join(directory, 'state.json'));
    await syncDirectory(directory);
    this.ownership.delete(receiptId);
    return true;
  }

  async release(receiptId) {
    const { directory } = await this.ownedReservation(receiptId);
    const entries = await readdir(directory);
    if (entries.length !== 1 || entries[0] !== 'state.json') {
      throw new Error('reservation contains unexpected state');
    }
    await unlink(path.join(directory, 'state.json'));
    await rmdir(directory);
    await syncDirectory(this.root);
    this.ownership.delete(receiptId);
    return true;
  }
}

function refusal(reason, status = 428, body = null, header = '') {
  return {
    status,
    headers: { 'Receipt-Required': header },
    body: body || { rejected: { reason } },
  };
}

export async function createReceiptRequiredDispatcher(options) {
  const {
    manifest,
    handlers,
    trustedKeys,
    store,
    approverKeys = {},
    rpId,
    allowedOrigins = [],
    quorumPolicies = {},
    audit = async () => {},
  } = options || {};
  const checkedManifest = validateActionRiskManifest(manifest);
  if (!checkedManifest.ok) throw new Error('action risk manifest is invalid');
  if (!isPlainObject(handlers)) throw new TypeError('handlers must be an object');
  if (!Array.isArray(trustedKeys) || trustedKeys.length === 0
      || trustedKeys.some((key) => typeof key !== 'string' || key.length === 0)) {
    throw new TypeError('at least one pinned EMILIA issuer key is required');
  }
  if (!store || !['reserve', 'commit', 'release'].every((method) => typeof store[method] === 'function')) {
    throw new TypeError('durable receipt store is required');
  }
  for (const requirement of manifest.actions) {
    if (!requirement.receipt_required || requirement.assurance_class === 'software') continue;
    if (!isPlainObject(approverKeys) || Object.keys(approverKeys).length === 0
        || typeof rpId !== 'string' || rpId.length === 0
        || !Array.isArray(allowedOrigins) || allowedOrigins.length === 0) {
      throw new TypeError('human-assurance trust pins are required');
    }
    if (requirement.assurance_class === 'quorum'
        && !isPlainObject(quorumPolicies[requirement.id])) {
      throw new TypeError(`pinned quorum policy is required: ${requirement.id}`);
    }
  }

  const gates = new Map();
  function gateFor(requirement) {
    let gate = gates.get(requirement.id);
    if (gate) return gate;
    gate = makeReceiptGate({
      action: requirement.action_type,
      trustedKeys,
      maxAgeSec: requirement.max_age_sec,
      statusCode: 428,
      manifestUrl: manifest.service.manifest_url,
      assuranceClass: requirement.assurance_class,
      quorum: requirement.quorum,
      requiredFields: requirement.execution_binding.required_fields,
      approverKeys,
      rpId,
      allowedOrigins,
      quorumPolicy: quorumPolicies[requirement.id],
      store,
    });
    gates.set(requirement.id, gate);
    return gate;
  }

  return async function guardedCallTool(name, args = {}, extra = {}) {
    const requirement = findActionRequirement(manifest, { protocol: 'mcp', tool: name });
    if (!requirement) {
      await audit({ decision: 'deny', reason: 'tool_not_registered', tool: String(name) });
      return refusal('tool_not_registered');
    }
    const handler = handlers[name];
    if (typeof handler !== 'function') {
      await audit({ decision: 'deny', reason: 'handler_unavailable', tool: name });
      return refusal('handler_unavailable');
    }
    if (!requirement.receipt_required) {
      try {
        const result = await handler(stripReceiptControlArgs(args), extra);
        await audit({ decision: 'allow', reason: 'receipt_not_required', tool: name });
        return { status: 200, headers: {}, body: result };
      } catch {
        await audit({ decision: 'deny', reason: 'handler_failed', tool: name });
        throw new Error('tool handler failed');
      }
    }

    let observedAction;
    try {
      observedAction = workloadSnapshot(args);
    } catch (error) {
      const reason = error instanceof Error ? error.message : 'workload_arguments_invalid';
      await audit({ decision: 'deny', reason, tool: name });
      return refusal(reason);
    }
    const receipt = receiptFrom(args, extra);
    const gate = gateFor(requirement);
    const result = await gate.run(receipt, { observedAction }, async (check) => {
      await audit({
        decision: 'invoke',
        reason: 'receipt_verified_and_reserved',
        tool: name,
        receipt_id_digest: crypto.createHash('sha256').update(check.receiptId).digest('hex'),
      });
      try {
        const handlerResult = await handler(observedAction, extra);
        await audit({ decision: 'allow', reason: 'effect_succeeded', tool: name });
        return handlerResult;
      } catch (error) {
        await audit({ decision: 'deny', reason: 'effect_indeterminate', tool: name });
        throw error;
      }
    });
    if (!result.ok) {
      const reason = result.body?.rejected?.reason || 'receipt_required';
      await audit({ decision: 'deny', reason, tool: name });
      return refusal(
        reason,
        result.status,
        result.body,
        receiptRequiredHeader({
          action: requirement.action_type,
          actionHash: result.body?.required?.action_hash,
          assuranceClass: requirement.assurance_class,
          quorum: requirement.quorum,
          maxAgeSec: requirement.max_age_sec,
          manifestUrl: manifest.service.manifest_url,
          requiredFields: requirement.execution_binding.required_fields,
        }),
      );
    }
    return {
      status: 200,
      headers: {},
      body: {
        result: result.result,
        evidence: {
          receipt_id: result.receiptId,
          outcome: result.outcome,
        },
      },
    };
  };
}
