'use strict';
// Proof Gatekeeper decision logic + Groth16 proving (snarkjs).
//
// Protocol source of truth: https://agentgames.zkverify.io/build
// (task envelope + response examples + Security checklist, verified 2026-11-15).
//
// Task envelope (snake_case):
//   { type: "agent-games.proof-gatekeeper.v1", task_id, mode, issued_at,
//     deadline_at, input: { registered_vk, proof_vk, minimum, public_balance,
//     expiry_block, current_block, recipient, condition_recipient, amount,
//     max_transfer, proof_tx } }
//
// Decision: APPROVE only when ALL five checks pass, else REJECT.
// The circuit is the referee: the proof attests the decision is consistent
// with the inputs, so a wrong decision cannot produce a valid proof.

const fs = require('fs');
const path = require('path');
const { keccak256 } = require('js-sha3');

// BN128 scalar field prime.
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const REASON = {
  OK: 'OK',
  VK_SUBSTITUTION: 'VK_SUBSTITUTION', // only code confirmed verbatim on /build
  INSUFFICIENT_BALANCE: 'INSUFFICIENT_BALANCE',
  EXPIRED: 'EXPIRED',
  RECIPIENT_MISMATCH: 'RECIPIENT_MISMATCH',
  AMOUNT_EXCEEDS_MAX: 'AMOUNT_EXCEEDS_MAX',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
};

// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------

function toBigInt(value, name) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new Error(`${name} must be an integer, got ${value}`);
    }
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^-?\d+$/.test(s)) return BigInt(s);
  }
  throw new Error(`${name} is not a valid integer/hex value: ${String(value).slice(0, 80)}`);
}

// Reduce to a bn128 field element, returned as a decimal string.
// (The real registered vkHash 0x6b79...77b0 EXCEEDS the field prime, so the
// reduction is load-bearing, not cosmetic. snarkjs would reduce it too, but
// doing it explicitly keeps the mapping deterministic and testable.)
function toField(value, name) {
  const b = toBigInt(value, name);
  return (((b % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME).toString(10);
}

function hexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

// task_id -> circuit taskId field element.
// Numeric task ids are used as-is. String ids (e.g. "gk_8d31_...") are
// keccak256-hashed into the field. keccak is the platform's house hash
// (Steal the VFY publicInputsHash is keccak256 of ABI-packed fields), so it
// is the most likely mapping if the platform recomputes this signal.
function taskIdToField(taskId) {
  if (taskId === undefined || taskId === null || taskId === '') {
    throw new Error('task_id is missing');
  }
  if (typeof taskId === 'number' && Number.isInteger(taskId)) {
    return BigInt(taskId).toString(10);
  }
  if (typeof taskId === 'string' && /^\d+$/.test(taskId.trim())) {
    return BigInt(taskId.trim()).toString(10);
  }
  const hashHex = keccak256(String(taskId));
  return (BigInt('0x' + hashHex) % FIELD_PRIME).toString(10);
}

// Deterministic per-task salt: identical task -> identical proof, so replays
// and retries are byte-identical (no randomness anywhere in the agent).
function saltForTask(taskId) {
  const hashHex = keccak256('agent-games-gatekeeper-salt:' + String(taskId));
  return (BigInt('0x' + hashHex) % FIELD_PRIME).toString(10);
}

// ---------------------------------------------------------------------------
// Decision logic — the five checks, evaluated in a fixed order.
// Returns { decision: 1|0, reasonCode }.
// ---------------------------------------------------------------------------

function decide(input) {
  const required = [
    'registered_vk',
    'proof_vk',
    'minimum',
    'public_balance',
    'expiry_block',
    'current_block',
    'recipient',
    'condition_recipient',
    'amount',
    'max_transfer',
  ];
  for (const k of required) {
    if (input[k] === undefined || input[k] === null || input[k] === '') {
      throw new Error(`input.${k} is missing`);
    }
  }

  // (1) The proof's verification key must be the registered key.
  if (!hexEqual(input.registered_vk, input.proof_vk)) {
    return { decision: 0, reasonCode: REASON.VK_SUBSTITUTION };
  }
  // (2) Public balance must meet the minimum.
  if (toBigInt(input.public_balance, 'public_balance') < toBigInt(input.minimum, 'minimum')) {
    return { decision: 0, reasonCode: REASON.INSUFFICIENT_BALANCE };
  }
  // (3) The condition must not be expired (strict: current < expiry).
  if (toBigInt(input.current_block, 'current_block') >= toBigInt(input.expiry_block, 'expiry_block')) {
    return { decision: 0, reasonCode: REASON.EXPIRED };
  }
  // (4) The recipient must match the condition recipient.
  if (!hexEqual(input.recipient, input.condition_recipient)) {
    return { decision: 0, reasonCode: REASON.RECIPIENT_MISMATCH };
  }
  // (5) The amount must not exceed the max transfer.
  if (toBigInt(input.amount, 'amount') > toBigInt(input.max_transfer, 'max_transfer')) {
    return { decision: 0, reasonCode: REASON.AMOUNT_EXCEEDS_MAX };
  }
  return { decision: 1, reasonCode: REASON.OK };
}

// ---------------------------------------------------------------------------
// Circuit input mapping (camelCase signal names, decimal strings).
// ---------------------------------------------------------------------------

function toCircuitInput(taskId, input, decision) {
  return {
    registeredVkHash: toField(input.registered_vk, 'registered_vk'),
    proofVkHash: toField(input.proof_vk, 'proof_vk'),
    minimum: toField(input.minimum, 'minimum'),
    publicBalance: toField(input.public_balance, 'public_balance'),
    expiryBlock: toField(input.expiry_block, 'expiry_block'),
    currentBlock: toField(input.current_block, 'current_block'),
    recipient: toField(input.recipient, 'recipient'),
    conditionRecipient: toField(input.condition_recipient, 'condition_recipient'),
    amount: toField(input.amount, 'amount'),
    maxTransfer: toField(input.max_transfer, 'max_transfer'),
    decision: String(decision),
    taskId: taskIdToField(taskId),
    salt: saltForTask(taskId),
  };
}

// ---------------------------------------------------------------------------
// Circuit artifacts (resolved once, cached across warm invocations).
// ---------------------------------------------------------------------------

let cachedArtifacts = null;

function loadArtifacts() {
  if (cachedArtifacts) return cachedArtifacts;
  const candidates = [
    path.join(__dirname, '..', 'circuits'), // api/circuits (Vercel, includeFiles)
    path.join(__dirname, 'circuits'),
    path.join(process.cwd(), 'api', 'circuits'),
    path.join(process.cwd(), 'circuits'),
  ];
  for (const dir of candidates) {
    const wasmPath = path.join(dir, 'gatekeeper.wasm');
    const zkeyPath = path.join(dir, 'gatekeeper_final.zkey');
    if (fs.existsSync(wasmPath) && fs.existsSync(zkeyPath)) {
      cachedArtifacts = { wasmPath, zkeyPath, dir };
      return cachedArtifacts;
    }
  }
  throw new Error(
    'gatekeeper circuit artifacts not found (gatekeeper.wasm / gatekeeper_final.zkey)'
  );
}

// ---------------------------------------------------------------------------
// Proving. snarkjs is required lazily so the preflight path never pays for it.
// ---------------------------------------------------------------------------

async function prove(circuitInput) {
  const snarkjs = require('snarkjs');
  const { wasmPath, zkeyPath } = loadArtifacts();
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    wasmPath,
    zkeyPath
  );
  return { proof, publicSignals, proveMs: Date.now() - t0 };
}

module.exports = {
  decide,
  toCircuitInput,
  prove,
  loadArtifacts,
  taskIdToField,
  saltForTask,
  toField,
  FIELD_PRIME,
  REASON,
};
