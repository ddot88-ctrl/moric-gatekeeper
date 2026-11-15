// Deterministic decision checklist for Proof Gatekeeper.
// Pure function: task + seen-set -> { decision, reason_code }.
// No I/O, no randomness, no model — the code decides, never a language model.
//
// Reason codes are the 7 trap varieties from /events/proof-gatekeeper:
//   VALID_CONDITION, VK_SUBSTITUTION, THRESHOLD_MISMATCH, PROOF_REUSED,
//   EXPIRED_CONDITION, RECIPIENT_MISMATCH, AMOUNT_OVERFLOW
// plus two local codes for malformed input:
//   INVALID_ENVELOPE (missing/invalid fields, wrong type, bad timestamp)
//   HMAC_MISMATCH is handled by the server before this is called.
//
// Check order matters only for which reason_code is reported when several
// traps coincide; the decision (REJECT) is the same either way. Order follows
// the event page's trap list: VK first, then threshold, reuse, expiry,
// recipient, amount.
export const REASON_CODES = {
  VALID: 'VALID_CONDITION',
  VK: 'VK_SUBSTITUTION',
  THRESHOLD: 'THRESHOLD_MISMATCH',
  REUSED: 'PROOF_REUSED',
  EXPIRED: 'EXPIRED_CONDITION',
  RECIPIENT: 'RECIPIENT_MISMATCH',
  AMOUNT: 'AMOUNT_OVERFLOW',
  INVALID: 'INVALID_ENVELOPE',
};

function normHex(h) {
  return typeof h === 'string' ? h.toLowerCase() : h;
}

function isHexAddress(s) {
  return typeof s === 'string' && /^0x[0-9a-fA-F]{40}$/.test(s);
}

function isHexHash(s) {
  return typeof s === 'string' && /^0x[0-9a-fA-F]+$/.test(s);
}

function toBigInt(v) {
  try {
    if (typeof v === 'bigint') return v;
    if (typeof v === 'number') return BigInt(v);
    if (typeof v === 'string') return BigInt(v);
    return null;
  } catch {
    return null;
  }
}

// Validate the envelope shape. Returns an error reason string, or null if OK.
export function validateEnvelope(task) {
  if (!task || typeof task !== 'object') return 'task is not an object';
  if (task.type !== 'agent-games.proof-gatekeeper.v1') return `unexpected type: ${task.type}`;
  if (typeof task.task_id !== 'string' || task.task_id.length === 0) return 'missing task_id';
  const input = task.input;
  if (!input || typeof input !== 'object') return 'missing input';
  if (!isHexHash(input.registered_vk)) return 'bad registered_vk';
  if (!isHexHash(input.proof_vk)) return 'bad proof_vk';
  if (!isHexAddress(input.recipient)) return 'bad recipient';
  if (!isHexAddress(input.condition_recipient)) return 'bad condition_recipient';
  if (!isHexHash(input.proof_tx)) return 'bad proof_tx';
  for (const f of ['minimum', 'public_balance', 'amount', 'max_transfer']) {
    if (toBigInt(input[f]) === null || toBigInt(input[f]) < 0n) return `bad ${f}`;
  }
  for (const f of ['expiry_block', 'current_block']) {
    if (toBigInt(input[f]) === null || toBigInt(input[f]) < 0n) return `bad ${f}`;
  }
  // Timestamp sanity: a task whose deadline already passed cannot be approved.
  // (The security checklist requires "task signature and timestamp are valid".)
  if (task.deadline_at) {
    const deadline = Date.parse(task.deadline_at);
    if (Number.isNaN(deadline)) return 'bad deadline_at';
    if (deadline < Date.now()) return 'deadline already passed';
  }
  if (task.issued_at && Number.isNaN(Date.parse(task.issued_at))) return 'bad issued_at';
  return null;
}

// The checklist. `seenProofRefs` is a Set of proof_tx values already used.
// Returns { decision: 'APPROVE' | 'REJECT', reason_code, detail }.
// Fail closed: ANY validation failure or check failure => REJECT.
export function decide(task, seenProofRefs = new Set()) {
  const invalid = validateEnvelope(task);
  if (invalid) {
    return { decision: 'REJECT', reason_code: REASON_CODES.INVALID, detail: invalid };
  }
  const input = task.input;

  // 1. Verification key must match the registered condition key.
  if (normHex(input.proof_vk) !== normHex(input.registered_vk)) {
    return { decision: 'REJECT', reason_code: REASON_CODES.VK, detail: 'proof_vk != registered_vk' };
  }
  // 2. Public balance must meet the minimum threshold.
  if (toBigInt(input.public_balance) < toBigInt(input.minimum)) {
    return { decision: 'REJECT', reason_code: REASON_CODES.THRESHOLD, detail: 'public_balance < minimum' };
  }
  // 3. Proof reference must not have been used before.
  if (seenProofRefs.has(normHex(input.proof_tx))) {
    return { decision: 'REJECT', reason_code: REASON_CODES.REUSED, detail: 'proof_tx already used' };
  }
  // 4. Condition must not be expired (current block before expiry block).
  if (toBigInt(input.current_block) >= toBigInt(input.expiry_block)) {
    return { decision: 'REJECT', reason_code: REASON_CODES.EXPIRED, detail: 'current_block >= expiry_block' };
  }
  // 5. Recipient in the proof must match the payment condition address.
  if (normHex(input.recipient) !== normHex(input.condition_recipient)) {
    return { decision: 'REJECT', reason_code: REASON_CODES.RECIPIENT, detail: 'recipient != condition_recipient' };
  }
  // 6. Amount must be within the single-transfer cap.
  if (toBigInt(input.amount) > toBigInt(input.max_transfer)) {
    return { decision: 'REJECT', reason_code: REASON_CODES.AMOUNT, detail: 'amount > max_transfer' };
  }

  return { decision: 'APPROVE', reason_code: REASON_CODES.VALID, detail: 'all checks pass' };
}
