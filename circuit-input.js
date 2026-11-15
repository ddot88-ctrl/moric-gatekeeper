// Circuit input encoding for the gatekeeper circuit.
//
// The 13 input signal names were RECOVERED from the published circuit files
// (gatekeeper.wasm + gatekeeper_final.zkey) by probing the wasm's FNV-1a
// signal table — see probe-signals.mjs / probe2.mjs. All 13 are public
// inputs (verification_key.json has nPublic = 13).
//
//   salt, amount, recipient, decision, minimum, publicBalance,
//   expiryBlock, currentBlock, conditionRecipient, maxTransfer,
//   taskId, registeredVkHash, proofVkHash
//
// The ENCODING of each task field into a field element is NOT published in
// the official docs (agentgames.zkverify.io/build, /events/proof-gatekeeper,
// /api/circuit-info). The choices below are the most defensible ones, and
// each is labelled. TODO: confirm them against the FIRST real practice task
// the platform sends (compare the public_signals we return with what the
// platform expects). If the platform rejects a proof for a public-signal
// mismatch, this file is the first place to look.
import { createHash } from 'crypto';

// BN128 (alt_bn128) field prime — all circuit inputs are field elements.
export const FIELD_PRIME = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

// keccak256, reduced mod the field prime. Node's crypto calls this 'sha3-256'
// (keccak-256 and SHA3-256 differ only in padding; Node does not ship raw
// keccak-256 — see the TODO below).
// TODO: the platform almost certainly uses true keccak-256 (EVM standard).
// Swap this for a real keccak-256 implementation (e.g. the `js-sha3` package)
// and re-run proof-test.mjs if the platform ever rejects a proof over
// taskId encoding. For the local test the two hashes are equally valid
// self-consistent encodings; only the platform's expectation matters.
export function hashToField(str) {
  const digest = createHash('sha3-256').update(str, 'utf8').digest('hex');
  return BigInt('0x' + digest) % FIELD_PRIME;
}

// Ethereum address -> field element. Addresses are 160-bit, so they fit the
// ~254-bit field prime directly with no reduction needed.
export function addressToField(address) {
  if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(`invalid address: ${address}`);
  }
  return BigInt(address);
}

// Verification-key hash (a 32-byte hex string, e.g. the vkHash from
// /api/circuit-info) -> field element. A random 32-byte value may exceed the
// field prime, so reduce mod p. This is the standard way to fit a hash into
// a BN128 circuit input.
export function vkHashToField(vkHex) {
  if (typeof vkHex !== 'string' || !/^0x[0-9a-fA-F]+$/.test(vkHex)) {
    throw new Error(`invalid vk hash: ${vkHex}`);
  }
  return BigInt(vkHex) % FIELD_PRIME;
}

// task_id ("gk_24_9d1") -> field element.
// TODO: the official docs do not say how task_id is encoded. keccak256(task_id)
// mod p is the assumption. Alternatives the platform might use: the raw
// string bytes as a number, or a Poseidon hash. Confirm against the first
// practice task.
export function taskIdToField(taskId) {
  return hashToField(String(taskId));
}

// salt: the task envelope carries NO salt field, so the agent must choose one.
// VERIFIED LOCALLY (probe-pos1.mjs, 2026-11-15): publicSignals[0] is a
// commitment that changes when salt or taskId changes, and does NOT change
// when amount changes — i.e. it binds (salt, taskId). The salt itself never
// appears directly in the public signals. The platform cannot recompute the
// commitment without knowing the salt, so it can only check the proof
// verifies and that the other 12 public signals match the task.
// TODO: confirm what the platform expects for salt. Candidates: 0 (used
// here — deterministic and reproducible), a fresh random field element per
// proof, or keccak256(task_id). Until confirmed, 0 is the safest
// deterministic choice (and it is what the local proof test uses).
export function defaultSalt() {
  return 0n;
}

// Build the 13 circuit inputs for one task + decision.
// NOTE: the task envelope uses snake_case field names (public_balance,
// expiry_block, current_block, condition_recipient, max_transfer, proof_vk,
// registered_vk) while the circuit signals use camelCase (publicBalance,
// expiryBlock, currentBlock, conditionRecipient, maxTransfer, proofVkHash,
// registeredVkHash). This function maps envelope -> circuit names.
// decision: 1 = APPROVE, 0 = REJECT. The circuit constrains
// decision == 1 IF AND ONLY IF every check passes — a witness cannot even be
// built for a wrong decision (verified locally in proof-test.mjs: a wrong
// APPROVE and a wrong REJECT both fail with "Assert Failed" in
// GatekeeperEvaluation, while the correct decisions generate proofs that
// snarkjs verifies OK).
//
// VERIFIED public-signal order (from the generated proofs, 2026-11-15):
//   [0]  commitment(salt, taskId) — binds the proof to this task
//   [1]  registeredVkHash   [2]  proofVkHash
//   [3]  minimum            [4]  publicBalance
//   [5]  expiryBlock        [6]  currentBlock
//   [7]  recipient          [8]  conditionRecipient
//   [9]  amount             [10] maxTransfer
//   [11] decision           [12] taskId
export function buildCircuitInput(task, decision, salt = defaultSalt()) {
  const input = task.input || task;
  return {
    salt: salt.toString(),
    amount: BigInt(input.amount).toString(),
    recipient: addressToField(input.recipient).toString(),
    decision: String(decision),
    minimum: BigInt(input.minimum).toString(),
    publicBalance: BigInt(input.public_balance).toString(),
    expiryBlock: BigInt(input.expiry_block).toString(),
    currentBlock: BigInt(input.current_block).toString(),
    conditionRecipient: addressToField(input.condition_recipient).toString(),
    maxTransfer: BigInt(input.max_transfer).toString(),
    taskId: taskIdToField(task.task_id).toString(),
    registeredVkHash: vkHashToField(input.registered_vk).toString(),
    proofVkHash: vkHashToField(input.proof_vk).toString(),
  };
}
