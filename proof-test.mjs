// Local proof test: generate + verify a Groth16 proof with the real gatekeeper circuit.
// Input encoding assumptions (TODO: confirm against a platform practice task):
//   - addresses (recipient, conditionRecipient): BigInt(address) directly (160-bit, fits the field)
//   - vk hashes (registeredVkHash, proofVkHash): BigInt(vkHex) mod FIELD_PRIME
//   - taskId: keccak256(task_id string) mod FIELD_PRIME
//   - salt: 0 (no salt field in the task envelope; agent-chosen, documented assumption)
//   - minimum, publicBalance, amount, maxTransfer, expiryBlock, currentBlock: plain integers
//   - decision: 1 = APPROVE, 0 = REJECT
import { createHash } from 'crypto';
import * as snarkjs from 'snarkjs';
import { writeFileSync, readFileSync } from 'fs';

const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const keccakMod = (s) => BigInt('0x' + createHash('sha3-256').update(s).digest('hex')) % FIELD_PRIME;
const addrToField = (a) => BigInt(a);
const vkToField = (h) => BigInt(h) % FIELD_PRIME;

const WASM = 'circuits/gatekeeper.wasm';
const ZKEY = 'circuits/gatekeeper_final.zkey';
const VK = JSON.parse(readFileSync('circuits/verification_key.json', 'utf8'));

function buildInput({ taskId, registeredVk, proofVk, minimum, publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision, salt = 0 }) {
  return {
    salt: salt.toString(),
    amount: amount.toString(),
    recipient: addrToField(recipient).toString(),
    decision: decision.toString(),
    minimum: minimum.toString(),
    publicBalance: publicBalance.toString(),
    expiryBlock: expiryBlock.toString(),
    currentBlock: currentBlock.toString(),
    conditionRecipient: addrToField(conditionRecipient).toString(),
    maxTransfer: maxTransfer.toString(),
    taskId: keccakMod(taskId).toString(),
    registeredVkHash: vkToField(registeredVk).toString(),
    proofVkHash: vkToField(proofVk).toString(),
  };
}

const VALID = {
  taskId: 'gk_24_9d1',
  registeredVk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
  proofVk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
  minimum: 1000,
  publicBalance: 1460,
  expiryBlock: 19842201,
  currentBlock: 19832000,
  recipient: '0xDe42a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c',
  conditionRecipient: '0xDe42a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c',
  amount: 500,
  maxTransfer: 1000,
};

async function tryProve(label, input) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const dt = ((Date.now() - t0) / 1000).toFixed(1);
    const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
    console.log(`${label}: PROOF GENERATED in ${dt}s, proof bytes=${JSON.stringify(proof).length}, verify=${ok ? 'OK' : 'FAIL'}`);
    console.log(`  publicSignals: [${publicSignals.join(', ')}]`);
    return { proof, publicSignals, ok };
  } catch (e) {
    const dt = ((Date.now() - t0) / 1000).toFixed(1);
    console.log(`${label}: PROOF GENERATION FAILED in ${dt}s — ${String(e.message || e).split('\n')[0]}`);
    return null;
  }
}

console.log('--- Gatekeeper circuit local proof test ---\n');

// 1. Valid condition, decision=APPROVE (1) -> should generate + verify
const r1 = await tryProve('1. VALID + APPROVE(1)', buildInput({ ...VALID, decision: 1 }));
if (r1) writeFileSync('/tmp/gk_proof_valid.json', JSON.stringify({ proof: r1.proof, publicSignals: r1.publicSignals }, null, 2));

// 2. Trap (recipient mismatch), decision=APPROVE (1) -> circuit should REFUSE (witness fails)
await tryProve('2. RECIPIENT_MISMATCH + APPROVE(1)', buildInput({ ...VALID, conditionRecipient: '0x1111111111111111111111111111111111111111', decision: 1 }));

// 3. Trap (recipient mismatch), decision=REJECT (0) -> should generate + verify
await tryProve('3. RECIPIENT_MISMATCH + REJECT(0)', buildInput({ ...VALID, conditionRecipient: '0x1111111111111111111111111111111111111111', decision: 0 }));

// 4. Valid condition, decision=REJECT (0) -> circuit should REFUSE
await tryProve('4. VALID + REJECT(0)', buildInput({ ...VALID, decision: 0 }));

// 5. VK substitution (proofVk != registeredVk), decision=REJECT (0) -> should generate + verify
await tryProve('5. VK_SUBSTITUTION + REJECT(0)', buildInput({ ...VALID, proofVk: '0x0000000000000000000000000000000000000000000000000000000000000001', decision: 0 }));

// 6. Threshold mismatch (balance < minimum), decision=REJECT (0) -> should generate + verify
await tryProve('6. THRESHOLD_MISMATCH + REJECT(0)', buildInput({ ...VALID, publicBalance: 500, decision: 0 }));

console.log('\nDone.');
