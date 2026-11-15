// Probe the gatekeeper circuit: brute-force input signal names by FNV-1a hash.
// The wasm maps input signal names to indices via their FNV-1a 64-bit hash
// (see circom_runtime js/witness_calculator.js). getInputSignalSize(hMSB, hLSB)
// returns >= 0 when the signal exists, < 0 when it does not.
import { readFileSync } from 'fs';

function fnvHash(str) {
  const uint64_max = BigInt(2) ** BigInt(64);
  let hash = BigInt('0xCBF29CE484222325');
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash *= BigInt(0x100000001B3);
    hash %= uint64_max;
  }
  let shash = hash.toString(16);
  shash = '0'.repeat(16 - shash.length).concat(shash);
  return shash;
}

const wasmBuf = readFileSync('circuits/gatekeeper.wasm');
const mod = await WebAssembly.compile(wasmBuf);
const instance = await WebAssembly.instantiate(mod, {
  runtime: {
    exceptionHandler: () => {},
    printErrorMessage: () => {},
    writeBufferMessage: () => {},
    showSharedRWMemory: () => {},
  },
});
const ex = instance.exports;
console.log('wasm version:', ex.getVersion(), ex.getMinorVersion(), ex.getPatchVersion());
console.log('getInputSize() =', ex.getInputSize());
console.log('getWitnessSize() =', ex.getWitnessSize());

const bases = [
  // task envelope fields (snake_case)
  'registered_vk', 'proof_vk', 'minimum', 'public_balance', 'expiry_block',
  'current_block', 'recipient', 'condition_recipient', 'amount', 'max_transfer',
  'proof_tx', 'task_id', 'mode', 'type', 'issued_at', 'deadline_at',
  // camelCase variants
  'registeredVk', 'proofVk', 'publicBalance', 'expiryBlock', 'currentBlock',
  'conditionRecipient', 'maxTransfer', 'proofTx', 'taskId',
  // decision / validity
  'decision', 'approve', 'approved', 'isApproved', 'valid', 'isValid',
  'result', 'outcome', 'pass', 'checksPass', 'allChecksPass',
  // vk hashes
  'vk_hash', 'vkHash', 'registeredVkHash', 'proofVkHash', 'registered_vk_hash',
  'proof_vk_hash', 'vkHashRegistered', 'vkHashProof',
  // balance / threshold synonyms
  'balance', 'threshold', 'min', 'minBalance', 'min_threshold', 'pub_balance',
  'publicBalanceValue',
  // block synonyms
  'expiry', 'expiration', 'exp_block', 'block', 'currentHeight', 'blockHeight',
  'block_number', 'currentBlockNumber',
  // recipient synonyms
  'expectedRecipient', 'to', 'payee', 'target', 'expected_recipient',
  // amount synonyms
  'cap', 'transferCap', 'maxAmount', 'transfer_cap', 'value',
  // proof reference synonyms
  'proof_ref', 'proofRef', 'proof_reference', 'reference', 'ref', 'tx',
  'txHash', 'proofHash', 'hash', 'proof_id', 'proofId',
  // reuse
  'used', 'reused', 'isReused', 'seen', 'alreadyUsed', 'isUsed', 'reuse',
  'proof_reused', 'proofReused',
  // misc
  'in0', 'in1', 'a', 'b', 'x', 'y', 'input', 'out', 'validCondition',
  'conditionValid', 'isValidCondition', 'gatekeeperDecision',
];

const found = [];
for (const name of bases) {
  const h = fnvHash(name);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  try {
    const size = ex.getInputSignalSize(hMSB, hLSB);
    if (size >= 0) {
      found.push([name, size]);
      console.log(`FOUND  ${name}  (size ${size})`);
    }
  } catch (e) {
    // signal does not exist
  }
}
// also try main.<name> prefix
for (const name of bases) {
  const prefixed = 'main.' + name;
  const h = fnvHash(prefixed);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  try {
    const size = ex.getInputSignalSize(hMSB, hLSB);
    if (size >= 0) {
      found.push([prefixed, size]);
      console.log(`FOUND  ${prefixed}  (size ${size})`);
    }
  } catch (e) {}
}
console.log(`\nTotal found: ${found.length} of ${ex.getInputSize()} inputs`);
console.log(JSON.stringify(found));
