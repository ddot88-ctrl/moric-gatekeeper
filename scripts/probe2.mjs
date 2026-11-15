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
  return '0'.repeat(16 - shash.length).concat(shash);
}
const wasmBuf = readFileSync('circuits/gatekeeper.wasm');
const mod = await WebAssembly.compile(wasmBuf);
const instance = await WebAssembly.instantiate(mod, {
  runtime: { exceptionHandler: () => {}, printErrorMessage: () => {}, writeBufferMessage: () => {}, showSharedRWMemory: () => {} },
});
const ex = instance.exports;
console.log('getInputSize() =', ex.getInputSize(), '| getWitnessSize() =', ex.getWitnessSize());
const candidates = [
  // 13th-signal hunt
  'proofTxHash', 'proof_tx_hash', 'tx_hash', 'referenceHash', 'refHash',
  'proofRefHash', 'nonce', 'salt', 'chainId', 'chain_id', 'domain', 'domainId',
  'issuedAt', 'deadlineAt', 'deadline', 'timestamp', 'time', 'createdAt',
  'vkHash', 'vk_hash', 'proofVk', 'registeredVk', 'proof_vk', 'registered_vk',
  'proofTx', 'tx', 'txHash', 'hash', 'proofHash', 'proofRef', 'proof_ref',
  'reference', 'ref', 'proofId', 'proof_id', 'valid', 'isValid', 'approved',
  'approve', 'isApproved', 'used', 'reused', 'isReused', 'seen',
  'conditionValid', 'isValidCondition', 'validCondition', 'allChecksPass',
  'checksPass', 'pass', 'result', 'outcome', 'balance', 'threshold',
  'minimumBalance', 'minBalance', 'public_balance', 'expiry_block',
  'current_block', 'condition_recipient', 'max_transfer', 'proof_tx',
  'task_id', 'mode', 'type', 'amount', 'recipient', 'decision', 'minimum',
  'publicBalance', 'expiryBlock', 'currentBlock', 'conditionRecipient',
  'maxTransfer', 'taskId', 'registeredVkHash', 'proofVkHash',
  // more naming variants
  'registeredVkHashHex', 'proofVkHashHex', 'vk', 'proofKey', 'conditionKey',
  'registeredKey', 'key', 'vkRegistered', 'vkProof', 'registered', 'proof',
  'transferAmount', 'transfer_amount', 'maxAmount', 'cap', 'limit',
  'expiryHeight', 'currentHeight', 'blockNumber', 'block_number',
  'recipientAddress', 'conditionAddress', 'toAddress', 'fromAddress',
  'sender', 'payer', 'payee', 'amountWei', 'amount_value',
  'isExpired', 'expired', 'isValidProof', 'proofValid', 'verified',
  'decisionValue', 'decisionBit', 'approveBit', 'shouldApprove',
  'gatekeeper', 'gatekeeperDecision', 'event', 'eventId', 'round', 'roundId',
  'agentId', 'agent_id', 'participant', 'owner',
  'proofTxHashHex', 'txHashHex', 'refHashHex', 'hashHex',
  'publicSignals', 'pubSignals', 'pubInputs', 'publicInputs',
  'inputHash', 'taskHash', 'envelopeHash', 'payloadHash',
];
const found = [];
for (const name of candidates) {
  const h = fnvHash(name);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  try {
    const size = ex.getInputSignalSize(hMSB, hLSB);
    if (size >= 1) { found.push([name, size]); console.log(`EXISTS  ${name}  (size ${size})`); }
  } catch (e) {}
}
console.log(`\nReal inputs found: ${found.length} (circuit expects ${ex.getInputSize()})`);
