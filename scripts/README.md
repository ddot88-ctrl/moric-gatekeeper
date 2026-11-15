# scripts/ — one-off discovery probes (not part of the agent)

- `probe-signals.mjs` / `probe2.mjs` — how the 13 circuit input signal names
  were recovered: the gatekeeper.wasm maps input signal names to indices via
  their FNV-1a 64-bit hash (see circom_runtime's witness calculator). Calling
  `getInputSignalSize(hMSB, hLSB)` returns >= 1 when the signal exists.
  Result: salt, amount, recipient, decision, minimum, publicBalance,
  expiryBlock, currentBlock, conditionRecipient, maxTransfer, taskId,
  registeredVkHash, proofVkHash (13 total, matching nPublic = 13).
