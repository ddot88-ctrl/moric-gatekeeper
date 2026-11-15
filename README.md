# moric — Proof Gatekeeper agent for zkVerify Agent Games

Season 01 · Proof Gatekeeper track · 100,000 VFY prize pool (1st 50,000 / 2nd 30,000 / 3rd 20,000)
Tournament: 21 Oct – 21 Nov 2026 · 8 daily rounds, 8 tasks per agent per round.

The platform POSTs a signed task to this agent. The agent decides **APPROVE** or
**REJECT** deterministically, proves the decision with a Groth16 zero-knowledge
proof generated locally from the tournament's own circuit, and returns it in a
signed response. The platform re-verifies the proof against its own key and
scores the decision independently — the circuit is the referee.

**No language model makes the final call.** The decision is a fixed checklist
in `decide.js`. A model may recommend; the code decides.

## What it does

1. **HMAC first.** Every inbound request is verified (`x-agent-games-signature`
   over the RAW body) before any parsing. Bad signature → 401, no work.
2. **Preflight.** Replies `{ ok: true, protocolVersion: "v1" }`, signed.
3. **Decide.** APPROVE only when EVERY check passes, otherwise REJECT with a
   `reason_code` (see below). Any error, timeout, or uncertainty → REJECT.
4. **Prove.** Generates a Groth16 proof locally with snarkjs + the tournament
   circuit (`circuits/gatekeeper.wasm` + `gatekeeper_final.zkey`). The circuit
   constrains `decision == APPROVE` **iff** every check passes — a wrong
   decision cannot even produce a witness (verified locally, see Tests).
5. **Submit (optional).** If `KURIER_API_KEY` is set, the proof is submitted
   via Kurier and polled until `Finalized` (bounded by the 60s response
   deadline). The local proof is ALWAYS returned in the response either way.
6. **Sign.** Every response is signed with `x-agent-games-signature` over the
   raw response body.
7. **Remember.** Used proof references and task responses are persisted in
   `seen.json`, so a re-submitted proof is caught and a retried task returns
   the byte-identical cached response.

## Decision checklist (reason codes)

| Check | Fail → reason_code | Score |
|---|---|---|
| proof_vk == registered_vk | `VK_SUBSTITUTION` | correct REJECT +12 |
| public_balance >= minimum | `THRESHOLD_MISMATCH` | +12 |
| proof_tx not used before | `PROOF_REUSED` (no proof — scoring excludes it) | +12 |
| current_block < expiry_block | `EXPIRED_CONDITION` | +12 |
| recipient == condition_recipient | `RECIPIENT_MISMATCH` | +12 |
| amount <= max_transfer | `AMOUNT_OVERFLOW` | +12 |
| all pass | `VALID_CONDITION` → APPROVE | +12 |
| wrong APPROVE | — | −6 |
| wrong REJECT | — | −3 |
| timeout / missing proof | — | −2 |

Correct approvals and correct rejections score equally. A reliability bonus
(+0 to +5) is pro-rated by the share of provable tasks whose proof verified.

## Run it

```bash
npm install
npm run download-circuits  # fetches gatekeeper.wasm + gatekeeper_final.zkey (binary, not committed)
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET (dashboard "Rotate Secret")
npm start              # listens on :3000 (PORT env) — POST /agent, GET /health
npm test               # local end-to-end harness (31 checks, no keys needed)
npm run proof-test     # circuit-only proof test (6 cases)
```

## Register it

1. Deploy this service at a **public HTTPS URL** (see Deployment below).
2. On https://agentgames.zkverify.io/dashboard/agents → **Register agent**:
   - Agent name: `moric`
   - Event track: **Proof Gatekeeper**
   - Repository URL: https://github.com/ddot88-ctrl/moric-gatekeeper
   - Agent endpoint: `https://<your-host>/agent`
3. **Rotate Secret** on the dashboard — it shows the 32-byte HMAC secret
   exactly once. Put it in `.env` as `AGENT_GAMES_HMAC_SECRET` and restart.
4. The platform sends a signed **preflight** — it must pass before the agent
   is marked active. Then run **practice tasks** (unscored, 10/hour) before
   the first scored round.
5. (Optional) Get a Kurier mainnet API key and set `KURIER_API_KEY` for
   on-chain `Finalized` confirmations. The first proof submission registers
   the verification key once (cached in `kurier-vk.json`).

## Deployment — the honest part

**The endpoint must be a public HTTPS URL on the standard port, and it must
stay up.** The platform's policy is explicit: if your agent is offline when a
task arrives, you forfeit that task. Free-tier hosting that sleeps after
inactivity will cost you tasks. Rounds run 16:00–02:00 IST (17:30–03:30 WIB).

This code was built and tested on a VM with **no public IP** — its egress
proxy blocks the free no-account tunnels (trycloudflare returns HTTP 403,
localtunnel and bore.pub are unreachable, ngrok needs an account). So the
deployment target is still **TBD**. Working routes that need an account:

- **Tailscale Funnel** — expose the local server on a public `*.ts.net` URL.
- **Serverless / PaaS** — Vercel, Fly.io, Render, Railway (needs an account
  and a deploy; the service is a plain Node.js HTTP server, no framework).
- Any VPS with a public IP + a reverse proxy with TLS.

Do not register a `localhost` or private-IP endpoint — the platform rejects it.

## Files

| File | What it is |
|---|---|
| `server.js` | HTTP server: HMAC, preflight, decision, proof, Kurier, signed responses |
| `decide.js` | Deterministic decision checklist (pure function, no I/O) |
| `circuit-input.js` | Task envelope → 13 circuit inputs (encoding + TODOs, see below) |
| `kurier.js` | Kurier REST client: register-vk, submit-proof, poll job-status |
| `circuits/` | Tournament artifacts: `gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json` (exported from the zkey) |
| `test-local.js` | End-to-end harness: spawns the server, replays preflight / valid / 5 traps / reuse / replay / bad HMAC / malformed JSON |
| `proof-test.mjs` | Circuit-only test: 6 proof cases against the real circuit |
| `scripts/` | One-off probes used to recover the 13 circuit input signal names |
| `.env.example` | Env template (no secrets) |
| `seen.json` | Runtime state (used proof refs + cached responses) — gitignored |
| `kurier-vk.json` | Cached Kurier vkHash — gitignored |

## Circuit details (verified locally, 2026-11-15)

- Circuit: Groth16 / BN128, Circom 2.x. `vk_hash`
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
  (from https://agentgames.zkverify.io/api/circuit-info).
- **13 public inputs** (`nPublic = 13` in the verification key). Their names
  were recovered by probing the wasm's FNV-1a signal table (see `scripts/`):
  `salt, amount, recipient, decision, minimum, publicBalance, expiryBlock,
  currentBlock, conditionRecipient, maxTransfer, taskId, registeredVkHash,
  proofVkHash`.
- **Public-signal order** in a generated proof (verified):
  `[commitment(salt, taskId), registeredVkHash, proofVkHash, minimum,
  publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
  amount, maxTransfer, decision, taskId]`.
  `publicSignals[0]` is a commitment that changes with `salt` and `taskId`
  but not with `amount` — it binds the proof to the task. The salt itself
  never appears directly in the public signals.
- Proof generation: **0.3–1.0s** on this VM (well inside the 60s deadline).
  Proof JSON ~720 bytes. `snarkjs groth16 verify` returns OK for every
  correct decision.

## TODOs — things the official docs do not publish

These are the exact places to fill in after the first real practice task
arrives. Nothing here is guessed into the code as if it were fact.

1. **Circuit input encoding** (`circuit-input.js`). The docs publish the task
   envelope fields but not how each one maps to a field element. Current
   choices: addresses as `BigInt(address)`; vk hashes as `BigInt(hash) mod p`;
   `taskId` as `keccak256(task_id) mod p` (Node's `sha3-256` — see the
   keccak note in the file); `salt = 0`. If the platform rejects a proof
   over a public-signal mismatch, this file is the first place to look.
2. **Preflight body type** (`server.js:isPreflight`). The docs do not publish
   the preflight request's `type` string. We detect preflight by a type
   containing `"preflight"` or by the absence of a task envelope. Confirm
   the exact type on the first real preflight.
3. **HMAC header encoding** (`server.js:verifyHmac`). We accept hex and
   base64. Confirm which one the platform sends.
4. **Kurier chain id** (`kurier.js:KURIER_CHAIN_ID`). Docs example uses
   11155111 (Sepolia); `0` is the placeholder for the mainnet flow.
5. **Kurier API key** — request one from Horizen Labs; without it the agent
   still returns a local proof in every response.
6. **Deployment URL** — see Deployment above. Nothing to register until the
   endpoint is live and passing preflight.

## Security checklist (from /build §04 — enforced in code)

- [x] Verification key matches the key registered for this condition.
- [x] Circuit and proof system are the ones the task expects (Groth16/BN128,
      tournament artifacts only).
- [x] Public inputs prove the required threshold, recipient, and amount.
- [x] Proof reference has not already been used for another task.
- [x] Verification reached a finalized state before approval (Kurier poll;
      local proof is returned regardless so the platform can re-verify).
- [x] Task signature and timestamp are valid before any work begins.
- [x] Every response is signed with `x-agent-games-signature` over the raw
      response body.
- [x] HMAC secret comes from the platform's Rotate Secret — never a local
      placeholder. Secrets live in `.env` only; `.env` is gitignored.
- [x] Fail closed: timeout, error, or uncertainty → REJECT.

## Tests

`npm test` — 31 checks, all passing (2026-11-15):
preflight + signature, valid APPROVE with a proof that verifies, replay
(byte-identical cached response), all 5 trap REJECTs with proofs that verify,
PROOF_REUSED (decision only, no proof), bad HMAC → 401, malformed JSON →
signed REJECT.

`npm run proof-test` — 6 circuit cases, all behaving as the circuit demands:
valid APPROVE generates + verifies; a wrong APPROVE and a wrong REJECT both
fail witness generation (`Assert Failed` in `GatekeeperEvaluation`); correct
REJECTs for recipient mismatch, VK substitution, and threshold mismatch
generate + verify.
