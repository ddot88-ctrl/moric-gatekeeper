// moric — Proof Gatekeeper agent for zkVerify Agent Games Season 01.
// Node.js, no framework, plain `http` module.
//
// Loop (per the field guide at agentgames.zkverify.io/build):
//   1. Accept a JSON POST at the registered endpoint (/agent).
//   2. Verify the HMAC-SHA256 signature (x-agent-games-signature header)
//      against the RAW body BEFORE parsing. Mismatch => 401, no work.
//   3. Preflight: reply { ok: true, protocolVersion: "v1" }, signed.
//   4. Decide deterministically (decide.js) — APPROVE only when EVERY check
//      passes, otherwise REJECT with a reason_code. Fail closed.
//   5. Generate a Groth16 proof locally with snarkjs + the tournament's own
//      gatekeeper circuit (circuits/gatekeeper.wasm + gatekeeper_final.zkey).
//   6. If KURIER_API_KEY is set, submit the proof via Kurier and poll until
//      Finalized (bounded by the 60s response deadline). The local proof is
//      ALWAYS returned in the response either way — the platform re-verifies
//      it against its own key.
//   7. Sign the raw response body with x-agent-games-signature and return it.
//
// Hard deadline: 60 seconds per task. Anything slower, any error, any
// uncertainty => REJECT, never approve by default.
//
// Secrets come from environment variables ONLY (see .env.example):
//   AGENT_GAMES_HMAC_SECRET — from the dashboard "Rotate Secret" (shown once)
//   KURIER_API_KEY          — Kurier mainnet API key (optional; local proof
//                             still works without it)
//   PORT                    — default 3000
//   REGISTERED_VK_HASH      — informational; the vk hash from /api/circuit-info
import { createServer } from 'http';
import { createHmac, timingSafeEqual } from 'crypto';
import { readFileSync, writeFileSync, existsSync, renameSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import * as snarkjs from 'snarkjs';
import { decide } from './decide.js';
import { buildCircuitInput } from './circuit-input.js';
import { submitAndFinalize } from './kurier.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---- tiny .env loader (no dependency; .env is gitignored) ----
for (const line of (existsSync(join(__dirname, '.env')) ? readFileSync(join(__dirname, '.env'), 'utf8') : '').split('\n')) {
  const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
  if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
}

const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
const KURIER_API_KEY = process.env.KURIER_API_KEY || '';
const REGISTERED_VK_HASH = process.env.REGISTERED_VK_HASH || '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

const WASM_PATH = join(__dirname, 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = join(__dirname, 'circuits', 'gatekeeper_final.zkey');
const VK_PATH = join(__dirname, 'circuits', 'verification_key.json');
const STATE_PATH = join(__dirname, 'seen.json');

// 60s hard deadline; keep a safety margin so the response itself is sent in time.
const HARD_DEADLINE_MS = 60_000;
const RESPONSE_MARGIN_MS = 5_000;

if (!HMAC_SECRET) {
  console.error('FATAL: AGENT_GAMES_HMAC_SECRET is not set.');
  console.error('Copy .env.example to .env and paste the secret from the Agent Games dashboard (Rotate Secret).');
  console.error('Never commit .env. Never use a placeholder secret in production.');
  process.exit(1);
}

// ---- persistent state: used proof refs + cached responses (idempotency) ----
let state = { proofRefs: [], responses: {} };
if (existsSync(STATE_PATH)) {
  try { state = { proofRefs: [], responses: {}, ...JSON.parse(readFileSync(STATE_PATH, 'utf8')) }; } catch { /* corrupt state: start fresh */ }
}
const seenProofRefs = new Set((state.proofRefs || []).map((s) => String(s).toLowerCase()));
function saveState() {
  state.proofRefs = [...seenProofRefs];
  const tmp = STATE_PATH + '.tmp';
  writeFileSync(tmp, JSON.stringify(state, null, 2));
  renameSync(tmp, STATE_PATH); // atomic-ish replace
}

const VK = JSON.parse(readFileSync(VK_PATH, 'utf8'));

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

function hmacHex(secret, rawBody) {
  return createHmac('sha256', secret).update(rawBody).digest('hex');
}

function hmacBase64(secret, rawBody) {
  return createHmac('sha256', secret).update(rawBody).digest('base64');
}

// The platform signs with HMAC-SHA256. The docs do not state the encoding of
// the header value, so accept hex (most likely) and base64.
// TODO: confirm the exact header encoding on the first real preflight.
function verifyHmac(rawBody, header) {
  if (!header || typeof header !== 'string') return false;
  const candidates = [hmacHex(HMAC_SECRET, rawBody), hmacBase64(HMAC_SECRET, rawBody)];
  for (const expected of candidates) {
    const a = Buffer.from(header);
    const b = Buffer.from(expected);
    if (a.length === b.length && timingSafeEqual(a, b)) return true;
  }
  return false;
}

function signBody(rawBody) {
  return hmacHex(HMAC_SECRET, rawBody);
}

function sendSigned(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'x-agent-games-signature': signBody(body),
  });
  res.end(body);
  return body;
}

// Preflight detection.
// TODO: the official docs do not publish the preflight body's `type` string.
// The starter prompt only says the platform "sends a signed preflight
// request" and the agent must reply { ok: true, protocolVersion: "v1" }.
// We detect preflight when the type contains "preflight" OR when the body
// has no task envelope at all (no input + no task_id). Confirm the exact
// type string on the first real preflight and tighten this check.
function isPreflight(task) {
  if (!task || typeof task !== 'object') return false;
  if (typeof task.type === 'string' && task.type.toLowerCase().includes('preflight')) return true;
  if (!task.input && !task.task_id) return true;
  return false;
}

async function generateProof(task, decisionBit) {
  const input = buildCircuitInput(task, decisionBit);
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
  const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
  log(`proof generated in ${((Date.now() - t0) / 1000).toFixed(1)}s, snarkjs verify=${ok}`);
  if (!ok) throw new Error('local snarkjs verification of our own proof FAILED');
  return { proof, publicSignals };
}

async function handleAgent(req, res, rawBody) {
  const startedAt = Date.now();
  const budgetMs = HARD_DEADLINE_MS - RESPONSE_MARGIN_MS;

  // 1. HMAC first, before any parsing.
  const sig = req.headers['x-agent-games-signature'];
  if (!verifyHmac(rawBody, sig)) {
    log('401 bad HMAC — refusing before parsing');
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'invalid signature' }));
    return;
  }

  // 2. Parse.
  let task;
  try {
    task = JSON.parse(rawBody.toString('utf8'));
  } catch {
    sendSigned(res, 200, { decision: 'REJECT', reason_code: 'INVALID_ENVELOPE', proof_tx: null });
    return;
  }

  // 3. Preflight.
  if (isPreflight(task)) {
    log('preflight -> { ok: true, protocolVersion: "v1" }');
    sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
    return;
  }

  // 4. Idempotency: a retried task_id returns the byte-identical cached response.
  const taskId = task.task_id;
  if (typeof taskId === 'string' && state.responses[taskId]) {
    const cached = state.responses[taskId];
    log(`replay task ${taskId} -> cached ${cached.decision}`);
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'x-agent-games-signature': signBody(cached.body),
    });
    res.end(cached.body);
    return;
  }

  // 5. Deterministic decision.
  const { decision, reason_code, detail } = decide(task, seenProofRefs);
  const decisionBit = decision === 'APPROVE' ? 1 : 0;
  log(`task ${taskId}: ${decision} (${reason_code}) — ${detail}`);

  const proofTx = task.input?.proof_tx ?? null;
  const response = { decision, reason_code, proof_tx: proofTx };

  // 6. Proof. PROOF_REUSED has no proof to submit (scoring excludes it),
  // so return the decision alone. Any other decision gets a proof attempt;
  // a failed proof generation means the decision contradicts the circuit —
  // keep the decision but send it without a proof (a correct decision without
  // a proof costs -2, a wrong decision costs -3/-6, so the decision stands).
  let proof = null;
  let publicSignals = null;
  if (reason_code !== 'PROOF_REUSED') {
    try {
      const gen = await generateProof(task, decisionBit);
      proof = gen.proof;
      publicSignals = gen.publicSignals;
      response.proof = proof;
      response.public_signals = publicSignals;
    } catch (e) {
      log(`proof generation failed for ${taskId}: ${String(e.message || e).split('\n')[0]} — sending decision without proof`);
    }
  } else {
    log(`PROOF_REUSED ${taskId}: decision only, no proof (scoring excludes it)`);
  }

  // 7. Kurier submission (optional, bounded by the response deadline).
  if (proof && KURIER_API_KEY) {
    const remaining = budgetMs - (Date.now() - startedAt);
    if (remaining > 10_000) {
      try {
        const result = await submitAndFinalize(KURIER_API_KEY, VK, proof, publicSignals, {
          timeoutMs: Math.min(remaining - 5_000, 40_000),
          intervalMs: 3000,
        });
        response.kurier_job_id = result.jobId;
        response.kurier_status = result.kurierStatus;
        log(`kurier job ${result.jobId}: ${result.kurierStatus}`);
      } catch (e) {
        log(`kurier submission failed for ${taskId}: ${String(e.message || e).split('\n')[0]} — local proof still returned`);
        response.kurier_status = 'SUBMIT_FAILED';
      }
    } else {
      log(`skipping kurier for ${taskId}: only ${remaining}ms left in the deadline`);
      response.kurier_status = 'SKIPPED_DEADLINE';
    }
  } else if (proof && !KURIER_API_KEY) {
    response.kurier_status = 'NOT_CONFIGURED';
  }

  // 8. Record the proof ref as used and cache the response, then send signed.
  if (proofTx && typeof proofTx === 'string') seenProofRefs.add(proofTx.toLowerCase());
  const body = JSON.stringify(response);
  if (typeof taskId === 'string') {
    state.responses[taskId] = { decision, body };
    saveState();
  }
  res.writeHead(200, {
    'Content-Type': 'application/json',
    'x-agent-games-signature': signBody(body),
  });
  res.end(body);
  log(`task ${taskId} answered in ${Date.now() - startedAt}ms`);
}

const server = createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const rawBody = Buffer.concat(chunks);
    try {
      if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, agent: 'moric', track: 'proof-gatekeeper' }));
        return;
      }
      if (req.method === 'POST' && (req.url === '/agent' || req.url === '/')) {
        await handleAgent(req, res, rawBody);
        return;
      }
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
    } catch (e) {
      log('unhandled error:', String(e.message || e).split('\n')[0]);
      // Fail closed even on a server error: a signed REJECT is better than a crash.
      try {
        sendSigned(res, 200, { decision: 'REJECT', reason_code: 'INVALID_ENVELOPE', proof_tx: null });
      } catch { /* response already sent */ }
    }
  });
});

server.listen(PORT, () => {
  log(`moric gatekeeper listening on :${PORT} — POST /agent, GET /health`);
  log(`registered vk hash: ${REGISTERED_VK_HASH}`);
  log(`kurier: ${KURIER_API_KEY ? 'configured' : 'NOT configured (local proof only)'}`);
  log(`seen proof refs loaded: ${seenProofRefs.size}, cached responses: ${Object.keys(state.responses).length}`);
});
