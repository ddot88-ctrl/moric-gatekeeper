// moric — Proof Gatekeeper agent, Vercel serverless edition.
// Same request flow as server.js (HMAC -> preflight -> decide -> prove ->
// signed response), repackaged as a Vercel Serverless Function.
//
// Vercel-specific differences from server.js (read before deploying):
//   1. No long-running process: this is one invocation per request.
//      The raw body is read from the request stream (@vercel/node does NOT
//      pre-parse the body, so the HMAC check still sees the exact bytes).
//   2. Hobby tier: ~10s execution limit. The hot path (HMAC + decide +
//      local Groth16 proof) measures ~1-2s; that is what fits. Kurier
//      submission is SKIPPED in-request — the local proof is always returned
//      and the platform re-verifies it against its own key. (On a
//      long-running server, Kurier polling is bounded by the 60s deadline;
//      on serverless the function freezes after the response, so a
//      fire-and-forget Kurier call is not reliable. If on-chain Finalized
//      confirmations are ever required, run Kurier from a separate cron/queue,
//      not from this handler.)
//   3. No filesystem persistence: seen.json does not exist here. Used proof
//      refs + cached responses live in module-level memory — per warm
//      instance only. A retried task hitting a different instance will be
//      re-decided (the decision is deterministic, so the answer is the same)
//      but the PROOF_REUSED check may miss. Upgrade path: a shared store
//      (Vercel KV / Upstash Redis) for seenProofRefs.
//   4. Circuit files (circuits/gatekeeper.wasm + gatekeeper_final.zkey) are
//      NOT in the repo (binary). They are downloaded at BUILD time by the
//      `vercel-build` script (package.json) and bundled into the function
//      via vercel.json `includeFiles: "circuits/**"`.
//   5. Secrets come from Vercel env vars (dashboard), never from .env —
//      there is no .env loader here. AGENT_GAMES_HMAC_SECRET is read per
//      invocation; if it is missing the handler returns 500 (it cannot
//      verify or sign anything without it).
//
// Env vars (Vercel dashboard -> Settings -> Environment Variables):
//   AGENT_GAMES_HMAC_SECRET — required, from the dashboard "Rotate Secret"
//   KURIER_API_KEY          — optional; accepted but NOT used in-request here
//   REGISTERED_VK_HASH      — optional, informational only
import { createHmac, timingSafeEqual } from 'crypto';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import * as snarkjs from 'snarkjs';
import { decide } from '../decide.js';
import { buildCircuitInput } from '../circuit-input.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const WASM_PATH = join(ROOT, 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = join(ROOT, 'circuits', 'gatekeeper_final.zkey');
const VK_PATH = join(ROOT, 'circuits', 'verification_key.json');

// Vercel hobby limit is 10s. Keep a safety margin: if proof generation
// would start with less than ~3s of budget left, answer the decision
// without a proof (a correct decision without a proof costs -2; a timeout
// with no response costs -2 as well, but a response at least records the
// decision). In practice proof generation measures ~1-2s, so this rarely
// triggers.
const VERCEL_BUDGET_MS = 10_000;
const PROOF_CUTOFF_MS = 7_000;

// In-memory only (see header note 3). Warm instances keep this across
// invocations; cold starts and other instances start empty.
const seenProofRefs = new Set();
const cachedResponses = new Map();

// Verification key, loaded lazily on first proof (cold start stays light,
// and a missing file fails closed per-request instead of killing the module).
let VK = null;
function getVk() {
  if (!VK) VK = JSON.parse(readFileSync(VK_PATH, 'utf8'));
  return VK;
}

function log(...args) {
  console.log(new Date().toISOString(), '[vercel-agent]', ...args);
}

function hmacHex(secret, rawBody) {
  return createHmac('sha256', secret).update(rawBody).digest('hex');
}

function hmacBase64(secret, rawBody) {
  return createHmac('sha256', secret).update(rawBody).digest('base64');
}

// Same HMAC acceptance as server.js: hex (most likely) or base64.
function verifyHmac(secret, rawBody, header) {
  if (!header || typeof header !== 'string') return false;
  const candidates = [hmacHex(secret, rawBody), hmacBase64(secret, rawBody)];
  for (const expected of candidates) {
    const a = Buffer.from(header);
    const b = Buffer.from(expected);
    if (a.length === b.length && timingSafeEqual(a, b)) return true;
  }
  return false;
}

function signBody(secret, rawBody) {
  return hmacHex(secret, rawBody);
}

function sendSigned(res, secret, statusCode, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'x-agent-games-signature': signBody(secret, body),
  });
  res.end(body);
  return body;
}

// Same preflight detection as server.js (see its TODO: confirm the exact
// preflight `type` string on the first real preflight).
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
  const ok = await snarkjs.groth16.verify(getVk(), publicSignals, proof);
  log(`proof generated in ${((Date.now() - t0) / 1000).toFixed(1)}s, snarkjs verify=${ok}`);
  if (!ok) throw new Error('local snarkjs verification of our own proof FAILED');
  return { proof, publicSignals };
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1_000_000) {
        reject(new Error('body too large'));
        req.destroy();
      } else {
        chunks.push(c);
      }
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export default async function handler(req, res) {
  const startedAt = Date.now();

  // GET is a plain liveness check (no HMAC — the platform's tasks are POST).
  if (req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, agent: 'moric', track: 'proof-gatekeeper', runtime: 'vercel' }));
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'method not allowed' }));
    return;
  }

  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!secret) {
    log('500: AGENT_GAMES_HMAC_SECRET is not set in Vercel env vars');
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'server misconfigured: HMAC secret not set' }));
    return;
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (e) {
    log('body read failed:', String(e.message || e).split('\n')[0]);
    sendSigned(res, secret, 200, { decision: 'REJECT', reason_code: 'INVALID_ENVELOPE', proof_tx: null });
    return;
  }

  try {
    // 1. HMAC first, before any parsing.
    const sig = req.headers['x-agent-games-signature'];
    if (!verifyHmac(secret, rawBody, sig)) {
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
      sendSigned(res, secret, 200, { decision: 'REJECT', reason_code: 'INVALID_ENVELOPE', proof_tx: null });
      return;
    }

    // 3. Preflight.
    if (isPreflight(task)) {
      log('preflight -> { ok: true, protocolVersion: "v1" }');
      sendSigned(res, secret, 200, { ok: true, protocolVersion: 'v1' });
      return;
    }

    // 4. Idempotency: a retried task_id returns the byte-identical cached
    // response (per-instance memory only — see header note 3).
    const taskId = task.task_id;
    if (typeof taskId === 'string' && cachedResponses.has(taskId)) {
      const cached = cachedResponses.get(taskId);
      log(`replay task ${taskId} -> cached ${cached.decision}`);
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'x-agent-games-signature': signBody(secret, cached.body),
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

    // 6. Proof. Same rules as server.js: PROOF_REUSED has no proof;
    // a failed proof generation keeps the decision but sends it without
    // a proof. Extra serverless guard: do not start proof generation if
    // the 10s budget is nearly spent.
    let proof = null;
    let publicSignals = null;
    if (reason_code !== 'PROOF_REUSED') {
      const elapsed = Date.now() - startedAt;
      if (elapsed > PROOF_CUTOFF_MS) {
        log(`skipping proof for ${taskId}: ${elapsed}ms already spent of the ${VERCEL_BUDGET_MS}ms budget`);
      } else {
        try {
          const gen = await generateProof(task, decisionBit);
          proof = gen.proof;
          publicSignals = gen.publicSignals;
          response.proof = proof;
          response.public_signals = publicSignals;
        } catch (e) {
          log(`proof generation failed for ${taskId}: ${String(e.message || e).split('\n')[0]} — sending decision without proof`);
        }
      }
    } else {
      log(`PROOF_REUSED ${taskId}: decision only, no proof (scoring excludes it)`);
    }

    // 7. Kurier: SKIPPED in-request on serverless (see header note 2).
    // The local proof is always returned; the platform re-verifies it.
    if (proof) {
      response.kurier_status = process.env.KURIER_API_KEY ? 'SKIPPED_SERVERLESS' : 'NOT_CONFIGURED';
    }

    // 8. Record the proof ref as used and cache the response, then send signed.
    if (proofTx && typeof proofTx === 'string') seenProofRefs.add(proofTx.toLowerCase());
    const body = JSON.stringify(response);
    if (typeof taskId === 'string') {
      cachedResponses.set(taskId, { decision, body });
    }
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'x-agent-games-signature': signBody(secret, body),
    });
    res.end(body);
    log(`task ${taskId} answered in ${Date.now() - startedAt}ms`);
  } catch (e) {
    log('unhandled error:', String(e.message || e).split('\n')[0]);
    // Fail closed even on a handler error: a signed REJECT is better than a crash.
    try {
      sendSigned(res, secret, 200, { decision: 'REJECT', reason_code: 'INVALID_ENVELOPE', proof_tx: null });
    } catch { /* response already sent */ }
  }
}
