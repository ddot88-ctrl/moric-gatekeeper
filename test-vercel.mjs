// Local test for the Vercel serverless handler (api/agent.js + api/health.js).
// Invokes the handler directly with mock req/res objects (no server, no
// deploy) and replays the same envelopes as test-local.js:
//   preflight, valid APPROVE, all 5 trap REJECTs, replay (idempotency),
//   proof reuse, bad HMAC, malformed JSON, missing HMAC secret.
// Verifies: decisions, reason codes, response HMAC signatures, and that every
// returned proof verifies with snarkjs against the real verification key.
// No Kurier key is used here (KURIER_API_KEY unset -> kurier_status NOT_CONFIGURED).
// Run: node test-vercel.mjs
import { Readable } from 'stream';
import { createHmac } from 'crypto';
import * as snarkjs from 'snarkjs';
import { readFileSync } from 'fs';
import handler from './api/agent.js';
import healthHandler from './api/health.js';

const TEST_SECRET = 'test-secret-for-local-only-NEVER-USE-IN-PRODUCTION';
const VK = JSON.parse(readFileSync(new URL('./circuits/verification_key.json', import.meta.url), 'utf8'));

const ADDR_A = '0xDe42a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c';
const ADDR_B = '0x1111111111111111111111111111111111111111';
const VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0x0000000000000000000000000000000000000000000000000000000000000001';

function task(overrides = {}, inputOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_vercel_001',
    mode: 'competition',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    input: {
      registered_vk: VK_HASH,
      proof_vk: VK_HASH,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: ADDR_A,
      condition_recipient: ADDR_A,
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xa4c1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      ...inputOverrides,
    },
    ...overrides,
  };
}

function sign(body, secret = TEST_SECRET) {
  return createHmac('sha256', secret).update(body).digest('hex');
}

// Mock Vercel req: a readable stream carrying the raw body, with the
// method/url/headers the handler reads. Mock res: captures status + headers
// + body. Awaiting the handler is enough — res.end() happens before it returns.
function mockReq({ method, url, headers, body }) {
  const stream = Readable.from([Buffer.from(body)]);
  stream.method = method;
  stream.url = url;
  stream.headers = headers;
  return stream;
}

function mockRes() {
  const res = {
    statusCode: null,
    headers: {},
    body: '',
    writeHead(status, headers) {
      this.statusCode = status;
      Object.assign(this.headers, headers || {});
    },
    end(chunk) {
      if (chunk) this.body += chunk;
    },
  };
  return res;
}

async function invoke(fn, opts) {
  const req = mockReq(opts);
  const res = mockRes();
  await fn(req, res);
  let json = null;
  try { json = JSON.parse(res.body); } catch { /* not JSON */ }
  return { status: res.statusCode, body: res.body, json, sig: res.headers['x-agent-games-signature'] };
}

async function post(path, obj, { badSig = false, rawBody = null } = {}) {
  const body = rawBody !== null ? rawBody : JSON.stringify(obj);
  return invoke(handler, {
    method: 'POST',
    url: path,
    headers: {
      'content-type': 'application/json',
      'x-agent-games-signature': badSig ? 'deadbeef' : sign(body),
    },
    body,
  });
}

function verifyResponseSig(text, sig) {
  if (!sig) return false;
  return sign(text) === sig;
}

async function verifyProof(proof, publicSignals) {
  return snarkjs.groth16.verify(VK, publicSignals, proof);
}

let passed = 0;
let failed = 0;
function check(label, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS  ${label}`); }
  else { failed++; console.log(`  FAIL  ${label} ${extra}`); }
}

async function main() {
  process.env.AGENT_GAMES_HMAC_SECRET = TEST_SECRET;
  delete process.env.KURIER_API_KEY;
  const t0 = Date.now();

  // 0. health handler (GET /health)
  const h = await invoke(healthHandler, { method: 'GET', url: '/health', headers: {}, body: '' });
  check('GET /health -> ok', h.status === 200 && h.json?.ok === true && h.json?.runtime === 'vercel');

  // 0b. GET /agent -> liveness JSON, no HMAC needed
  const g = await invoke(handler, { method: 'GET', url: '/agent', headers: {}, body: '' });
  check('GET /agent -> ok (liveness, no HMAC)', g.status === 200 && g.json?.ok === true);

  // 1. preflight
  const pf = await post('/agent', { type: 'agent-games.preflight.v1' });
  check('preflight -> { ok: true, protocolVersion: "v1" }',
    pf.status === 200 && pf.json?.ok === true && pf.json?.protocolVersion === 'v1');
  check('preflight response is HMAC-signed', verifyResponseSig(pf.body, pf.sig));

  // 2. valid task -> APPROVE + proof that verifies
  const valid = task();
  const v = await post('/agent', valid);
  check('valid task -> APPROVE / VALID_CONDITION',
    v.status === 200 && v.json?.decision === 'APPROVE' && v.json?.reason_code === 'VALID_CONDITION');
  check('valid response is HMAC-signed', verifyResponseSig(v.body, v.sig));
  check('valid response carries proof + public_signals',
    !!v.json?.proof && Array.isArray(v.json?.public_signals) && v.json.public_signals.length === 13);
  check('valid response kurier_status NOT_CONFIGURED (no key, skipped in-request)',
    v.json?.kurier_status === 'NOT_CONFIGURED');
  if (v.json?.proof) {
    const ok = await verifyProof(v.json.proof, v.json.public_signals);
    check('valid APPROVE proof verifies with snarkjs', ok === true);
    console.log(`       proof bytes: ${JSON.stringify(v.json.proof).length}`);
  }

  // 3. replay same task_id -> byte-identical cached response
  const replay = await post('/agent', valid);
  check('replay task_id -> byte-identical cached body', replay.body === v.body);

  // 4. trap cases (each a fresh task_id, fresh proof_tx)
  const traps = [
    ['VK_SUBSTITUTION', { proof_vk: OTHER_VK }],
    ['THRESHOLD_MISMATCH', { public_balance: '500' }],
    ['EXPIRED_CONDITION', { current_block: 19842201 }],
    ['RECIPIENT_MISMATCH', { condition_recipient: ADDR_B }],
    ['AMOUNT_OVERFLOW', { amount: '1500' }],
  ];
  let n = 2;
  for (const [code, inputOver] of traps) {
    const t = task({ task_id: `gk_vercel_00${n}` }, { ...inputOver, proof_tx: `0xc${n}`.padEnd(66, '0') });
    const r = await post('/agent', t);
    check(`${code} -> REJECT / ${code}`,
      r.status === 200 && r.json?.decision === 'REJECT' && r.json?.reason_code === code);
    check(`${code} response is HMAC-signed`, verifyResponseSig(r.body, r.sig));
    check(`${code} carries a proof (non-reused trap)`, !!r.json?.proof && Array.isArray(r.json?.public_signals));
    if (r.json?.proof) {
      const ok = await verifyProof(r.json.proof, r.json.public_signals);
      check(`${code} REJECT proof verifies with snarkjs`, ok === true);
    }
    n++;
  }

  // 5. proof reuse: same proof_tx as the valid task, new task_id
  const reuse = task({ task_id: 'gk_vercel_099' }); // same proof_tx as `valid`
  const ru = await post('/agent', reuse);
  check('PROOF_REUSED -> REJECT / PROOF_REUSED, no proof',
    ru.status === 200 && ru.json?.decision === 'REJECT' && ru.json?.reason_code === 'PROOF_REUSED' && !ru.json?.proof);

  // 6. bad HMAC -> 401, no decision
  const bad = await post('/agent', task({ task_id: 'gk_vercel_100' }), { badSig: true });
  check('bad HMAC -> 401', bad.status === 401);

  // 7. malformed JSON -> signed REJECT INVALID_ENVELOPE
  const mal = await post('/agent', null, { rawBody: '{not json' });
  check('malformed JSON -> REJECT / INVALID_ENVELOPE (signed)',
    mal.status === 200 && mal.json?.decision === 'REJECT' && mal.json?.reason_code === 'INVALID_ENVELOPE'
    && verifyResponseSig(mal.body, mal.sig));

  // 8. missing HMAC secret -> 500 (fail loudly, cannot verify or sign)
  delete process.env.AGENT_GAMES_HMAC_SECRET;
  const nosecret = await post('/agent', task({ task_id: 'gk_vercel_101' }));
  check('missing HMAC secret -> 500', nosecret.status === 500);
  process.env.AGENT_GAMES_HMAC_SECRET = TEST_SECRET;

  console.log(`\n${passed} passed, ${failed} failed (total ${((Date.now() - t0) / 1000).toFixed(1)}s)`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error('test harness error:', e); process.exit(1); });
