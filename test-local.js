// Local end-to-end test harness for the moric gatekeeper.
// Spawns server.js with a TEST HMAC secret, then replays sample envelopes:
//   preflight, valid APPROVE, all 6 trap REJECTs, replay (idempotency),
//   proof reuse, bad HMAC, malformed JSON.
// Verifies: decisions, reason codes, response HMAC signatures, and that every
// returned proof verifies with snarkjs against the real verification key.
// No Kurier key is used here (KURIER_API_KEY unset -> kurier_status NOT_CONFIGURED).
// Run: npm test   (or: node test-local.js)
import { spawn } from 'child_process';
import { createHmac } from 'crypto';
import * as snarkjs from 'snarkjs';
import { readFileSync } from 'fs';

const PORT = 3456;
const TEST_SECRET = 'test-secret-for-local-only-NEVER-USE-IN-PRODUCTION';
const BASE = `http://127.0.0.1:${PORT}`;
const VK = JSON.parse(readFileSync(new URL('./circuits/verification_key.json', import.meta.url), 'utf8'));

const ADDR_A = '0xDe42a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c';
const ADDR_B = '0x1111111111111111111111111111111111111111';
const VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0x0000000000000000000000000000000000000000000000000000000000000001';

function task(overrides = {}, inputOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_test_001',
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

function sign(body) {
  return createHmac('sha256', TEST_SECRET).update(body).digest('hex');
}

async function post(path, obj, { badSig = false, rawBody = null } = {}) {
  const body = rawBody !== null ? rawBody : JSON.stringify(obj);
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-agent-games-signature': badSig ? 'deadbeef' : sign(body),
    },
    body,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, text, json, sig: res.headers.get('x-agent-games-signature') };
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
  const server = spawn('node', ['server.js'], {
    cwd: new URL('.', import.meta.url).pathname,
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: TEST_SECRET },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', (d) => process.stdout.write('[server] ' + d));
  server.stderr.on('data', (d) => process.stdout.write('[server:err] ' + d));

  // wait for health
  let up = false;
  for (let i = 0; i < 30 && !up; i++) {
    try {
      const r = await fetch(BASE + '/health');
      if (r.ok) up = true;
    } catch { await new Promise((r) => setTimeout(r, 500)); }
  }
  if (!up) { console.log('FAIL: server did not come up'); server.kill(); process.exit(1); }
  console.log('server up on :' + PORT);

  // 1. health
  const h = await fetch(BASE + '/health');
  check('GET /health -> ok', h.ok && (await h.json()).ok === true);

  // 2. preflight
  const pf = await post('/agent', { type: 'agent-games.preflight.v1' });
  check('preflight -> { ok: true, protocolVersion: "v1" }',
    pf.status === 200 && pf.json?.ok === true && pf.json?.protocolVersion === 'v1');
  check('preflight response is HMAC-signed', verifyResponseSig(pf.text, pf.sig));

  // 3. valid task -> APPROVE + proof that verifies
  const valid = task();
  const v = await post('/agent', valid);
  check('valid task -> APPROVE / VALID_CONDITION',
    v.status === 200 && v.json?.decision === 'APPROVE' && v.json?.reason_code === 'VALID_CONDITION');
  check('valid response is HMAC-signed', verifyResponseSig(v.text, v.sig));
  check('valid response carries proof + public_signals',
    !!v.json?.proof && Array.isArray(v.json?.public_signals) && v.json.public_signals.length === 13);
  if (v.json?.proof) {
    const ok = await verifyProof(v.json.proof, v.json.public_signals);
    check('valid APPROVE proof verifies with snarkjs', ok === true);
    console.log(`       proof bytes: ${JSON.stringify(v.json.proof).length}`);
  }

  // 4. replay same task_id -> byte-identical cached response
  const replay = await post('/agent', valid);
  check('replay task_id -> byte-identical cached body', replay.text === v.text);

  // 5. trap cases (each a fresh task_id, fresh proof_tx except the reuse case)
  const traps = [
    ['VK_SUBSTITUTION', { proof_vk: OTHER_VK }],
    ['THRESHOLD_MISMATCH', { public_balance: '500' }],
    ['EXPIRED_CONDITION', { current_block: 19842201 }],
    ['RECIPIENT_MISMATCH', { condition_recipient: ADDR_B }],
    ['AMOUNT_OVERFLOW', { amount: '1500' }],
  ];
  let n = 2;
  for (const [code, inputOver] of traps) {
    const t = task({ task_id: `gk_test_00${n}` }, { ...inputOver, proof_tx: `0xb${n}`.padEnd(66, '0') });
    const r = await post('/agent', t);
    check(`${code} -> REJECT / ${code}`,
      r.status === 200 && r.json?.decision === 'REJECT' && r.json?.reason_code === code);
    check(`${code} response is HMAC-signed`, verifyResponseSig(r.text, r.sig));
    check(`${code} carries a proof (non-reused trap)`, !!r.json?.proof && Array.isArray(r.json?.public_signals));
    if (r.json?.proof) {
      const ok = await verifyProof(r.json.proof, r.json.public_signals);
      check(`${code} REJECT proof verifies with snarkjs`, ok === true);
    }
    n++;
  }

  // 6. proof reuse: same proof_tx as the valid task, new task_id
  const reuse = task({ task_id: 'gk_test_099' }); // same proof_tx as `valid`
  const ru = await post('/agent', reuse);
  check('PROOF_REUSED -> REJECT / PROOF_REUSED, no proof',
    ru.status === 200 && ru.json?.decision === 'REJECT' && ru.json?.reason_code === 'PROOF_REUSED' && !ru.json?.proof);

  // 7. bad HMAC -> 401, no decision
  const bad = await post('/agent', task({ task_id: 'gk_test_100' }), { badSig: true });
  check('bad HMAC -> 401', bad.status === 401);

  // 8. malformed JSON -> signed REJECT INVALID_ENVELOPE
  const mal = await post('/agent', null, { rawBody: '{not json' });
  check('malformed JSON -> REJECT / INVALID_ENVELOPE (signed)',
    mal.status === 200 && mal.json?.decision === 'REJECT' && mal.json?.reason_code === 'INVALID_ENVELOPE'
    && verifyResponseSig(mal.text, mal.sig));

  console.log(`\n${passed} passed, ${failed} failed`);
  server.kill();
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error('test harness error:', e); process.exit(1); });
