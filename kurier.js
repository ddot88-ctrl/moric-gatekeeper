// Kurier (zkVerify REST API) client — the RECOMMENDED verification path.
// Docs: https://docs.zkverify.io/handbook/quickstart and
// https://docs.zkverify.io/overview/getting-started/kurier
//
// Flow: register the verification key ONCE (returns a vkHash), then for each
// proof: submit-proof with that vkHash, poll job-status until "Finalized".
//
// Endpoints (mainnet): https://api.kurier.xyz/api/v1
//   POST /register-vk/:API_KEY
//   POST /submit-proof/:API_KEY
//   GET  /job-status/:API_KEY/:jobId
//
// The API key is passed as a URL path segment (Kurier's design, not a
// header). Never log the full URL. The key comes from KURIER_API_KEY env only.
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VK_CACHE_FILE = join(__dirname, 'kurier-vk.json');

export const KURIER_API_URL = process.env.KURIER_API_URL || 'https://api.kurier.xyz/api/v1';

// TODO: confirm KURIER_CHAIN_ID for Agent Games. The zkVerify docs example
// uses 11155111 (Sepolia) for a testnet flow; the tournament verifies on
// zkVerify mainnet with no EVM destination chain named in the field guide,
// so 0 is the placeholder. If Kurier rejects the submission, try the
// zkVerify mainnet chain id from the docs, or ask in the Agent Games channel.
export const KURIER_CHAIN_ID = Number(process.env.KURIER_CHAIN_ID || 0);

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-JSON error body */ }
  if (!res.ok) {
    throw new Error(`Kurier ${res.status}: ${text.slice(0, 300)}`);
  }
  return json;
}

async function getJson(url) {
  const res = await fetch(url, { method: 'GET' });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-JSON error body */ }
  if (!res.ok) {
    throw new Error(`Kurier ${res.status}: ${text.slice(0, 300)}`);
  }
  return json;
}

// Register the verification key once; cache the vkHash locally.
// vkObject is the parsed verification_key.json (snarkjs zkey export).
// Returns the vkHash string.
export async function registerVk(apiKey, vkObject) {
  if (existsSync(VK_CACHE_FILE)) {
    const cached = JSON.parse(readFileSync(VK_CACHE_FILE, 'utf8'));
    if (cached.vkHash) return cached.vkHash;
  }
  const regParams = {
    proofType: 'groth16',
    proofOptions: { library: 'snarkjs', curve: 'bn128' },
    vk: vkObject,
  };
  const res = await postJson(`${KURIER_API_URL}/register-vk/${apiKey}`, regParams);
  const vkHash = res.vkHash || res.meta?.vkHash || res.data?.vkHash;
  if (!vkHash) throw new Error(`register-vk returned no vkHash: ${JSON.stringify(res).slice(0, 300)}`);
  writeFileSync(VK_CACHE_FILE, JSON.stringify({ vkHash, registeredAt: new Date().toISOString() }, null, 2));
  return vkHash;
}

// Submit one proof. Returns { jobId }.
export async function submitProof(apiKey, { proof, publicSignals, vkHash }) {
  const params = {
    proofType: 'groth16',
    vkRegistered: true,
    chainId: KURIER_CHAIN_ID,
    proofData: {
      proof,
      publicSignals,
      vk: vkHash,
    },
  };
  const res = await postJson(`${KURIER_API_URL}/submit-proof/${apiKey}`, params);
  const jobId = res.jobId || res.data?.jobId;
  if (!jobId) throw new Error(`submit-proof returned no jobId: ${JSON.stringify(res).slice(0, 300)}`);
  return { jobId };
}

// Poll job-status until Finalized (or timeout). Returns the final status object.
// Statuses: Submitted -> IncludedInBlock -> Finalized.
export async function pollJob(apiKey, jobId, { timeoutMs = 40000, intervalMs = 3000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    last = await getJson(`${KURIER_API_URL}/job-status/${apiKey}/${jobId}`);
    const status = last.status || last.data?.status;
    if (status === 'Finalized') return { status, ...last };
    if (status && !['Submitted', 'IncludedInBlock', 'Pending', 'Processing'].includes(status)) {
      return { status, ...last };
    }
    await sleep(intervalMs);
  }
  return { status: 'TIMEOUT', lastStatus: last?.status || last?.data?.status || null, ...last };
}

// Full flow for one proof: ensure vk registered, submit, poll.
// Returns { vkHash, jobId, kurierStatus } — never throws for a poll timeout
// (returns kurierStatus TIMEOUT instead); throws only on submit errors.
export async function submitAndFinalize(apiKey, vkObject, proof, publicSignals, opts = {}) {
  const vkHash = await registerVk(apiKey, vkObject);
  const { jobId } = await submitProof(apiKey, { proof, publicSignals, vkHash });
  const polled = await pollJob(apiKey, jobId, opts);
  return { vkHash, jobId, kurierStatus: polled.status || 'UNKNOWN' };
}
