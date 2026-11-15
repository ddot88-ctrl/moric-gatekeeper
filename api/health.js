// Liveness check for the Vercel deployment: GET /health (rewritten to /api/health).
// No HMAC — this is for our own monitoring, not a platform task.
export default function handler(req, res) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: true, agent: 'moric', track: 'proof-gatekeeper', runtime: 'vercel' }));
}
