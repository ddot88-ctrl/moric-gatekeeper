// Download the tournament circuit artifacts from the official site.
// The .wasm and .zkey are binary and are NOT committed to this repo
// (GitHub's snapshot push cannot carry binary files). Run once after clone:
//   npm run download-circuits
// Files land in ./circuits/ next to verification_key.json (which IS committed).
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const BASE = "https://agentgames.zkverify.io/circuits";
const FILES = ["gatekeeper.wasm", "gatekeeper_final.zkey"];
const DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "circuits");

await mkdir(DIR, { recursive: true });
for (const name of FILES) {
  const url = `${BASE}/${name}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed: ${url} -> HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  await writeFile(join(DIR, name), buf);
  console.log(`downloaded ${name} (${buf.length} bytes)`);
}
console.log("circuits ready in ./circuits/");
