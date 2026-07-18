#!/usr/bin/env node
/**
 * End-to-end UTAP demo against a running CFP (default: local `wrangler dev`).
 *
 *   Terminal 1:  cp .dev.vars.example .dev.vars   # + run `npm run genkey`
 *                npm run dev
 *   Terminal 2:  npm run demo
 *
 * Plays three parties — a human principal, a procurement agent, and a mock
 * vendor — through the full lifecycle: keys → budgets → delegation → mint →
 * reserve → redeem, then independently verifies the audit hash chain.
 */
import { webcrypto as crypto } from "node:crypto";

const BASE = process.env.CFP_URL ?? "http://localhost:8787";
const BOOTSTRAP = process.env.BOOTSTRAP_TOKEN ?? "dev-bootstrap";

// ---- minimal JCS (RFC 8785) + crypto helpers (mirrors src/lib) -------------
const jcs = (v) => {
  if (v === null || typeof v === "number" || typeof v === "boolean" || typeof v === "string")
    return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map((x) => jcs(x === undefined ? null : x)).join(",") + "]";
  const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
};
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const utf8 = (s) => new TextEncoder().encode(s);

async function newActor(did) {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  return {
    did,
    privateKey: pair.privateKey,
    publicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey),
  };
}
async function signJcs(actor, context, value) {
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, actor.privateKey, utf8(context + jcs(value)));
  return "ed25519:" + b64u(new Uint8Array(sig));
}
async function authHeader(actor) {
  const payload = { sub: actor.did, exp: Math.floor(Date.now() / 1000) + 300, nonce: crypto.randomUUID() };
  const sig = await signJcs(actor, "utap.v0.1.auth.", payload);
  return `Bearer utapv0.${b64u(utf8(jcs(payload)))}.${sig.slice("ed25519:".length)}`;
}
async function api(path, { method, auth, body } = {}) {
  method ??= body !== undefined ? "POST" : "GET";
  const headers = { "content-type": "application/json" };
  if (auth) headers.authorization = auth;
  if (["POST", "DELETE", "PUT"].includes(method)) headers["idempotency-key"] = crypto.randomUUID();
  const res = await fetch(BASE + path, { method, headers, body: body && JSON.stringify(body) });
  const json = await res.json().catch(() => null);
  if (!res.ok && res.status !== 202) {
    throw new Error(`${method} ${path} -> ${res.status}: ${JSON.stringify(json)}`);
  }
  return json;
}
const sha256hex = async (bytes) =>
  Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("hex");

// ---- the demo ---------------------------------------------------------------
const ORG = "acme.example";
const step = (msg) => console.log(`\n\x1b[1m▶ ${msg}\x1b[0m`);

step("Creating actors: human principal, procurement agent, mock vendor");
const person = await newActor(`did:web:${ORG}:person:gkavanagh`);
const agent = await newActor(`did:web:${ORG}:agent:procure-01`);
const vendor = await newActor("did:web:vendor.example");

for (const actor of [person, agent, vendor]) {
  await api(`/v1/principals/${encodeURIComponent(actor.did)}/keys/k1`, {
    method: "PUT",
    auth: `Bearer ${BOOTSTRAP}`,
    body: { jwk: { kty: actor.publicJwk.kty, crv: actor.publicJwk.crv, x: actor.publicJwk.x } },
  });
  console.log(`  registered ${actor.did}`);
}

step("Configuring budget hierarchy: bud_acme → bud_acme_eng_q3");
const year = new Date().getFullYear();
const period = { start: `${year}-01-01`, end: `${year + 1}-12-31` };
await api("/v1/budgets/bud_acme", {
  method: "PUT",
  auth: `Bearer ${BOOTSTRAP}`,
  body: { org: ORG, limit: "500000.00", ccy: "EUR", period },
});
await api("/v1/budgets/bud_acme_eng_q3", {
  method: "PUT",
  auth: `Bearer ${BOOTSTRAP}`,
  body: {
    org: ORG, parent: "bud_acme", limit: "250000.00", ccy: "EUR", period,
    policy: { purposes_allow: ["COMPUTE.*"], per_txn_max: "50000.00" },
  },
});
console.log("  budgets configured");

step("Human principal delegates spending authority to the agent");
const now = Math.floor(Date.now() / 1000);
const unsignedDelegation = {
  iss: person.did,
  sub: agent.did,
  scope: {
    max_amount: "50000.00", ccy: "EUR", purposes: ["COMPUTE.*", "DATA.LICENSE"],
    budget_refs: ["bud_acme_eng_q3"], max_depth: 2,
  },
  nbf: now - 60,
  exp: now + 7 * 86400,
  jti: "dlg_demo_" + Math.random().toString(36).slice(2, 10),
};
const delegation = {
  ...unsignedDelegation,
  sig: await signJcs(person, "utap.v0.1.delegation.", unsignedDelegation),
};
await api("/v1/delegations", { auth: await authHeader(person), body: { credential: delegation } });
console.log(`  delegation ${delegation.jti}: ${person.did} → ${agent.did}, max 50000.00 EUR`);

step("Agent mints a 40000.00 EUR token for GPU inference");
const minted = await api("/v1/tokens", {
  auth: await authHeader(agent),
  body: {
    amount: { value: "40000.00", ccy: "EUR" },
    purpose: {
      code: "COMPUTE.INFERENCE",
      desc: "GPU inference, batch job 8817",
      constraints: { merchant_allow: [vendor.did], mcc_allow: ["7372"] },
    },
    budget_ref: "bud_acme_eng_q3",
    chain: [delegation],
    ttl_seconds: 3600,
  },
});
const tid = minted.token.tid;
console.log(`  minted ${tid} (state=${minted.token.state})`);
console.log(`  payment URI params: ${minted.uri_query}`);

step("Vendor reserves (merchant hold) and redeems the token");
await api(`/v1/tokens/${tid}/reserve`, { auth: await authHeader(vendor), body: {} });
console.log("  reserved — token now bound to the vendor");
const redeemed = await api(`/v1/tokens/${tid}/redeem`, {
  auth: await authHeader(vendor),
  body: { mcc: "7372" },
});
console.log(`  redeemed — budget available after: ${redeemed.budget_after} EUR`);

step("Double-spend attempt (second redeem) — must be rejected");
try {
  await api(`/v1/tokens/${tid}/redeem`, { auth: await authHeader(vendor), body: { mcc: "7372" } });
  console.error("  ✗ UNEXPECTED: second redeem succeeded");
  process.exit(1);
} catch (e) {
  console.log(`  ✓ rejected: ${e.message.split(":").slice(1).join(":").trim().slice(0, 100)}`);
}

step("Independently verifying the audit hash chain");
const audit = await api(`/v1/audit/${ORG}/entries`, { auth: await authHeader(person) });
let prev = "sha256:" + (await sha256hex(utf8("utap.v0.1.audit-genesis:" + ORG)));
let verified = 0;
for (const entry of audit.entries) {
  const { entry_hash, ...rest } = entry;
  if (rest.prev_hash !== prev) throw new Error(`chain broken at seq ${entry.seq}`);
  const recomputed =
    "sha256:" + (await sha256hex(Buffer.concat([utf8(jcs(rest)), utf8(rest.prev_hash)])));
  if (recomputed !== entry_hash) throw new Error(`hash mismatch at seq ${entry.seq}`);
  prev = entry_hash;
  verified++;
}
console.log(`  ✓ ${verified} entries verified, head ${prev.slice(0, 30)}…`);
console.log(
  "  events:",
  audit.entries.map((e) => e.event).join(", "),
);

console.log("\n\x1b[32m✔ Demo complete: mint → reserve → redeem with double-spend rejection and a verifiable audit trail.\x1b[0m");
