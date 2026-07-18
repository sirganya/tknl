import { SELF } from "cloudflare:test";
import type { DelegationCredential } from "../src/types";
import { generateEd25519Jwk, SIG_CONTEXT, signJcs } from "../src/lib/crypto";
import { b64u, utf8 } from "../src/lib/encoding";
import { jcs } from "../src/lib/jcs";

export const BOOTSTRAP = "test-bootstrap-token";
const BASE = "https://cfp.example.ie";

export interface Actor {
  did: string;
  privateJwk: JsonWebKey;
  publicJwk: JsonWebKey;
}

export async function makeActor(did: string): Promise<Actor> {
  const pair = await generateEd25519Jwk();
  return { did, ...pair };
}

/** Register an actor's public key via the bootstrap endpoint. */
export async function registerActor(actor: Actor, kid = "k1"): Promise<void> {
  const res = await SELF.fetch(
    `${BASE}/v1/principals/${encodeURIComponent(actor.did)}/keys/${kid}`,
    {
      method: "PUT",
      headers: { authorization: `Bearer ${BOOTSTRAP}`, "content-type": "application/json" },
      body: JSON.stringify({ jwk: actor.publicJwk }),
    },
  );
  if (res.status !== 201) throw new Error(`registerActor failed: ${res.status} ${await res.text()}`);
}

/** Build the signed short-lived request credential used as Bearer auth. */
export async function authHeader(actor: Actor): Promise<string> {
  const payload = {
    sub: actor.did,
    exp: Math.floor(Date.now() / 1000) + 300,
    nonce: crypto.randomUUID(),
  };
  const sig = await signJcs(actor.privateJwk, SIG_CONTEXT.auth, payload);
  return `Bearer utapv0.${b64u(utf8(jcs(payload)))}.${sig.slice("ed25519:".length)}`;
}

export async function signDelegation(
  issuer: Actor,
  unsigned: Omit<DelegationCredential, "sig">,
): Promise<DelegationCredential> {
  const sig = await signJcs(issuer.privateJwk, SIG_CONTEXT.delegation, unsigned);
  return { ...unsigned, sig };
}

export interface CallOptions {
  method?: string;
  auth?: string;
  body?: unknown;
  idempotencyKey?: string;
}

export async function api(path: string, opts: CallOptions = {}): Promise<{ status: number; body: any }> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.auth) headers["authorization"] = opts.auth;
  const method = opts.method ?? (opts.body !== undefined ? "POST" : "GET");
  if (["POST", "DELETE", "PATCH"].includes(method)) {
    headers["idempotency-key"] = opts.idempotencyKey ?? crypto.randomUUID();
  }
  const res = await SELF.fetch(`${BASE}${path}`, {
    method,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

export function bootstrapAuth(): string {
  return `Bearer ${BOOTSTRAP}`;
}
