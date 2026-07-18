import type { Env } from "./env";
import { b64uDecode, fromUtf8, utf8 } from "./lib/encoding";
import { SIG_CONTEXT, sha256, verifyJcsAny } from "./lib/crypto";
import { isAgentDid, isPersonDid, isValidDid, orgOfDid } from "./lib/did";

/**
 * Request authentication.
 *
 * Agents, merchants and principals authenticate with a short-lived signed
 * request credential (never a long-lived static secret):
 *
 *   Authorization: Bearer utapv0.<b64u(JCS(payload))>.<b64u(sig)>
 *   payload = { sub: <did>, exp: <unix seconds>, nonce: <string> }
 *
 * The signature is Ed25519 by one of the sub DID's registered keys over
 * utf8("utap.v0.1.auth." + JCS(payload)). Bootstrap/admin calls use the
 * BOOTSTRAP_TOKEN secret directly. In production, enterprise clients would
 * additionally present mTLS client certificates via Cloudflare Access.
 */
export type AuthContext =
  | { kind: "bootstrap" }
  | { kind: "did"; did: string; org: string; isPerson: boolean; isAgent: boolean };

interface AuthPayload {
  sub: string;
  exp: number;
  nonce: string;
}

const MAX_CREDENTIAL_TTL_S = 15 * 60;

/** Constant-time secret comparison: compare SHA-256 digests with a full XOR
 * fold, so neither content nor length differences short-circuit. */
async function secretsMatch(a: string, b: string): Promise<boolean> {
  const [da, db] = await Promise.all([sha256(utf8(a)), sha256(utf8(b))]);
  let diff = 0;
  for (let i = 0; i < da.length; i++) diff |= da[i]! ^ db[i]!;
  return diff === 0;
}

export async function authenticate(request: Request, env: Env): Promise<AuthContext | null> {
  const header = request.headers.get("authorization");
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice("Bearer ".length).trim();

  if (env.BOOTSTRAP_TOKEN && (await secretsMatch(token, env.BOOTSTRAP_TOKEN))) {
    return { kind: "bootstrap" };
  }

  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "utapv0") return null;
  let payload: AuthPayload;
  try {
    payload = JSON.parse(fromUtf8(b64uDecode(parts[1]!))) as AuthPayload;
  } catch {
    return null;
  }
  if (typeof payload.sub !== "string" || !isValidDid(payload.sub)) return null;
  if (typeof payload.exp !== "number" || typeof payload.nonce !== "string") return null;
  if (payload.nonce.length < 8 || payload.nonce.length > 200) return null;

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now || payload.exp > now + MAX_CREDENTIAL_TTL_S + 60) return null;

  const principal = env.PRINCIPAL_DO.get(env.PRINCIPAL_DO.idFromName(payload.sub));
  const keys = await principal.getKeys();
  if (keys.length === 0) return null;

  const ok = await verifyJcsAny(keys, SIG_CONTEXT.auth, payload, "ed25519:" + parts[2]!);
  if (!ok) return null;

  // Single-use nonce: a captured credential cannot be replayed within its
  // TTL. Consumed only after signature verification so unauthenticated
  // parties cannot poison another DID's nonce space.
  const fresh = await principal.consumeAuthNonce(payload.nonce, payload.exp * 1000);
  if (!fresh) return null;

  return {
    kind: "did",
    did: payload.sub,
    org: orgOfDid(payload.sub),
    isPerson: isPersonDid(payload.sub),
    isAgent: isAgentDid(payload.sub),
  };
}

export function requireDid(auth: AuthContext | null): auth is Extract<AuthContext, { kind: "did" }> {
  return auth !== null && auth.kind === "did";
}
