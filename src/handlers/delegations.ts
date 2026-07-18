import type { Env } from "../env";
import type { AuthContext } from "../auth";
import type { DelegationCredential } from "../types";
import { errorJson, json, statusForCode } from "../http";
import { SIG_CONTEXT, verifyJcsAny } from "../lib/crypto";
import { isPersonDid, isValidDid, orgOfDid } from "../lib/did";
import { minBig, toMinor } from "../lib/money";
import { credentialSigningPayload } from "../lib/chain";
import { auditAppend } from "../services/audit";

const MAX_CHAIN_RESOLVE_DEPTH = 10;

function principalStub(env: Env, did: string) {
  return env.PRINCIPAL_DO.get(env.PRINCIPAL_DO.idFromName(did));
}

function validateShape(cred: DelegationCredential): string | null {
  if (!isValidDid(cred.iss) || !isValidDid(cred.sub)) return "iss and sub must be valid DIDs";
  if (cred.iss === cred.sub) return "iss and sub must differ";
  if (!cred.jti?.startsWith("dlg_")) return "jti must be a dlg_ identifier";
  if (typeof cred.nbf !== "number" || typeof cred.exp !== "number" || cred.nbf >= cred.exp) {
    return "nbf/exp must be numbers with nbf < exp";
  }
  const s = cred.scope;
  if (!s || typeof s.max_amount !== "string" || typeof s.ccy !== "string") return "scope.max_amount/ccy required";
  if (!Array.isArray(s.purposes) || s.purposes.length === 0) return "scope.purposes required";
  if (typeof s.max_depth !== "number" || s.max_depth < 0) return "scope.max_depth must be >= 0";
  try {
    toMinor(s.max_amount, s.ccy);
  } catch {
    return "scope.max_amount is not a valid amount";
  }
  return null;
}

/**
 * POST /v1/delegations — the delegator signs the credential client-side; the
 * CFP verifies it against the issuer's registered keys and records it so it
 * can be resolved and revoked. Full chain semantics are enforced at mint.
 */
export async function handleIssueDelegation(
  env: Env,
  auth: AuthContext | null,
  body: unknown,
): Promise<Response> {
  if (!auth || auth.kind !== "did") return errorJson(401, "unauthenticated", "credential required");
  const cred = (body as { credential?: DelegationCredential })?.credential;
  if (!cred) return errorJson(400, "bad_request", "body must be { credential }");
  const shapeError = validateShape(cred);
  if (shapeError) return errorJson(400, "bad_credential", shapeError);
  if (cred.iss !== auth.did) return errorJson(403, "forbidden", "only the delegator may register its credential");
  if (!isPersonDid(cred.iss) && !cred.parent_jti) {
    return errorJson(400, "parent_required", "non-root delegations must reference parent_jti");
  }

  const issuer = principalStub(env, cred.iss);
  const keys = await issuer.getKeys();
  const valid = await verifyJcsAny(keys, SIG_CONTEXT.delegation, credentialSigningPayload(cred), cred.sig);
  if (!valid) return errorJson(400, "bad_signature", "credential signature does not verify against issuer keys");

  const stored = await issuer.putDelegation(cred);
  if (!stored.ok) return errorJson(statusForCode(stored.code), stored.code, stored.error);
  await env.CONFIG_KV.put(`dlg:${cred.jti}`, JSON.stringify({ iss: cred.iss }));

  const audited = await auditAppend(env, orgOfDid(cred.iss), {
    event: "DELEGATION_ISSUED",
    principal: cred.iss,
    agent: cred.sub,
    detail: `jti ${cred.jti}, max ${cred.scope.max_amount} ${cred.scope.ccy}`,
  });
  if (!audited.ok) return errorJson(503, "audit_failed", audited.error);

  return json({ credential: cred }, 201);
}

async function findCredential(env: Env, jti: string): Promise<DelegationCredential | null> {
  const idx = await env.CONFIG_KV.get<{ iss: string }>(`dlg:${jti}`, "json");
  if (!idx) return null;
  return principalStub(env, idx.iss).getDelegation(jti);
}

/** DELETE /v1/delegations/{jti} — revocation is immediate and consistent
 * because the issuer's PrincipalDO is the single writer for its list. */
export async function handleRevokeDelegation(
  env: Env,
  auth: AuthContext | null,
  jti: string,
): Promise<Response> {
  if (!auth || auth.kind !== "did") return errorJson(401, "unauthenticated", "credential required");
  const cred = await findCredential(env, jti);
  if (!cred) return errorJson(404, "not_found", "unknown delegation");

  const sameOrgPerson = auth.isPerson && auth.org === orgOfDid(cred.iss);
  if (auth.did !== cred.iss && !sameOrgPerson) {
    return errorJson(403, "forbidden", "only the delegator or a same-org human principal may revoke");
  }

  await principalStub(env, cred.iss).revoke(jti);
  const audited = await auditAppend(env, orgOfDid(cred.iss), {
    event: "DELEGATION_REVOKED",
    principal: cred.iss,
    agent: cred.sub,
    detail: `jti ${jti} revoked by ${auth.did}`,
  });
  if (!audited.ok) return errorJson(503, "audit_failed", audited.error);
  return json({ revoked: jti });
}

/** GET /v1/delegations/{jti}/chain — resolve parent links and verify the
 * chain's structure (signatures, continuity, time, revocation, depth). */
export async function handleGetChain(env: Env, auth: AuthContext | null, jti: string): Promise<Response> {
  if (!auth) return errorJson(401, "unauthenticated", "credential required");

  const chain: DelegationCredential[] = [];
  let cursor: string | null = jti;
  while (cursor && chain.length < MAX_CHAIN_RESOLVE_DEPTH) {
    const cred: DelegationCredential | null = await findCredential(env, cursor);
    if (!cred) return errorJson(404, "not_found", `credential ${cursor} not found`);
    chain.unshift(cred);
    cursor = cred.parent_jti ?? null;
  }

  const now = Math.floor(Date.now() / 1000);
  const problems: string[] = [];
  let effectiveMax: bigint | null = null;
  const rootIss = chain[0]!.iss;
  if (!isPersonDid(rootIss)) problems.push("root issuer is not a person DID");

  for (let i = 0; i < chain.length; i++) {
    const cred = chain[i]!;
    if (i > 0 && cred.iss !== chain[i - 1]!.sub) problems.push(`hop ${i}: iss/sub discontinuity`);
    if (now < cred.nbf) problems.push(`hop ${i}: not yet valid`);
    if (now >= cred.exp) problems.push(`hop ${i}: expired`);
    if (await principalStub(env, cred.iss).isRevoked(cred.jti)) problems.push(`hop ${i}: revoked`);
    const keys = await principalStub(env, cred.iss).getKeys();
    if (!(await verifyJcsAny(keys, SIG_CONTEXT.delegation, credentialSigningPayload(cred), cred.sig))) {
      problems.push(`hop ${i}: signature invalid`);
    }
    const hopsBelow = chain.length - 1 - i;
    if (hopsBelow > cred.scope.max_depth) problems.push(`hop ${i}: depth exceeded`);
    try {
      const hopMax = toMinor(cred.scope.max_amount, cred.scope.ccy);
      effectiveMax = effectiveMax === null ? hopMax : minBig(effectiveMax, hopMax);
    } catch {
      problems.push(`hop ${i}: bad max_amount`);
    }
  }

  return json({
    chain,
    valid: problems.length === 0,
    problems,
    principal: rootIss,
    agent: chain[chain.length - 1]!.sub,
    effective_max_amount_minor: effectiveMax?.toString() ?? null,
  });
}
