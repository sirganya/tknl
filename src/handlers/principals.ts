import type { Env } from "../env";
import type { AuthContext } from "../auth";
import { errorJson, json, statusForCode } from "../http";
import { isValidDid, orgOfDid } from "../lib/did";
import { auditAppend } from "../services/audit";

/**
 * PUT /v1/principals/{did}/keys/{kid} — register a public key for a DID.
 *
 * Bootstrap-only for first registration of an org's DIDs; afterwards a DID may
 * rotate its own keys and a human principal may register keys for DIDs in its
 * own org. In production this maps onto a real did:web resolution + mTLS
 * onboarding flow; the reference keeps a CFP-local key registry.
 */
export async function handlePutKey(
  env: Env,
  auth: AuthContext | null,
  did: string,
  kid: string,
  body: unknown,
): Promise<Response> {
  if (!isValidDid(did)) return errorJson(400, "bad_did", "invalid DID");
  const jwk = (body as { jwk?: JsonWebKey })?.jwk;
  if (!jwk) return errorJson(400, "bad_request", "body must be { jwk }");

  const allowed =
    auth?.kind === "bootstrap" ||
    (auth?.kind === "did" && (auth.did === did || (auth.isPerson && auth.org === orgOfDid(did))));
  if (!allowed) return errorJson(auth ? 403 : 401, "forbidden", "not authorised to register keys for this DID");

  const result = await env.PRINCIPAL_DO.get(env.PRINCIPAL_DO.idFromName(did)).addKey(kid, jwk);
  if (!result.ok) return errorJson(statusForCode(result.code), result.code, result.error);

  const audited = await auditAppend(env, orgOfDid(did), {
    event: "PRINCIPAL_KEY_ADDED",
    principal: did,
    detail: `kid ${kid} added by ${auth?.kind === "did" ? auth.did : "bootstrap"}`,
  });
  if (!audited.ok) return errorJson(503, "audit_failed", audited.error);

  return json({ did, kid }, 201);
}

/** GET /v1/principals/{did}/keys — public keys are public. */
export async function handleGetKeys(env: Env, did: string): Promise<Response> {
  if (!isValidDid(did)) return errorJson(400, "bad_did", "invalid DID");
  const keys = await env.PRINCIPAL_DO.get(env.PRINCIPAL_DO.idFromName(did)).getKeys();
  return json({ did, keys });
}
