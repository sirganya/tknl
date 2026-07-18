import type { Env } from "../env";
import type { AuthContext } from "../auth";
import { errorJson, json, statusForCode } from "../http";
import { SIG_CONTEXT, verifyJcsAny } from "../lib/crypto";
import { auditAppend } from "../services/audit";
import { performMint } from "./mint";

interface ApprovalBody {
  approval: { approval_id: string; decision: "approve" | "deny"; nonce: string };
  sig: string;
}

/**
 * POST /v1/approvals/{id} — above-threshold spends are only minted on an
 * approval credential signed by the human principal's own key (UTAP §7). Any
 * authenticated party may relay the signed credential; the signature is what
 * authorises.
 */
export async function handleDecideApproval(
  env: Env,
  auth: AuthContext | null,
  id: string,
  body: unknown,
): Promise<Response> {
  if (!auth) return errorJson(401, "unauthenticated", "credential required");
  const b = body as ApprovalBody | null;
  if (!b?.approval || typeof b.sig !== "string") {
    return errorJson(400, "bad_request", "body must be { approval: {approval_id, decision, nonce}, sig }");
  }
  if (b.approval.approval_id !== id) return errorJson(400, "id_mismatch", "approval_id does not match path");
  if (b.approval.decision !== "approve" && b.approval.decision !== "deny") {
    return errorJson(400, "bad_decision", "decision must be approve or deny");
  }

  const stub = env.APPROVAL_DO.get(env.APPROVAL_DO.idFromName(id));
  const rec = await stub.get();
  if (!rec) return errorJson(404, "not_found", "unknown approval");

  const principalKeys = await env.PRINCIPAL_DO.get(env.PRINCIPAL_DO.idFromName(rec.principal)).getKeys();
  const valid = await verifyJcsAny(principalKeys, SIG_CONTEXT.approval, b.approval, b.sig);
  if (!valid) {
    return errorJson(403, "bad_signature", "approval must be signed by the human principal's key");
  }

  if (b.approval.decision === "deny") {
    const decided = await stub.decide("denied", rec.principal);
    if (!decided.ok) return errorJson(statusForCode(decided.code), decided.code, decided.error);
    const audited = await auditAppend(env, rec.org, {
      event: "APPROVAL_DENIED",
      principal: rec.principal,
      agent: rec.agent,
      budget_ref: rec.budgetRef,
      amount: rec.request.amount,
      detail: `approval ${id} denied`,
    });
    if (!audited.ok) return errorJson(503, "audit_failed", audited.error);
    return json({ approval_id: id, status: "denied" });
  }

  // Approve: mark approved, then mint. If mint fails (e.g. budget drained in
  // the meantime) the approval stays approved with no token, and this endpoint
  // may be retried until a token is attached.
  if (rec.status === "pending") {
    const decided = await stub.decide("approved", rec.principal);
    if (!decided.ok) return errorJson(statusForCode(decided.code), decided.code, decided.error);
  } else if (rec.status !== "approved" || rec.tid) {
    return errorJson(409, "already_decided", `approval is ${rec.status}`);
  }

  const outcome = await performMint(env, rec.request, rec.agent, { approved: true });
  if (outcome.kind === "error") return errorJson(outcome.status, outcome.code, outcome.error);
  if (outcome.kind !== "minted") return errorJson(500, "unexpected", "approval mint did not produce a token");

  await stub.attachToken(outcome.token.tid);
  const audited = await auditAppend(env, rec.org, {
    event: "APPROVAL_GRANTED",
    tid: outcome.token.tid,
    principal: rec.principal,
    agent: rec.agent,
    budget_ref: rec.budgetRef,
    amount: rec.request.amount,
    detail: `approval ${id} granted`,
  });
  if (!audited.ok) {
    console.error("APPROVAL_GRANTED audit failed after successful mint", { id, error: audited.error });
  }
  return json({ approval_id: id, status: "approved", token: outcome.token, uri_query: outcome.uriQuery }, 201);
}

export async function handleGetApproval(env: Env, auth: AuthContext | null, id: string): Promise<Response> {
  const rec = await env.APPROVAL_DO.get(env.APPROVAL_DO.idFromName(id)).get();
  if (!rec) return errorJson(404, "not_found", "unknown approval");
  const allowed =
    auth?.kind === "bootstrap" ||
    (auth?.kind === "did" && (auth.did === rec.agent || auth.did === rec.principal || auth.org === rec.org));
  if (!allowed) return errorJson(auth ? 403 : 401, "forbidden", "not authorised for this approval");
  const { request: _request, ...publicView } = rec;
  return json({ approval: { ...publicView, amount: rec.request.amount } });
}
