import type { Env } from "../env";
import type { AuthContext } from "../auth";
import { errorJson, json, statusForCode } from "../http";
import { toMinor } from "../lib/money";
import { auditAppend } from "../services/audit";
import { commitWalk, uncommitWalk } from "../services/budgetWalk";
import { performMint, type MintRequest } from "./mint";

function requireDidAuth(auth: AuthContext | null) {
  if (!auth || auth.kind !== "did") return null;
  return auth;
}

export async function handleMint(env: Env, auth: AuthContext | null, body: unknown): Promise<Response> {
  const caller = requireDidAuth(auth);
  if (!caller) return errorJson(401, "unauthenticated", "agent credential required");
  if (!caller.isAgent) return errorJson(403, "forbidden", "only agents mint tokens");

  const outcome = await performMint(env, body as MintRequest, caller.did);
  switch (outcome.kind) {
    case "minted":
      return json({ token: outcome.token, uri_query: outcome.uriQuery }, 201);
    case "approval_required":
      return json(
        {
          status: "approval_required",
          approval_id: outcome.approvalId,
          detail: `amount exceeds requires_human_approval_above (${outcome.threshold}); a human principal must approve via POST /v1/approvals/${outcome.approvalId}`,
        },
        202,
      );
    case "error":
      return errorJson(outcome.status, outcome.code, outcome.error);
  }
}

export async function handleGetToken(env: Env, auth: AuthContext | null, tid: string): Promise<Response> {
  const rec = await env.TOKEN_DO.get(env.TOKEN_DO.idFromName(tid)).get();
  if (!rec) return errorJson(404, "not_found", "unknown token");

  // Possession of a token ID grants nothing without authentication: only the
  // CFP-known parties (chain participants, the bound merchant, or a merchant
  // on the purpose allow-list) may read full token state (UTAP §4.2, §11).
  let allowed = auth?.kind === "bootstrap";
  if (auth?.kind === "did") {
    const allow = rec.token.purpose.constraints?.merchant_allow;
    allowed =
      rec.participants.includes(auth.did) ||
      rec.merchant === auth.did ||
      (allow?.includes(auth.did) ?? false);
  }
  if (!allowed) return errorJson(auth ? 403 : 401, "forbidden", "not authorised for this token");

  return json({ token: rec.token, merchant: rec.merchant ?? null, history: rec.history });
}

export async function handleReserve(env: Env, auth: AuthContext | null, tid: string): Promise<Response> {
  const caller = requireDidAuth(auth);
  if (!caller) return errorJson(401, "unauthenticated", "merchant credential required");

  const stub = env.TOKEN_DO.get(env.TOKEN_DO.idFromName(tid));
  const result = await stub.reserve(caller.did);
  if (!result.ok) return errorJson(statusForCode(result.code), result.code, result.error);

  if (!result.replay) {
    const rec = (await stub.get())!;
    const audited = await auditAppend(env, rec.org, {
      event: "TOKEN_RESERVED",
      tid,
      principal: rec.token.principal,
      agent: rec.agent,
      amount: rec.token.amt,
      purpose_code: rec.token.purpose.code,
      budget_ref: rec.token.budget_ref,
      merchant: caller.did,
    });
    if (!audited.ok) {
      await stub.revertReserve();
      return errorJson(503, "audit_failed", "audit append failed; reservation rolled back");
    }
  }
  return json({ token: result.token });
}

export async function handleRedeem(
  env: Env,
  auth: AuthContext | null,
  tid: string,
  body: unknown,
): Promise<Response> {
  const caller = requireDidAuth(auth);
  if (!caller) return errorJson(401, "unauthenticated", "merchant credential required");
  const mcc = (body as { mcc?: string } | null)?.mcc;

  const stub = env.TOKEN_DO.get(env.TOKEN_DO.idFromName(tid));
  const before = await stub.get();
  if (!before) return errorJson(404, "not_found", "unknown token");

  // 1–3: state + merchant + purpose-constraint checks, serialised in the DO.
  const redeemed = await stub.redeem(caller.did, mcc);
  if (!redeemed.ok) return errorJson(statusForCode(redeemed.code), redeemed.code, redeemed.error);

  // 4: convert reservation to spend at every level of the budget walk.
  const amountMinor = toMinor(before.token.amt.value, before.token.amt.ccy).toString();
  const reReserveExpiry = Date.now() + 15 * 60 * 1000;
  const committed = await commitWalk(env, before.budgetPath, tid, amountMinor, reReserveExpiry);
  if (!committed.ok) {
    await stub.revertRedeem();
    return errorJson(statusForCode(committed.code), committed.code, committed.error);
  }

  // 5: synchronous audit append — failure compensates both prior steps.
  const audited = await auditAppend(env, before.org, {
    event: "TOKEN_REDEEMED",
    tid,
    principal: before.token.principal,
    agent: before.agent,
    delegation_chain_hash: before.token.delegation_chain_hash,
    amount: before.token.amt,
    purpose_code: before.token.purpose.code,
    budget_ref: before.token.budget_ref,
    budget_after: committed.leafAvailableAfter,
    merchant: caller.did,
  });
  if (!audited.ok) {
    await uncommitWalk(env, before.budgetPath, tid, amountMinor, reReserveExpiry);
    await stub.revertRedeem();
    return errorJson(503, "audit_failed", "audit append failed; redemption rolled back");
  }

  // 6: settlement is async (mock ledger in the reference implementation).
  try {
    await env.AUDIT_QUEUE.send({ type: "settle", tid, org: before.org });
  } catch (e) {
    console.error("settle enqueue failed; daily cron will pick it up", { tid, error: String(e) });
  }

  return json({ token: redeemed.token, budget_after: committed.leafAvailableAfter });
}

export async function handleVoid(env: Env, auth: AuthContext | null, tid: string): Promise<Response> {
  const caller = requireDidAuth(auth);
  if (!caller) return errorJson(401, "unauthenticated", "principal credential required");
  const result = await env.TOKEN_DO.get(env.TOKEN_DO.idFromName(tid)).voidToken(caller.did);
  if (!result.ok) return errorJson(statusForCode(result.code), result.code, result.error);
  return json({ token: result.token });
}
