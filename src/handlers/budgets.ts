import type { Env } from "../env";
import type { AuthContext } from "../auth";
import type { BudgetConfig, BudgetPolicy } from "../types";
import { errorJson, json, statusForCode } from "../http";
import { auditAppend } from "../services/audit";

function budgetStub(env: Env, ref: string) {
  return env.BUDGET_DO.get(env.BUDGET_DO.idFromName(ref));
}

interface PutBudgetBody {
  org?: string;
  parent?: string | null;
  limit: string;
  ccy: string;
  period: { start: string; end: string };
  policy?: BudgetPolicy;
}

/** PUT /v1/budgets/{ref} — create/update a budget node (bootstrap or a human
 * principal of the owning org). Children must be created after their parent. */
export async function handlePutBudget(
  env: Env,
  auth: AuthContext | null,
  ref: string,
  body: unknown,
): Promise<Response> {
  const b = body as PutBudgetBody | null;
  if (!b || typeof b.limit !== "string" || typeof b.ccy !== "string" || !b.period?.start || !b.period?.end) {
    return errorJson(400, "bad_request", "body must include limit, ccy, period {start, end}");
  }

  let org: string;
  if (auth?.kind === "bootstrap") {
    if (!b.org) return errorJson(400, "org_required", "bootstrap calls must specify org");
    org = b.org;
  } else if (auth?.kind === "did" && auth.isPerson) {
    org = auth.org;
    if (b.org && b.org !== org) return errorJson(403, "forbidden", "cannot create budgets for another org");
  } else {
    return errorJson(auth ? 403 : 401, "forbidden", "human principal or bootstrap credential required");
  }

  const parent = b.parent ?? null;
  if (parent) {
    const parentState = await budgetStub(env, parent).getState();
    if (!parentState.ok) return errorJson(422, "parent_not_found", `parent budget ${parent} is not configured`);
    if (parentState.budget.org !== org) return errorJson(403, "forbidden", "parent budget belongs to another org");
    if (parentState.budget.ccy !== b.ccy) return errorJson(422, "ccy_mismatch", "parent budget uses a different currency");
  }

  const cfg: BudgetConfig = {
    budget_ref: ref,
    org,
    parent,
    limit: b.limit,
    ccy: b.ccy,
    period: b.period,
    policy: b.policy ?? {},
  };
  const configured = await budgetStub(env, ref).configure(cfg);
  if (!configured.ok) return errorJson(statusForCode(configured.code), configured.code, configured.error);

  const audited = await auditAppend(env, org, {
    event: "BUDGET_CONFIGURED",
    budget_ref: ref,
    amount: { value: b.limit, ccy: b.ccy },
    detail: `parent=${parent ?? "none"} period=${b.period.start}..${b.period.end}`,
  });
  if (!audited.ok) return errorJson(503, "audit_failed", audited.error);

  try {
    await env.AUDIT_QUEUE.send({ type: "budget.index", ref, org, parent, ccy: b.ccy });
  } catch (e) {
    console.error("budget index enqueue failed", { ref, error: String(e) });
  }

  const state = await budgetStub(env, ref).getState();
  return json(state.ok ? { budget: state.budget } : { budget: cfg }, 201);
}

export async function handleGetBudget(env: Env, auth: AuthContext | null, ref: string): Promise<Response> {
  const state = await budgetStub(env, ref).getState();
  if (!state.ok) return errorJson(404, "not_found", "budget not configured");
  const allowed =
    auth?.kind === "bootstrap" || (auth?.kind === "did" && auth.org === state.budget.org);
  if (!allowed) return errorJson(auth ? 403 : 401, "forbidden", "not authorised for this budget");
  return json({ budget: state.budget });
}

/** POST /v1/budgets/{ref}/policy — human principal only (UTAP §10). */
export async function handleUpdatePolicy(
  env: Env,
  auth: AuthContext | null,
  ref: string,
  body: unknown,
): Promise<Response> {
  const state = await budgetStub(env, ref).getState();
  if (!state.ok) return errorJson(404, "not_found", "budget not configured");

  const isOrgPerson = auth?.kind === "did" && auth.isPerson && auth.org === state.budget.org;
  if (!isOrgPerson && auth?.kind !== "bootstrap") {
    return errorJson(auth ? 403 : 401, "forbidden", "policy updates require a human principal of the owning org");
  }

  const policy = (body as { policy?: BudgetPolicy })?.policy;
  if (!policy) return errorJson(400, "bad_request", "body must be { policy }");

  const updated = await budgetStub(env, ref).updatePolicy(policy);
  if (!updated.ok) return errorJson(statusForCode(updated.code), updated.code, updated.error);

  const audited = await auditAppend(env, state.budget.org, {
    event: "BUDGET_POLICY_UPDATED",
    budget_ref: ref,
    detail: `by ${auth?.kind === "did" ? auth.did : "bootstrap"}: ${JSON.stringify(policy)}`,
  });
  if (!audited.ok) return errorJson(503, "audit_failed", audited.error);

  const after = await budgetStub(env, ref).getState();
  return json({ budget: after.ok ? after.budget : null });
}
