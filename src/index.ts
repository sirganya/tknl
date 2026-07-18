import type { Env, QueueMessage } from "./env";
import { authenticate, type AuthContext } from "./auth";
import { ApiError, errorJson } from "./http";
import { withIdempotency } from "./idempotency";
import { toMinor } from "./lib/money";
import { auditAppend, checkpointOrg } from "./services/audit";
import { handleMint, handleGetToken, handleReserve, handleRedeem, handleVoid } from "./handlers/tokens";
import { handleIssueDelegation, handleRevokeDelegation, handleGetChain } from "./handlers/delegations";
import { handlePutBudget, handleGetBudget, handleUpdatePolicy } from "./handlers/budgets";
import { handleDecideApproval, handleGetApproval } from "./handlers/approvals";
import { handlePutKey, handleGetKeys } from "./handlers/principals";
import { handleAuditEntries, handleAuditCheckpoints, handleAuditProof } from "./handlers/audit";
import { handleCfpMetadata, handleJwks } from "./handlers/wellknown";

export { TokenDO } from "./do/token";
export { BudgetDO } from "./do/budget";
export { PrincipalDO } from "./do/principal";
export { AuditChainDO } from "./do/audit";
export { AuditDirectoryDO } from "./do/auditDirectory";
export { IdempotencyDO } from "./do/idempotency";
export { ApprovalDO } from "./do/approval";

interface Ctx {
  env: Env;
  request: Request;
  url: URL;
  params: Record<string, string>;
  auth: AuthContext | null;
  body: unknown;
}

interface Route {
  method: string;
  pattern: string[]; // segments; ":name" captures (URL-decoded)
  idempotent?: boolean; // wrap with the idempotency layer
  handler: (ctx: Ctx) => Promise<Response> | Response;
}

const routes: Route[] = [
  { method: "GET", pattern: [".well-known", "utap-cfp.json"], handler: (c) => handleCfpMetadata(c.env, c.url) },
  { method: "GET", pattern: [".well-known", "jwks.json"], handler: (c) => handleJwks(c.env) },

  { method: "POST", pattern: ["v1", "tokens"], idempotent: true, handler: (c) => handleMint(c.env, c.auth, c.body) },
  { method: "GET", pattern: ["v1", "tokens", ":tid"], handler: (c) => handleGetToken(c.env, c.auth, c.params["tid"]!) },
  { method: "POST", pattern: ["v1", "tokens", ":tid", "reserve"], idempotent: true, handler: (c) => handleReserve(c.env, c.auth, c.params["tid"]!) },
  { method: "POST", pattern: ["v1", "tokens", ":tid", "redeem"], idempotent: true, handler: (c) => handleRedeem(c.env, c.auth, c.params["tid"]!, c.body) },
  { method: "POST", pattern: ["v1", "tokens", ":tid", "void"], idempotent: true, handler: (c) => handleVoid(c.env, c.auth, c.params["tid"]!) },

  { method: "POST", pattern: ["v1", "delegations"], idempotent: true, handler: (c) => handleIssueDelegation(c.env, c.auth, c.body) },
  { method: "DELETE", pattern: ["v1", "delegations", ":jti"], idempotent: true, handler: (c) => handleRevokeDelegation(c.env, c.auth, c.params["jti"]!) },
  { method: "GET", pattern: ["v1", "delegations", ":jti", "chain"], handler: (c) => handleGetChain(c.env, c.auth, c.params["jti"]!) },

  { method: "PUT", pattern: ["v1", "budgets", ":ref"], handler: (c) => handlePutBudget(c.env, c.auth, c.params["ref"]!, c.body) },
  { method: "GET", pattern: ["v1", "budgets", ":ref"], handler: (c) => handleGetBudget(c.env, c.auth, c.params["ref"]!) },
  { method: "POST", pattern: ["v1", "budgets", ":ref", "policy"], idempotent: true, handler: (c) => handleUpdatePolicy(c.env, c.auth, c.params["ref"]!, c.body) },

  { method: "POST", pattern: ["v1", "approvals", ":id"], idempotent: true, handler: (c) => handleDecideApproval(c.env, c.auth, c.params["id"]!, c.body) },
  { method: "GET", pattern: ["v1", "approvals", ":id"], handler: (c) => handleGetApproval(c.env, c.auth, c.params["id"]!) },

  { method: "PUT", pattern: ["v1", "principals", ":did", "keys", ":kid"], handler: (c) => handlePutKey(c.env, c.auth, c.params["did"]!, c.params["kid"]!, c.body) },
  { method: "GET", pattern: ["v1", "principals", ":did", "keys"], handler: (c) => handleGetKeys(c.env, c.params["did"]!) },

  { method: "GET", pattern: ["v1", "audit", ":org", "entries"], handler: (c) => handleAuditEntries(c.env, c.auth, c.params["org"]!, c.url) },
  { method: "GET", pattern: ["v1", "audit", ":org", "checkpoints"], handler: (c) => handleAuditCheckpoints(c.env, c.params["org"]!) },
  { method: "GET", pattern: ["v1", "audit", ":org", "proof", ":seq"], handler: (c) => handleAuditProof(c.env, c.params["org"]!, c.params["seq"]!) },
];

function match(route: Route, method: string, segments: string[]): Record<string, string> | null {
  if (route.method !== method || route.pattern.length !== segments.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < segments.length; i++) {
    const p = route.pattern[i]!;
    const s = segments[i]!;
    if (p.startsWith(":")) params[p.slice(1)] = decodeURIComponent(s);
    else if (p !== s) return null;
  }
  return params;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const segments = url.pathname.split("/").filter(Boolean);

    try {
      for (const route of routes) {
        const params = match(route, request.method, segments);
        if (!params) continue;

        const bodyText = ["POST", "PUT", "DELETE", "PATCH"].includes(request.method)
          ? await request.text()
          : "";
        let body: unknown = null;
        if (bodyText) {
          try {
            body = JSON.parse(bodyText);
          } catch {
            return errorJson(400, "bad_json", "request body is not valid JSON");
          }
        }

        const auth = await authenticate(request, env);
        const ctx: Ctx = { env, request, url, params, auth, body };

        if (route.idempotent) {
          const callerKey = auth === null ? "anon" : auth.kind === "bootstrap" ? "bootstrap" : auth.did;
          return await withIdempotency(env, callerKey, request, bodyText, () =>
            Promise.resolve(route.handler(ctx)),
          );
        }
        return await route.handler(ctx);
      }
      return errorJson(404, "not_found", `no route for ${request.method} ${url.pathname}`);
    } catch (e) {
      if (e instanceof ApiError) return errorJson(e.status, e.code, e.message);
      console.error("unhandled error", { path: url.pathname, error: String(e) });
      return errorJson(500, "internal", "internal error");
    }
  },

  /** Async fan-out: D1 indexing, org/budget registries, mock settlement. */
  async queue(batch: MessageBatch<QueueMessage>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      try {
        await handleQueueMessage(env, message.body);
        message.ack();
      } catch (e) {
        console.error("queue message failed", { type: message.body.type, error: String(e) });
        message.retry();
      }
    }
  },

  async scheduled(event: ScheduledController, env: Env): Promise<void> {
    if (event.cron === "0 * * * *") await runCheckpoints(env);
    else if (event.cron === "15 3 * * *") await runReconciliation(env);
    else {
      await runCheckpoints(env);
      await runReconciliation(env);
    }
  },
} satisfies ExportedHandler<Env, QueueMessage>;

async function handleQueueMessage(env: Env, msg: QueueMessage): Promise<void> {
  switch (msg.type) {
    case "audit.index": {
      const e = msg.entry;
      const amountMinor = e.amount ? Number(toMinor(e.amount.value, e.amount.ccy)) : null;
      await env.DB.prepare(
        `INSERT OR IGNORE INTO audit_entries
           (org, seq, ts, event, tid, principal, agent, amount_minor, ccy, purpose_code, budget_ref, merchant, prev_hash, entry_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          e.org, e.seq, e.ts, e.event, e.tid ?? null, e.principal ?? null, e.agent ?? null,
          amountMinor, e.amount?.ccy ?? null, e.purpose_code ?? null, e.budget_ref ?? null,
          e.merchant ?? null, e.prev_hash, e.entry_hash,
        )
        .run();
      await env.DB.prepare("INSERT OR IGNORE INTO orgs (org, first_seen) VALUES (?, ?)")
        .bind(e.org, e.ts)
        .run();
      break;
    }
    case "budget.index": {
      await env.DB.prepare("INSERT OR REPLACE INTO budgets (ref, org, parent, ccy) VALUES (?, ?, ?, ?)")
        .bind(msg.ref, msg.org, msg.parent, msg.ccy)
        .run();
      break;
    }
    case "settle": {
      await settleToken(env, msg.tid, msg.org);
      break;
    }
  }
}

/** Mock-ledger settlement. The D1 insert doubles as the exactly-once guard for
 * at-least-once queue delivery: a second delivery changes no rows and stops. */
async function settleToken(env: Env, tid: string, org: string): Promise<void> {
  const stub = env.TOKEN_DO.get(env.TOKEN_DO.idFromName(tid));
  const rec = await stub.get();
  if (!rec || rec.token.state === "settled") return;
  if (rec.token.state !== "redeemed") {
    console.error("settle skipped: token not redeemed", { tid, state: rec.token.state });
    return;
  }

  const result = await env.DB.prepare(
    "INSERT OR IGNORE INTO mock_ledger (tid, org, amount_minor, ccy, merchant, settled_ts) VALUES (?, ?, ?, ?, ?, ?)",
  )
    .bind(
      tid, org, Number(toMinor(rec.token.amt.value, rec.token.amt.ccy)), rec.token.amt.ccy,
      rec.merchant ?? null, new Date().toISOString(),
    )
    .run();
  if (result.meta.changes === 0) return; // another delivery already settled it

  const settled = await stub.settle();
  if (!settled.ok) throw new Error(`settle transition failed: ${settled.error}`);

  const audited = await auditAppend(env, org, {
    event: "TOKEN_SETTLED",
    tid,
    principal: rec.token.principal,
    agent: rec.agent,
    amount: rec.token.amt,
    purpose_code: rec.token.purpose.code,
    budget_ref: rec.token.budget_ref,
    merchant: rec.merchant,
  });
  if (!audited.ok) throw new Error(`TOKEN_SETTLED audit failed: ${audited.error}`);
}

/** Hourly: per-org Merkle checkpoint into D1 + R2 (UTAP §9), covering every
 * chain segment with uncheckpointed entries — including a just-sealed
 * previous period. */
async function runCheckpoints(env: Env): Promise<void> {
  const orgs = await env.DB.prepare("SELECT org FROM orgs").all<{ org: string }>();
  for (const { org } of orgs.results) {
    const result = await checkpointOrg(env, org);
    if (!result.ok) console.error("checkpoint failed", { org, errors: result.errors });
  }
}

/**
 * Daily: for every budget, the derived spend from the audit chain (its own
 * leaf entries plus all descendants') must equal the BudgetDO's counter.
 * Divergence is a P1 — either a bug or tampering — and is itself audited.
 */
async function runReconciliation(env: Env): Promise<void> {
  const rows = await env.DB.prepare("SELECT ref, org, parent, ccy FROM budgets").all<{
    ref: string;
    org: string;
    parent: string | null;
    ccy: string;
  }>();
  const children = new Map<string, string[]>();
  for (const row of rows.results) {
    if (row.parent) children.set(row.parent, [...(children.get(row.parent) ?? []), row.ref]);
  }
  const subtree = (ref: string): string[] => [ref, ...(children.get(ref) ?? []).flatMap(subtree)];

  for (const row of rows.results) {
    const refs = subtree(row.ref);
    const placeholders = refs.map(() => "?").join(",");
    const sum = await env.DB.prepare(
      `SELECT COALESCE(SUM(amount_minor), 0) AS total FROM audit_entries
       WHERE org = ? AND event = 'TOKEN_REDEEMED' AND budget_ref IN (${placeholders})`,
    )
      .bind(row.org, ...refs)
      .first<{ total: number }>();

    const state = await env.BUDGET_DO.get(env.BUDGET_DO.idFromName(row.ref)).getState();
    if (!state.ok) continue;
    const doSpent = toMinor(state.budget.spent, state.budget.ccy);
    const derived = BigInt(sum?.total ?? 0);
    if (doSpent !== derived) {
      console.error("RECONCILIATION DIVERGENCE (P1)", {
        ref: row.ref, doSpentMinor: doSpent.toString(), derivedMinor: derived.toString(),
      });
      await auditAppend(env, row.org, {
        event: "RECONCILIATION_DIVERGENCE",
        budget_ref: row.ref,
        detail: `BudgetDO spent=${doSpent} vs audit-derived=${derived} (minor units)`,
      });
    }
  }
}
