import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import type { DOResult, Token, TokenState } from "../types";
import { err } from "../types";

/**
 * TokenDO — one per token, addressed by idFromName(tid).
 *
 * The DO is single-threaded, so concurrent redeem attempts are serialised by
 * the platform and double-spend prevention is a property of the state machine,
 * not of any lock we build:
 *
 *   issued ──▶ reserved ──▶ redeemed ──▶ settled
 *      │           │
 *      ├──▶ void   └──▶ void
 *      └──▶ expired
 */
export interface TokenRecord {
  token: Token;
  org: string;
  agent: string;
  /** Every DID in the delegation chain — used for read/void authorisation. */
  participants: string[];
  /** Budget refs leaf→root, so expiry/void can release the whole reservation walk. */
  budgetPath: string[];
  merchant?: string;
  mcc?: string;
  history: Array<{ state: TokenState; ts: string; actor?: string }>;
}

const TRANSITIONS: Record<TokenState, TokenState[]> = {
  issued: ["reserved", "void", "expired"],
  reserved: ["redeemed", "void", "expired"],
  redeemed: ["settled"],
  settled: [],
  void: [],
  expired: [],
};

export class TokenDO extends DurableObject<Env> {
  async create(rec: TokenRecord): Promise<DOResult> {
    const existing = await this.ctx.storage.get<TokenRecord>("rec");
    if (existing) return err("exists", `token ${rec.token.tid} already exists`);
    if (rec.token.state !== "issued") return err("bad_state", "tokens must be created in state issued");
    rec.history = [{ state: "issued", ts: new Date().toISOString() }];
    await this.ctx.storage.put("rec", rec);
    await this.ctx.storage.setAlarm(rec.token.exp * 1000);
    return { ok: true };
  }

  async get(): Promise<TokenRecord | null> {
    return (await this.ctx.storage.get<TokenRecord>("rec")) ?? null;
  }

  /** Rollback half of the mint saga: remove a token whose audit append failed. */
  async destroy(): Promise<DOResult> {
    const rec = await this.ctx.storage.get<TokenRecord>("rec");
    if (rec && rec.token.state !== "issued") {
      return err("bad_state", "refusing to destroy a token that has progressed past issued");
    }
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.deleteAlarm();
    return { ok: true };
  }

  /**
   * Merchant hold: issued → reserved, binding the token to one merchant DID.
   * This is the anti-replay step — any later reserve/redeem by a different
   * merchant is rejected. Same-merchant retries are idempotent.
   */
  async reserve(merchant: string): Promise<DOResult<{ token: Token; replay: boolean }>> {
    const rec = await this.ctx.storage.get<TokenRecord>("rec");
    if (!rec) return err("not_found", "unknown token");
    if (rec.token.state === "reserved" && rec.merchant === merchant) {
      return { ok: true, token: rec.token, replay: true };
    }
    const check = this.checkTransition(rec, "reserved");
    if (!check.ok) return check;
    const allow = rec.token.purpose.constraints?.merchant_allow;
    if (allow && !allow.includes(merchant)) {
      return err("merchant_not_allowed", "token purpose does not permit this merchant");
    }
    rec.token.state = "reserved";
    rec.merchant = merchant;
    rec.history.push({ state: "reserved", ts: new Date().toISOString(), actor: merchant });
    await this.ctx.storage.put("rec", rec);
    return { ok: true, token: rec.token, replay: false };
  }

  /** reserved → redeemed, only by the merchant the token is bound to. */
  async redeem(merchant: string, mcc?: string): Promise<DOResult<{ token: Token }>> {
    const rec = await this.ctx.storage.get<TokenRecord>("rec");
    if (!rec) return err("not_found", "unknown token");
    const check = this.checkTransition(rec, "redeemed");
    if (!check.ok) return check;
    if (rec.merchant !== merchant) {
      return err("merchant_mismatch", "token is reserved for a different merchant");
    }
    const constraints = rec.token.purpose.constraints;
    if (constraints?.merchant_allow && !constraints.merchant_allow.includes(merchant)) {
      return err("merchant_not_allowed", "token purpose does not permit this merchant");
    }
    if (constraints?.mcc_allow) {
      if (!mcc) return err("mcc_required", "token purpose requires a merchant category code");
      if (!constraints.mcc_allow.includes(mcc)) {
        return err("mcc_not_allowed", `mcc ${mcc} not permitted for this purpose`);
      }
    }
    rec.token.state = "redeemed";
    rec.mcc = mcc;
    rec.history.push({ state: "redeemed", ts: new Date().toISOString(), actor: merchant });
    await this.ctx.storage.put("rec", rec);
    return { ok: true, token: rec.token };
  }

  /** Compensation: a failed audit append after redeem rolls the state back. */
  async revertRedeem(): Promise<DOResult> {
    const rec = await this.ctx.storage.get<TokenRecord>("rec");
    if (!rec) return err("not_found", "unknown token");
    if (rec.token.state !== "redeemed") return err("bad_state", "not in redeemed");
    rec.token.state = "reserved";
    rec.history.push({ state: "reserved", ts: new Date().toISOString(), actor: "compensation" });
    await this.ctx.storage.put("rec", rec);
    return { ok: true };
  }

  /** Compensation: a failed audit append after reserve rolls the state back. */
  async revertReserve(): Promise<DOResult> {
    const rec = await this.ctx.storage.get<TokenRecord>("rec");
    if (!rec) return err("not_found", "unknown token");
    if (rec.token.state !== "reserved") return err("bad_state", "not in reserved");
    rec.token.state = "issued";
    delete rec.merchant;
    rec.history.push({ state: "issued", ts: new Date().toISOString(), actor: "compensation" });
    await this.ctx.storage.put("rec", rec);
    return { ok: true };
  }

  /** redeemed → settled (async settlement consumer / cron). */
  async settle(): Promise<DOResult<{ token: Token }>> {
    const rec = await this.ctx.storage.get<TokenRecord>("rec");
    if (!rec) return err("not_found", "unknown token");
    if (rec.token.state === "settled") return { ok: true, token: rec.token };
    const check = this.checkTransition(rec, "settled");
    if (!check.ok) return check;
    rec.token.state = "settled";
    rec.history.push({ state: "settled", ts: new Date().toISOString() });
    await this.ctx.storage.put("rec", rec);
    return { ok: true, token: rec.token };
  }

  /**
   * Explicit cancellation by the principal or any delegator above the agent.
   * The DO owns the full side-effect sequence (audit first — an unauditable
   * transition must not happen — then state, then reservation release, with
   * the budget TTL sweep as backstop if a release call fails).
   */
  async voidToken(caller: string): Promise<DOResult<{ token: Token }>> {
    const rec = await this.ctx.storage.get<TokenRecord>("rec");
    if (!rec) return err("not_found", "unknown token");
    if (rec.token.state === "void") return { ok: true, token: rec.token };
    const check = this.checkTransition(rec, "void");
    if (!check.ok) return check;
    const delegators = rec.participants.filter((did) => did !== rec.agent);
    if (!delegators.includes(caller)) {
      return err("forbidden", "only the principal or a delegator above the agent may void");
    }
    const audited = await this.auditAndFinalise(rec, "void", "TOKEN_VOIDED", caller);
    if (!audited.ok) return audited;
    return { ok: true, token: rec.token };
  }

  /** Expiry sweep — fires at token exp. */
  async alarm(): Promise<void> {
    const rec = await this.ctx.storage.get<TokenRecord>("rec");
    if (!rec) return;
    if (rec.token.state !== "issued" && rec.token.state !== "reserved") return;
    const result = await this.auditAndFinalise(rec, "expired", "TOKEN_EXPIRED");
    if (!result.ok) {
      // Audit chain unavailable — retry shortly rather than losing the expiry.
      await this.ctx.storage.setAlarm(Date.now() + 60_000);
    }
  }

  private async auditAndFinalise(
    rec: TokenRecord,
    state: "void" | "expired",
    event: "TOKEN_VOIDED" | "TOKEN_EXPIRED",
    actor?: string,
  ): Promise<DOResult> {
    const audit = this.env.AUDIT_DO.get(this.env.AUDIT_DO.idFromName(rec.org));
    const appended = await audit.append(rec.org, {
      event,
      tid: rec.token.tid,
      principal: rec.token.principal,
      agent: rec.agent,
      delegation_chain_hash: rec.token.delegation_chain_hash,
      amount: rec.token.amt,
      purpose_code: rec.token.purpose.code,
      budget_ref: rec.token.budget_ref,
      ...(actor ? { detail: `by ${actor}` } : {}),
    });
    if (!appended.ok) return err("audit_failed", `audit append failed: ${appended.error}`);

    rec.token.state = state;
    rec.history.push({ state, ts: new Date().toISOString(), actor });
    await this.ctx.storage.put("rec", rec);

    for (const ref of rec.budgetPath) {
      try {
        await this.env.BUDGET_DO.get(this.env.BUDGET_DO.idFromName(ref)).release(rec.token.tid);
      } catch (e) {
        // Reservation TTL sweep in BudgetDO cleans this up.
        console.error("budget release failed", { tid: rec.token.tid, ref, error: String(e) });
      }
    }
    return { ok: true };
  }

  private checkTransition(rec: TokenRecord, to: TokenState): DOResult {
    const from = rec.token.state;
    if (!TRANSITIONS[from].includes(to)) {
      return err("invalid_transition", `cannot transition ${from} -> ${to}`);
    }
    return { ok: true };
  }
}
