import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import type { BudgetConfig, BudgetState, DOResult } from "../types";
import { err } from "../types";
import { fromMinor, toMinor } from "../lib/money";
import { purposeAllowed } from "../lib/purpose";

/**
 * BudgetDO — one per budget node, addressed by idFromName(budget_ref).
 *
 * Nodes form a tree (org → division → team → project). The Worker orchestrates
 * a leaf-to-root reservation walk (consistent lock ordering, UTAP §7); each
 * node is the single writer for its own counters so a decrement is atomic by
 * construction. Reservations carry a TTL and are swept by alarm — the release
 * half of the mint saga's compensation path.
 *
 * ## Scaling path: sharding a hot node (documented, deliberately NOT built)
 *
 * A single node serialises its subtree's reservations. When measurement shows
 * a node's request rate is the limit, split it into N sub-counters
 * (`{ref}#0..N-1`), each holding a fixed share of the limit. A reservation
 * hashes its tid to a shard; on "insufficient" it may try one sibling before
 * failing. A rebalance cron periodically moves headroom between shards
 * (drain: lower a shard's share no further than its current spent+reserved;
 * top up another by the drained amount, so the sum of shares never exceeds
 * the parent limit at any instant). Costs exactness at the margin — a request
 * can be refused while another shard still has headroom — which is the
 * accepted trade for N× write throughput. Ancestor nodes aggregate shard
 * totals via their own walk entries, so the tree invariant is unchanged.
 * See docs/scaling.md.
 */
interface Reservation {
  amountMinor: string;
  expiresAtMs: number;
}

export interface ReserveArgs {
  tid: string;
  amountMinor: string;
  ccy: string;
  purposeCode: string;
  expiresAtMs: number;
}

export class BudgetDO extends DurableObject<Env> {
  async configure(cfg: BudgetConfig): Promise<DOResult> {
    let limitMinor: bigint;
    try {
      limitMinor = toMinor(cfg.limit, cfg.ccy);
    } catch (e) {
      return err("bad_limit", String(e));
    }
    if (limitMinor < 0n) return err("bad_limit", "limit must be non-negative");
    const existing = await this.ctx.storage.get<BudgetConfig>("cfg");
    if (existing && existing.ccy !== cfg.ccy) {
      return err("ccy_change", "cannot change a budget's currency");
    }
    await this.ctx.storage.put("cfg", cfg);
    if ((await this.ctx.storage.get("spent")) === undefined) {
      await this.ctx.storage.put("spent", "0");
    }
    if ((await this.ctx.storage.get("reserved")) === undefined) {
      await this.ctx.storage.put("reserved", "0");
    }
    return { ok: true };
  }

  async updatePolicy(policy: BudgetConfig["policy"]): Promise<DOResult> {
    const cfg = await this.ctx.storage.get<BudgetConfig>("cfg");
    if (!cfg) return err("not_found", "budget not configured");
    await this.ctx.storage.put("cfg", { ...cfg, policy });
    return { ok: true };
  }

  async getState(): Promise<DOResult<{ budget: BudgetState }>> {
    const cfg = await this.ctx.storage.get<BudgetConfig>("cfg");
    if (!cfg) return err("not_found", "budget not configured");
    const spent = BigInt((await this.ctx.storage.get<string>("spent")) ?? "0");
    const reserved = await this.reservedTotal();
    const limit = toMinor(cfg.limit, cfg.ccy);
    const available = limit - spent - reserved;
    return {
      ok: true,
      budget: {
        ...cfg,
        spent: fromMinor(spent, cfg.ccy),
        reserved: fromMinor(reserved, cfg.ccy),
        available: fromMinor(available < 0n ? 0n : available, cfg.ccy),
      },
    };
  }

  /**
   * Atomically reserve funds for a token. Policy (purpose allow-list,
   * per-transaction cap, period) is enforced at every node it passes through.
   * Re-reserving the same tid with the same amount is an idempotent no-op.
   */
  async reserve(args: ReserveArgs): Promise<DOResult<{ availableAfter: string }>> {
    const cfg = await this.ctx.storage.get<BudgetConfig>("cfg");
    if (!cfg) return err("not_found", "budget not configured");
    if (cfg.ccy !== args.ccy) return err("ccy_mismatch", `budget is ${cfg.ccy}, token is ${args.ccy}`);

    const amount = BigInt(args.amountMinor);
    if (amount <= 0n) return err("bad_amount", "reservation must be positive");

    const today = new Date().toISOString().slice(0, 10);
    if (today < cfg.period.start || today > cfg.period.end) {
      return err("out_of_period", `budget period ${cfg.period.start}..${cfg.period.end} does not cover today`);
    }
    if (cfg.policy.purposes_allow && !purposeAllowed(cfg.policy.purposes_allow, args.purposeCode)) {
      return err("purpose_not_allowed", `budget policy does not permit purpose ${args.purposeCode}`);
    }
    if (cfg.policy.per_txn_max && amount > toMinor(cfg.policy.per_txn_max, cfg.ccy)) {
      return err("per_txn_max", `amount exceeds per-transaction cap ${cfg.policy.per_txn_max}`);
    }

    const existing = await this.ctx.storage.get<Reservation>(`res:${args.tid}`);
    if (existing) {
      if (existing.amountMinor !== args.amountMinor) {
        return err("reservation_conflict", `tid ${args.tid} already reserved with a different amount`);
      }
      const spent0 = BigInt((await this.ctx.storage.get<string>("spent")) ?? "0");
      const avail0 = toMinor(cfg.limit, cfg.ccy) - spent0 - (await this.reservedTotal());
      return { ok: true, availableAfter: fromMinor(avail0 < 0n ? 0n : avail0, cfg.ccy) };
    }

    const spent = BigInt((await this.ctx.storage.get<string>("spent")) ?? "0");
    const reserved = await this.reservedTotal();
    const limit = toMinor(cfg.limit, cfg.ccy);
    if (spent + reserved + amount > limit) {
      return err("insufficient_budget", `available ${fromMinor(limit - spent - reserved, cfg.ccy)}, requested ${fromMinor(amount, cfg.ccy)}`);
    }

    await this.ctx.storage.put<Reservation>(`res:${args.tid}`, {
      amountMinor: args.amountMinor,
      expiresAtMs: args.expiresAtMs,
    });
    await this.setReserved(reserved + amount);
    await this.scheduleSweep(args.expiresAtMs);
    const available = limit - spent - reserved - amount;
    return { ok: true, availableAfter: fromMinor(available, cfg.ccy) };
  }

  /** Convert a reservation into spend (redeem step 4). */
  async commit(tid: string): Promise<DOResult<{ availableAfter: string; spentAfter: string }>> {
    const cfg = await this.ctx.storage.get<BudgetConfig>("cfg");
    if (!cfg) return err("not_found", "budget not configured");
    const res = await this.ctx.storage.get<Reservation>(`res:${tid}`);
    if (!res) return err("no_reservation", `no reservation for ${tid}`);
    const spent = BigInt((await this.ctx.storage.get<string>("spent")) ?? "0") + BigInt(res.amountMinor);
    await this.ctx.storage.delete(`res:${tid}`);
    await this.setReserved((await this.reservedTotal()) - BigInt(res.amountMinor));
    await this.ctx.storage.put("spent", spent.toString());
    const available = toMinor(cfg.limit, cfg.ccy) - spent - (await this.reservedTotal());
    return {
      ok: true,
      availableAfter: fromMinor(available < 0n ? 0n : available, cfg.ccy),
      spentAfter: fromMinor(spent, cfg.ccy),
    };
  }

  /** Release a reservation. Idempotent — releasing a missing tid is a no-op. */
  async release(tid: string): Promise<DOResult> {
    const res = await this.ctx.storage.get<Reservation>(`res:${tid}`);
    if (res) {
      await this.ctx.storage.delete(`res:${tid}`);
      await this.setReserved((await this.reservedTotal()) - BigInt(res.amountMinor));
    }
    return { ok: true };
  }

  /** Compensation: undo a commit (only used when a later saga step failed). */
  async uncommit(tid: string, amountMinor: string, expiresAtMs: number): Promise<DOResult> {
    const spent = BigInt((await this.ctx.storage.get<string>("spent")) ?? "0") - BigInt(amountMinor);
    await this.ctx.storage.put("spent", (spent < 0n ? 0n : spent).toString());
    if ((await this.ctx.storage.get<Reservation>(`res:${tid}`)) === undefined) {
      await this.ctx.storage.put<Reservation>(`res:${tid}`, { amountMinor, expiresAtMs });
      await this.setReserved((await this.reservedTotal()) + BigInt(amountMinor));
    }
    await this.scheduleSweep(expiresAtMs);
    return { ok: true };
  }

  /** Expiry sweep: drop lapsed reservations, reschedule for the next one. */
  async alarm(): Promise<void> {
    const now = Date.now();
    const all = await this.ctx.storage.list<Reservation>({ prefix: "res:" });
    let nextExpiry: number | null = null;
    let released = 0n;
    for (const [key, res] of all) {
      if (res.expiresAtMs <= now) {
        await this.ctx.storage.delete(key);
        released += BigInt(res.amountMinor);
      } else if (nextExpiry === null || res.expiresAtMs < nextExpiry) {
        nextExpiry = res.expiresAtMs;
      }
    }
    if (released > 0n) await this.setReserved((await this.reservedTotal()) - released);
    if (nextExpiry !== null) await this.ctx.storage.setAlarm(nextExpiry);
  }

  /**
   * Safety valve: recompute the reserved total from a full reservation list
   * and overwrite the counter if it drifted. A mismatch indicates a bug in
   * one of the counter-maintaining paths — it is logged, not silently fixed.
   */
  async reconcile(): Promise<DOResult<{ counterMinor: string; computedMinor: string; matched: boolean }>> {
    const counter = await this.reservedTotal();
    const all = await this.ctx.storage.list<Reservation>({ prefix: "res:" });
    let computed = 0n;
    for (const res of all.values()) computed += BigInt(res.amountMinor);
    const matched = counter === computed;
    if (!matched) {
      console.error("BUG: reserved counter drift", {
        counter: counter.toString(),
        computed: computed.toString(),
      });
      await this.setReserved(computed);
    }
    return { ok: true, counterMinor: counter.toString(), computedMinor: computed.toString(), matched };
  }

  /** Maintained running total — O(1) instead of listing every reservation on
   * each reserve/getState, which matters on hot budget nodes. */
  private async reservedTotal(): Promise<bigint> {
    return BigInt((await this.ctx.storage.get<string>("reserved")) ?? "0");
  }

  private async setReserved(value: bigint): Promise<void> {
    if (value < 0n) {
      // The counter is only ever decremented by amounts read from existing
      // res: records, so going negative indicates a bookkeeping bug.
      console.error("BUG: reserved counter would go negative; clamping to 0", {
        value: value.toString(),
      });
    }
    await this.ctx.storage.put("reserved", (value < 0n ? 0n : value).toString());
  }

  private async scheduleSweep(candidateMs: number): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || candidateMs < current) {
      await this.ctx.storage.setAlarm(candidateMs);
    }
  }
}
