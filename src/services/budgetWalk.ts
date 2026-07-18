import type { Env } from "../env";
import type { BudgetState, DOResult } from "../types";
import { err } from "../types";

/**
 * Hierarchical budget orchestration (UTAP §7).
 *
 * Reservations walk from the leaf to the root, reserving at each level; if any
 * ancestor rejects, all reservations already taken in that walk are released.
 * Walk order is always leaf-to-root so concurrent requests on overlapping
 * subtrees acquire their (implicit) locks in a consistent order.
 */
const MAX_DEPTH = 10;

function stub(env: Env, ref: string) {
  return env.BUDGET_DO.get(env.BUDGET_DO.idFromName(ref));
}

/** Resolve the leaf→root path of budget refs, guarding against cycles. */
export async function resolveBudgetPath(
  env: Env,
  leafRef: string,
): Promise<DOResult<{ path: string[]; leaf: BudgetState }>> {
  const path: string[] = [];
  const seen = new Set<string>();
  let leaf: BudgetState | null = null;
  let ref: string | null = leafRef;
  while (ref) {
    if (seen.has(ref)) return err("budget_cycle", `budget hierarchy contains a cycle at ${ref}`);
    if (path.length >= MAX_DEPTH) return err("budget_too_deep", "budget hierarchy exceeds max depth");
    seen.add(ref);
    const state = await stub(env, ref).getState();
    if (!state.ok) {
      return path.length === 0
        ? err("budget_not_found", `budget ${ref} is not configured`)
        : err("budget_broken_parent", `ancestor budget ${ref} is not configured`);
    }
    if (leaf === null) leaf = state.budget;
    path.push(ref);
    ref = state.budget.parent;
  }
  return { ok: true, path, leaf: leaf! };
}

export interface WalkReserveArgs {
  tid: string;
  amountMinor: string;
  ccy: string;
  purposeCode: string;
  expiresAtMs: number;
}

/** Reserve at every level leaf→root; roll back on any rejection. */
export async function reserveWalk(
  env: Env,
  path: string[],
  args: WalkReserveArgs,
): Promise<DOResult<{ leafAvailableAfter: string }>> {
  let leafAvailableAfter = "";
  for (let i = 0; i < path.length; i++) {
    const result = await stub(env, path[i]!).reserve(args);
    if (!result.ok) {
      await releaseWalk(env, path.slice(0, i), args.tid);
      return err(result.code, `budget ${path[i]}: ${result.error}`);
    }
    if (i === 0) leafAvailableAfter = result.availableAfter;
  }
  return { ok: true, leafAvailableAfter };
}

/** Convert reservations to spend at every level; compensate on failure. */
export async function commitWalk(
  env: Env,
  path: string[],
  tid: string,
  amountMinor: string,
  reReserveExpiresAtMs: number,
): Promise<DOResult<{ leafAvailableAfter: string; leafSpentAfter: string }>> {
  let leafAvailableAfter = "";
  let leafSpentAfter = "";
  for (let i = 0; i < path.length; i++) {
    const result = await stub(env, path[i]!).commit(tid);
    if (!result.ok) {
      for (let j = 0; j < i; j++) {
        await stub(env, path[j]!).uncommit(tid, amountMinor, reReserveExpiresAtMs);
      }
      return err(result.code, `budget ${path[i]}: ${result.error}`);
    }
    if (i === 0) {
      leafAvailableAfter = result.availableAfter;
      leafSpentAfter = result.spentAfter;
    }
  }
  return { ok: true, leafAvailableAfter, leafSpentAfter };
}

/** Compensation for a failed step after commit: put the spend back into reservation. */
export async function uncommitWalk(
  env: Env,
  path: string[],
  tid: string,
  amountMinor: string,
  expiresAtMs: number,
): Promise<void> {
  for (const ref of path) {
    await stub(env, ref).uncommit(tid, amountMinor, expiresAtMs);
  }
}

export async function releaseWalk(env: Env, path: string[], tid: string): Promise<void> {
  for (const ref of path) {
    try {
      await stub(env, ref).release(tid);
    } catch (e) {
      // The BudgetDO TTL sweep is the backstop for a failed release.
      console.error("release failed", { ref, tid, error: String(e) });
    }
  }
}
