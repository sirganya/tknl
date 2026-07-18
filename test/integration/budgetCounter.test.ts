import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

/**
 * The reserved running total is a maintained counter (O(1) on hot nodes)
 * rather than a list-and-sum. This workout drives every path that touches it
 * — including double-release and release of an unknown tid — and asserts the
 * counter matches a full list-based recomputation (reconcile()).
 */
describe("BudgetDO reserved counter", () => {
  it("stays consistent through reserve/release/commit/uncommit, including degenerate releases", async () => {
    const ref = "bud_counter_test";
    const stub = env.BUDGET_DO.get(env.BUDGET_DO.idFromName(ref));
    const configured = await stub.configure({
      budget_ref: ref,
      org: "counter.example",
      parent: null,
      limit: "1000.00",
      ccy: "EUR",
      period: { start: "2000-01-01", end: "2099-12-31" },
      policy: {},
    });
    expect(configured.ok).toBe(true);

    const reserve = (tid: string, amountMinor: string) =>
      stub.reserve({ tid, amountMinor, ccy: "EUR", purposeCode: "COMPUTE.X", expiresAtMs: Date.now() + 60_000 });

    expect((await reserve("t1", "10000")).ok).toBe(true);
    expect((await reserve("t2", "20000")).ok).toBe(true);
    expect((await reserve("t3", "30000")).ok).toBe(true);
    expect((await reserve("t3", "30000")).ok).toBe(true); // idempotent re-reserve: no double count

    expect((await stub.release("t2")).ok).toBe(true);
    expect((await stub.release("t2")).ok).toBe(true); // double release: no-op
    expect((await stub.release("never-reserved")).ok).toBe(true); // unknown tid: no-op

    expect((await stub.commit("t1")).ok).toBe(true);
    expect((await stub.uncommit("t1", "10000", Date.now() + 60_000)).ok).toBe(true); // compensation
    expect((await stub.commit("t1")).ok).toBe(true);

    const state = await stub.getState();
    expect(state.ok).toBe(true);
    if (state.ok) {
      expect(state.budget.reserved).toBe("300.00"); // t3 only
      expect(state.budget.spent).toBe("100.00"); // t1
    }

    const reconciled = await stub.reconcile();
    expect(reconciled.ok).toBe(true);
    if (reconciled.ok) {
      expect(reconciled.matched).toBe(true);
      expect(reconciled.counterMinor).toBe("30000");
      expect(reconciled.computedMinor).toBe("30000");
    }
  });
});
