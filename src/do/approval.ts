import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import type { DOResult } from "../types";
import { err } from "../types";
import type { MintRequest } from "../handlers/mint";

/**
 * ApprovalDO — one per approval id.
 *
 * When a mint crosses a budget's `requires_human_approval_above` threshold,
 * the CFP emits an approval request instead of a token. The pending mint
 * request is parked here; the token is only minted once an approval credential
 * signed by the human principal's key arrives (UTAP §7).
 */
export interface ApprovalRecord {
  id: string;
  org: string;
  agent: string;
  principal: string;
  budgetRef: string;
  thresholdExceeded: string;
  request: MintRequest;
  status: "pending" | "approved" | "denied";
  createdTs: string;
  decidedTs?: string;
  decidedBy?: string;
  tid?: string;
}

export class ApprovalDO extends DurableObject<Env> {
  async put(rec: ApprovalRecord): Promise<DOResult> {
    if (await this.ctx.storage.get("rec")) return err("exists", "approval already exists");
    await this.ctx.storage.put("rec", rec);
    return { ok: true };
  }

  async get(): Promise<ApprovalRecord | null> {
    return (await this.ctx.storage.get<ApprovalRecord>("rec")) ?? null;
  }

  async decide(decision: "approved" | "denied", by: string): Promise<DOResult<{ record: ApprovalRecord }>> {
    const rec = await this.ctx.storage.get<ApprovalRecord>("rec");
    if (!rec) return err("not_found", "unknown approval");
    if (rec.status !== "pending") return err("already_decided", `approval is ${rec.status}`);
    rec.status = decision;
    rec.decidedTs = new Date().toISOString();
    rec.decidedBy = by;
    await this.ctx.storage.put("rec", rec);
    return { ok: true, record: rec };
  }

  async attachToken(tid: string): Promise<void> {
    const rec = await this.ctx.storage.get<ApprovalRecord>("rec");
    if (rec) {
      rec.tid = tid;
      await this.ctx.storage.put("rec", rec);
    }
  }
}
