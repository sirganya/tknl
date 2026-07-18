import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

/**
 * AuditDirectoryDO — one per org: the authoritative map of that org's audit
 * chain segments (see AuditChainDO for the sharding design).
 *
 * The directory is deliberately OFF the append hot path: the active segment
 * name is derived from the clock (`org:YYYY-MM-DD`), so appends only touch the
 * directory once per (org, period) — at segment initialisation — plus on the
 * rare sealed-retry at a period boundary. Reads (entries, proofs, checkpoints,
 * cross-segment verification) enumerate segments through it.
 */
export interface SegmentRecord {
  /** "legacy" for the pre-sharding single DO (addressed by org alone), else
   * the UTC day "YYYY-MM-DD" (DO addressed by `org:period`). */
  period: string;
  /** First global sequence number this segment may assign. */
  firstSeq: number;
  /** Last global sequence number, recorded when the segment is sealed. */
  lastSeq?: number;
}

/** The legacy segment sorts before any date. */
function sortKey(period: string): string {
  return "seg:" + (period === "legacy" ? "0000-00-00" : period);
}

export class AuditDirectoryDO extends DurableObject<Env> {
  /**
   * Atomically record a boundary transition: mark the predecessor sealed with
   * its final seq, and register the successor. Idempotent — replaying the same
   * advance (e.g. a segment re-running init after a crash) changes nothing.
   */
  async advance(args: {
    sealed?: { period: string; lastSeq: number };
    next: SegmentRecord;
  }): Promise<void> {
    if (args.sealed) {
      const key = sortKey(args.sealed.period);
      const existing = await this.ctx.storage.get<SegmentRecord>(key);
      await this.ctx.storage.put<SegmentRecord>(key, {
        period: args.sealed.period,
        firstSeq: existing?.firstSeq ?? 1,
        lastSeq: args.sealed.lastSeq,
      });
    }
    const nextKey = sortKey(args.next.period);
    if ((await this.ctx.storage.get(nextKey)) === undefined) {
      await this.ctx.storage.put<SegmentRecord>(nextKey, args.next);
    }
  }

  /** All segments in chain order (legacy first, then by period). */
  async list(): Promise<SegmentRecord[]> {
    const map = await this.ctx.storage.list<SegmentRecord>({ prefix: "seg:" });
    return [...map.values()];
  }

  async latest(): Promise<SegmentRecord | null> {
    const all = await this.list();
    return all.length ? all[all.length - 1]! : null;
  }
}
