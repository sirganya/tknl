import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import type { AuditEntry, AuditEntryBody, Checkpoint, DOResult } from "../types";
import { err } from "../types";
import { concatBytes, hex, utf8 } from "../lib/encoding";
import { sha256 } from "../lib/crypto";
import { jcs } from "../lib/jcs";
import { merkleProof, merkleRoot, type ProofStep } from "../lib/merkle";

/**
 * AuditChainDO — one per organisation. Append-only, hash-chained ledger.
 *
 *   entry_hash(n) = sha256( utf8(JCS(entry minus entry_hash)) || utf8(prev_hash(n)) )
 *   prev_hash(n)  = entry_hash(n-1); genesis uses a fixed org-scoped seed.
 *
 * This DO is the source of truth for audit history. D1 rows and R2 segments
 * are derived from it (via the fan-out queue and hourly checkpoint job) and
 * can always be rebuilt. Audit appends are synchronous and in the critical
 * path of every value operation: if append fails, the operation fails.
 */
const SEQ_PAD = 12;

function entryKey(seq: number): string {
  return "e:" + seq.toString().padStart(SEQ_PAD, "0");
}

function checkpointKey(seq: number): string {
  return "cp:" + seq.toString().padStart(SEQ_PAD, "0");
}

export async function genesisHash(org: string): Promise<string> {
  return "sha256:" + hex(await sha256(utf8("utap.v0.1.audit-genesis:" + org)));
}

export async function computeEntryHash(entryWithoutHash: Omit<AuditEntry, "entry_hash">): Promise<string> {
  const digest = await sha256(
    concatBytes(utf8(jcs(entryWithoutHash)), utf8(entryWithoutHash.prev_hash)),
  );
  return "sha256:" + hex(digest);
}

export class AuditChainDO extends DurableObject<Env> {
  async append(org: string, body: AuditEntryBody): Promise<DOResult<{ entry: AuditEntry }>> {
    const storedOrg = await this.ctx.storage.get<string>("org");
    if (storedOrg === undefined) await this.ctx.storage.put("org", org);
    else if (storedOrg !== org) return err("org_mismatch", "audit chain belongs to a different org");

    const seq = ((await this.ctx.storage.get<number>("seq")) ?? 0) + 1;
    const prevHash = (await this.ctx.storage.get<string>("head")) ?? (await genesisHash(org));

    const withoutHash: Omit<AuditEntry, "entry_hash"> = {
      ...body,
      seq,
      ts: new Date().toISOString(),
      org,
      prev_hash: prevHash,
    };
    const entry: AuditEntry = { ...withoutHash, entry_hash: await computeEntryHash(withoutHash) };

    await this.ctx.storage.put(entryKey(seq), entry);
    await this.ctx.storage.put("seq", seq);
    await this.ctx.storage.put("head", entry.entry_hash);

    // D1 indexing is derived data — enqueue best-effort, never fail the append.
    try {
      await this.env.AUDIT_QUEUE.send({ type: "audit.index", entry });
    } catch (e) {
      console.error("audit fan-out enqueue failed", { org, seq, error: String(e) });
    }
    return { ok: true, entry };
  }

  async head(): Promise<{ seq: number; head: string | null }> {
    return {
      seq: (await this.ctx.storage.get<number>("seq")) ?? 0,
      head: (await this.ctx.storage.get<string>("head")) ?? null,
    };
  }

  async getEntries(fromSeq: number, toSeq: number, limit = 500): Promise<AuditEntry[]> {
    const map = await this.ctx.storage.list<AuditEntry>({
      start: entryKey(Math.max(1, fromSeq)),
      end: entryKey(toSeq) + "￿",
      limit: Math.min(limit, 1000),
    });
    return [...map.values()];
  }

  /**
   * Hourly checkpoint: Merkle root over entries since the last checkpoint,
   * segment archived to R2, root row inserted into D1. The DO's own
   * checkpoint record is committed last, so a failed external write is
   * retried on the next cron rather than leaving a gap.
   */
  async checkpoint(): Promise<DOResult<{ checkpoint: Checkpoint | null }>> {
    const org = await this.ctx.storage.get<string>("org");
    const seq = (await this.ctx.storage.get<number>("seq")) ?? 0;
    const lastCp = (await this.ctx.storage.get<number>("lastCheckpointSeq")) ?? 0;
    if (!org || seq <= lastCp) return { ok: true, checkpoint: null };

    const entries = await this.getEntries(lastCp + 1, seq, 1000);
    const covered = entries[entries.length - 1]!.seq;
    const root = await merkleRoot(entries.map((e) => e.entry_hash));
    const cp: Checkpoint = {
      org,
      from_seq: lastCp + 1,
      seq: covered,
      merkle_root: root,
      ts: new Date().toISOString(),
    };

    const segmentKey = `audit/${org}/${String(cp.from_seq).padStart(SEQ_PAD, "0")}-${String(cp.seq).padStart(SEQ_PAD, "0")}.json`;
    try {
      await this.env.AUDIT_ARCHIVE.put(segmentKey, JSON.stringify({ checkpoint: cp, entries }), {
        customMetadata: { org, merkle_root: root },
      });
      await this.env.DB.prepare(
        "INSERT OR REPLACE INTO checkpoints (org, seq, merkle_root, ts, anchor_ref) VALUES (?, ?, ?, ?, ?)",
      )
        .bind(org, cp.seq, cp.merkle_root, cp.ts, null)
        .run();
    } catch (e) {
      return err("archive_failed", `checkpoint external write failed: ${String(e)}`);
    }

    await this.ctx.storage.put(checkpointKey(cp.seq), cp);
    await this.ctx.storage.put("lastCheckpointSeq", cp.seq);
    return { ok: true, checkpoint: cp };
  }

  async getCheckpoints(): Promise<Checkpoint[]> {
    const map = await this.ctx.storage.list<Checkpoint>({ prefix: "cp:" });
    return [...map.values()];
  }

  /** Merkle inclusion proof for one entry against its covering checkpoint. */
  async proof(seq: number): Promise<
    DOResult<{ entry: AuditEntry; proof: ProofStep[]; checkpoint: Checkpoint }>
  > {
    const entry = await this.ctx.storage.get<AuditEntry>(entryKey(seq));
    if (!entry) return err("not_found", `no entry with seq ${seq}`);

    const checkpoints = await this.getCheckpoints();
    const cp = checkpoints.find((c) => c.from_seq <= seq && seq <= c.seq);
    if (!cp) return err("not_checkpointed", `entry ${seq} is not covered by a checkpoint yet`);

    const segment = await this.getEntries(cp.from_seq, cp.seq, 1000);
    const index = segment.findIndex((e) => e.seq === seq);
    const proof = await merkleProof(
      segment.map((e) => e.entry_hash),
      index,
    );
    return { ok: true, entry, proof, checkpoint: cp };
  }

  /** Recompute the whole chain — used by reconciliation and tests. */
  async verifyChainIntegrity(): Promise<DOResult<{ seq: number; head: string | null }>> {
    const org = await this.ctx.storage.get<string>("org");
    if (!org) return { ok: true, seq: 0, head: null };
    const seq = (await this.ctx.storage.get<number>("seq")) ?? 0;
    let prev = await genesisHash(org);
    for (let s = 1; s <= seq; s++) {
      const entry = await this.ctx.storage.get<AuditEntry>(entryKey(s));
      if (!entry) return err("gap", `missing entry at seq ${s}`);
      if (entry.prev_hash !== prev) return err("broken_link", `prev_hash mismatch at seq ${s}`);
      const { entry_hash, ...withoutHash } = entry;
      if ((await computeEntryHash(withoutHash)) !== entry_hash) {
        return err("bad_hash", `entry_hash mismatch at seq ${s}`);
      }
      prev = entry_hash;
    }
    return { ok: true, seq, head: prev };
  }
}
