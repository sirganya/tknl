import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

/**
 * IdempotencyDO — one per (caller, Idempotency-Key) pair.
 *
 * The DO's single-writer property serialises concurrent requests with the same
 * key: the first marks itself in-progress, replays return the stored response,
 * and a same-key request with a different payload is rejected outright.
 * Records self-expire via alarm after 24 hours.
 */
const TTL_MS = 24 * 60 * 60 * 1000;

interface Record_ {
  fingerprint: string;
  status: "in_progress" | "done";
  httpStatus?: number;
  body?: string;
  createdAt: number;
}

export type BeginResult =
  | { state: "new" }
  | { state: "in_progress" }
  | { state: "mismatch" }
  | { state: "replay"; httpStatus: number; body: string };

export class IdempotencyDO extends DurableObject<Env> {
  async begin(fingerprint: string): Promise<BeginResult> {
    const rec = await this.ctx.storage.get<Record_>("rec");
    if (rec) {
      if (rec.fingerprint !== fingerprint) return { state: "mismatch" };
      if (rec.status === "in_progress") return { state: "in_progress" };
      return { state: "replay", httpStatus: rec.httpStatus!, body: rec.body! };
    }
    const now = Date.now();
    await this.ctx.storage.put<Record_>("rec", { fingerprint, status: "in_progress", createdAt: now });
    await this.ctx.storage.setAlarm(now + TTL_MS);
    return { state: "new" };
  }

  async complete(httpStatus: number, body: string): Promise<void> {
    const rec = await this.ctx.storage.get<Record_>("rec");
    if (!rec) return;
    await this.ctx.storage.put<Record_>("rec", { ...rec, status: "done", httpStatus, body });
  }

  /** Release the in-progress claim (e.g. handler threw) so a retry can run. */
  async abort(): Promise<void> {
    const rec = await this.ctx.storage.get<Record_>("rec");
    if (rec && rec.status === "in_progress") await this.ctx.storage.delete("rec");
  }

  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
