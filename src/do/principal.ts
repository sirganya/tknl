import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import type { DelegationCredential, DOResult } from "../types";
import { err } from "../types";

/**
 * PrincipalDO — one per principal DID (person, agent, or merchant org).
 *
 * Single writer for the DID's key set and its revocation list, which is what
 * makes revocation immediate and consistent (UTAP §8). Also stores delegation
 * credentials issued *by* this principal, keyed by jti.
 */
export class PrincipalDO extends DurableObject<Env> {
  async addKey(kid: string, jwk: JsonWebKey): Promise<DOResult> {
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
      return err("bad_key", "public key must be an Ed25519 OKP JWK with x");
    }
    if ((jwk as { d?: string }).d !== undefined) {
      return err("bad_key", "refusing to store a private key");
    }
    await this.ctx.storage.put(`key:${kid}`, { kty: "OKP", crv: "Ed25519", x: jwk.x, kid });
    return { ok: true };
  }

  async getKeys(): Promise<JsonWebKey[]> {
    const map = await this.ctx.storage.list<JsonWebKey>({ prefix: "key:" });
    return [...map.values()];
  }

  async hasKeys(): Promise<boolean> {
    const map = await this.ctx.storage.list({ prefix: "key:", limit: 1 });
    return map.size > 0;
  }

  async revoke(jti: string): Promise<DOResult> {
    await this.ctx.storage.put(`rev:${jti}`, new Date().toISOString());
    return { ok: true };
  }

  async isRevoked(jti: string): Promise<boolean> {
    return (await this.ctx.storage.get(`rev:${jti}`)) !== undefined;
  }

  async putDelegation(cred: DelegationCredential): Promise<DOResult> {
    const existing = await this.ctx.storage.get<DelegationCredential>(`dlg:${cred.jti}`);
    if (existing && existing.sig !== cred.sig) {
      return err("jti_conflict", `a different credential with jti ${cred.jti} already exists`);
    }
    await this.ctx.storage.put(`dlg:${cred.jti}`, cred);
    return { ok: true };
  }

  async getDelegation(jti: string): Promise<DelegationCredential | null> {
    return (await this.ctx.storage.get<DelegationCredential>(`dlg:${jti}`)) ?? null;
  }
}
