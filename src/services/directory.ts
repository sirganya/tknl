import type { Env } from "../env";
import type { PrincipalDirectory } from "../lib/chain";

/** PrincipalDirectory backed by PrincipalDOs — the single writers for key
 * sets and revocation lists, so revocation is immediate and consistent. */
export function doDirectory(env: Env): PrincipalDirectory {
  return {
    getKeys(did: string): Promise<JsonWebKey[]> {
      return env.PRINCIPAL_DO.get(env.PRINCIPAL_DO.idFromName(did)).getKeys();
    },
    isRevoked(issuerDid: string, jti: string): Promise<boolean> {
      return env.PRINCIPAL_DO.get(env.PRINCIPAL_DO.idFromName(issuerDid)).isRevoked(jti);
    },
  };
}
