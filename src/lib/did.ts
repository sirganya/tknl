/**
 * DID conventions used by the reference implementation (did:web only):
 *   did:web:acme.example                      — an organisation / merchant
 *   did:web:acme.example:person:gkavanagh     — a human principal
 *   did:web:acme.example:agent:procure-01     — an agent
 */
export function isValidDid(did: string): boolean {
  return /^did:web:[a-z0-9.-]+(:[a-z0-9_-]+)*$/i.test(did);
}

export function isPersonDid(did: string): boolean {
  return isValidDid(did) && did.split(":").includes("person");
}

export function isAgentDid(did: string): boolean {
  return isValidDid(did) && did.split(":").includes("agent");
}

/** Organisation a DID belongs to — the did:web host segment. */
export function orgOfDid(did: string): string {
  const parts = did.split(":");
  if (parts.length < 3 || parts[0] !== "did" || parts[1] !== "web" || !parts[2]) {
    throw new Error(`invalid did: ${did}`);
  }
  return parts[2].toLowerCase();
}
