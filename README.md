# UTAP CFP Reference Implementation

A working reference implementation of the **Central Financial Provider (CFP)** role defined in
**UTAP v0.1**, built on Cloudflare Workers. It exists to prove the protocol runs, to give
implementers something to test against, and to serve as the technical basis for a production or
sovereign-operated CFP.

**In scope:** token lifecycle, double-spend prevention, delegation chain verification, budget
enforcement, purpose binding, hash-chained audit trail, public verification API.

**Out of scope (v0.1):** real funds, fiat settlement, MiCA-regulated e-money issuance, KYC/AML.
Settlement writes to a mock ledger behind a deliberately clean boundary where a licensed
institution's rails can attach.

## Architecture

| Concern | Primitive | Where |
|---|---|---|
| API edge, authn, validation, routing | Worker | `src/index.ts`, `src/auth.ts` |
| Token state, double-spend prevention | Durable Object per token | `src/do/token.ts` |
| Budget counters, hierarchical reservation | Durable Object per budget node | `src/do/budget.ts` |
| Key registry, delegation store, revocation | Durable Object per principal DID | `src/do/principal.ts` |
| Hash-chained audit ledger | Durable Object per org | `src/do/audit.ts` |
| Idempotency records | Durable Object per (caller, key) | `src/do/idempotency.ts` |
| Human approval gates | Durable Object per approval | `src/do/approval.ts` |
| Queryable audit index, registries, mock ledger | D1 (derived, rebuildable) | `migrations/0001_init.sql` |
| Immutable audit archive segments | R2 | written by hourly checkpoint |
| Async fan-out (indexing, settlement) | Queues | consumer in `src/index.ts` |
| Delegation jti → issuer lookup | Workers KV | eventually consistent is fine here |
| Checkpointing + reconciliation | Cron Triggers | `0 * * * *`, `15 3 * * *` |

There is **no external primary database**. Anything touching value lives in a single-writer
Durable Object; D1 and R2 are derived views that can be rebuilt from the AuditChainDO.

### Double-spend prevention

One DO per token (`idFromName(tid)`), single-threaded by the platform. Concurrent redeems are
serialised; the state machine rejects any transition not permitted from the current state:

```
issued ──▶ reserved ──▶ redeemed ──▶ settled
   │           │
   ├──▶ void   └──▶ void
   └──▶ expired
```

A token can be redeemed at most once, globally, with no distributed lock, consensus protocol, or
central database. The integration suite demonstrates this with 5 concurrent redeems → exactly one
200.

### Sagas, not transactions

Reservation (BudgetDO) and token creation (TokenDO) are different DOs, so mint is a saga: every
failure path releases the reservation walk, budget reservations carry a TTL, and the BudgetDO
alarm sweep is the backstop for a crashed Worker. Redeem compensates in reverse
(`uncommit` + `revertRedeem`) if the synchronous audit append fails — an unauditable transaction
is not a valid transaction under UTAP.

### Audit chain

Append-only, hash-chained, and **sharded by (org, UTC day)** so a single DO never caps an org's
transaction rate (`src/do/audit.ts`): the active segment is the DO `org:YYYY-MM-DD`, and the
pre-sharding per-org DO is served in place as the read-only "legacy" segment. Continuity across
segments is anchored in the predecessor: a segment's first append atomically **seals** its
predecessor (which thereafter rejects every append) and only then chains from its final head, so
a fork at the period boundary is impossible; sequence numbers are global and monotonic.
`src/services/audit.ts` routes appends to the clock-derived active segment (no directory lookup
on the hot path) and fans reads, proofs, checkpoints, and cross-segment verification out via the
per-org `AuditDirectoryDO`. Hash format per entry:

```
entry_hash(n) = sha256( utf8(JCS(entry minus entry_hash)) || utf8(prev_hash(n)) )
prev_hash(n)  = entry_hash(n-1)
prev_hash(1)  = sha256( utf8("utap.v0.1.audit-genesis:" + org) )
```

Hourly cron computes a Merkle root over entries since the last checkpoint, stores it in D1 and
archives the segment to R2. `GET /v1/audit/{org}/proof/{seq}` returns a Merkle inclusion proof an
external auditor can verify against a published root without trusting the CFP
(leaf = `sha256(0x00 || utf8(entry_hash))`, node = `sha256(0x01 || left || right)`). For a
sovereign CFP, external anchoring of roots should be mandatory; `checkpoints.anchor_ref` is the
hook.

### Canonicalisation and signatures

All signed/hashed structures use **JCS (RFC 8785)** (`src/lib/jcs.ts`). Signatures are Ed25519
over `utf8(context || JCS(value))` with domain-separating context strings so a signature over one
structure can never be replayed as another:

| Context | Signs |
|---|---|
| `utap.v0.1.token.` | token minus `sig` (CFP key, state as issued) |
| `utap.v0.1.delegation.` | delegation credential minus `sig` (delegator key) |
| `utap.v0.1.auth.` | request auth payload `{sub, exp, nonce}` (caller key) |
| `utap.v0.1.approval.` | `{approval_id, decision, nonce}` (human principal key) |

Signature encoding is `ed25519:<base64url>`; hashes are `sha256:<hex>`.

### Authentication

Requests carry a short-lived signed credential (never a long-lived secret):

```
Authorization: Bearer utapv0.<b64u(JCS({sub, exp, nonce}))>.<b64u(signature)>
```

verified against the `sub` DID's keys registered in its PrincipalDO. Bootstrap/admin endpoints use
the `BOOTSTRAP_TOKEN` secret. Production deployments would add mTLS via Cloudflare Access for
enterprise clients. DIDs follow `did:web:<org>[:person|agent:<name>]`; the root of every
delegation chain must be a `person` DID, and revocation is immediate because the issuer's
PrincipalDO is the single writer for its revocation list.

Every mutating request requires an `Idempotency-Key` header; replays return the original response,
same key with a different payload is rejected (422), concurrent duplicates 409. An `in_progress`
claim older than 2 minutes is treated as abandoned and may be taken over by a retry.

Additional hardening:

- **Auth nonces are single-use.** Each request credential authenticates exactly once (tracked in
  the sub DID's PrincipalDO), so a captured credential cannot be replayed within its TTL. Sign a
  fresh credential per request.
- **Unbound tokens require explicit opt-in.** A token whose purpose has no `merchant_allow` list
  is a bearer instrument — any registered DID that sees the URI could reserve and redeem it. Mints
  without `merchant_allow` are rejected unless the request sets `allow_unbound: true`, and the
  `TOKEN_ISSUED` audit entry records the choice.
- **Bootstrap token comparison is constant-time** (SHA-256 digests compared with a full XOR fold).

## API surface (v0.1)

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/tokens` | Mint (agent credential + delegation chain in body) |
| GET | `/v1/tokens/{tid}` | Token state (authorised parties only) |
| POST | `/v1/tokens/{tid}/reserve` | Merchant hold (binds token to merchant DID) |
| POST | `/v1/tokens/{tid}/redeem` | Merchant redemption (body: `{mcc?}`) |
| POST | `/v1/tokens/{tid}/void` | Cancel unredeemed token (principal/delegator) |
| POST | `/v1/delegations` | Register a delegator-signed credential |
| DELETE | `/v1/delegations/{jti}` | Revoke |
| GET | `/v1/delegations/{jti}/chain` | Resolve and verify chain |
| PUT | `/v1/budgets/{ref}` | Create/update budget node (bootstrap / org person) |
| GET | `/v1/budgets/{ref}` | Budget state |
| POST | `/v1/budgets/{ref}/policy` | Update policy (human principal only) |
| POST | `/v1/approvals/{id}` | Human approval for above-threshold spend |
| GET | `/v1/approvals/{id}` | Approval status |
| PUT | `/v1/principals/{did}/keys/{kid}` | Register public key (bootstrap/self/org person) |
| GET | `/v1/principals/{did}/keys` | Public keys |
| GET | `/v1/audit/{org}/entries?from=&to=` | Audit query (org credential) |
| GET | `/v1/audit/{org}/proof/{seq}` | Merkle inclusion proof (public) |
| GET | `/v1/audit/{org}/checkpoints` | Checkpoint roots (public) |
| GET | `/.well-known/utap-cfp.json` | CFP metadata |
| GET | `/.well-known/jwks.json` | CFP public keys |

Token URIs are bearer references, not the token body: `POST /v1/tokens` returns `uri_query`
(`utap_v`, `utap_tid`, `utap_cfp`, `utap_sig`) for the merchant to append to its own payment URL;
full state is fetched from the CFP under merchant authentication.

## Getting started

```sh
npm install
npm test               # 35 unit + integration tests (workerd via vitest-pool-workers)
npm run typecheck

# local dev
node scripts/genkey.mjs            # generate a CFP signing key
cp .dev.vars.example .dev.vars     # paste the CFP_SIGNING_KEY line, set BOOTSTRAP_TOKEN
npm run dev                        # wrangler dev on :8787

# end-to-end demo (two humans-worth of actors + a mock vendor, in a second terminal)
npm run demo
```

The demo registers keys, configures a budget hierarchy, issues a delegation, mints a 40 000 EUR
token, reserves and redeems it as the vendor, proves the double-spend rejection, and then
re-verifies the audit hash chain from genesis — entirely through the public API.

## Website

`site/` is a static one-page explainer of the protocol and this implementation, built for
Cloudflare Pages (no build step — plain HTML/CSS, light/dark aware, responsive).

```sh
npx wrangler login          # once
npm run site:deploy         # deploys site/ to the utap-cfp Pages project
```

Alternatively connect the repo to Pages in the Cloudflare dashboard (Workers & Pages → Create →
Pages → connect to Git) with build output directory `site` and no build command.

### Deploying

1. Create the resources: `wrangler d1 create utap-audit-index`, `wrangler r2 bucket create
   utap-audit-archive`, `wrangler queues create utap-audit-fanout`, a KV namespace — and put the
   real IDs into `wrangler.jsonc`.
2. `wrangler d1 migrations apply utap-audit-index --remote`
3. `wrangler secret put CFP_SIGNING_KEY` (from `npm run genkey`) and `wrangler secret put
   BOOTSTRAP_TOKEN`.
4. `npm run deploy`

## Tests

- `test/unit/` — JCS vectors, money (bigint minor units), purpose patterns, Merkle proofs, and the
  full delegation-chain verifier matrix (tamper, expiry, revocation, depth, scope intersection,
  context binding).
- `test/integration/flows.test.ts` — full lifecycle against the real Worker + DOs + D1 + R2 +
  queues in workerd: mint/reserve/redeem with audit verification and R2 archive checks, concurrent
  double-spend, idempotency replay, void + reservation release, scope/revocation enforcement,
  human approval gate, token privacy.

The suite doubles as the seed of a conformance suite: everything asserts through the public API
plus the published verification formulas.

## Design decisions worth knowing about

- **Audit append is synchronous** and in the critical path; D1 indexing and R2 archiving are
  async and derived. Failure of the append fails (and compensates) the operation.
- **Money is bigint minor units** everywhere internally; wire format is a decimal string with the
  currency's full exponent.
- **Budget walks are leaf→root** for reservation, commit and release — consistent ordering, no
  deadlock between overlapping subtrees. Policy (purpose allow-list, per-txn cap, period) is
  enforced at every node the walk passes.
- **`requires_human_approval_above`** parks the mint in an ApprovalDO and returns 202; the token
  is only minted on an approval credential signed by the human principal's own key.
- **Token expiry is a DO alarm** on the TokenDO (not a global sweep); budget reservation TTLs are
  swept by BudgetDO alarms. Daily reconciliation cron compares each BudgetDO's spend against the
  audit-derived total (including descendant budgets) and appends `RECONCILIATION_DIVERGENCE` on
  mismatch — that is a P1: a bug or tampering.
- **GDPR position (flagged open, not solved):** the chain stores pseudonymous DIDs; the
  DID-to-person mapping is expected to live in a separately erasable store. Entry reads require an
  org credential; proofs and checkpoint roots are public.

## Known limits and scaling paths (see docs/scaling.md)

- The audit chain is sharded per (org, UTC day) with sealed-predecessor continuity —
  implemented; finer periods drop in without format changes if one org-day is still too hot.
- A hot budget node serialises its subtree's reservations. The `reserved` running-total counter
  keeps each operation O(1) (with a `reconcile()` safety valve); full sub-counter sharding with
  cron rebalancing is designed in `docs/scaling.md` and deliberately not built until measurement
  demands it.

## Open questions (tracked from the spec)

- GDPR erasure vs immutable audit — legal, not engineering.
- Settlement medium (MiCA e-money vs commercial bank money vs validation-only) — determines
  licensing and who can operate a CFP.
- Multi-CFP interoperability (cross-CFP redemption and chain verification).
- External anchoring target for checkpoint roots — must be credible, durable, jurisdictionally
  neutral.
