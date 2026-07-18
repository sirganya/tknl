-- UTAP CFP reference — D1 schema (derived index, rebuildable from AuditChainDO + R2)

CREATE TABLE audit_entries (
  org           TEXT NOT NULL,
  seq           INTEGER NOT NULL,
  ts            TEXT NOT NULL,
  event         TEXT NOT NULL,
  tid           TEXT,
  principal     TEXT,
  agent         TEXT,
  amount_minor  INTEGER,
  ccy           TEXT,
  purpose_code  TEXT,
  budget_ref    TEXT,
  merchant      TEXT,
  prev_hash     TEXT NOT NULL,
  entry_hash    TEXT NOT NULL,
  PRIMARY KEY (org, seq)
);
CREATE INDEX idx_audit_principal ON audit_entries(org, principal, ts);
CREATE INDEX idx_audit_budget    ON audit_entries(org, budget_ref, ts);
CREATE INDEX idx_audit_tid       ON audit_entries(tid);

CREATE TABLE checkpoints (
  org          TEXT NOT NULL,
  seq          INTEGER NOT NULL,
  merkle_root  TEXT NOT NULL,
  ts           TEXT NOT NULL,
  anchor_ref   TEXT,
  PRIMARY KEY (org, seq)
);

-- Registry tables so cron jobs can enumerate orgs/budgets (DOs are not enumerable).
CREATE TABLE orgs (
  org        TEXT PRIMARY KEY,
  first_seen TEXT NOT NULL
);

CREATE TABLE budgets (
  ref    TEXT PRIMARY KEY,
  org    TEXT NOT NULL,
  parent TEXT,
  ccy    TEXT NOT NULL
);

-- Mock settlement ledger. In production a licensed institution's rails attach here.
CREATE TABLE mock_ledger (
  tid          TEXT PRIMARY KEY,
  org          TEXT NOT NULL,
  amount_minor INTEGER NOT NULL,
  ccy          TEXT NOT NULL,
  merchant     TEXT,
  settled_ts   TEXT NOT NULL
);
