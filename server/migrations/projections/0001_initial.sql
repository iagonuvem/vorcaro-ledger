PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS proj_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS proj_accounts (
  account_id              TEXT PRIMARY KEY,
  entity_id               TEXT NOT NULL,
  name                    TEXT NOT NULL,
  account_type            TEXT NOT NULL,
  institution_name        TEXT NOT NULL,
  account_number_masked   TEXT NOT NULL,
  currency                TEXT NOT NULL,
  balance_minor_units     INTEGER NOT NULL,
  as_of_sequence          INTEGER NOT NULL,
  status                  TEXT NOT NULL,
  conflicted              INTEGER NOT NULL DEFAULT 0 CHECK (conflicted IN (0,1))
) STRICT;

CREATE TABLE IF NOT EXISTS proj_cash_position (
  entity_id                 TEXT NOT NULL,
  currency                  TEXT NOT NULL,
  total_minor_units         INTEGER NOT NULL,
  default_currency          TEXT,
  default_total_minor_units INTEGER,
  default_currency_snapshot_id TEXT,
  pending_delta_minor_units INTEGER NOT NULL,
  as_of_sequence            INTEGER NOT NULL,
  PRIMARY KEY (entity_id, currency)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS proj_transactions (
  transaction_id     TEXT PRIMARY KEY,
  account_id         TEXT NOT NULL,
  entity_id          TEXT NOT NULL,
  vendor_id          TEXT,
  direction          TEXT NOT NULL,
  amount_minor_units INTEGER NOT NULL,
  currency           TEXT NOT NULL,
  transaction_currency TEXT NOT NULL,
  exchange_rate      TEXT NOT NULL,
  local_rate         INTEGER NOT NULL,
  default_currency   TEXT NOT NULL,
  default_amount_minor_units INTEGER NOT NULL,
  default_currency_snapshot_id TEXT NOT NULL,
  occurred_at        TEXT NOT NULL,
  classification     TEXT,
  reconciled         INTEGER NOT NULL DEFAULT 0 CHECK (reconciled IN (0,1)),
  source_event_id    TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_proj_txn_account ON proj_transactions (account_id, occurred_at);

CREATE TABLE IF NOT EXISTS proj_budget_lines (
  budget_id          TEXT NOT NULL,
  category           TEXT NOT NULL,
  amount_minor_units INTEGER NOT NULL,
  currency           TEXT NOT NULL,
  transaction_currency TEXT,
  exchange_rate      TEXT,
  local_rate         INTEGER,
  default_currency   TEXT,
  default_amount_minor_units INTEGER,
  default_currency_snapshot_id TEXT,
  status             TEXT NOT NULL,
  PRIMARY KEY (budget_id, category)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS proj_approvals_open (
  approval_id        TEXT PRIMARY KEY,
  target_object_type TEXT NOT NULL,
  target_object_id   TEXT NOT NULL,
  account_id         TEXT,
  amount_minor_units INTEGER,
  currency           TEXT,
  transaction_currency TEXT,
  exchange_rate      TEXT,
  local_rate         INTEGER,
  default_currency   TEXT,
  default_amount_minor_units INTEGER,
  default_currency_snapshot_id TEXT,
  required_count     INTEGER NOT NULL,
  signature_count    INTEGER NOT NULL,
  requested_by       TEXT NOT NULL,
  created_at         TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS proj_conflicts_open (
  conflict_id           TEXT PRIMARY KEY,
  object_type           TEXT NOT NULL,
  object_id             TEXT NOT NULL,
  event_ids             TEXT NOT NULL CHECK (json_valid(event_ids)),
  detected_at_sequence  INTEGER NOT NULL
) STRICT;
