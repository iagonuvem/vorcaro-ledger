# Vorcaro Sovereign Finance Ledger — Common Types

Shared entity definitions for the Vorcaro server (`SERVER_IMPLEMENTATION_PLAN.md`) and
the Electron client (`APP_IMPLEMENTATION_PLAN.md`). These types live in
`packages/protocol` as zod schemas; this document is their human-readable spec.
Where this document and `PLAN.md` disagree, `PLAN.md` wins.

Types are written as TypeScript `type` aliases. The zod schemas in
`packages/protocol` are the executable source of truth; a CI check keeps this file
and the schemas in sync (schema hash pinned in the doc header when generated).

---

## 1. Conventions

| Convention | Rule |
|---|---|
| IDs | ULID strings, prefixed by kind: `evt_`, `exec_`, `dev_`, `acct_`, `txn_`, `bud_`, `fct_`, `apr_`, `vnd_`, `ent_`, `att_`, `ai_`, `cfl_`, `kp_`, `rcv_`, `pol_`. Client-generated where the client creates the object. |
| Timestamps | ISO 8601 UTC strings (`2026-07-01T14:23:11Z`). `client_*` timestamps are recorded but never trusted for policy; `server_*` timestamps are authoritative. |
| Money | Always `{ amount_minor_units: bigint; currency: CurrencyCode }`. Integer minor units (cents); **never floats**. `CurrencyCode` is ISO 4217 (`"USD"`, `"EUR"`, …). |
| Hashes | `sha256:<hex>` strings. |
| Signatures | Ed25519 over RFC 8785 JCS canonical bytes, base64. |
| Enums | Closed string unions. Clients and server branch on enum values, never on message strings. |
| Event-sourced state | Finance entities (Account, Transaction, Budget, Forecast, Approval, Vendor, Conflict) are **derived state**: they exist only as fold results of accepted ledger events. Their types below describe the materialized view (server projections / client `object_cache`), not mutable rows. |

```ts
type Money = {
  amount_minor_units: bigint;
  currency: string; // ISO 4217
};
```

---

## 2. Ledger Core

### 2.1 LedgerEvent

The one envelope everything travels in. Client-signed fields vs. server-assigned
fields per `PLAN.md` §6.

```ts
type EventStatus = "pending" | "accepted" | "rejected" | "conflicted" | "quarantined";

type EventType =
  // Finance domain
  | "ACCOUNT_CREATED" | "ACCOUNT_UPDATED" | "ACCOUNT_CLOSED"
  | "BANK_STATEMENT_IMPORTED"
  | "TRANSACTION_RECORDED" | "TRANSACTION_CLASSIFIED"
  | "INTERNAL_TRANSFER_RECORDED"
  | "FORECAST_CREATED" | "FORECAST_ADJUSTED"
  | "BUDGET_CREATED" | "BUDGET_APPROVED" | "BUDGET_OVERRIDDEN"
  | "PAYMENT_REQUESTED" | "PAYMENT_APPROVAL_CREATED"
  | "PAYMENT_APPROVED" | "PAYMENT_REJECTED"
  | "VENDOR_CREATED" | "VENDOR_UPDATED"
  | "RECONCILIATION_COMPLETED"
  | "ATTACHMENT_ADDED"
  | "DATA_EXPORTED"
  // Governance / security
  | "CONFLICT_RESOLVED"
  | "STATUS_TRANSITION"
  | "POLICY_CHANGED"
  | "DEVICE_ENROLLED" | "DEVICE_REVOKED"
  | "KEY_ROTATED" | "RECOVERY_PERFORMED";

type ObjectType =
  | "account" | "transaction" | "budget" | "forecast" | "approval"
  | "vendor" | "financial_entity" | "attachment" | "conflict"
  | "policy" | "device" | "executive_key" | "export";

// Plaintext-signed routing/policy metadata (PLAN.md §4.3): lets the server run
// cert checks, replay protection, threshold policy, and conflict detection
// before decrypting the payload. Multi-account: account_id is REQUIRED on all
// money-moving events; counterparty_account_id on internal transfers.
type PolicyMetadata = {
  account_id?: string;
  counterparty_account_id?: string;
  entity_id?: string;
  amount_minor_units?: bigint;
  currency?: string;
};

// What the client builds and signs.
type ClientEventEnvelope = {
  event_id: string;                // ULID; doubles as idempotency key
  event_type: EventType;
  actor_id: string;
  device_id: string;
  client_timestamp: string;
  base_server_sequence: bigint;    // last verified state; basis for conflict detection
  device_event_counter: bigint;    // per-device monotonic; replay protection
  object_type: ObjectType;
  object_id: string;
  policy_metadata: PolicyMetadata;
  payload_hash: string;            // SHA256 of encrypted_payload
  encrypted_payload: string;       // AES-256-GCM, base64
  client_signature: string;        // Ed25519 over JCS(envelope minus signature)
};

// What the server appends. Superset of the client envelope.
type LedgerEvent = ClientEventEnvelope & {
  server_sequence: bigint | null;  // gapless for accepted; assigned at append
  previous_ledger_hash: string | null;
  resulting_ledger_hash: string | null;
  server_signature: string | null;
  status: EventStatus;
  error_code: ErrorCode | null;    // persisted outcome for idempotent acknowledgements
  server_timestamp: string;        // authoritative for policy and audit
  accepted_at: string | null;
};
```

### 2.2 ServerAck

```ts
type ServerAck = {
  event_id: string;
  status: EventStatus;
  server_sequence: bigint | null;
  resulting_ledger_hash: string | null;
  server_timestamp: string;
  error_code: ErrorCode | null;
  server_signature: string;        // over JCS of the fields above
};
```

### 2.3 Checkpoint

Rollback-detection anchor (`PLAN.md` §4.3). Append-only on every device.

```ts
type Checkpoint = {
  sequence: bigint;
  ledger_hash: string;
  issued_at: string;
  key_version: number;             // server signing key version
  signature: string;
};
```

### 2.4 LedgerSnapshot

```ts
type LedgerSnapshot = {
  id: string;
  up_to_sequence: bigint;
  content_hash: string;
  storage_ref: string;             // MinIO object reference
  signature: string;
  created_at: string;
};
```

### 2.5 SyncState (client-side singleton)

```ts
type SyncState = {
  last_verified_sequence: bigint;
  last_verified_ledger_hash: string;
  revocation_list_version: number;
  active_policy_version: number;
  last_sync_at: string | null;
};
```

### 2.6 ErrorCode

Closed enum; clients branch on codes, never message strings.

```ts
type ErrorCode =
  | "CERT_REVOKED" | "CERT_UNKNOWN" | "EXECUTIVE_INACTIVE"
  | "REPLAY_COUNTER" | "DUPLICATE_EVENT"
  | "BAD_SIGNATURE" | "BAD_PAYLOAD_HASH" | "SCHEMA_INVALID"
  | "STALE_BASE" | "CONFLICT"
  | "POLICY_DENIED" | "APPROVALS_REQUIRED"
  | "UNKNOWN_ACCOUNT" | "ACCOUNT_CLOSED"
  | "POLICY_VERSION_MISMATCH";
```

---

## 3. Identity & Security

### 3.1 Executive

```ts
type Role =
  | "CEO" | "CFO" | "COO" | "TREASURER" | "GENERAL_COUNSEL"
  | "INTERNAL_AUDIT" | "SECURITY_RECOVERY_OFFICER" | "FINANCE_CONTROLLER";

type Executive = {
  id: string;
  display_name: string;
  role: Role;
  status: "active" | "quarantined" | "deactivated";
  signing_public_key: string;      // current key version's public key
  key_version: number;
  created_at: string;
};
```

### 3.2 ExecutiveKey (key history)

Forward-only revocation (`PLAN.md` §5.2): old events verify against the key
version whose authority window covers their sequence.

```ts
type ExecutiveKey = {
  executive_id: string;
  key_version: number;
  signing_public_key: string;
  valid_from_sequence: bigint;
  valid_until_sequence: bigint | null; // null = still active
};
```

### 3.3 Device

```ts
type Device = {
  id: string;
  executive_id: string;
  certificate_fingerprint: string;
  public_key: string;
  status: "enrolled" | "revoked" | "quarantined";
  hardware_backed: boolean;
  enrolled_at: string;
  revoked_at: string | null;
  last_seen_at: string | null;
  risk_score: number;              // 0–100
  max_event_counter: bigint;       // replay watermark (server-side)
};
```

### 3.4 KeyPackage

Envelope encryption (`PLAN.md` §5.1): DEKs wrapped for an executive key version.

```ts
type KeyPackage = {
  id: string;
  executive_id: string;
  key_version: number;
  wrapped_data_key: string;        // DEK wrapped for the executive's unwrapping key
  recovery_wrapped_key: string;    // DEK wrapped for the recovery master key
  status: "active" | "revoked";
  created_at: string;
  revoked_at: string | null;
};
```

### 3.5 RecoveryPolicy & RecoveryCeremony

```ts
type RecoveryPolicy = {
  id: string;
  required_approvals: number;      // M in M-of-N (default 3)
  custodian_ids: string[];         // N custodians (default 5)
  version: number;
};

type RecoveryCeremony = {
  id: string;
  executive_id: string;
  initiated_by: string;
  new_public_key: string;
  status: "open" | "threshold_met" | "executed" | "aborted";
  required_approvals: number;
  approvals: RecoveryApproval[];
  created_at: string;
  completed_at: string | null;
};

type RecoveryApproval = {
  ceremony_id: string;
  approver_id: string;
  approval_signature: string;      // Ed25519 over JCS({ceremony_id, executive_id, new_public_key})
  created_at: string;
};
```

### 3.6 Permission & PolicyDocument

Policy-as-code (`PLAN.md` §9): versioned JSON interpreted identically by server
and client (`evaluate(policy, event, context) → allow | deny | require_approvals[]`).

```ts
type Permission = {
  role: Role;
  object_type: ObjectType;
  actions: ("read" | "create" | "approve" | "resolve" | "export")[];
  conditions?: Record<string, unknown>;   // ABAC conditions (entity, amount, account)
};

type ApprovalRule = {
  event_types: EventType[];
  threshold?: Money;               // applies when policy_metadata amount exceeds it
  required_roles: Role[];
  required_count: number;          // multi-party M
};

type PolicyDocument = {
  id: string;
  version: number;
  permissions: Permission[];
  approval_rules: ApprovalRule[];
  document_hash: string;
  activated_at_sequence: bigint | null;
  signature: string;
};
```

### 3.7 RevocationList

```ts
type RevocationList = {
  version: number;
  revoked_device_ids: string[];
  revoked_key_versions: { executive_id: string; key_version: number }[];
  wipe_directives: { device_id: string; signature: string }[];
  issued_at: string;
  signature: string;
};
```

---

## 4. Finance Domain (event-sourced views)

### 4.1 FinancialEntity

A legal entity (company, subsidiary) that owns accounts and budgets.

```ts
type FinancialEntity = {
  id: string;
  name: string;
  jurisdiction: string;
  base_currency: string;
  status: "active" | "archived";
  created_at: string;
};
```

### 4.2 Account (bank account — unbounded count)

The ledger accepts and tracks **any number of accounts**. Each is created by an
`ACCOUNT_CREATED` event; balance is the fold of accepted events referencing its
`account_id`.

```ts
type AccountType = "checking" | "savings" | "treasury" | "credit" | "payment_provider";

type Account = {
  id: string;                      // acct_<ULID>; the ledger object_id
  entity_id: string;
  name: string;                    // executive-facing label
  account_type: AccountType;
  institution_name: string;
  account_number_masked: string;   // last 4 only; full number lives in encrypted payload
  currency: string;
  balance: Money;                  // derived; as of `as_of_sequence`
  as_of_sequence: bigint;
  status: "active" | "frozen" | "closed";
  conflicted: boolean;
  created_at: string;
};
```

### 4.3 Vendor

```ts
type Vendor = {
  id: string;
  name: string;
  jurisdiction: string | null;
  default_currency: string;
  risk_score: number | null;       // AI-scored, advisory (labeled)
  status: "active" | "blocked" | "archived";
  created_at: string;
};
```

### 4.4 Transaction

```ts
type TransactionDirection = "inflow" | "outflow" | "internal_transfer";

type Transaction = {
  id: string;
  account_id: string;
  counterparty_account_id: string | null;  // set for internal transfers
  entity_id: string;
  vendor_id: string | null;
  direction: TransactionDirection;
  amount: Money;
  occurred_at: string;             // bank-reported date
  description: string;
  classification: string | null;   // category; set by TRANSACTION_CLASSIFIED
  classification_source: "human" | "ai_suggested_human_confirmed" | null;
  reconciled: boolean;
  source_event_id: string;
  created_at: string;
};
```

### 4.5 Budget

```ts
type BudgetLine = {
  category: string;
  amount: Money;
};

type Budget = {
  id: string;
  entity_id: string;
  name: string;
  period_start: string;            // yyyy-MM-dd
  period_end: string;
  lines: BudgetLine[];
  status: "draft" | "approved" | "overridden" | "archived";
  approved_by: string[];           // executive ids, from approval events
  conflicted: boolean;
  created_at: string;
};
```

### 4.6 Forecast

```ts
type ForecastPoint = {
  date: string;                    // yyyy-MM-dd
  projected: Money;
};

type Forecast = {
  id: string;
  entity_id: string;
  account_id: string | null;       // null = entity-wide across all accounts
  name: string;
  horizon_end: string;
  points: ForecastPoint[];
  assumptions: string;
  version: number;                 // bumped by each FORECAST_ADJUSTED
  conflicted: boolean;
  created_at: string;
};
```

### 4.7 Approval

Multi-party approval state for a sensitive operation (`PLAN.md` §9).

```ts
type ApprovalSignature = {
  approver_id: string;
  key_version: number;
  event_id: string;                // the PAYMENT_APPROVED / co-approval event
  signed_at: string;
};

type Approval = {
  id: string;
  target_object_type: ObjectType;
  target_object_id: string;
  account_id: string | null;       // account the money moves from, if applicable
  amount: Money | null;
  required_count: number;
  required_roles: Role[];
  signatures: ApprovalSignature[];
  status: "open" | "approved" | "rejected" | "expired";
  requested_by: string;
  created_at: string;
  resolved_at: string | null;
};
```

### 4.8 Conflict

```ts
type Conflict = {
  id: string;
  object_type: ObjectType;
  object_id: string;
  event_ids: string[];             // the conflicting events (≥ 2), permanent in ledger
  detected_at_sequence: bigint;
  status: "open" | "resolved";
  resolution_event_id: string | null;  // the CONFLICT_RESOLVED event
  ai_proposal_id: string | null;   // optional AIInsight, advisory only
  created_at: string;
  resolved_at: string | null;
};
```

### 4.9 Attachment

```ts
type Attachment = {
  id: string;
  object_type: ObjectType;
  object_id: string;
  filename: string;
  content_type: string;
  content_hash: string;
  storage_ref: string;             // MinIO object; encrypted at rest
  size_bytes: number;
  uploaded_by: string;
  created_at: string;
};
```

---

## 5. Audit & AI

### 5.1 AuditLog entry

Hash-chained like the ledger; used server-side (`audit_log`) and client-side
(`local_audit`) with the same shape.

```ts
type AuditCategory =
  | "auth" | "sync" | "admin" | "recovery" | "revocation"
  | "export" | "ipc_anomaly" | "chain_verification" | "ai_access";

type AuditLogEntry = {
  id: bigint;
  category: AuditCategory;
  actor: string;                   // executive/device/service identity
  detail: Record<string, unknown>; // never contains payload plaintext or key material
  previous_hash: string;
  entry_hash: string;
  created_at: string;
};
```

### 5.2 AIInsight

Advisory only (`PLAN.md` §10). No write path from insights to ledger events.

```ts
type AIInsightKind =
  | "cash_flow_summary" | "burn_rate" | "anomaly" | "duplicate_invoice"
  | "vendor_risk" | "variance_explanation" | "reconciliation_suggestion"
  | "conflict_resolution_proposal" | "board_summary_draft";

type AIInsight = {
  id: string;
  kind: AIInsightKind;
  related_object_type: ObjectType | null;
  related_object_id: string | null;
  body: string;                    // rendered only in labeled "AI analysis — advisory" containers
  model_version: string;
  origin: "local" | "vorcaro_server";
  created_at: string;
};
```
