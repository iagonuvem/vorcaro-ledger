import { z } from "zod";

export const eventStatuses = ["pending", "accepted", "rejected", "conflicted", "quarantined"] as const;

export const eventTypes = [
  "ACCOUNT_CREATED",
  "ACCOUNT_UPDATED",
  "ACCOUNT_CLOSED",
  "BANK_STATEMENT_IMPORTED",
  "TRANSACTION_RECORDED",
  "TRANSACTION_CLASSIFIED",
  "INTERNAL_TRANSFER_RECORDED",
  "FORECAST_CREATED",
  "FORECAST_ADJUSTED",
  "BUDGET_CREATED",
  "BUDGET_APPROVED",
  "BUDGET_OVERRIDDEN",
  "PAYMENT_REQUESTED",
  "PAYMENT_APPROVAL_CREATED",
  "PAYMENT_APPROVED",
  "PAYMENT_REJECTED",
  "VENDOR_CREATED",
  "VENDOR_UPDATED",
  "RECONCILIATION_COMPLETED",
  "ATTACHMENT_ADDED",
  "DATA_EXPORTED",
  "CONFLICT_RESOLVED",
  "STATUS_TRANSITION",
  "POLICY_CHANGED",
  "DEVICE_ENROLLED",
  "DEVICE_REVOKED",
  "KEY_ROTATED",
  "RECOVERY_PERFORMED"
] as const;

export const objectTypes = [
  "account",
  "transaction",
  "budget",
  "forecast",
  "approval",
  "vendor",
  "financial_entity",
  "attachment",
  "conflict",
  "policy",
  "device",
  "executive_key",
  "export"
] as const;

export const errorCodes = [
  "CERT_REVOKED",
  "CERT_UNKNOWN",
  "EXECUTIVE_INACTIVE",
  "REPLAY_COUNTER",
  "DUPLICATE_EVENT",
  "BAD_SIGNATURE",
  "BAD_PAYLOAD_HASH",
  "SCHEMA_INVALID",
  "STALE_BASE",
  "CONFLICT",
  "POLICY_DENIED",
  "APPROVALS_REQUIRED",
  "UNKNOWN_ACCOUNT",
  "ACCOUNT_CLOSED",
  "POLICY_VERSION_MISMATCH"
] as const;

export const roles = [
  "CEO",
  "CFO",
  "COO",
  "TREASURER",
  "GENERAL_COUNSEL",
  "INTERNAL_AUDIT",
  "SECURITY_RECOVERY_OFFICER",
  "FINANCE_CONTROLLER"
] as const;

export const auditCategories = [
  "auth",
  "sync",
  "admin",
  "recovery",
  "revocation",
  "export",
  "ipc_anomaly",
  "chain_verification",
  "ai_access"
] as const;

export const aiInsightKinds = [
  "cash_flow_summary",
  "burn_rate",
  "anomaly",
  "duplicate_invoice",
  "vendor_risk",
  "variance_explanation",
  "reconciliation_suggestion",
  "conflict_resolution_proposal",
  "board_summary_draft"
] as const;

export const currencyCodeSchema = z.string().regex(/^[A-Z]{3}$/);
export const hashSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/);
export const base64Schema = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/);
export const isoUtcTimestampSchema = z.string().datetime({ offset: true });
export const isoDateSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);

export const eventStatusSchema = z.enum(eventStatuses);
export const eventTypeSchema = z.enum(eventTypes);
export const objectTypeSchema = z.enum(objectTypes);
export const errorCodeSchema = z.enum(errorCodes);
export const roleSchema = z.enum(roles);

export const moneySchema = z
  .object({
    amount_minor_units: z.bigint(),
    currency: currencyCodeSchema
  })
  .strict();

export const policyMetadataSchema = z
  .object({
    account_id: z.string().min(1).optional(),
    counterparty_account_id: z.string().min(1).optional(),
    entity_id: z.string().min(1).optional(),
    amount_minor_units: z.bigint().optional(),
    currency: currencyCodeSchema.optional()
  })
  .strict();

export const clientEventEnvelopeSchema = z
  .object({
    event_id: z.string().min(1),
    event_type: eventTypeSchema,
    actor_id: z.string().min(1),
    device_id: z.string().min(1),
    client_timestamp: isoUtcTimestampSchema,
    base_server_sequence: z.bigint().nonnegative(),
    device_event_counter: z.bigint().positive(),
    object_type: objectTypeSchema,
    object_id: z.string().min(1),
    policy_metadata: policyMetadataSchema,
    payload_hash: hashSchema,
    encrypted_payload: base64Schema,
    client_signature: base64Schema
  })
  .strict();

export const unsignedClientEventEnvelopeSchema = clientEventEnvelopeSchema.omit({
  client_signature: true
});

export const ledgerEventSchema = clientEventEnvelopeSchema
  .extend({
    server_sequence: z.bigint().positive().nullable(),
    previous_ledger_hash: hashSchema.nullable(),
    resulting_ledger_hash: hashSchema.nullable(),
    server_signature: base64Schema.nullable(),
    status: eventStatusSchema,
    server_timestamp: isoUtcTimestampSchema,
    accepted_at: isoUtcTimestampSchema.nullable()
  })
  .strict();

export const serverAckSchema = z
  .object({
    event_id: z.string().min(1),
    status: eventStatusSchema,
    server_sequence: z.bigint().positive().nullable(),
    resulting_ledger_hash: hashSchema.nullable(),
    server_timestamp: isoUtcTimestampSchema,
    error_code: errorCodeSchema.nullable(),
    server_signature: base64Schema
  })
  .strict();

export const unsignedServerAckSchema = serverAckSchema.omit({
  server_signature: true
});

export const checkpointSchema = z
  .object({
    sequence: z.bigint().nonnegative(),
    ledger_hash: hashSchema,
    issued_at: isoUtcTimestampSchema,
    key_version: z.number().int().positive(),
    signature: base64Schema
  })
  .strict();

export const unsignedCheckpointSchema = checkpointSchema.omit({
  signature: true
});

export const ledgerSnapshotSchema = z
  .object({
    id: z.string().min(1),
    up_to_sequence: z.bigint().nonnegative(),
    content_hash: hashSchema,
    storage_ref: z.string().min(1),
    signature: base64Schema,
    created_at: isoUtcTimestampSchema
  })
  .strict();

export const syncStateSchema = z
  .object({
    last_verified_sequence: z.bigint().nonnegative(),
    last_verified_ledger_hash: hashSchema,
    revocation_list_version: z.number().int().nonnegative(),
    active_policy_version: z.number().int().nonnegative(),
    last_sync_at: isoUtcTimestampSchema.nullable()
  })
  .strict();

export const executiveSchema = z
  .object({
    id: z.string().min(1),
    display_name: z.string().min(1),
    role: roleSchema,
    status: z.enum(["active", "quarantined", "deactivated"]),
    signing_public_key: base64Schema,
    key_version: z.number().int().positive(),
    created_at: isoUtcTimestampSchema
  })
  .strict();

export const executiveKeySchema = z
  .object({
    executive_id: z.string().min(1),
    key_version: z.number().int().positive(),
    signing_public_key: base64Schema,
    valid_from_sequence: z.bigint().nonnegative(),
    valid_until_sequence: z.bigint().nonnegative().nullable()
  })
  .strict();

export const deviceSchema = z
  .object({
    id: z.string().min(1),
    executive_id: z.string().min(1),
    certificate_fingerprint: z.string().min(1),
    public_key: base64Schema,
    status: z.enum(["enrolled", "revoked", "quarantined"]),
    hardware_backed: z.boolean(),
    enrolled_at: isoUtcTimestampSchema,
    revoked_at: isoUtcTimestampSchema.nullable(),
    last_seen_at: isoUtcTimestampSchema.nullable(),
    risk_score: z.number().int().min(0).max(100),
    max_event_counter: z.bigint().nonnegative()
  })
  .strict();

export const keyPackageSchema = z
  .object({
    id: z.string().min(1),
    executive_id: z.string().min(1),
    key_version: z.number().int().positive(),
    wrapped_data_key: base64Schema,
    recovery_wrapped_key: base64Schema,
    status: z.enum(["active", "revoked"]),
    created_at: isoUtcTimestampSchema,
    revoked_at: isoUtcTimestampSchema.nullable()
  })
  .strict();

export const recoveryApprovalSchema = z
  .object({
    ceremony_id: z.string().min(1),
    approver_id: z.string().min(1),
    approval_signature: base64Schema,
    created_at: isoUtcTimestampSchema
  })
  .strict();

export const recoveryPolicySchema = z
  .object({
    id: z.string().min(1),
    required_approvals: z.number().int().positive(),
    custodian_ids: z.array(z.string().min(1)),
    version: z.number().int().positive()
  })
  .strict();

export const recoveryCeremonySchema = z
  .object({
    id: z.string().min(1),
    executive_id: z.string().min(1),
    initiated_by: z.string().min(1),
    new_public_key: base64Schema,
    status: z.enum(["open", "threshold_met", "executed", "aborted"]),
    required_approvals: z.number().int().positive(),
    approvals: z.array(recoveryApprovalSchema),
    created_at: isoUtcTimestampSchema,
    completed_at: isoUtcTimestampSchema.nullable()
  })
  .strict();

export const permissionSchema = z
  .object({
    role: roleSchema,
    object_type: objectTypeSchema,
    actions: z.array(z.enum(["read", "create", "approve", "resolve", "export"])),
    conditions: z.record(z.unknown()).optional()
  })
  .strict();

export const approvalRuleSchema = z
  .object({
    event_types: z.array(eventTypeSchema),
    threshold: moneySchema.optional(),
    required_roles: z.array(roleSchema),
    required_count: z.number().int().positive()
  })
  .strict();

export const policyDocumentSchema = z
  .object({
    id: z.string().min(1),
    version: z.number().int().positive(),
    permissions: z.array(permissionSchema),
    approval_rules: z.array(approvalRuleSchema),
    document_hash: hashSchema,
    activated_at_sequence: z.bigint().nonnegative().nullable(),
    signature: base64Schema
  })
  .strict();

export const revocationListSchema = z
  .object({
    version: z.number().int().nonnegative(),
    revoked_device_ids: z.array(z.string().min(1)),
    revoked_key_versions: z.array(
      z
        .object({
          executive_id: z.string().min(1),
          key_version: z.number().int().positive()
        })
        .strict()
    ),
    wipe_directives: z.array(
      z
        .object({
          device_id: z.string().min(1),
          signature: base64Schema
        })
        .strict()
    ),
    issued_at: isoUtcTimestampSchema,
    signature: base64Schema
  })
  .strict();

export const financialEntitySchema = z
  .object({
    id: z.string().min(1),
    name: z.string().min(1),
    jurisdiction: z.string().min(1),
    base_currency: currencyCodeSchema,
    status: z.enum(["active", "archived"]),
    created_at: isoUtcTimestampSchema
  })
  .strict();

export const accountSchema = z
  .object({
    id: z.string().min(1),
    entity_id: z.string().min(1),
    name: z.string().min(1),
    account_type: z.enum(["checking", "savings", "treasury", "credit", "payment_provider"]),
    institution_name: z.string().min(1),
    account_number_masked: z.string().min(1),
    currency: currencyCodeSchema,
    balance: moneySchema,
    as_of_sequence: z.bigint().nonnegative(),
    status: z.enum(["active", "frozen", "closed"]),
    conflicted: z.boolean(),
    created_at: isoUtcTimestampSchema
  })
  .strict();

export const vendorSchema = z
  .object({
    id: z.string().min(1),
    name: z.string().min(1),
    jurisdiction: z.string().min(1).nullable(),
    default_currency: currencyCodeSchema,
    risk_score: z.number().int().min(0).max(100).nullable(),
    status: z.enum(["active", "blocked", "archived"]),
    created_at: isoUtcTimestampSchema
  })
  .strict();

export const transactionSchema = z
  .object({
    id: z.string().min(1),
    account_id: z.string().min(1),
    counterparty_account_id: z.string().min(1).nullable(),
    entity_id: z.string().min(1),
    vendor_id: z.string().min(1).nullable(),
    direction: z.enum(["inflow", "outflow", "internal_transfer"]),
    amount: moneySchema,
    occurred_at: isoUtcTimestampSchema,
    description: z.string(),
    classification: z.string().nullable(),
    classification_source: z.enum(["human", "ai_suggested_human_confirmed"]).nullable(),
    reconciled: z.boolean(),
    source_event_id: z.string().min(1),
    created_at: isoUtcTimestampSchema
  })
  .strict();

export const budgetLineSchema = z
  .object({
    category: z.string().min(1),
    amount: moneySchema
  })
  .strict();

export const budgetSchema = z
  .object({
    id: z.string().min(1),
    entity_id: z.string().min(1),
    name: z.string().min(1),
    period_start: isoDateSchema,
    period_end: isoDateSchema,
    lines: z.array(budgetLineSchema),
    status: z.enum(["draft", "approved", "overridden", "archived"]),
    approved_by: z.array(z.string().min(1)),
    conflicted: z.boolean(),
    created_at: isoUtcTimestampSchema
  })
  .strict();

export const forecastPointSchema = z
  .object({
    date: isoDateSchema,
    projected: moneySchema
  })
  .strict();

export const forecastSchema = z
  .object({
    id: z.string().min(1),
    entity_id: z.string().min(1),
    account_id: z.string().min(1).nullable(),
    name: z.string().min(1),
    horizon_end: isoDateSchema,
    points: z.array(forecastPointSchema),
    assumptions: z.string(),
    version: z.number().int().positive(),
    conflicted: z.boolean(),
    created_at: isoUtcTimestampSchema
  })
  .strict();

export const approvalSignatureSchema = z
  .object({
    approver_id: z.string().min(1),
    key_version: z.number().int().positive(),
    event_id: z.string().min(1),
    signed_at: isoUtcTimestampSchema
  })
  .strict();

export const approvalSchema = z
  .object({
    id: z.string().min(1),
    target_object_type: objectTypeSchema,
    target_object_id: z.string().min(1),
    account_id: z.string().min(1).nullable(),
    amount: moneySchema.nullable(),
    required_count: z.number().int().positive(),
    required_roles: z.array(roleSchema),
    signatures: z.array(approvalSignatureSchema),
    status: z.enum(["open", "approved", "rejected", "expired"]),
    requested_by: z.string().min(1),
    created_at: isoUtcTimestampSchema,
    resolved_at: isoUtcTimestampSchema.nullable()
  })
  .strict();

export const conflictSchema = z
  .object({
    id: z.string().min(1),
    object_type: objectTypeSchema,
    object_id: z.string().min(1),
    event_ids: z.array(z.string().min(1)).min(2),
    detected_at_sequence: z.bigint().positive(),
    status: z.enum(["open", "resolved"]),
    resolution_event_id: z.string().min(1).nullable(),
    ai_proposal_id: z.string().min(1).nullable(),
    created_at: isoUtcTimestampSchema,
    resolved_at: isoUtcTimestampSchema.nullable()
  })
  .strict();

export const attachmentSchema = z
  .object({
    id: z.string().min(1),
    object_type: objectTypeSchema,
    object_id: z.string().min(1),
    filename: z.string().min(1),
    content_type: z.string().min(1),
    content_hash: hashSchema,
    storage_ref: z.string().min(1),
    size_bytes: z.number().int().nonnegative(),
    uploaded_by: z.string().min(1),
    created_at: isoUtcTimestampSchema
  })
  .strict();

export const auditLogEntrySchema = z
  .object({
    id: z.bigint().nonnegative(),
    category: z.enum(auditCategories),
    actor: z.string().min(1),
    detail: z.record(z.unknown()),
    previous_hash: hashSchema,
    entry_hash: hashSchema,
    created_at: isoUtcTimestampSchema
  })
  .strict();

export const aiInsightSchema = z
  .object({
    id: z.string().min(1),
    kind: z.enum(aiInsightKinds),
    related_object_type: objectTypeSchema.nullable(),
    related_object_id: z.string().min(1).nullable(),
    body: z.string(),
    model_version: z.string().min(1),
    origin: z.enum(["local", "vorcaro_server"]),
    created_at: isoUtcTimestampSchema
  })
  .strict();

export type EventStatus = z.infer<typeof eventStatusSchema>;
export type EventType = z.infer<typeof eventTypeSchema>;
export type ObjectType = z.infer<typeof objectTypeSchema>;
export type ErrorCode = z.infer<typeof errorCodeSchema>;
export type Role = z.infer<typeof roleSchema>;
export type Money = z.infer<typeof moneySchema>;
export type PolicyMetadata = z.infer<typeof policyMetadataSchema>;
export type ClientEventEnvelope = z.infer<typeof clientEventEnvelopeSchema>;
export type UnsignedClientEventEnvelope = z.infer<typeof unsignedClientEventEnvelopeSchema>;
export type LedgerEvent = z.infer<typeof ledgerEventSchema>;
export type ServerAck = z.infer<typeof serverAckSchema>;
export type UnsignedServerAck = z.infer<typeof unsignedServerAckSchema>;
export type Checkpoint = z.infer<typeof checkpointSchema>;
export type UnsignedCheckpoint = z.infer<typeof unsignedCheckpointSchema>;
export type LedgerSnapshot = z.infer<typeof ledgerSnapshotSchema>;
export type SyncState = z.infer<typeof syncStateSchema>;
export type Executive = z.infer<typeof executiveSchema>;
export type ExecutiveKey = z.infer<typeof executiveKeySchema>;
export type Device = z.infer<typeof deviceSchema>;
export type KeyPackage = z.infer<typeof keyPackageSchema>;
export type RecoveryPolicy = z.infer<typeof recoveryPolicySchema>;
export type RecoveryCeremony = z.infer<typeof recoveryCeremonySchema>;
export type RecoveryApproval = z.infer<typeof recoveryApprovalSchema>;
export type Permission = z.infer<typeof permissionSchema>;
export type ApprovalRule = z.infer<typeof approvalRuleSchema>;
export type PolicyDocument = z.infer<typeof policyDocumentSchema>;
export type RevocationList = z.infer<typeof revocationListSchema>;
export type FinancialEntity = z.infer<typeof financialEntitySchema>;
export type Account = z.infer<typeof accountSchema>;
export type Vendor = z.infer<typeof vendorSchema>;
export type Transaction = z.infer<typeof transactionSchema>;
export type BudgetLine = z.infer<typeof budgetLineSchema>;
export type Budget = z.infer<typeof budgetSchema>;
export type ForecastPoint = z.infer<typeof forecastPointSchema>;
export type Forecast = z.infer<typeof forecastSchema>;
export type ApprovalSignature = z.infer<typeof approvalSignatureSchema>;
export type Approval = z.infer<typeof approvalSchema>;
export type Conflict = z.infer<typeof conflictSchema>;
export type Attachment = z.infer<typeof attachmentSchema>;
export type AuditLogEntry = z.infer<typeof auditLogEntrySchema>;
export type AIInsight = z.infer<typeof aiInsightSchema>;
