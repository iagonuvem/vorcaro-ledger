import { z } from "zod";
import { eventTypeSchema, objectTypeSchema, type CanonicalJson } from "@vorcaro/protocol";

export const ipcChannels = {
  shellGetState: "shell:get-state",
  workspaceGetSnapshot: "workspace:get-snapshot",
  eventCreate: "event:create",
  vaultStatus: "vault:status",
  vaultCreate: "vault:create",
  vaultUnlock: "vault:unlock",
  vaultLock: "vault:lock",
  securityAcknowledge: "security:acknowledge"
} as const;

export const emptyRequestSchema = z.object({}).strict();

export const eventStatusSchema = z.enum(["accepted", "pending", "rejected", "conflicted", "quarantined"]);

export const canonicalJsonSchema: z.ZodType<CanonicalJson> = z.lazy(() =>
  z.union([
    z.null(),
    z.boolean(),
    z.number().finite(),
    z.string(),
    z.array(canonicalJsonSchema),
    z.record(canonicalJsonSchema)
  ])
);

export const createEventPolicyMetadataRequestSchema = z
  .object({
    account_id: z.string().min(1).optional(),
    counterparty_account_id: z.string().min(1).optional(),
    entity_id: z.string().min(1).optional(),
    amount_minor_units: z.string().regex(/^-?(0|[1-9]\d*)$/).optional(),
    currency: z.string().regex(/^[A-Z]{3}$/).optional(),
    transaction_currency: z.string().regex(/^[A-Z]{3}$/).optional(),
    exchange_rate: z
      .string()
      .regex(/^(0|[1-9]\d*)(\.\d{1,12})?$/)
      .optional(),
    default_currency_snapshot_id: z.string().min(1).optional(),
    local_rate: z.string().regex(/^(0|[1-9]\d*)$/).optional()
  })
  .strict();

export const createEventRequestSchema = z
  .object({
    eventType: eventTypeSchema,
    objectType: objectTypeSchema,
    objectId: z.string().min(1),
    policyMetadata: createEventPolicyMetadataRequestSchema,
    payload: canonicalJsonSchema
  })
  .strict();

export const createEventResponseSchema = z
  .object({
    eventId: z.string().min(1),
    deviceEventCounter: z.string().regex(/^[1-9]\d*$/),
    baseServerSequence: z.string().regex(/^(0|[1-9]\d*)$/),
    submitState: z.literal("queued"),
    localPolicy: z.discriminatedUnion("outcome", [
      z.object({ outcome: z.literal("not_configured") }).strict(),
      z.object({ outcome: z.literal("allow") }).strict(),
      z
        .object({
          outcome: z.literal("deny"),
          errorCode: z.enum([
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
          ])
        })
        .strict(),
      z
        .object({
          outcome: z.literal("require_approvals"),
          requiredRoles: z.array(z.string().min(1)),
          requiredCount: z.number().int().positive(),
          errorCode: z.literal("APPROVALS_REQUIRED")
        })
        .strict()
    ])
  })
  .strict();

export const shellStateSchema = z
  .object({
    appProtocolUrl: z.literal("app://index.html"),
    integrity: z.enum(["verified", "development_unsigned"]),
    navigationPolicy: z.literal("app_only"),
    rendererNetwork: z.literal("disabled"),
    vault: z.enum(["locked", "unlocked"])
  })
  .strict();

export const securityAcknowledgementRequestSchema = z
  .object({
    kind: z.enum(["checkpoint_tripwire", "quarantine"]),
    acknowledgedAt: z.string().datetime({ offset: true })
  })
  .strict();

export const securityAcknowledgementResponseSchema = z
  .object({
    recorded: z.literal(true)
  })
  .strict();

export const vaultPassphraseRequestSchema = z
  .object({
    passphrase: z.string().min(12)
  })
  .strict();

export const vaultStatusSchema = z
  .object({
    state: z.enum(["uninitialized", "locked", "unlocked"]),
    keyVersion: z.number().int().positive().nullable(),
    failedUnlocks: z.number().int().nonnegative(),
    lockedUntil: z.string().datetime({ offset: true }).nullable()
  })
  .strict();

export const metricSchema = z
  .object({
    label: z.string().min(1),
    value: z.string().min(1),
    detail: z.string().min(1),
    status: eventStatusSchema.optional()
  })
  .strict();

export const accountRowSchema = z
  .object({
    entity: z.string().min(1),
    account: z.string().min(1),
    acceptedBalance: z.string().min(1),
    pendingDelta: z.string().min(1),
    status: eventStatusSchema,
    sequence: z.string().min(1)
  })
  .strict();

export const flowRowSchema = z
  .object({
    kind: z.string().min(1),
    counterparty: z.string().min(1),
    amount: z.string().min(1),
    status: eventStatusSchema,
    utc: z.string().datetime({ offset: true })
  })
  .strict();

export const approvalRowSchema = z
  .object({
    object: z.string().min(1),
    amount: z.string().min(1),
    policy: z.string().min(1),
    progress: z.string().min(1),
    status: eventStatusSchema,
    sequence: z.string().min(1)
  })
  .strict();

export const conflictRowSchema = z
  .object({
    object: z.string().min(1),
    acceptedVersion: z.string().min(1),
    conflictingVersion: z.string().min(1),
    sequence: z.string().min(1),
    status: z.literal("conflicted"),
    aiProposal: z.string().min(1)
  })
  .strict();

export const ledgerRowSchema = z
  .object({
    event: z.string().min(1),
    object: z.string().min(1),
    actor: z.string().min(1),
    status: eventStatusSchema,
    sequence: z.string().min(1),
    keyVersion: z.string().min(1),
    device: z.string().min(1),
    hash: z.string().min(1),
    utc: z.string().datetime({ offset: true })
  })
  .strict();

export const checkpointRowSchema = z
  .object({
    sequence: z.string().min(1),
    hash: z.string().min(1),
    verifiedAt: z.string().datetime({ offset: true }),
    status: z.literal("accepted")
  })
  .strict();

export const exportRequestSchema = z
  .object({
    name: z.string().min(1),
    scope: z.string().min(1),
    format: z.string().min(1),
    status: eventStatusSchema,
    policy: z.string().min(1)
  })
  .strict();

export const factRowSchema = z.tuple([z.string().min(1), z.string().min(1)]);

export const executiveWorkspaceSnapshotSchema = z
  .object({
    metrics: z.array(metricSchema),
    accounts: z.array(accountRowSchema),
    flows: z.array(flowRowSchema),
    approvals: z.array(approvalRowSchema),
    conflicts: z.array(conflictRowSchema),
    ledgerRows: z.array(ledgerRowSchema),
    checkpoints: z.array(checkpointRowSchema),
    exportRequests: z.array(exportRequestSchema),
    syncFacts: z.array(factRowSchema),
    deviceFacts: z.array(factRowSchema),
    securitySettings: z.array(factRowSchema),
    applicationSettings: z.array(factRowSchema),
    advisoryText: z.string().min(1),
    signatureConsequence: z.string().min(1),
    conflictResolutionConsequence: z.string().min(1),
    exportWarning: z.string().min(1)
  })
  .strict();

export type EventStatus = z.infer<typeof eventStatusSchema>;
export type CreateEventRequest = z.infer<typeof createEventRequestSchema>;
export type CreateEventResponse = z.infer<typeof createEventResponseSchema>;
export type ShellState = z.infer<typeof shellStateSchema>;
export type SecurityAcknowledgementRequest = z.infer<typeof securityAcknowledgementRequestSchema>;
export type VaultPassphraseRequest = z.infer<typeof vaultPassphraseRequestSchema>;
export type VaultStatus = z.infer<typeof vaultStatusSchema>;
export type ExecutiveWorkspaceSnapshot = z.infer<typeof executiveWorkspaceSnapshotSchema>;
export type Metric = z.infer<typeof metricSchema>;
export type AccountRow = z.infer<typeof accountRowSchema>;
export type FlowRow = z.infer<typeof flowRowSchema>;
export type ApprovalRow = z.infer<typeof approvalRowSchema>;
export type ConflictRow = z.infer<typeof conflictRowSchema>;
export type LedgerRow = z.infer<typeof ledgerRowSchema>;
export type CheckpointRow = z.infer<typeof checkpointRowSchema>;
export type ExportRequest = z.infer<typeof exportRequestSchema>;

export type VorcaroApi = {
  getShellState: () => Promise<ShellState>;
  getExecutiveWorkspaceSnapshot: () => Promise<ExecutiveWorkspaceSnapshot>;
  createEvent: (request: CreateEventRequest) => Promise<CreateEventResponse>;
  getVaultStatus: () => Promise<VaultStatus>;
  createVault: (request: VaultPassphraseRequest) => Promise<VaultStatus>;
  unlockVault: (request: VaultPassphraseRequest) => Promise<VaultStatus>;
  lockVault: () => Promise<VaultStatus>;
  acknowledgeSecurityBanner: (request: SecurityAcknowledgementRequest) => Promise<{ recorded: true }>;
};
