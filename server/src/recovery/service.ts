import type { DatabaseSync } from "node:sqlite";

import {
  canonicalBytes,
  clientEventEnvelopeSchema,
  computeLedgerHash,
  constantTimeEqual,
  payloadHash,
  recoveryCeremonySchema,
  sha256Hex,
  verifyClientEventSignature,
  verifyBytes,
  type ClientEventEnvelope,
  type ErrorCode,
  type RecoveryCeremony,
  type ServerAck
} from "@vorcaro/protocol";

import { writeAuditLog } from "../api/audit.js";
import type { KeyManagementService } from "../kms/service.js";
import { GENESIS_LEDGER_HASH } from "../ledger/appender.js";

export type RecoveryPolicyConfig = {
  readonly requiredApprovals: number;
  readonly custodianIds: readonly string[];
};

export type RecoveryServiceOptions = {
  readonly database: DatabaseSync;
  readonly kms: KeyManagementService;
  readonly serverSigningKeyHandle: string;
  readonly recoveryMasterKeyHandle: string;
  readonly policy: RecoveryPolicyConfig;
  readonly now?: () => string;
};

export type InitiateRecoveryInput = {
  readonly ceremonyId?: string;
  readonly executiveId: string;
  readonly initiatedBy: string;
  readonly newPublicKey: string;
};

export type ApproveRecoveryInput = {
  readonly ceremonyId: string;
  readonly approverId: string;
  readonly approvalSignature: string;
};

export type ExecuteRecoveryInput = {
  readonly ceremonyId: string;
  readonly executedBy: string;
  readonly executorDeviceId: string;
  readonly recoveryPerformedEvent: ClientEventEnvelope;
  readonly keyRotatedEvent: ClientEventEnvelope;
};

export type ExecuteRecoveryResult = {
  readonly ceremony: RecoveryCeremony;
  readonly newKeyVersion: number;
  readonly rewrappedKeyPackageIds: readonly string[];
  readonly acknowledgements: readonly ServerAck[];
};

type CeremonyRow = {
  readonly id: string;
  readonly executive_id: string;
  readonly initiated_by: string;
  readonly new_public_key: string;
  readonly status: "open" | "threshold_met" | "executed" | "aborted";
  readonly required_approvals: number;
  readonly created_at: string;
  readonly completed_at: string | null;
};

type ApprovalRow = {
  readonly ceremony_id: string;
  readonly approver_id: string;
  readonly approval_signature: string;
  readonly created_at: string;
};

type ExecutiveRow = {
  readonly id: string;
  readonly status: string;
  readonly signing_public_key: string;
  readonly key_version: number;
};

type ExecutiveKeyRow = {
  readonly signing_public_key: string;
};

type DeviceExecutiveRow = {
  readonly device_status: string;
  readonly executive_id: string;
  readonly executive_status: string;
  readonly max_event_counter: number;
};

type ChainHeadRow = {
  readonly server_sequence: number;
  readonly resulting_ledger_hash: string;
};

type ExistingEventRow = {
  readonly id: string;
};

type KeyPackageRow = {
  readonly id: string;
  readonly recovery_wrapped_key: Buffer;
};

export class RecoveryService {
  private readonly database: DatabaseSync;
  private readonly kms: KeyManagementService;
  private readonly serverSigningKeyHandle: string;
  private readonly recoveryMasterKeyHandle: string;
  private readonly policy: RecoveryPolicyConfig;
  private readonly now: () => string;

  constructor(options: RecoveryServiceOptions) {
    if (options.policy.requiredApprovals <= 0 || options.policy.requiredApprovals > options.policy.custodianIds.length) {
      throw new RecoveryError("POLICY_DENIED");
    }

    this.database = options.database;
    this.kms = options.kms;
    this.serverSigningKeyHandle = options.serverSigningKeyHandle;
    this.recoveryMasterKeyHandle = options.recoveryMasterKeyHandle;
    this.policy = options.policy;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  initiateCeremony(input: InitiateRecoveryInput): RecoveryCeremony {
    this.assertCustodian(input.initiatedBy);
    const now = this.now();
    const ceremonyId = input.ceremonyId ?? RecoveryService.ceremonyId(input.executiveId, input.newPublicKey, now);

    this.database.exec("BEGIN IMMEDIATE");

    try {
      const executive = this.getExecutive(input.executiveId);

      if (executive.status === "deactivated") {
        throw new RecoveryError("EXECUTIVE_INACTIVE");
      }

      this.database
        .prepare(
          `INSERT INTO recovery_ceremonies (
            id, executive_id, initiated_by, new_public_key, status,
            required_approvals, created_at, completed_at
          ) VALUES (?, ?, ?, ?, 'open', ?, ?, NULL)`
        )
        .run(
          ceremonyId,
          input.executiveId,
          input.initiatedBy,
          input.newPublicKey,
          this.policy.requiredApprovals,
          now
        );
      this.database
        .prepare("UPDATE executives SET status = 'quarantined' WHERE id = ?")
        .run(input.executiveId);
      this.database
        .prepare("UPDATE devices SET status = 'quarantined', last_seen_at = ? WHERE executive_id = ? AND status = 'enrolled'")
        .run(now, input.executiveId);
      writeAuditLog(this.database, {
        category: "recovery",
        actor: input.initiatedBy,
        detail: {
          event: "recovery_ceremony_initiated",
          ceremony_id: ceremonyId,
          executive_id: input.executiveId
        },
        createdAt: now
      });

      this.database.exec("COMMIT");
      return this.readCeremony(ceremonyId);
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  approveCeremony(input: ApproveRecoveryInput): RecoveryCeremony {
    this.assertCustodian(input.approverId);
    const now = this.now();

    this.database.exec("BEGIN IMMEDIATE");

    try {
      const ceremony = this.getCeremony(input.ceremonyId);

      if (ceremony.status !== "open" && ceremony.status !== "threshold_met") {
        throw new RecoveryError("POLICY_DENIED");
      }

      this.assertApprovalSignature(ceremony, input.approverId, input.approvalSignature);
      this.database
        .prepare(
          `INSERT INTO recovery_approvals (
            ceremony_id, approver_id, approval_signature, created_at
          ) VALUES (?, ?, ?, ?)`
        )
        .run(input.ceremonyId, input.approverId, input.approvalSignature, now);
      writeAuditLog(this.database, {
        category: "recovery",
        actor: input.approverId,
        detail: {
          event: "recovery_approval_submitted",
          ceremony_id: input.ceremonyId
        },
        createdAt: now
      });

      if (this.approvalCount(input.ceremonyId) >= ceremony.required_approvals) {
        this.database
          .prepare("UPDATE recovery_ceremonies SET status = 'threshold_met' WHERE id = ?")
          .run(input.ceremonyId);
        writeAuditLog(this.database, {
          category: "recovery",
          actor: input.approverId,
          detail: {
            event: "recovery_threshold_met",
            ceremony_id: input.ceremonyId
          },
          createdAt: now
        });
      }

      this.database.exec("COMMIT");
      return this.readCeremony(input.ceremonyId);
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  executeCeremony(input: ExecuteRecoveryInput): ExecuteRecoveryResult {
    const now = this.now();
    const recoveryPerformedEvent = clientEventEnvelopeSchema.parse(input.recoveryPerformedEvent);
    const keyRotatedEvent = clientEventEnvelopeSchema.parse(input.keyRotatedEvent);

    this.database.exec("BEGIN IMMEDIATE");

    try {
      const ceremony = this.getCeremony(input.ceremonyId);

      if (ceremony.status !== "threshold_met") {
        throw new RecoveryError("APPROVALS_REQUIRED");
      }

      this.assertExecutionEvent({
        event: recoveryPerformedEvent,
        eventType: "RECOVERY_PERFORMED",
        objectId: ceremony.id,
        executedBy: input.executedBy,
        executorDeviceId: input.executorDeviceId
      });
      const targetExecutive = this.getExecutive(ceremony.executive_id);
      const newKeyVersion = targetExecutive.key_version + 1;
      this.assertExecutionEvent({
        event: keyRotatedEvent,
        eventType: "KEY_ROTATED",
        objectId: RecoveryService.rotatedKeyObjectId(ceremony.executive_id, newKeyVersion),
        executedBy: input.executedBy,
        executorDeviceId: input.executorDeviceId
      });
      this.assertDeviceCanExecute(input.executorDeviceId, input.executedBy, recoveryPerformedEvent.device_event_counter);
      this.assertDeviceCanExecute(input.executorDeviceId, input.executedBy, keyRotatedEvent.device_event_counter);
      this.assertConsecutiveCounters(recoveryPerformedEvent, keyRotatedEvent);
      this.assertEventSignature(recoveryPerformedEvent);
      this.assertEventSignature(keyRotatedEvent);
      this.assertPayloadHash(recoveryPerformedEvent);
      this.assertPayloadHash(keyRotatedEvent);

      const headSequence = this.currentHeadSequence();
      const rewrappedKeyPackageIds = this.rewrapKeyPackages({
        executiveId: ceremony.executive_id,
        oldKeyVersion: targetExecutive.key_version,
        newKeyVersion,
        createdAt: now
      });

      this.database
        .prepare(
          `UPDATE executive_keys
          SET valid_until_sequence = ?
          WHERE executive_id = ?
            AND key_version = ?`
        )
        .run(headSequence, ceremony.executive_id, targetExecutive.key_version);
      this.database
        .prepare(
          `INSERT INTO executive_keys (
            executive_id, key_version, signing_public_key,
            valid_from_sequence, valid_until_sequence
          ) VALUES (?, ?, ?, ?, NULL)`
        )
        .run(ceremony.executive_id, newKeyVersion, ceremony.new_public_key, headSequence);
      this.database
        .prepare(
          `UPDATE executives
          SET signing_public_key = ?,
            key_version = ?,
            status = 'active'
          WHERE id = ?`
        )
        .run(ceremony.new_public_key, newKeyVersion, ceremony.executive_id);

      const acknowledgements = [
        this.appendAcceptedEvent(recoveryPerformedEvent, now),
        this.appendAcceptedEvent(keyRotatedEvent, now)
      ];

      this.database
        .prepare("UPDATE recovery_ceremonies SET status = 'executed', completed_at = ? WHERE id = ?")
        .run(now, ceremony.id);
      writeAuditLog(this.database, {
        category: "recovery",
        actor: input.executedBy,
        detail: {
          event: "recovery_ceremony_executed",
          ceremony_id: ceremony.id,
          executive_id: ceremony.executive_id,
          new_key_version: newKeyVersion,
          rewrapped_key_package_count: rewrappedKeyPackageIds.length
        },
        createdAt: now
      });

      this.database.exec("COMMIT");
      return {
        ceremony: this.readCeremony(ceremony.id),
        newKeyVersion,
        rewrappedKeyPackageIds,
        acknowledgements
      };
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private rewrapKeyPackages(input: {
    readonly executiveId: string;
    readonly oldKeyVersion: number;
    readonly newKeyVersion: number;
    readonly createdAt: string;
  }): string[] {
    const packages = this.database
      .prepare(
        `SELECT id, recovery_wrapped_key
        FROM key_packages
        WHERE executive_id = ?
          AND key_version = ?
          AND status = 'active'
        ORDER BY id ASC`
      )
      .all(input.executiveId, input.oldKeyVersion) as KeyPackageRow[];
    const insertedIds: string[] = [];

    for (const keyPackage of packages) {
      const newPackageId = RecoveryService.rewrappedKeyPackageId(keyPackage.id, input.newKeyVersion);
      const wrappedDataKey = this.kms.rewrapKey({
        unwrapKeyHandle: this.recoveryMasterKeyHandle,
        wrapKeyHandle: RecoveryService.executiveWrapKeyHandle(input.executiveId, input.newKeyVersion),
        wrappedKey: keyPackage.recovery_wrapped_key
      });

      this.database
        .prepare(
          `INSERT INTO key_packages (
            id, executive_id, key_version, wrapped_data_key,
            recovery_wrapped_key, status, created_at, revoked_at
          ) VALUES (?, ?, ?, ?, ?, 'active', ?, NULL)`
        )
        .run(
          newPackageId,
          input.executiveId,
          input.newKeyVersion,
          wrappedDataKey,
          keyPackage.recovery_wrapped_key,
          input.createdAt
        );
      insertedIds.push(newPackageId);
    }

    this.database
      .prepare(
        `UPDATE key_packages
        SET status = 'revoked',
          revoked_at = ?
        WHERE executive_id = ?
          AND key_version = ?
          AND status = 'active'`
      )
      .run(input.createdAt, input.executiveId, input.oldKeyVersion);

    return insertedIds;
  }

  private appendAcceptedEvent(event: ClientEventEnvelope, serverTimestamp: string): ServerAck {
    if (this.eventExists(event.event_id)) {
      throw new RecoveryError("DUPLICATE_EVENT");
    }

    const serverSequence = this.nextServerSequence();
    const previousLedgerHash = this.previousLedgerHash();
    const resultingLedgerHash = computeLedgerHash(previousLedgerHash, BigInt(serverSequence), event);
    const acknowledgement = {
      event_id: event.event_id,
      status: "accepted" as const,
      server_sequence: BigInt(serverSequence),
      resulting_ledger_hash: resultingLedgerHash,
      server_timestamp: serverTimestamp,
      error_code: null
    };
    const serverSignature = this.kms.signWithKey({
      keyHandle: this.serverSigningKeyHandle,
      bytes: canonicalBytes(acknowledgement)
    });

    this.database
      .prepare(
        `INSERT INTO ledger_events (
          id, server_sequence, event_type, actor_id, device_id, device_event_counter,
          base_server_sequence, object_type, object_id, policy_metadata,
          encrypted_payload, payload_hash, previous_ledger_hash, resulting_ledger_hash,
          client_signature, server_signature, status, error_code,
          client_timestamp, server_timestamp, accepted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'accepted', NULL, ?, ?, ?)`
      )
      .run(
        event.event_id,
        serverSequence,
        event.event_type,
        event.actor_id,
        event.device_id,
        RecoveryService.toSqlInteger(event.device_event_counter),
        RecoveryService.toSqlInteger(event.base_server_sequence),
        event.object_type,
        event.object_id,
        RecoveryService.stringifyPolicyMetadata(event.policy_metadata),
        Buffer.from(event.encrypted_payload, "base64"),
        event.payload_hash,
        previousLedgerHash,
        resultingLedgerHash,
        event.client_signature,
        serverSignature,
        event.client_timestamp,
        serverTimestamp,
        serverTimestamp
      );
    this.database
      .prepare(
        `INSERT INTO object_heads (object_type, object_id, head_sequence, conflicted)
        VALUES (?, ?, ?, 0)
        ON CONFLICT(object_type, object_id) DO UPDATE SET
          head_sequence = excluded.head_sequence,
          conflicted = 0`
      )
      .run(event.object_type, event.object_id, serverSequence);
    this.database
      .prepare("UPDATE devices SET max_event_counter = ?, last_seen_at = ? WHERE id = ?")
      .run(RecoveryService.toSqlInteger(event.device_event_counter), serverTimestamp, event.device_id);

    return {
      ...acknowledgement,
      server_signature: serverSignature
    };
  }

  private assertApprovalSignature(ceremony: CeremonyRow, approverId: string, approvalSignature: string): void {
    const approver = this.getExecutive(approverId);

    if (
      !verifyBytes(
        RecoveryService.approvalBytes(ceremony.id, ceremony.executive_id, ceremony.new_public_key),
        approvalSignature,
        approver.signing_public_key
      )
    ) {
      throw new RecoveryError("BAD_SIGNATURE");
    }
  }

  private assertExecutionEvent(input: {
    readonly event: ClientEventEnvelope;
    readonly eventType: "RECOVERY_PERFORMED" | "KEY_ROTATED";
    readonly objectId: string;
    readonly executedBy: string;
    readonly executorDeviceId: string;
  }): void {
    if (
      input.event.event_type !== input.eventType ||
      input.event.actor_id !== input.executedBy ||
      input.event.device_id !== input.executorDeviceId ||
      input.event.object_type !== "executive_key" ||
      input.event.object_id !== input.objectId
    ) {
      throw new RecoveryError("SCHEMA_INVALID");
    }
  }

  private assertDeviceCanExecute(deviceId: string, executiveId: string, counter: bigint): void {
    const row = this.database
      .prepare(
        `SELECT
          devices.status AS device_status,
          devices.executive_id,
          devices.max_event_counter,
          executives.status AS executive_status
        FROM devices
        JOIN executives ON executives.id = devices.executive_id
        WHERE devices.id = ?`
      )
      .get(deviceId) as DeviceExecutiveRow | undefined;

    if (
      row === undefined ||
      row.device_status !== "enrolled" ||
      row.executive_id !== executiveId ||
      row.executive_status !== "active"
    ) {
      throw new RecoveryError("CERT_REVOKED");
    }

    if (counter <= BigInt(row.max_event_counter)) {
      throw new RecoveryError("REPLAY_COUNTER");
    }
  }

  private assertConsecutiveCounters(first: ClientEventEnvelope, second: ClientEventEnvelope): void {
    if (second.device_event_counter !== first.device_event_counter + 1n) {
      throw new RecoveryError("REPLAY_COUNTER");
    }
  }

  private assertEventSignature(event: ClientEventEnvelope): void {
    const key = this.database
      .prepare(
        `SELECT signing_public_key
        FROM executive_keys
        WHERE executive_id = ?
          AND valid_from_sequence <= ?
          AND (valid_until_sequence IS NULL OR valid_until_sequence >= ?)
        ORDER BY key_version DESC
        LIMIT 1`
      )
      .get(
        event.actor_id,
        RecoveryService.toSqlInteger(event.base_server_sequence),
        RecoveryService.toSqlInteger(event.base_server_sequence)
      ) as ExecutiveKeyRow | undefined;

    if (key === undefined || !verifyClientEventSignature(event, key.signing_public_key)) {
      throw new RecoveryError("BAD_SIGNATURE");
    }
  }

  private assertPayloadHash(event: ClientEventEnvelope): void {
    if (!constantTimeEqual(payloadHash(event.encrypted_payload), event.payload_hash)) {
      throw new RecoveryError("BAD_PAYLOAD_HASH");
    }
  }

  private assertCustodian(custodianId: string): void {
    if (!this.policy.custodianIds.includes(custodianId)) {
      throw new RecoveryError("POLICY_DENIED");
    }
  }

  private getExecutive(executiveId: string): ExecutiveRow {
    const row = this.database
      .prepare("SELECT id, status, signing_public_key, key_version FROM executives WHERE id = ?")
      .get(executiveId) as ExecutiveRow | undefined;

    if (row === undefined) {
      throw new RecoveryError("EXECUTIVE_INACTIVE");
    }

    return row;
  }

  private getCeremony(ceremonyId: string): CeremonyRow {
    const row = this.database
      .prepare(
        `SELECT
          id, executive_id, initiated_by, new_public_key, status,
          required_approvals, created_at, completed_at
        FROM recovery_ceremonies
        WHERE id = ?`
      )
      .get(ceremonyId) as CeremonyRow | undefined;

    if (row === undefined) {
      throw new RecoveryError("SCHEMA_INVALID");
    }

    return row;
  }

  private readCeremony(ceremonyId: string): RecoveryCeremony {
    const ceremony = this.getCeremony(ceremonyId);
    const approvals = this.database
      .prepare(
        `SELECT ceremony_id, approver_id, approval_signature, created_at
        FROM recovery_approvals
        WHERE ceremony_id = ?
        ORDER BY created_at ASC, approver_id ASC`
      )
      .all(ceremonyId) as ApprovalRow[];

    return recoveryCeremonySchema.parse({
      id: ceremony.id,
      executive_id: ceremony.executive_id,
      initiated_by: ceremony.initiated_by,
      new_public_key: ceremony.new_public_key,
      status: ceremony.status,
      required_approvals: ceremony.required_approvals,
      approvals,
      created_at: ceremony.created_at,
      completed_at: ceremony.completed_at
    });
  }

  private approvalCount(ceremonyId: string): number {
    const row = this.database
      .prepare("SELECT COUNT(*) AS count FROM recovery_approvals WHERE ceremony_id = ?")
      .get(ceremonyId) as { readonly count: number };
    return row.count;
  }

  private eventExists(eventId: string): boolean {
    const row = this.database
      .prepare("SELECT id FROM ledger_events WHERE id = ?")
      .get(eventId) as ExistingEventRow | undefined;
    return row !== undefined;
  }

  private nextServerSequence(): number {
    const row = this.database
      .prepare("SELECT COALESCE(MAX(server_sequence), 0) + 1 AS next_sequence FROM ledger_events")
      .get() as { readonly next_sequence: number };
    return row.next_sequence;
  }

  private currentHeadSequence(): number {
    const row = this.database
      .prepare("SELECT COALESCE(MAX(server_sequence), 0) AS sequence FROM ledger_events")
      .get() as { readonly sequence: number };
    return row.sequence;
  }

  private previousLedgerHash(): string {
    const row = this.database
      .prepare(
        `SELECT server_sequence, resulting_ledger_hash
        FROM ledger_events
        WHERE server_sequence IS NOT NULL
        ORDER BY server_sequence DESC
        LIMIT 1`
      )
      .get() as ChainHeadRow | undefined;

    return row?.resulting_ledger_hash ?? GENESIS_LEDGER_HASH;
  }

  static approvalBytes(ceremonyId: string, executiveId: string, newPublicKey: string): Buffer {
    return canonicalBytes({
      ceremony_id: ceremonyId,
      executive_id: executiveId,
      new_public_key: newPublicKey
    });
  }

  static executiveWrapKeyHandle(executiveId: string, keyVersion: number): string {
    return `executive:${executiveId}:${keyVersion}`;
  }

  static rotatedKeyObjectId(executiveId: string, keyVersion: number): string {
    return `${executiveId}:${keyVersion}`;
  }

  static ceremonyId(executiveId: string, newPublicKey: string, createdAt: string): string {
    return `rcv_${sha256Hex(`${executiveId}:${newPublicKey}:${createdAt}`).slice(0, 26)}`;
  }

  static rewrappedKeyPackageId(oldPackageId: string, newKeyVersion: number): string {
    return `kp_${sha256Hex(`${oldPackageId}:${newKeyVersion}`).slice(0, 26)}`;
  }

  static stringifyPolicyMetadata(policyMetadata: ClientEventEnvelope["policy_metadata"]): string {
    return JSON.stringify(policyMetadata, (_key, value: unknown) =>
      typeof value === "bigint" ? value.toString(10) : value
    );
  }

  static toSqlInteger(value: bigint): number {
    const asNumber = Number(value);

    if (!Number.isSafeInteger(asNumber)) {
      throw new RangeError("SQLite integer value exceeds JavaScript safe integer range");
    }

    return asNumber;
  }
}

export class RecoveryError extends Error {
  readonly errorCode: ErrorCode;

  constructor(errorCode: ErrorCode) {
    super(errorCode);
    this.errorCode = errorCode;
  }
}
