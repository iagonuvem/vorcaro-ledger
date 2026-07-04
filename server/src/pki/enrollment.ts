import { randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

import {
  canonicalBytes,
  clientEventEnvelopeSchema,
  computeLedgerHash,
  constantTimeEqual,
  payloadHash,
  revocationListSchema,
  sha256Digest,
  signBytes,
  verifyBytes,
  verifyClientEventSignature,
  type ClientEventEnvelope,
  type ErrorCode,
  type RevocationList,
  type ServerAck
} from "@vorcaro/protocol";

import { writeAuditLog } from "../api/audit.js";
import { signServerAck } from "@vorcaro/protocol";
import { GENESIS_LEDGER_HASH } from "../ledger/appender.js";
import type { CertificateAuthority, IssuedDeviceCertificate } from "./authority.js";

export type PkiServiceOptions = {
  readonly database: DatabaseSync;
  readonly certificateAuthority: CertificateAuthority;
  readonly serverSigningSecretKey: string;
  readonly now?: () => string;
  readonly deviceCertificateLifetimeDays?: number;
  readonly enrollmentChallengeLifetimeMinutes?: number;
};

export type IssueEnrollmentTokenInput = {
  readonly executiveId: string;
  readonly issuedBy: string;
  readonly expiresAt: string;
  readonly token?: string;
};

export type IssuedEnrollmentToken = {
  readonly token: string;
  readonly tokenHash: string;
  readonly expiresAt: string;
};

export type BeginEnrollmentInput = {
  readonly token: string;
  readonly deviceId: string;
  readonly publicKey: string;
};

export type EnrollmentChallenge = {
  readonly challengeId: string;
  readonly challenge: string;
  readonly expiresAt: string;
};

export type CompleteEnrollmentInput = {
  readonly token: string;
  readonly challengeId: string;
  readonly proofSignature: string;
  readonly hardwareBacked: boolean;
  readonly enrollmentEvent: ClientEventEnvelope;
};

export type CompleteEnrollmentResult = {
  readonly certificate: IssuedDeviceCertificate;
  readonly acknowledgement: ServerAck;
};

export type RevokeDeviceInput = {
  readonly deviceId: string;
  readonly revokedBy: string;
  readonly reason: string;
};

type TokenRow = {
  readonly token_hash: string;
  readonly executive_id: string;
  readonly expires_at: string;
  readonly consumed_at: string | null;
};

type ChallengeRow = {
  readonly id: string;
  readonly token_hash: string;
  readonly executive_id: string;
  readonly device_id: string;
  readonly public_key: string;
  readonly challenge: string;
  readonly expires_at: string;
  readonly consumed_at: string | null;
};

type ExecutiveKeyRow = {
  readonly signing_public_key: string;
};

type ChainHeadRow = {
  readonly server_sequence: number;
  readonly resulting_ledger_hash: string;
};

type DeviceRow = {
  readonly id: string;
  readonly certificate_fingerprint: string;
  readonly status: string;
};

type RevokedDeviceRow = {
  readonly id: string;
};

type RevocationVersionRow = {
  readonly version: number | null;
};

export class PkiService {
  private readonly database: DatabaseSync;
  private readonly certificateAuthority: CertificateAuthority;
  private readonly serverSigningSecretKey: string;
  private readonly now: () => string;
  private readonly deviceCertificateLifetimeDays: number;
  private readonly enrollmentChallengeLifetimeMinutes: number;

  constructor(options: PkiServiceOptions) {
    this.database = options.database;
    this.certificateAuthority = options.certificateAuthority;
    this.serverSigningSecretKey = options.serverSigningSecretKey;
    this.now = options.now ?? (() => new Date().toISOString());
    this.deviceCertificateLifetimeDays = options.deviceCertificateLifetimeDays ?? 7;
    this.enrollmentChallengeLifetimeMinutes = options.enrollmentChallengeLifetimeMinutes ?? 10;
  }

  static hashEnrollmentToken(token: string): string {
    return sha256Digest(token);
  }

  issueEnrollmentToken(input: IssueEnrollmentTokenInput): IssuedEnrollmentToken {
    const token = input.token ?? randomBytes(32).toString("base64url");
    const tokenHash = PkiService.hashEnrollmentToken(token);

    this.database
      .prepare(
        `INSERT INTO enrollment_tokens (
          token_hash, executive_id, issued_by, expires_at, consumed_at
        ) VALUES (?, ?, ?, ?, NULL)`
      )
      .run(tokenHash, input.executiveId, input.issuedBy, input.expiresAt);

    writeAuditLog(this.database, {
      category: "admin",
      actor: input.issuedBy,
      detail: {
        event: "enrollment_token_issued",
        executive_id: input.executiveId,
        token_hash: tokenHash
      },
      createdAt: this.now()
    });

    return {
      token,
      tokenHash,
      expiresAt: input.expiresAt
    };
  }

  beginEnrollment(input: BeginEnrollmentInput): EnrollmentChallenge {
    const tokenHash = PkiService.hashEnrollmentToken(input.token);
    const now = this.now();
    const token = this.getUsableToken(tokenHash, now);
    const challengeId = `enr_${randomUUID()}`;
    const challenge = randomBytes(32).toString("base64url");
    const expiresAt = PkiService.addMinutes(now, this.enrollmentChallengeLifetimeMinutes);

    this.database
      .prepare(
        `INSERT INTO enrollment_challenges (
          id, token_hash, executive_id, device_id, public_key,
          challenge, expires_at, consumed_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)`
      )
      .run(
        challengeId,
        token.token_hash,
        token.executive_id,
        input.deviceId,
        input.publicKey,
        challenge,
        expiresAt,
        now
      );

    writeAuditLog(this.database, {
      category: "auth",
      actor: token.executive_id,
      detail: {
        event: "enrollment_challenge_issued",
        challenge_id: challengeId,
        device_id: input.deviceId
      },
      createdAt: now
    });

    return {
      challengeId,
      challenge,
      expiresAt
    };
  }

  completeEnrollment(input: CompleteEnrollmentInput): CompleteEnrollmentResult {
    const event = clientEventEnvelopeSchema.parse(input.enrollmentEvent);
    const now = this.now();
    const tokenHash = PkiService.hashEnrollmentToken(input.token);
    const challenge = this.getUsableChallenge(input.challengeId, tokenHash, now);

    this.assertEnrollmentEventMatchesChallenge(event, challenge);
    this.assertDeviceProof(input.proofSignature, challenge);
    this.assertEventSignature(event);
    this.assertPayloadHash(event);

    this.database.exec("BEGIN IMMEDIATE");

    try {
      const certificate = this.certificateAuthority.issueDeviceCertificate({
        executiveId: challenge.executive_id,
        deviceId: challenge.device_id,
        publicKey: challenge.public_key,
        challengeId: challenge.id,
        issuedAt: now,
        expiresAt: PkiService.addDays(now, this.deviceCertificateLifetimeDays)
      });
      const acknowledgement = this.appendEnrollmentEvent({
        event,
        certificateFingerprint: certificate.certificateFingerprint,
        publicKey: challenge.public_key,
        hardwareBacked: input.hardwareBacked,
        serverTimestamp: now
      });

      this.database
        .prepare("UPDATE enrollment_tokens SET consumed_at = ? WHERE token_hash = ?")
        .run(now, challenge.token_hash);
      this.database
        .prepare("UPDATE enrollment_challenges SET consumed_at = ? WHERE id = ?")
        .run(now, challenge.id);
      writeAuditLog(this.database, {
        category: "auth",
        actor: challenge.executive_id,
        detail: {
          event: "device_enrolled",
          device_id: challenge.device_id,
          certificate_fingerprint: certificate.certificateFingerprint
        },
        createdAt: now
      });

      this.database.exec("COMMIT");
      return {
        certificate,
        acknowledgement
      };
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  revokeDevice(input: RevokeDeviceInput): RevocationList {
    const now = this.now();
    const device = this.database
      .prepare("SELECT id, certificate_fingerprint, status FROM devices WHERE id = ?")
      .get(input.deviceId) as DeviceRow | undefined;

    if (device === undefined) {
      throw new PkiError("CERT_UNKNOWN");
    }

    this.database.exec("BEGIN IMMEDIATE");

    try {
      this.certificateAuthority.revokeDeviceCertificate({
        deviceId: device.id,
        certificateFingerprint: device.certificate_fingerprint,
        revokedAt: now,
        reason: input.reason
      });
      this.database
        .prepare("UPDATE devices SET status = 'revoked', revoked_at = ? WHERE id = ?")
        .run(now, input.deviceId);
      const revocationList = this.writeRevocationList(now);

      writeAuditLog(this.database, {
        category: "revocation",
        actor: input.revokedBy,
        detail: {
          event: "device_revoked",
          device_id: input.deviceId,
          reason: input.reason,
          revocation_list_version: revocationList.version
        },
        createdAt: now
      });

      this.database.exec("COMMIT");
      return revocationList;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private appendEnrollmentEvent(input: {
    readonly event: ClientEventEnvelope;
    readonly certificateFingerprint: string;
    readonly publicKey: string;
    readonly hardwareBacked: boolean;
    readonly serverTimestamp: string;
  }): ServerAck {
    const serverSequence = this.nextServerSequence();
    const previousLedgerHash = this.previousLedgerHash();
    const resultingLedgerHash = computeLedgerHash(previousLedgerHash, BigInt(serverSequence), input.event);
    const acknowledgement = signServerAck(
      {
        event_id: input.event.event_id,
        status: "accepted",
        server_sequence: BigInt(serverSequence),
        resulting_ledger_hash: resultingLedgerHash,
        server_timestamp: input.serverTimestamp,
        error_code: null
      },
      this.serverSigningSecretKey
    );

    this.database
      .prepare(
        `INSERT INTO devices (
          id, executive_id, certificate_fingerprint, public_key, status,
          hardware_backed, enrolled_at, revoked_at, last_seen_at, risk_score, max_event_counter
        ) VALUES (?, ?, ?, ?, 'enrolled', ?, ?, NULL, ?, 0, ?)`
      )
      .run(
        input.event.device_id,
        input.event.actor_id,
        input.certificateFingerprint,
        input.publicKey,
        input.hardwareBacked ? 1 : 0,
        input.serverTimestamp,
        input.serverTimestamp,
        PkiService.toSqlInteger(input.event.device_event_counter)
      );

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
        input.event.event_id,
        serverSequence,
        input.event.event_type,
        input.event.actor_id,
        input.event.device_id,
        PkiService.toSqlInteger(input.event.device_event_counter),
        PkiService.toSqlInteger(input.event.base_server_sequence),
        input.event.object_type,
        input.event.object_id,
        PkiService.stringifyPolicyMetadata(input.event.policy_metadata),
        Buffer.from(input.event.encrypted_payload, "base64"),
        input.event.payload_hash,
        previousLedgerHash,
        resultingLedgerHash,
        input.event.client_signature,
        acknowledgement.server_signature,
        input.event.client_timestamp,
        input.serverTimestamp,
        input.serverTimestamp
      );

    this.database
      .prepare(
        `INSERT INTO object_heads (object_type, object_id, head_sequence, conflicted)
        VALUES (?, ?, ?, 0)
        ON CONFLICT(object_type, object_id) DO UPDATE SET
          head_sequence = excluded.head_sequence,
          conflicted = 0`
      )
      .run(input.event.object_type, input.event.object_id, serverSequence);

    return acknowledgement;
  }

  private getUsableToken(tokenHash: string, now: string): TokenRow {
    const token = this.database
      .prepare(
        `SELECT token_hash, executive_id, expires_at, consumed_at
        FROM enrollment_tokens
        WHERE token_hash = ?`
      )
      .get(tokenHash) as TokenRow | undefined;

    if (token === undefined || !constantTimeEqual(token.token_hash, tokenHash)) {
      throw new PkiError("CERT_UNKNOWN");
    }

    if (token.consumed_at !== null || PkiService.isExpired(token.expires_at, now)) {
      throw new PkiError("POLICY_DENIED");
    }

    return token;
  }

  private getUsableChallenge(challengeId: string, tokenHash: string, now: string): ChallengeRow {
    const challenge = this.database
      .prepare(
        `SELECT
          id, token_hash, executive_id, device_id, public_key,
          challenge, expires_at, consumed_at
        FROM enrollment_challenges
        WHERE id = ?`
      )
      .get(challengeId) as ChallengeRow | undefined;

    if (challenge === undefined || !constantTimeEqual(challenge.token_hash, tokenHash)) {
      throw new PkiError("CERT_UNKNOWN");
    }

    if (challenge.consumed_at !== null || PkiService.isExpired(challenge.expires_at, now)) {
      throw new PkiError("POLICY_DENIED");
    }

    return challenge;
  }

  private assertEnrollmentEventMatchesChallenge(event: ClientEventEnvelope, challenge: ChallengeRow): void {
    if (
      event.event_type !== "DEVICE_ENROLLED" ||
      event.actor_id !== challenge.executive_id ||
      event.device_id !== challenge.device_id ||
      event.object_type !== "device" ||
      event.object_id !== challenge.device_id
    ) {
      throw new PkiError("SCHEMA_INVALID");
    }
  }

  private assertDeviceProof(proofSignature: string, challenge: ChallengeRow): void {
    const proofBytes = canonicalBytes({
      challenge_id: challenge.id,
      challenge: challenge.challenge,
      device_id: challenge.device_id,
      public_key: challenge.public_key
    });

    if (!verifyBytes(proofBytes, proofSignature, challenge.public_key)) {
      throw new PkiError("BAD_SIGNATURE");
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
        PkiService.toSqlInteger(event.base_server_sequence),
        PkiService.toSqlInteger(event.base_server_sequence)
      ) as ExecutiveKeyRow | undefined;

    if (key === undefined || !verifyClientEventSignature(event, key.signing_public_key)) {
      throw new PkiError("BAD_SIGNATURE");
    }
  }

  private assertPayloadHash(event: ClientEventEnvelope): void {
    if (!constantTimeEqual(payloadHash(event.encrypted_payload), event.payload_hash)) {
      throw new PkiError("BAD_PAYLOAD_HASH");
    }
  }

  private writeRevocationList(issuedAt: string): RevocationList {
    const current = this.database
      .prepare("SELECT MAX(version) AS version FROM revocation_list_versions")
      .get() as RevocationVersionRow;
    const version = (current.version ?? 0) + 1;
    const revokedDeviceIds = (
      this.database
        .prepare("SELECT id FROM devices WHERE status = 'revoked' ORDER BY id ASC")
        .all() as RevokedDeviceRow[]
    ).map((row) => row.id);
    const unsigned = {
      version,
      revoked_device_ids: revokedDeviceIds,
      revoked_key_versions: [],
      wipe_directives: [],
      issued_at: issuedAt
    };
    const revocationList = revocationListSchema.parse({
      ...unsigned,
      signature: signBytes(canonicalBytes(unsigned), this.serverSigningSecretKey)
    });

    this.database
      .prepare(
        `INSERT INTO revocation_list_versions (
          version, document, signature, issued_at
        ) VALUES (?, ?, ?, ?)`
      )
      .run(
        revocationList.version,
        JSON.stringify(revocationList),
        revocationList.signature,
        revocationList.issued_at
      );

    return revocationList;
  }

  private nextServerSequence(): number {
    const row = this.database
      .prepare("SELECT COALESCE(MAX(server_sequence), 0) + 1 AS next_sequence FROM ledger_events")
      .get() as { readonly next_sequence: number };
    return row.next_sequence;
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

  static addMinutes(isoTimestamp: string, minutes: number): string {
    return new Date(Date.parse(isoTimestamp) + minutes * 60_000).toISOString();
  }

  static addDays(isoTimestamp: string, days: number): string {
    return new Date(Date.parse(isoTimestamp) + days * 24 * 60 * 60_000).toISOString();
  }

  static isExpired(expiresAt: string, now: string): boolean {
    return Date.parse(expiresAt) <= Date.parse(now);
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

export class PkiError extends Error {
  readonly errorCode: ErrorCode;

  constructor(errorCode: ErrorCode) {
    super(errorCode);
    this.errorCode = errorCode;
  }
}
