import type { DatabaseSync } from "node:sqlite";

import {
  clientEventEnvelopeSchema,
  policyDocumentSchema,
  type ClientEventEnvelope,
  type PolicyDocument,
  type ServerAck
} from "@vorcaro/protocol";

import { writeAuditLog } from "../api/audit.js";
import type { LedgerAppender } from "../ledger/appender.js";
import { PolicyEngine, PolicyError } from "./engine.js";

export type ActivatePolicyInput = {
  readonly policy: PolicyDocument;
  readonly activationEvent: ClientEventEnvelope;
  readonly certificateFingerprint: string;
  readonly activatedBy: string;
};

export type ActivatePolicyResult = {
  readonly policy: PolicyDocument;
  readonly acknowledgement: ServerAck;
};

type PolicySummaryRow = {
  readonly id: string;
  readonly version: number;
  readonly document_hash: string;
  readonly activated_at_sequence: number | null;
};

type PolicyDocumentRow = {
  readonly document: string;
};

export type PolicySummary = {
  readonly id: string;
  readonly version: number;
  readonly document_hash: string;
  readonly activated_at_sequence: bigint | null;
};

export type PolicyServiceOptions = {
  readonly database: DatabaseSync;
  readonly appender: LedgerAppender;
  readonly now?: () => string;
};

export class PolicyService {
  private readonly database: DatabaseSync;
  private readonly appender: LedgerAppender;
  private readonly now: () => string;

  constructor(options: PolicyServiceOptions) {
    this.database = options.database;
    this.appender = options.appender;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  async activatePolicy(input: ActivatePolicyInput): Promise<ActivatePolicyResult> {
    const policy = policyDocumentSchema.parse(input.policy);
    const activationEvent = clientEventEnvelopeSchema.parse(input.activationEvent);
    PolicyEngine.assertDocumentHash(policy);
    PolicyService.assertActivationEvent(policy, activationEvent);

    const acknowledgement = await this.appender.append({
      event: activationEvent,
      certificateFingerprint: input.certificateFingerprint
    });

    if (acknowledgement.status !== "accepted" || acknowledgement.server_sequence === null) {
      throw new PolicyError(acknowledgement.error_code ?? "POLICY_DENIED");
    }

    const activatedPolicy = policyDocumentSchema.parse({
      ...policy,
      activated_at_sequence: acknowledgement.server_sequence
    });

    this.database
      .prepare(
        `INSERT INTO policies (
          id, version, document, document_hash, activated_at_sequence
        ) VALUES (?, ?, ?, ?, ?)`
      )
      .run(
        activatedPolicy.id,
        activatedPolicy.version,
        PolicyEngine.serializePolicyDocument(activatedPolicy),
        activatedPolicy.document_hash,
        PolicyService.toSqlInteger(acknowledgement.server_sequence)
      );
    writeAuditLog(this.database, {
      category: "admin",
      actor: input.activatedBy,
      detail: {
        event: "policy_activated",
        policy_id: activatedPolicy.id,
        policy_version: activatedPolicy.version,
        activated_at_sequence: acknowledgement.server_sequence.toString(10)
      },
      createdAt: this.now()
    });

    return {
      policy: activatedPolicy,
      acknowledgement
    };
  }

  listPolicies(): PolicySummary[] {
    return (
      this.database
        .prepare(
          `SELECT id, version, document_hash, activated_at_sequence
          FROM policies
          ORDER BY version DESC`
        )
        .all() as PolicySummaryRow[]
    ).map((row) => ({
      id: row.id,
      version: row.version,
      document_hash: row.document_hash,
      activated_at_sequence: row.activated_at_sequence === null ? null : BigInt(row.activated_at_sequence)
    }));
  }

  activePolicy(): PolicyDocument | null {
    return PolicyEngine.readActivePolicy(this.database);
  }

  policyDocument(version: number): PolicyDocument | null {
    const row = this.database
      .prepare("SELECT document FROM policies WHERE version = ?")
      .get(version) as PolicyDocumentRow | undefined;

    return row === undefined ? null : PolicyEngine.parsePolicyDocument(row.document);
  }

  static assertActivationEvent(policy: PolicyDocument, event: ClientEventEnvelope): void {
    if (
      event.event_type !== "POLICY_CHANGED" ||
      event.object_type !== "policy" ||
      event.object_id !== policy.id
    ) {
      throw new PolicyError("SCHEMA_INVALID");
    }

    if (event.policy_metadata.amount_minor_units !== undefined) {
      throw new PolicyError("SCHEMA_INVALID");
    }
  }

  static toSqlInteger(value: bigint): number {
    const asNumber = Number(value);

    if (!Number.isSafeInteger(asNumber)) {
      throw new RangeError("SQLite integer value exceeds JavaScript safe integer range");
    }

    return asNumber;
  }
}
