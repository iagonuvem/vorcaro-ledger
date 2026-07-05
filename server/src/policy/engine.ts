import type { DatabaseSync } from "node:sqlite";

import {
  canonicalBytes,
  policyDocumentSchema,
  sha256Digest,
  type CanonicalJson,
  type ClientEventEnvelope,
  type ErrorCode,
  type PolicyDocument
} from "@vorcaro/protocol";

export type PolicyAction = "read" | "create" | "approve" | "resolve" | "export";

export type PolicyDecision =
  | {
      readonly outcome: "allow";
    }
  | {
      readonly outcome: "deny";
      readonly errorCode: ErrorCode;
    }
  | {
      readonly outcome: "require_approvals";
      readonly requiredRoles: readonly string[];
      readonly requiredCount: number;
      readonly errorCode: "APPROVALS_REQUIRED";
    };

export type PolicyEvaluationContext = {
  readonly actorRole: string;
  readonly riskScore?: number;
};

type PolicyRow = {
  readonly document: string;
};

export class PolicyEngine {
  static evaluateActivePolicy(
    database: DatabaseSync,
    event: ClientEventEnvelope,
    context: PolicyEvaluationContext
  ): PolicyDecision {
    const policy = PolicyEngine.readActivePolicy(database);
    return policy === null ? { outcome: "allow" } : PolicyEngine.evaluate(policy, event, context);
  }

  static evaluate(
    policy: PolicyDocument,
    event: ClientEventEnvelope,
    context: PolicyEvaluationContext
  ): PolicyDecision {
    const action = PolicyEngine.actionForEvent(event.event_type);
    const permission = policy.permissions.find((candidate) =>
      candidate.role === context.actorRole &&
      candidate.object_type === event.object_type &&
      candidate.actions.includes(action)
    );

    if (permission === undefined) {
      return {
        outcome: "deny",
        errorCode: "POLICY_DENIED"
      };
    }

    if (!PolicyEngine.conditionsAllow(permission.conditions, event, context)) {
      return {
        outcome: "deny",
        errorCode: "POLICY_DENIED"
      };
    }

    const approvalRule = policy.approval_rules.find((rule) => {
      if (!rule.event_types.includes(event.event_type)) {
        return false;
      }

      if (rule.threshold === undefined) {
        return true;
      }

      return (
        event.policy_metadata.amount_minor_units !== undefined &&
        event.policy_metadata.currency === rule.threshold.currency &&
        event.policy_metadata.amount_minor_units >= rule.threshold.amount_minor_units
      );
    });

    if (approvalRule !== undefined) {
      return {
        outcome: "require_approvals",
        requiredRoles: approvalRule.required_roles,
        requiredCount: approvalRule.required_count,
        errorCode: "APPROVALS_REQUIRED"
      };
    }

    return { outcome: "allow" };
  }

  static readActivePolicy(database: DatabaseSync): PolicyDocument | null {
    const row = database
      .prepare(
        `SELECT document
        FROM policies
        WHERE activated_at_sequence IS NOT NULL
        ORDER BY version DESC
        LIMIT 1`
      )
      .get() as PolicyRow | undefined;

    return row === undefined ? null : PolicyEngine.parsePolicyDocument(row.document);
  }

  static parsePolicyDocument(raw: string): PolicyDocument {
    return policyDocumentSchema.parse(
      JSON.parse(raw, (_key, value: unknown) =>
        typeof value === "string" && /^\d+n$/.test(value) ? BigInt(value.slice(0, -1)) : value
      )
    );
  }

  static serializePolicyDocument(policy: PolicyDocument): string {
    return JSON.stringify(policy, (_key, value: unknown) =>
      typeof value === "bigint" ? `${value.toString(10)}n` : value
    );
  }

  static documentHash(policy: Omit<PolicyDocument, "document_hash" | "signature">): string {
    return sha256Digest(canonicalBytes(PolicyEngine.hashablePolicy(policy)));
  }

  static assertDocumentHash(policy: PolicyDocument): void {
    const unsigned = {
      id: policy.id,
      version: policy.version,
      permissions: policy.permissions,
      approval_rules: policy.approval_rules,
      activated_at_sequence: policy.activated_at_sequence
    };

    if (PolicyEngine.documentHash(unsigned) !== policy.document_hash) {
      throw new PolicyError("POLICY_VERSION_MISMATCH");
    }
  }

  static actionForEvent(eventType: ClientEventEnvelope["event_type"]): PolicyAction {
    if (eventType === "DATA_EXPORTED") {
      return "export";
    }

    if (eventType === "CONFLICT_RESOLVED") {
      return "resolve";
    }

    if (
      eventType === "PAYMENT_APPROVED" ||
      eventType === "PAYMENT_APPROVAL_CREATED" ||
      eventType === "BUDGET_APPROVED"
    ) {
      return "approve";
    }

    return "create";
  }

  static conditionsAllow(
    conditions: Record<string, unknown> | undefined,
    event: ClientEventEnvelope,
    context: PolicyEvaluationContext
  ): boolean {
    if (conditions === undefined) {
      return true;
    }

    if (typeof conditions.currency === "string" && event.policy_metadata.currency !== conditions.currency) {
      return false;
    }

    if (
      conditions.max_amount_minor_units !== undefined &&
      event.policy_metadata.amount_minor_units !== undefined &&
      event.policy_metadata.amount_minor_units > PolicyEngine.conditionBigInt(conditions.max_amount_minor_units)
    ) {
      return false;
    }

    if (
      typeof conditions.max_risk_score === "number" &&
      context.riskScore !== undefined &&
      context.riskScore > conditions.max_risk_score
    ) {
      return false;
    }

    return true;
  }

  static conditionBigInt(value: unknown): bigint {
    if (typeof value === "bigint") {
      return value;
    }

    if (typeof value === "number" && Number.isSafeInteger(value)) {
      return BigInt(value);
    }

    if (typeof value === "string" && /^\d+$/.test(value)) {
      return BigInt(value);
    }

    throw new PolicyError("SCHEMA_INVALID");
  }

  static hashablePolicy(policy: Omit<PolicyDocument, "document_hash" | "signature">): CanonicalJson {
    return {
      id: policy.id,
      version: policy.version,
      permissions: policy.permissions.map((permission) => ({
        role: permission.role,
        object_type: permission.object_type,
        actions: permission.actions,
        conditions: permission.conditions as CanonicalJson | undefined
      })),
      approval_rules: policy.approval_rules.map((rule) => ({
        event_types: rule.event_types,
        threshold: rule.threshold,
        required_roles: rule.required_roles,
        required_count: rule.required_count
      })),
      activated_at_sequence: policy.activated_at_sequence
    };
  }
}

export class PolicyError extends Error {
  readonly errorCode: ErrorCode;

  constructor(errorCode: ErrorCode) {
    super(errorCode);
    this.errorCode = errorCode;
  }
}
