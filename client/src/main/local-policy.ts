import {
  canonicalBytes,
  policyDocumentSchema,
  sha256Digest,
  sha256Hex,
  type CanonicalJson,
  type ClientEventEnvelope,
  type ErrorCode,
  type PolicyDocument
} from "@vorcaro/protocol";

export type PolicyAction = "read" | "create" | "approve" | "resolve" | "export";

export type LocalPolicyDecision =
  | {
      readonly outcome: "not_configured";
    }
  | {
      readonly outcome: "allow";
    }
  | {
      readonly outcome: "deny";
      readonly errorCode: ErrorCode;
    }
  | {
      readonly outcome: "require_approvals";
      readonly requiredRoles: string[];
      readonly requiredCount: number;
      readonly errorCode: "APPROVALS_REQUIRED";
    };

export type LocalPolicyEvaluationContext = {
  readonly actorRole: string;
  readonly riskScore?: number;
};

export class LocalPolicyEngine {
  static evaluate(
    policy: PolicyDocument | null,
    event: ClientEventEnvelope,
    context: LocalPolicyEvaluationContext
  ): LocalPolicyDecision {
    if (policy === null) {
      return { outcome: "not_configured" };
    }

    try {
      LocalPolicyEngine.assertDocumentHash(policy);
      return LocalPolicyEngine.evaluateConfigured(policy, event, context);
    } catch (error) {
      if (error instanceof LocalPolicyError) {
        return {
          outcome: "deny",
          errorCode: error.errorCode
        };
      }

      throw error;
    }
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
    return sha256Digest(canonicalBytes(LocalPolicyEngine.hashablePolicy(policy)));
  }

  static defaultCurrencySnapshot(policy: PolicyDocument): {
    readonly id: string;
    readonly hash: string;
  } {
    if (policy.activated_at_sequence === null) {
      throw new LocalPolicyError("POLICY_VERSION_MISMATCH");
    }

    const payload = {
      kind: "vorcaro-default-currency-snapshot",
      policy_id: policy.id,
      policy_hash: policy.document_hash,
      default_currency: policy.default_currency,
      effective_sequence: policy.activated_at_sequence.toString(10)
    } as const;
    const hash = sha256Digest(canonicalBytes(payload));

    return {
      id: `ccysnap_${sha256Hex(hash).slice(0, 26)}`,
      hash
    };
  }

  private static evaluateConfigured(
    policy: PolicyDocument,
    event: ClientEventEnvelope,
    context: LocalPolicyEvaluationContext
  ): LocalPolicyDecision {
    const action = LocalPolicyEngine.actionForEvent(event.event_type);
    const permission = policy.permissions.find((candidate) =>
      candidate.role === context.actorRole &&
      candidate.object_type === event.object_type &&
      candidate.actions.includes(action) &&
      LocalPolicyEngine.conditionsAllow(candidate.conditions, event, context)
    );

    if (permission === undefined) {
      return {
        outcome: "deny",
        errorCode: "POLICY_DENIED"
      };
    }

    LocalPolicyEngine.assertDefaultCurrencySnapshot(policy, event);

    const approvalRule = policy.approval_rules.find((rule) => {
      if (!rule.event_types.includes(event.event_type)) {
        return false;
      }

      if (rule.threshold === undefined) {
        return true;
      }

      return (
        rule.threshold.currency === policy.default_currency &&
        LocalPolicyEngine.defaultCurrencyAmountMinorUnits(event) >= rule.threshold.amount_minor_units
      );
    });

    if (approvalRule !== undefined) {
      return {
        outcome: "require_approvals",
        requiredRoles: [...approvalRule.required_roles],
        requiredCount: approvalRule.required_count,
        errorCode: "APPROVALS_REQUIRED"
      };
    }

    return { outcome: "allow" };
  }

  private static assertDocumentHash(policy: PolicyDocument): void {
    const unsigned = {
      id: policy.id,
      version: policy.version,
      default_currency: policy.default_currency,
      permissions: policy.permissions,
      approval_rules: policy.approval_rules,
      activated_at_sequence: policy.activated_at_sequence
    };

    if (LocalPolicyEngine.documentHash(unsigned) !== policy.document_hash) {
      throw new LocalPolicyError("POLICY_VERSION_MISMATCH");
    }
  }

  private static actionForEvent(eventType: ClientEventEnvelope["event_type"]): PolicyAction {
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

  private static conditionsAllow(
    conditions: Record<string, unknown> | undefined,
    event: ClientEventEnvelope,
    context: LocalPolicyEvaluationContext
  ): boolean {
    if (conditions === undefined) {
      return true;
    }

    if (
      typeof conditions.currency === "string" &&
      (event.policy_metadata.transaction_currency ?? event.policy_metadata.currency) !== conditions.currency
    ) {
      return false;
    }

    if (
      conditions.max_amount_minor_units !== undefined &&
      LocalPolicyEngine.defaultCurrencyAmountMinorUnits(event) >
        LocalPolicyEngine.conditionBigInt(conditions.max_amount_minor_units)
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

  private static conditionBigInt(value: unknown): bigint {
    if (typeof value === "bigint") {
      return value;
    }

    if (typeof value === "number" && Number.isSafeInteger(value)) {
      return BigInt(value);
    }

    if (typeof value === "string" && /^\d+$/.test(value)) {
      return BigInt(value);
    }

    throw new LocalPolicyError("SCHEMA_INVALID");
  }

  private static defaultCurrencyAmountMinorUnits(event: ClientEventEnvelope): bigint {
    const metadata = event.policy_metadata;

    if (metadata.local_rate === undefined || metadata.exchange_rate === undefined) {
      return metadata.amount_minor_units ?? 0n;
    }

    const rate = LocalPolicyEngine.parseExchangeRate(metadata.exchange_rate);
    const numerator = metadata.local_rate * rate.numerator;

    if (numerator === 0n) {
      return 0n;
    }

    return (numerator + rate.denominator - 1n) / rate.denominator;
  }

  private static assertDefaultCurrencySnapshot(policy: PolicyDocument, event: ClientEventEnvelope): void {
    if (event.policy_metadata.default_currency_snapshot_id === undefined || policy.activated_at_sequence === null) {
      return;
    }

    if (event.policy_metadata.default_currency_snapshot_id !== LocalPolicyEngine.defaultCurrencySnapshot(policy).id) {
      throw new LocalPolicyError("POLICY_VERSION_MISMATCH");
    }
  }

  private static parseExchangeRate(value: string): { readonly numerator: bigint; readonly denominator: bigint } {
    if (!/^(0|[1-9]\d*)(\.\d{1,12})?$/.test(value) || /^0(?:\.0+)?$/.test(value)) {
      throw new LocalPolicyError("SCHEMA_INVALID");
    }

    const [whole, fraction = ""] = value.split(".");
    return {
      numerator: BigInt(`${whole}${fraction}`),
      denominator: 10n ** BigInt(fraction.length)
    };
  }

  private static hashablePolicy(policy: Omit<PolicyDocument, "document_hash" | "signature">): CanonicalJson {
    return {
      id: policy.id,
      version: policy.version,
      default_currency: policy.default_currency,
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

export class LocalPolicyError extends Error {
  readonly errorCode: ErrorCode;

  constructor(errorCode: ErrorCode) {
    super(errorCode);
    this.errorCode = errorCode;
  }
}
