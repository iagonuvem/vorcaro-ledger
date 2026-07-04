import type { ErrorCode } from "@vorcaro/protocol";

export class ApiError extends Error {
  readonly statusCode: number;
  readonly errorCode: ErrorCode;

  constructor(statusCode: number, errorCode: ErrorCode) {
    super(errorCode);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
  }
}

export function errorStatus(errorCode: ErrorCode): number {
  switch (errorCode) {
    case "CERT_UNKNOWN":
    case "CERT_REVOKED":
    case "EXECUTIVE_INACTIVE":
      return 401;
    case "SCHEMA_INVALID":
    case "BAD_PAYLOAD_HASH":
    case "BAD_SIGNATURE":
    case "REPLAY_COUNTER":
      return 400;
    case "POLICY_DENIED":
    case "APPROVALS_REQUIRED":
      return 403;
    case "DUPLICATE_EVENT":
    case "CONFLICT":
    case "STALE_BASE":
      return 409;
    case "UNKNOWN_ACCOUNT":
    case "ACCOUNT_CLOSED":
    case "POLICY_VERSION_MISMATCH":
      return 422;
  }
}
