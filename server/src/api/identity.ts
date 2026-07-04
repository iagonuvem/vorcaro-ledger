import type { DatabaseSync } from "node:sqlite";
import type { NextFunction, Request, RequestHandler, Response } from "express";

import type { Role } from "@vorcaro/protocol";

import { ApiError } from "./errors.js";
import { writeAuditLog } from "./audit.js";

export type DeviceIdentity = {
  readonly certificateFingerprint: string;
  readonly device: {
    readonly id: string;
    readonly executive_id: string;
    readonly status: "enrolled" | "revoked" | "quarantined";
    readonly max_event_counter: number;
  };
  readonly executive: {
    readonly id: string;
    readonly role: Role;
    readonly status: "active" | "quarantined" | "deactivated";
  };
};

export type CertificateFingerprintResolver = (request: Request) => string | undefined;

export type IdentityRequest = Request & {
  identity?: DeviceIdentity;
};

type IdentityRow = {
  readonly certificate_fingerprint: string;
  readonly device_id: string;
  readonly executive_id: string;
  readonly device_status: "enrolled" | "revoked" | "quarantined";
  readonly max_event_counter: number;
  readonly executive_status: "active" | "quarantined" | "deactivated";
  readonly role: Role;
};

export function createIdentityMiddleware(options: {
  readonly database: DatabaseSync;
  readonly now: () => string;
  readonly certificateFingerprintResolver?: CertificateFingerprintResolver;
  readonly optionalPaths?: readonly string[];
}): RequestHandler {
  const resolveFingerprint = options.certificateFingerprintResolver ?? certificateFingerprintFromSocket;
  const optionalPaths = new Set(options.optionalPaths ?? []);

  return (request: Request, _response: Response, next: NextFunction): void => {
    if (optionalPaths.has(request.path)) {
      next();
      return;
    }

    const identityHeaderNames = Object.keys(request.headers).filter((headerName) =>
      /^(x-device-|x-executive-|x-actor-|x-identity)/i.test(headerName)
    );

    if (identityHeaderNames.length > 0) {
      writeAuditLog(options.database, {
        category: "auth",
        actor: "unknown",
        detail: {
          event: "ignored_identity_headers",
          header_names: identityHeaderNames.sort()
        },
        createdAt: options.now()
      });
    }

    const fingerprint = resolveFingerprint(request);
    if (fingerprint === undefined) {
      throw new ApiError(401, "CERT_UNKNOWN");
    }

    const row = options.database
      .prepare(
        `SELECT
          devices.certificate_fingerprint,
          devices.id AS device_id,
          devices.executive_id,
          devices.status AS device_status,
          devices.max_event_counter,
          executives.status AS executive_status,
          executives.role
        FROM devices
        JOIN executives ON executives.id = devices.executive_id
        WHERE devices.certificate_fingerprint = ?`
      )
      .get(fingerprint) as IdentityRow | undefined;

    if (row === undefined) {
      throw new ApiError(401, "CERT_UNKNOWN");
    }

    if (row.device_status !== "enrolled") {
      throw new ApiError(401, "CERT_REVOKED");
    }

    if (row.executive_status !== "active") {
      throw new ApiError(401, "EXECUTIVE_INACTIVE");
    }

    (request as IdentityRequest).identity = {
      certificateFingerprint: row.certificate_fingerprint,
      device: {
        id: row.device_id,
        executive_id: row.executive_id,
        status: row.device_status,
        max_event_counter: row.max_event_counter
      },
      executive: {
        id: row.executive_id,
        role: row.role,
        status: row.executive_status
      }
    };
    next();
  };
}

export function requireIdentity(request: Request): DeviceIdentity {
  const identity = (request as IdentityRequest).identity;

  if (identity === undefined) {
    throw new ApiError(401, "CERT_UNKNOWN");
  }

  return identity;
}

export function certificateFingerprintFromSocket(request: Request): string | undefined {
  const socket = request.socket as Request["socket"] & {
    getPeerCertificate?: (detailed?: boolean) => { fingerprint256?: string; fingerprint?: string } | null;
  };
  const certificate = socket.getPeerCertificate?.(true);
  const fingerprint = certificate?.fingerprint256 ?? certificate?.fingerprint;

  if (fingerprint === undefined || fingerprint.length === 0) {
    return undefined;
  }

  return fingerprint.replaceAll(":", "").toLowerCase();
}
