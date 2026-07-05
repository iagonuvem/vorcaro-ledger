import type { DatabaseSync } from "node:sqlite";
import express from "express";
import { z } from "zod";

import { policyDocumentSchema } from "@vorcaro/protocol";

import { createErrorHandler, parseEventSubmission } from "./device-api.js";
import { sendJson } from "./json.js";
import { PkiService } from "../pki/enrollment.js";
import { PolicyError } from "../policy/engine.js";
import type { PolicyService } from "../policy/service.js";
import type { RecoveryService } from "../recovery/service.js";

export type AdminApiOptions = {
  readonly database?: DatabaseSync;
  readonly pkiService?: PkiService;
  readonly policyService?: PolicyService;
  readonly recoveryService?: RecoveryService;
  readonly adminUiPath?: string;
  readonly now?: () => string;
};

type DeviceRow = {
  readonly id: string;
  readonly executive_id: string;
  readonly certificate_fingerprint: string;
  readonly status: string;
  readonly hardware_backed: number;
  readonly enrolled_at: string;
  readonly revoked_at: string | null;
  readonly last_seen_at: string | null;
  readonly risk_score: number;
  readonly max_event_counter: number;
};

type ExecutiveRow = {
  readonly id: string;
  readonly display_name: string;
  readonly role: string;
  readonly status: string;
  readonly key_version: number;
  readonly created_at: string;
};

type CeremonyRow = {
  readonly id: string;
  readonly executive_id: string;
  readonly initiated_by: string;
  readonly status: string;
  readonly required_approvals: number;
  readonly approvals: number;
  readonly created_at: string;
  readonly completed_at: string | null;
};

type ConflictRow = {
  readonly id: string;
  readonly object_type: string;
  readonly object_id: string;
  readonly event_ids: string;
  readonly detected_at_sequence: number;
  readonly status: string;
  readonly resolution_event_id: string | null;
  readonly created_at: string;
  readonly resolved_at: string | null;
};

type CheckpointRow = {
  readonly sequence: number;
  readonly ledger_hash: string;
  readonly issued_at: string;
  readonly key_version: number;
};

type AuditRow = {
  readonly id: number;
  readonly category: string;
  readonly actor: string;
  readonly detail: string;
  readonly entry_hash: string;
  readonly created_at: string;
};

type StatusHeadRow = {
  readonly server_sequence: number;
  readonly resulting_ledger_hash: string;
};

const revokeDeviceBodySchema = z
  .object({
    revoked_by: z.string().min(1).default("admin"),
    reason: z.string().min(1).default("admin_request")
  })
  .strict();
const activatePolicyBodySchema = z
  .object({
    policy: z.unknown(),
    activation_event: z.unknown(),
    certificate_fingerprint: z.string().min(1),
    activated_by: z.string().min(1)
  })
  .strict();
const initiateRecoveryBodySchema = z
  .object({
    ceremony_id: z.string().min(1).optional(),
    executive_id: z.string().min(1),
    initiated_by: z.string().min(1),
    new_public_key: z.string().min(1)
  })
  .strict();
const approveRecoveryBodySchema = z
  .object({
    approver_id: z.string().min(1),
    approval_signature: z.string().min(1)
  })
  .strict();
const executeRecoveryBodySchema = z
  .object({
    executed_by: z.string().min(1),
    executor_device_id: z.string().min(1),
    recovery_performed_event: z.unknown(),
    key_rotated_event: z.unknown()
  })
  .strict();
const issueEnrollmentTokenBodySchema = z
  .object({
    executive_id: z.string().min(1),
    issued_by: z.string().min(1).default("admin"),
    expires_at: z.string().datetime({ offset: true }).optional(),
    ttl_minutes: z.number().int().positive().max(1_440).default(60)
  })
  .strict();

export function createAdminApiApp(options: AdminApiOptions = {}): express.Express {
  const app = express();
  const now = options.now ?? (() => new Date().toISOString());
  app.disable("x-powered-by");
  app.use(express.json({ limit: "1mb", strict: true }));

  app.get("/admin/v1/status", (_request, response) => {
    if (options.database === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    sendJson(response, 200, {
      status: "accepted",
      database_open: true,
      chain_head: readStatusHead(options.database)
    });
  });

  app.get("/admin/v1/devices", (_request, response) => {
    if (options.database === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    sendJson(response, 200, { devices: readDevices(options.database) });
  });

  app.post("/admin/v1/devices/:id/revoke", (request, response) => {
    if (options.pkiService === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    const body = revokeDeviceBodySchema.parse(request.body);
    const revocationList = options.pkiService.revokeDevice({
      deviceId: request.params.id,
      revokedBy: body.revoked_by,
      reason: body.reason
    });

    sendJson(response, 200, { revocation_list: revocationList });
  });

  app.get("/admin/v1/executives", (_request, response) => {
    if (options.database === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    sendJson(response, 200, { executives: readExecutives(options.database) });
  });

  app.post("/admin/v1/enrollment-tokens", (request, response) => {
    if (options.pkiService === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    const body = issueEnrollmentTokenBodySchema.parse(request.body);
    sendJson(response, 201, {
      enrollment_token: options.pkiService.issueEnrollmentToken({
        executiveId: body.executive_id,
        issuedBy: body.issued_by,
        expiresAt: body.expires_at ?? PkiService.addMinutes(now(), body.ttl_minutes)
      })
    });
  });

  app.get("/admin/v1/recovery/ceremonies", (_request, response) => {
    if (options.database === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    sendJson(response, 200, { ceremonies: readRecoveryCeremonies(options.database) });
  });

  app.post("/admin/v1/recovery/ceremonies", (request, response) => {
    if (options.recoveryService === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    const body = initiateRecoveryBodySchema.parse(request.body);
    sendJson(
      response,
      200,
      {
        ceremony: options.recoveryService.initiateCeremony(
          body.ceremony_id === undefined
            ? {
                executiveId: body.executive_id,
                initiatedBy: body.initiated_by,
                newPublicKey: body.new_public_key
              }
            : {
                ceremonyId: body.ceremony_id,
                executiveId: body.executive_id,
                initiatedBy: body.initiated_by,
                newPublicKey: body.new_public_key
              }
        )
      }
    );
  });

  app.post("/admin/v1/recovery/ceremonies/:id/approve", (request, response) => {
    if (options.recoveryService === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    const body = approveRecoveryBodySchema.parse(request.body);
    sendJson(
      response,
      200,
      {
        ceremony: options.recoveryService.approveCeremony({
          ceremonyId: request.params.id,
          approverId: body.approver_id,
          approvalSignature: body.approval_signature
        })
      }
    );
  });

  app.post("/admin/v1/recovery/ceremonies/:id/execute", (request, response) => {
    if (options.recoveryService === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    const body = executeRecoveryBodySchema.parse(request.body);
    sendJson(
      response,
      200,
      options.recoveryService.executeCeremony({
        ceremonyId: request.params.id,
        executedBy: body.executed_by,
        executorDeviceId: body.executor_device_id,
        recoveryPerformedEvent: parseSingleEvent(body.recovery_performed_event),
        keyRotatedEvent: parseSingleEvent(body.key_rotated_event)
      })
    );
  });

  app.get("/admin/v1/conflicts", (_request, response) => {
    if (options.database === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    sendJson(response, 200, { conflicts: readConflicts(options.database) });
  });

  app.get("/admin/v1/checkpoints", (_request, response) => {
    if (options.database === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    sendJson(response, 200, { checkpoints: readCheckpoints(options.database) });
  });

  app.get("/admin/v1/audit", (_request, response) => {
    if (options.database === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    sendJson(response, 200, { audit: readAudit(options.database) });
  });

  app.get("/admin/v1/policies", (_request, response) => {
    if (options.policyService === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    sendJson(response, 200, {
      active_policy: options.policyService.activePolicy(),
      policies: options.policyService.listPolicies()
    });
  });

  app.post("/admin/v1/policies/activate", async (request, response, next) => {
    if (options.policyService === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    try {
      const body = activatePolicyBodySchema.parse(request.body);
      const result = await options.policyService.activatePolicy({
        policy: clientPolicy(body.policy),
        activationEvent: parseSingleEvent(body.activation_event),
        certificateFingerprint: body.certificate_fingerprint,
        activatedBy: body.activated_by
      });
      sendJson(response, 200, result);
    } catch (error) {
      next(error);
    }
  });

  if (options.adminUiPath !== undefined) {
    app.use("/", express.static(options.adminUiPath, { index: "index.html" }));
  }

  app.use(createErrorHandler());
  return app;
}

function parseSingleEvent(value: unknown) {
  const events = parseEventSubmission(value);
  const event = events[0];

  if (events.length !== 1 || event === undefined) {
    throw new PolicyError("SCHEMA_INVALID");
  }

  return event;
}

function clientPolicy(value: unknown) {
  return policyDocumentSchema.parse(value);
}

function readDevices(database: DatabaseSync) {
  return (
    database
      .prepare(
        `SELECT
          id, executive_id, certificate_fingerprint, status, hardware_backed,
          enrolled_at, revoked_at, last_seen_at, risk_score, max_event_counter
        FROM devices
        ORDER BY executive_id ASC, id ASC`
      )
      .all() as DeviceRow[]
  ).map((row) => ({
    ...row,
    hardware_backed: row.hardware_backed === 1,
    max_event_counter: BigInt(row.max_event_counter)
  }));
}

function readExecutives(database: DatabaseSync) {
  return database
    .prepare(
      `SELECT id, display_name, role, status, key_version, created_at
      FROM executives
      ORDER BY role ASC, display_name ASC`
    )
    .all() as ExecutiveRow[];
}

function readRecoveryCeremonies(database: DatabaseSync) {
  return database
    .prepare(
      `SELECT
        recovery_ceremonies.id,
        recovery_ceremonies.executive_id,
        recovery_ceremonies.initiated_by,
        recovery_ceremonies.status,
        recovery_ceremonies.required_approvals,
        COUNT(recovery_approvals.approver_id) AS approvals,
        recovery_ceremonies.created_at,
        recovery_ceremonies.completed_at
      FROM recovery_ceremonies
      LEFT JOIN recovery_approvals
        ON recovery_approvals.ceremony_id = recovery_ceremonies.id
      GROUP BY recovery_ceremonies.id
      ORDER BY recovery_ceremonies.created_at DESC`
    )
    .all() as CeremonyRow[];
}

function readConflicts(database: DatabaseSync) {
  return (
    database
      .prepare(
        `SELECT
          id, object_type, object_id, event_ids, detected_at_sequence,
          status, resolution_event_id, created_at, resolved_at
        FROM conflicts
        ORDER BY detected_at_sequence DESC`
      )
      .all() as ConflictRow[]
  ).map((row) => ({
    ...row,
    event_ids: JSON.parse(row.event_ids) as string[],
    detected_at_sequence: BigInt(row.detected_at_sequence)
  }));
}

function readCheckpoints(database: DatabaseSync) {
  return (
    database
      .prepare(
        `SELECT sequence, ledger_hash, issued_at, key_version
        FROM checkpoints
        ORDER BY sequence DESC
        LIMIT 50`
      )
      .all() as CheckpointRow[]
  ).map((row) => ({
    ...row,
    sequence: BigInt(row.sequence)
  }));
}

function readAudit(database: DatabaseSync) {
  return (
    database
      .prepare(
        `SELECT id, category, actor, detail, entry_hash, created_at
        FROM audit_log
        ORDER BY id DESC
        LIMIT 100`
      )
      .all() as AuditRow[]
  ).map((row) => ({
    ...row,
    detail: JSON.parse(row.detail) as Record<string, unknown>
  }));
}

function readStatusHead(database: DatabaseSync) {
  const row = database
    .prepare(
      `SELECT server_sequence, resulting_ledger_hash
      FROM ledger_events
      WHERE server_sequence IS NOT NULL
      ORDER BY server_sequence DESC
      LIMIT 1`
    )
    .get() as StatusHeadRow | undefined;

  return row === undefined
    ? {
        latest_sequence: 0n,
        latest_ledger_hash: null
      }
    : {
        latest_sequence: BigInt(row.server_sequence),
        latest_ledger_hash: row.resulting_ledger_hash
      };
}
