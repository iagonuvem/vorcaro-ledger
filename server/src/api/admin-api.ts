import express from "express";

import { createErrorHandler } from "./device-api.js";
import { sendJson } from "./json.js";
import type { PkiService } from "../pki/enrollment.js";

export type AdminApiOptions = {
  readonly pkiService?: PkiService;
};

export function createAdminApiApp(options: AdminApiOptions = {}): express.Express {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "1mb", strict: true }));

  app.post("/admin/v1/devices/:id/revoke", (request, response) => {
    if (options.pkiService === undefined) {
      sendJson(response, 501, { error_code: "POLICY_DENIED" });
      return;
    }

    const revocationList = options.pkiService.revokeDevice({
      deviceId: request.params.id,
      revokedBy: "admin",
      reason: typeof request.body?.reason === "string" ? request.body.reason : "admin_request"
    });

    sendJson(response, 200, { revocation_list: revocationList });
  });

  app.use("/admin/v1/devices", (_request, response) => {
    sendJson(response, 501, { error_code: "POLICY_DENIED" });
  });
  app.use("/admin/v1/executives", (_request, response) => {
    sendJson(response, 501, { error_code: "POLICY_DENIED" });
  });
  app.use("/admin/v1/quarantine", (_request, response) => {
    sendJson(response, 501, { error_code: "POLICY_DENIED" });
  });
  app.use("/admin/v1/audit", (_request, response) => {
    sendJson(response, 501, { error_code: "POLICY_DENIED" });
  });

  app.use(createErrorHandler());
  return app;
}
