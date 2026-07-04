import express from "express";

import { createErrorHandler } from "./device-api.js";
import { sendJson } from "./json.js";

export function createAdminApiApp(): express.Express {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "1mb", strict: true }));

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
