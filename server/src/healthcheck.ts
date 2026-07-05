import { accessSync, constants } from "node:fs";
import { get } from "node:https";
import { join } from "node:path";

import { VorcaroServerRuntime } from "./main.js";

export class HealthcheckCommand {
  static async run(environment: NodeJS.ProcessEnv = process.env): Promise<void> {
    if (
      environment.VORCARO_HEALTHCHECK_CLIENT_CERT_FILE !== undefined &&
      environment.VORCARO_HEALTHCHECK_CLIENT_KEY_FILE !== undefined &&
      environment.VORCARO_HEALTHCHECK_CA_FILE !== undefined
    ) {
      await HealthcheckCommand.runHttpsCheck(environment);
      return;
    }

    HealthcheckCommand.runFilesystemCheck(environment);
  }

  static runFilesystemCheck(environment: NodeJS.ProcessEnv): void {
    const dataDir = environment.VORCARO_DATA_DIR ?? "/var/lib/vorcaro";
    accessSync(join(dataDir, "ledger.db"), constants.R_OK | constants.W_OK);
    accessSync(join(dataDir, "projections.db"), constants.R_OK | constants.W_OK);
    accessSync(join(dataDir, ".vorcaro-server.lock"), constants.R_OK);
  }

  static runHttpsCheck(environment: NodeJS.ProcessEnv): Promise<void> {
    const adminPort = VorcaroServerRuntime.envPort(environment.VORCARO_ADMIN_PORT, 9443);
    const host = environment.VORCARO_HEALTHCHECK_HOST ?? "localhost";
    const request = get(
      {
        host,
        port: adminPort,
        path: "/admin/v1/status",
        method: "GET",
        key: VorcaroServerRuntime.readSecret(environment.VORCARO_HEALTHCHECK_CLIENT_KEY_FILE as string),
        cert: VorcaroServerRuntime.readSecret(environment.VORCARO_HEALTHCHECK_CLIENT_CERT_FILE as string),
        ca: VorcaroServerRuntime.readSecret(environment.VORCARO_HEALTHCHECK_CA_FILE as string),
        timeout: 5_000
      },
      (response) => {
        if (response.statusCode !== 200) {
          request.destroy(new Error(`Healthcheck status ${response.statusCode ?? "unknown"}`));
          return;
        }

        response.resume();
      }
    );

    return new Promise((resolveHealthcheck, reject) => {
      request.once("error", reject);
      request.once("timeout", () => {
        request.destroy(new Error("Healthcheck timed out"));
      });
      request.once("close", () => {
        resolveHealthcheck();
      });
    });
  }
}

void HealthcheckCommand.run().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
