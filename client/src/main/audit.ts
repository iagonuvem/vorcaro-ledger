import { mkdir, appendFile } from "node:fs/promises";
import path from "node:path";
import type { LocalStore } from "./local-store.js";

export type AuditSink = {
  recordIpcAnomaly: (message: string) => Promise<void>;
  recordSecurityAcknowledgement: (kind: string, acknowledgedAt: string) => Promise<void>;
};

export function createLocalAuditSink(userDataPath: string, getStore?: () => LocalStore | null): AuditSink {
  const auditFile = path.join(userDataPath, "local-audit.ndjson");

  async function append(category: string, body: Record<string, string>): Promise<void> {
    const store = getStore?.();
    if (store) {
      store.writeAudit({
        category: category === "security_acknowledgement" ? "security_acknowledgement" : "ipc_anomaly",
        body,
        recordedAt: new Date().toISOString()
      });
      return;
    }

    await mkdir(path.dirname(auditFile), { recursive: true });
    const record = {
      category,
      recorded_at: new Date().toISOString(),
      ...body
    };
    await appendFile(auditFile, `${JSON.stringify(record)}\n`, { encoding: "utf8" });
  }

  return {
    recordIpcAnomaly: (message) => append("ipc_anomaly", { message }),
    recordSecurityAcknowledgement: (kind, acknowledgedAt) =>
      append("security_acknowledgement", { kind, acknowledged_at: acknowledgedAt })
  };
}
