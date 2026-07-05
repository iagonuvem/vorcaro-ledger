import type { DatabaseSync } from "node:sqlite";

import { canonicalBytes, sha256Digest, type AuditLogEntry, type CanonicalJson } from "@vorcaro/protocol";

import { GENESIS_LEDGER_HASH } from "../ledger/appender.js";

export type WriteAuditInput = {
  readonly category: AuditLogEntry["category"];
  readonly actor: string;
  readonly detail: Record<string, unknown>;
  readonly createdAt: string;
};

type PreviousAuditRow = {
  readonly entry_hash: string;
};

export function writeAuditLog(database: DatabaseSync, input: WriteAuditInput): void {
  const previous = database
    .prepare("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
    .get() as PreviousAuditRow | undefined;
  const previousHash = previous?.entry_hash ?? GENESIS_LEDGER_HASH;
  const entryHash = sha256Digest(
    Buffer.concat([
      Buffer.from(previousHash, "utf8"),
      canonicalBytes({
        category: input.category,
        actor: input.actor,
        detail: input.detail,
        created_at: input.createdAt
      } as CanonicalJson)
    ])
  );

  database
    .prepare(
      `INSERT INTO audit_log (
        category, actor, detail, previous_hash, entry_hash, created_at
      ) VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(
      input.category,
      input.actor,
      JSON.stringify(input.detail),
      previousHash,
      entryHash,
      input.createdAt
    );
}
