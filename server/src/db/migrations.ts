import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import type { DatabaseSync } from "node:sqlite";

export type DatabaseKind = "ledger" | "projections";

const migrationsRoot = fileURLToPath(new URL("../../migrations", import.meta.url));

export function applyMigrations(database: DatabaseSync, kind: DatabaseKind): void {
  const directory = join(migrationsRoot, kind);
  const migrationFiles = readdirSync(directory)
    .filter((fileName) => fileName.endsWith(".sql"))
    .sort();

  database.exec("BEGIN IMMEDIATE");

  try {
    for (const migrationFile of migrationFiles) {
      database.exec(readFileSync(join(directory, migrationFile), "utf8"));
    }

    database.exec("COMMIT");
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }
}
