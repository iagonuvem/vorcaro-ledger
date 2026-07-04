import { DatabaseSync } from "node:sqlite";

import { applyMigrations, type DatabaseKind } from "./migrations.js";

export type OpenDatabaseOptions = {
  readonly path: string;
  readonly readonly?: boolean;
};

export function openLedgerDatabase(options: OpenDatabaseOptions): DatabaseSync {
  return openDatabase("ledger", options);
}

export function openProjectionsDatabase(options: OpenDatabaseOptions): DatabaseSync {
  return openDatabase("projections", options);
}

export function initializeLedgerDatabase(database: DatabaseSync): void {
  configureConnection(database);
  applyMigrations(database, "ledger");
}

export function initializeProjectionsDatabase(database: DatabaseSync): void {
  configureConnection(database);
  applyMigrations(database, "projections");
}

export function configureConnection(database: DatabaseSync): void {
  database.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    PRAGMA trusted_schema = OFF;
  `);
}

export function configureReadOnlyConnection(database: DatabaseSync): void {
  configureConnection(database);
  database.exec("PRAGMA query_only = ON");
}

function openDatabase(kind: DatabaseKind, options: OpenDatabaseOptions): DatabaseSync {
  const database = new DatabaseSync(options.path, { readOnly: options.readonly ?? false });

  if (options.readonly === true) {
    configureReadOnlyConnection(database);
    return database;
  }

  if (kind === "ledger") {
    initializeLedgerDatabase(database);
  } else {
    initializeProjectionsDatabase(database);
  }

  return database;
}
