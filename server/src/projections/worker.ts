import type { DatabaseSync } from "node:sqlite";

export type ProjectionWorkerOptions = {
  readonly ledgerDatabase: DatabaseSync;
  readonly projectionsDatabase: DatabaseSync;
};

type LedgerEventRow = {
  readonly id: string;
  readonly server_sequence: number;
  readonly event_type: string;
  readonly object_type: string;
  readonly object_id: string;
  readonly policy_metadata: string;
  readonly status: string;
  readonly server_timestamp: string;
};

type ConflictRow = {
  readonly id: string;
  readonly object_type: string;
  readonly object_id: string;
  readonly event_ids: string;
  readonly detected_at_sequence: number;
};

type AccountAggregateRow = {
  readonly entity_id: string;
  readonly currency: string;
  readonly total_minor_units: number;
  readonly as_of_sequence: number;
};

export type ProjectionRunResult = {
  readonly fromSequence: bigint;
  readonly toSequence: bigint;
  readonly appliedEvents: number;
};

export class ProjectionWorker {
  private readonly ledgerDatabase: DatabaseSync;
  private readonly projectionsDatabase: DatabaseSync;

  constructor(options: ProjectionWorkerOptions) {
    this.ledgerDatabase = options.ledgerDatabase;
    this.projectionsDatabase = options.projectionsDatabase;
  }

  applyNextBatch(limit = 500): ProjectionRunResult {
    const fromSequence = this.lastAppliedSequence();
    const events = this.readLedgerEventsAfter(fromSequence, limit);
    const toSequence = events.length === 0 ? fromSequence : events[events.length - 1]!.server_sequence;

    this.projectionsDatabase.exec("BEGIN IMMEDIATE");

    try {
      for (const event of events) {
        this.applyEvent(event);
      }

      this.syncOpenConflicts();
      this.rebuildCashPosition();
      this.setMeta("last_applied_sequence", String(toSequence));
      this.projectionsDatabase.exec("COMMIT");
    } catch (error) {
      this.projectionsDatabase.exec("ROLLBACK");
      throw error;
    }

    return {
      fromSequence: BigInt(fromSequence),
      toSequence: BigInt(toSequence),
      appliedEvents: events.length
    };
  }

  rebuildAll(): ProjectionRunResult {
    this.projectionsDatabase.exec("BEGIN IMMEDIATE");

    try {
      this.projectionsDatabase.exec(`
        DELETE FROM proj_accounts;
        DELETE FROM proj_cash_position;
        DELETE FROM proj_transactions;
        DELETE FROM proj_budget_lines;
        DELETE FROM proj_approvals_open;
        DELETE FROM proj_conflicts_open;
        DELETE FROM proj_meta;
      `);
      this.projectionsDatabase.exec("COMMIT");
    } catch (error) {
      this.projectionsDatabase.exec("ROLLBACK");
      throw error;
    }

    let result: ProjectionRunResult = {
      fromSequence: 0n,
      toSequence: 0n,
      appliedEvents: 0
    };
    let totalApplied = 0;

    while (true) {
      const batch = this.applyNextBatch(500);
      totalApplied += batch.appliedEvents;
      result = {
        fromSequence: 0n,
        toSequence: batch.toSequence,
        appliedEvents: totalApplied
      };

      if (batch.appliedEvents === 0) {
        return result;
      }
    }
  }

  private applyEvent(event: LedgerEventRow): void {
    if (event.status !== "accepted" && event.status !== "conflicted") {
      return;
    }

    if (event.event_type === "ACCOUNT_CREATED" && event.status === "accepted") {
      this.upsertAccount(event);
      return;
    }

    if (event.event_type === "ACCOUNT_CLOSED" && event.status === "accepted") {
      this.setAccountStatus(event.object_id, "closed", event.server_sequence);
      return;
    }

    if (event.event_type === "CONFLICT_RESOLVED" && event.status === "accepted") {
      this.clearProjectionConflict(event.object_type, event.object_id);
    }
  }

  private upsertAccount(event: LedgerEventRow): void {
    const metadata = parsePolicyMetadata(event.policy_metadata);
    const accountId = metadata.account_id ?? event.object_id;
    const entityId = metadata.entity_id ?? "unknown";
    const currency = metadata.currency ?? "USD";

    this.projectionsDatabase
      .prepare(
        `INSERT INTO proj_accounts (
          account_id, entity_id, name, account_type, institution_name,
          account_number_masked, currency, balance_minor_units,
          as_of_sequence, status, conflicted
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 0)
        ON CONFLICT(account_id) DO UPDATE SET
          entity_id = excluded.entity_id,
          currency = excluded.currency,
          as_of_sequence = excluded.as_of_sequence,
          status = excluded.status,
          conflicted = excluded.conflicted`
      )
      .run(
        accountId,
        entityId,
        accountId,
        "checking",
        "unknown",
        "unknown",
        currency,
        0,
        event.server_sequence
      );
  }

  private setAccountStatus(accountId: string, status: string, asOfSequence: number): void {
    this.projectionsDatabase
      .prepare(
        `UPDATE proj_accounts
        SET status = ?, as_of_sequence = ?
        WHERE account_id = ?`
      )
      .run(status, asOfSequence, accountId);
  }

  private syncOpenConflicts(): void {
    const conflicts = this.ledgerDatabase
      .prepare(
        `SELECT id, object_type, object_id, event_ids, detected_at_sequence
        FROM conflicts
        WHERE status = 'open'
        ORDER BY detected_at_sequence ASC`
      )
      .all() as ConflictRow[];

    this.projectionsDatabase.prepare("DELETE FROM proj_conflicts_open").run();
    this.projectionsDatabase.prepare("UPDATE proj_accounts SET conflicted = 0").run();

    for (const conflict of conflicts) {
      this.projectionsDatabase
        .prepare(
          `INSERT INTO proj_conflicts_open (
            conflict_id, object_type, object_id, event_ids, detected_at_sequence
          ) VALUES (?, ?, ?, ?, ?)`
        )
        .run(
          conflict.id,
          conflict.object_type,
          conflict.object_id,
          conflict.event_ids,
          conflict.detected_at_sequence
        );

      if (conflict.object_type === "account") {
        this.projectionsDatabase
          .prepare("UPDATE proj_accounts SET conflicted = 1 WHERE account_id = ?")
          .run(conflict.object_id);
      }
    }
  }

  private clearProjectionConflict(objectType: string, objectId: string): void {
    if (objectType !== "account") {
      return;
    }

    this.projectionsDatabase
      .prepare("UPDATE proj_accounts SET conflicted = 0 WHERE account_id = ?")
      .run(objectId);
  }

  private rebuildCashPosition(): void {
    this.projectionsDatabase.prepare("DELETE FROM proj_cash_position").run();
    const rows = this.projectionsDatabase
      .prepare(
        `SELECT
          entity_id,
          currency,
          SUM(balance_minor_units) AS total_minor_units,
          MAX(as_of_sequence) AS as_of_sequence
        FROM proj_accounts
        WHERE status <> 'closed'
        GROUP BY entity_id, currency`
      )
      .all() as AccountAggregateRow[];

    for (const row of rows) {
      this.projectionsDatabase
        .prepare(
          `INSERT INTO proj_cash_position (
            entity_id, currency, total_minor_units,
            pending_delta_minor_units, as_of_sequence
          ) VALUES (?, ?, ?, 0, ?)`
        )
        .run(row.entity_id, row.currency, row.total_minor_units, row.as_of_sequence);
    }
  }

  private readLedgerEventsAfter(sequence: number, limit: number): LedgerEventRow[] {
    return this.ledgerDatabase
      .prepare(
        `SELECT
          id, server_sequence, event_type, object_type, object_id,
          policy_metadata, status, server_timestamp
        FROM ledger_events
        WHERE server_sequence > ?
        ORDER BY server_sequence ASC
        LIMIT ?`
      )
      .all(sequence, limit) as LedgerEventRow[];
  }

  private lastAppliedSequence(): number {
    const row = this.projectionsDatabase
      .prepare("SELECT value FROM proj_meta WHERE key = 'last_applied_sequence'")
      .get() as { readonly value: string } | undefined;

    return row === undefined ? 0 : Number(row.value);
  }

  private setMeta(key: string, value: string): void {
    this.projectionsDatabase
      .prepare(
        `INSERT INTO proj_meta (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value`
      )
      .run(key, value);
  }
}

export function createProjectionWorker(options: ProjectionWorkerOptions): ProjectionWorker {
  return new ProjectionWorker(options);
}

function parsePolicyMetadata(raw: string): {
  account_id?: string;
  entity_id?: string;
  currency?: string;
} {
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  const metadata: {
    account_id?: string;
    entity_id?: string;
    currency?: string;
  } = {};

  if (typeof parsed.account_id === "string") {
    metadata.account_id = parsed.account_id;
  }

  if (typeof parsed.entity_id === "string") {
    metadata.entity_id = parsed.entity_id;
  }

  if (typeof parsed.currency === "string") {
    metadata.currency = parsed.currency;
  }

  return metadata;
}
