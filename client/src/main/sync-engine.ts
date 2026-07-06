import {
  checkpointSchema,
  computeLedgerHash,
  constantTimeEqual,
  ledgerEventSchema,
  payloadHash,
  serverAckSchema,
  verifyCheckpointSignature,
  verifyServerAckSignature,
  type ClientEventEnvelope,
  type Checkpoint,
  type LedgerEvent,
  type ServerAck
} from "@vorcaro/protocol";

import type { LocalStore } from "./local-store.js";

export type SyncEngineOptions = {
  readonly store: LocalStore;
  readonly serverSigningPublicKey: string;
  readonly checkpointPublicKey: string;
  readonly now?: () => string;
};

export type VerifiedStateAdvertisement = {
  readonly latestSequence: bigint;
  readonly latestLedgerHash: string;
  readonly latestCheckpoint: Checkpoint | null;
};

export class SyncEngine {
  private readonly store: LocalStore;
  private readonly serverSigningPublicKey: string;
  private readonly checkpointPublicKey: string;
  private readonly now: () => string;

  constructor(options: SyncEngineOptions) {
    this.store = options.store;
    this.serverSigningPublicKey = options.serverSigningPublicKey;
    this.checkpointPublicKey = options.checkpointPublicKey;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  verifyStateAdvertisement(state: VerifiedStateAdvertisement): void {
    const localHead = this.store.readVerifiedHead();

    if (state.latestSequence < localHead.sequence) {
      this.recordTripwire("server sequence moved behind local verified head");
      throw new SyncVerificationError("ROLLBACK_DETECTED");
    }

    if (state.latestSequence === localHead.sequence && state.latestLedgerHash !== localHead.ledgerHash) {
      this.recordTripwire("server head hash differs at local verified sequence");
      throw new SyncVerificationError("ROLLBACK_DETECTED");
    }

    if (state.latestCheckpoint !== null) {
      this.verifyAndStoreCheckpoint(state.latestCheckpoint);
    }
  }

  applyPulledEvents(events: readonly LedgerEvent[]): void {
    for (const candidate of events) {
      const event = ledgerEventSchema.parse(candidate);
      this.verifyPulledEvent(event);
      this.store.appendVerifiedLedgerEvent(event, this.now());
    }
  }

  verifyAndStoreCheckpoint(candidate: Checkpoint): void {
    const checkpoint = checkpointSchema.parse(candidate);

    if (!verifyCheckpointSignature(checkpoint, this.checkpointPublicKey)) {
      throw new SyncVerificationError("BAD_CHECKPOINT_SIGNATURE");
    }

    const knownHash = this.store.readLedgerHashAt(checkpoint.sequence);
    if (knownHash !== null && knownHash !== checkpoint.ledger_hash) {
      this.recordTripwire("checkpoint hash disagrees with local ledger memory");
      throw new SyncVerificationError("ROLLBACK_DETECTED");
    }

    this.store.storeVerifiedCheckpoint(checkpoint, this.now());
  }

  applyServerAck(candidate: ServerAck): void {
    const ack = serverAckSchema.parse(candidate);

    if (!verifyServerAckSignature(ack, this.serverSigningPublicKey)) {
      throw new SyncVerificationError("BAD_SERVER_SIGNATURE");
    }

    this.store.applyVerifiedServerAck(ack);
  }

  private verifyPulledEvent(event: LedgerEvent): void {
    if (event.server_sequence === null || event.resulting_ledger_hash === null || event.server_signature === null) {
      throw new SyncVerificationError("UNSEQUENCED_EVENT");
    }

    const localHead = this.store.readVerifiedHead();
    const expectedSequence = localHead.sequence + 1n;

    if (event.server_sequence !== expectedSequence) {
      throw new SyncVerificationError("CHAIN_GAP");
    }

    if (event.previous_ledger_hash !== localHead.ledgerHash) {
      this.recordTripwire("pulled event previous hash differs from local verified head");
      throw new SyncVerificationError("ROLLBACK_DETECTED");
    }

    if (!constantTimeEqual(payloadHash(event.encrypted_payload), event.payload_hash)) {
      throw new SyncVerificationError("BAD_PAYLOAD_HASH");
    }

    const expectedLedgerHash = computeLedgerHash(localHead.ledgerHash, event.server_sequence, clientEnvelopeFromLedger(event));
    if (event.resulting_ledger_hash !== expectedLedgerHash) {
      this.recordTripwire("pulled event resulting hash does not match canonical event bytes");
      throw new SyncVerificationError("BAD_LEDGER_HASH");
    }

    const ack = {
      event_id: event.event_id,
      status: event.status,
      server_sequence: event.server_sequence,
      resulting_ledger_hash: event.resulting_ledger_hash,
      server_timestamp: event.server_timestamp,
      error_code: event.error_code,
      server_signature: event.server_signature
    };

    if (!verifyServerAckSignature(ack, this.serverSigningPublicKey)) {
      throw new SyncVerificationError("BAD_SERVER_SIGNATURE");
    }
  }

  private recordTripwire(message: string): void {
    this.store.writeAudit({
      category: "chain_verification",
      body: { message },
      recordedAt: this.now()
    });
  }
}

function clientEnvelopeFromLedger(event: LedgerEvent): ClientEventEnvelope {
  return {
    event_id: event.event_id,
    event_type: event.event_type,
    actor_id: event.actor_id,
    device_id: event.device_id,
    client_timestamp: event.client_timestamp,
    base_server_sequence: event.base_server_sequence,
    device_event_counter: event.device_event_counter,
    object_type: event.object_type,
    object_id: event.object_id,
    policy_metadata: event.policy_metadata,
    payload_hash: event.payload_hash,
    encrypted_payload: event.encrypted_payload,
    client_signature: event.client_signature
  };
}

export class SyncVerificationError extends Error {
  readonly code:
    | "BAD_CHECKPOINT_SIGNATURE"
    | "BAD_LEDGER_HASH"
    | "BAD_PAYLOAD_HASH"
    | "BAD_SERVER_SIGNATURE"
    | "CHAIN_GAP"
    | "ROLLBACK_DETECTED"
    | "UNSEQUENCED_EVENT";

  constructor(code: SyncVerificationError["code"]) {
    super(code);
    this.code = code;
  }
}
