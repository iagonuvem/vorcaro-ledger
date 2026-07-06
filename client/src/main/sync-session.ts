import {
  canonicalBytes,
  checkpointSchema,
  ledgerEventSchema,
  policyDocumentSchema,
  serverAckSchema,
  verifyBytes,
  type CanonicalJson,
  type Checkpoint,
  type ClientEventEnvelope,
  type LedgerEvent,
  type PolicyDocument,
  type ServerAck
} from "@vorcaro/protocol";
import { z } from "zod";

import type { LocalStore } from "./local-store.js";
import { SyncEngine } from "./sync-engine.js";

export type SyncTransport = {
  readonly getState: () => Promise<StateResponse>;
  readonly getCheckpoints: (after: bigint) => Promise<CheckpointListResponse>;
  readonly getEvents: (afterSequence: bigint) => Promise<EventListResponse>;
  readonly getActivePolicy: () => Promise<PolicyResponse>;
  readonly pushEvents: (events: readonly ClientEventEnvelope[]) => Promise<ServerAck | { readonly acknowledgements: readonly ServerAck[] }>;
};

export type SyncSessionOptions = {
  readonly store: LocalStore;
  readonly engine: SyncEngine;
  readonly transport: SyncTransport;
  readonly serverSigningPublicKey: string;
  readonly pushBatchSize?: number;
};

export type SyncSessionState = "offline" | "connecting" | "verifying" | "pulling" | "pushing" | "idle";

export type SyncSessionResult = {
  readonly states: readonly SyncSessionState[];
  readonly pulledEvents: number;
  readonly pushedEvents: number;
};

export type StateResponse = {
  readonly latest_sequence: bigint;
  readonly latest_ledger_hash: string;
  readonly latest_checkpoint: Checkpoint | null;
  readonly revocation_list_version: number;
  readonly active_policy_version: number;
  readonly server_timestamp: string;
  readonly signature: string;
};

export type CheckpointListResponse = {
  readonly after: bigint;
  readonly checkpoints: readonly Checkpoint[];
  readonly server_timestamp: string;
  readonly signature: string;
};

export type EventListResponse = {
  readonly after_seq: bigint;
  readonly events: readonly LedgerEvent[];
  readonly server_timestamp: string;
  readonly signature: string;
};

export type PolicyResponse = {
  readonly policy: PolicyDocument | null;
  readonly server_timestamp: string;
  readonly signature: string;
};

const stateResponseSchema = z
  .object({
    latest_sequence: z.bigint().nonnegative(),
    latest_ledger_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    latest_checkpoint: checkpointSchema.nullable(),
    revocation_list_version: z.number().int().nonnegative(),
    active_policy_version: z.number().int().nonnegative(),
    server_timestamp: z.string().datetime({ offset: true }),
    signature: z.string().min(1)
  })
  .strict();

const checkpointListResponseSchema = z
  .object({
    after: z.bigint().nonnegative(),
    checkpoints: z.array(checkpointSchema),
    server_timestamp: z.string().datetime({ offset: true }),
    signature: z.string().min(1)
  })
  .strict();

const eventListResponseSchema = z
  .object({
    after_seq: z.bigint().nonnegative(),
    events: z.array(ledgerEventSchema),
    server_timestamp: z.string().datetime({ offset: true }),
    signature: z.string().min(1)
  })
  .strict();

const policyResponseSchema = z
  .object({
    policy: policyDocumentSchema.nullable(),
    server_timestamp: z.string().datetime({ offset: true }),
    signature: z.string().min(1)
  })
  .strict();

export class SyncSession {
  private readonly store: LocalStore;
  private readonly engine: SyncEngine;
  private readonly transport: SyncTransport;
  private readonly serverSigningPublicKey: string;
  private readonly pushBatchSize: number;

  constructor(options: SyncSessionOptions) {
    this.store = options.store;
    this.engine = options.engine;
    this.transport = options.transport;
    this.serverSigningPublicKey = options.serverSigningPublicKey;
    this.pushBatchSize = options.pushBatchSize ?? 50;
  }

  async runOnce(): Promise<SyncSessionResult> {
    const states: SyncSessionState[] = [];
    const transition = (state: SyncSessionState): void => {
      states.push(state);
    };

    transition("connecting");
    const state = this.verifyStateResponse(await this.transport.getState());

    transition("verifying");
    this.engine.verifyStateAdvertisement({
      latestSequence: state.latest_sequence,
      latestLedgerHash: state.latest_ledger_hash,
      latestCheckpoint: state.latest_checkpoint
    });

    const localHead = this.store.readVerifiedHead();
    const checkpoints = this.verifyCheckpointListResponse(await this.transport.getCheckpoints(localHead.sequence));
    for (const checkpoint of checkpoints.checkpoints) {
      this.engine.verifyAndStoreCheckpoint(checkpoint);
    }

    const policy = this.verifyPolicyResponse(await this.transport.getActivePolicy());
    if (policy.policy !== null) {
      this.store.writeActivePolicy(policy.policy);
    }

    transition("pulling");
    const eventList = this.verifyEventListResponse(await this.transport.getEvents(localHead.sequence));
    this.engine.applyPulledEvents(eventList.events);

    transition("pushing");
    const pending = this.store.readPendingEventsForPush(this.pushBatchSize);
    if (pending.length > 0) {
      const acknowledgementResponse = await this.transport.pushEvents(pending);
      const acknowledgements = "acknowledgements" in acknowledgementResponse
        ? acknowledgementResponse.acknowledgements
        : [acknowledgementResponse];
      for (const acknowledgement of acknowledgements) {
        this.engine.applyServerAck(acknowledgement);
      }
    }

    transition("idle");
    return {
      states,
      pulledEvents: eventList.events.length,
      pushedEvents: pending.length
    };
  }

  private verifyStateResponse(candidate: StateResponse): StateResponse {
    const response = stateResponseSchema.parse(candidate);
    this.verifySignedResponse(response);
    return response;
  }

  private verifyCheckpointListResponse(candidate: CheckpointListResponse): CheckpointListResponse {
    const response = checkpointListResponseSchema.parse(candidate);
    this.verifySignedResponse(response);
    return response;
  }

  private verifyEventListResponse(candidate: EventListResponse): EventListResponse {
    const response = eventListResponseSchema.parse(candidate);
    this.verifySignedResponse(response);
    return response;
  }

  private verifyPolicyResponse(candidate: PolicyResponse): PolicyResponse {
    const response = policyResponseSchema.parse(candidate);
    this.verifySignedResponse(response);
    return response;
  }

  private verifySignedResponse(response: { readonly signature: string; readonly [key: string]: unknown }): void {
    const { signature, ...body } = response;

    if (!verifyBytes(canonicalBytes(body as CanonicalJson), signature, this.serverSigningPublicKey)) {
      throw new SyncSessionError("BAD_RESPONSE_SIGNATURE");
    }
  }
}

export class SyncSessionError extends Error {
  readonly code: "BAD_RESPONSE_SIGNATURE";

  constructor(code: SyncSessionError["code"]) {
    super(code);
    this.code = code;
  }
}
