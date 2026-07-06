import { createCipheriv, randomBytes, randomUUID } from "node:crypto";

import {
  canonicalBytes,
  deriveSigningKeyPair,
  payloadHash,
  signClientEvent,
  type CanonicalJson,
  type ClientEventEnvelope,
  type EventType,
  type ObjectType,
  type PolicyMetadata,
  type UnsignedClientEventEnvelope
} from "@vorcaro/protocol";
import sodium from "sodium-native";

import type { LocalStore } from "./local-store.js";
import { LocalPolicyEngine, type LocalPolicyDecision } from "./local-policy.js";
import type { VaultService } from "./vault.js";

export type CreateEventInput = {
  readonly eventType: EventType;
  readonly objectType: ObjectType;
  readonly objectId: string;
  readonly policyMetadata: PolicyMetadata;
  readonly payload: CanonicalJson;
};

export type CreateEventResult = {
  readonly eventId: string;
  readonly deviceEventCounter: string;
  readonly baseServerSequence: string;
  readonly submitState: "queued";
  readonly localPolicy: LocalPolicyDecision;
};

export type EventCreatorOptions = {
  readonly store: LocalStore;
  readonly vault: VaultService;
  readonly now?: () => string;
};

export class EventCreator {
  private readonly store: LocalStore;
  private readonly vault: VaultService;
  private readonly now: () => string;

  constructor(options: EventCreatorOptions) {
    this.store = options.store;
    this.vault = options.vault;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  createEvent(input: CreateEventInput): CreateEventResult {
    const actorId = this.store.requireMeta("executive_id");
    const deviceId = this.store.requireMeta("device_id");
    const actorRole = this.store.requireMeta("executive_role");
    const riskScore = readOptionalRiskScore(this.store.readMeta("device_risk_score"));
    const encryptionKey = this.vault.encryptionUnwrappingKeyForInternalUse();
    const signingSeed = this.vault.signingKeySeedForInternalUse();

    try {
      const createdAt = this.now();
      const encryptedPayload = encryptPayload(input.payload, encryptionKey);
      let localPolicy: LocalPolicyDecision = { outcome: "not_configured" };
      const signed = this.store.createPendingEvent(({ deviceEventCounter, lastVerifiedSequence }) => {
        const event = signEvent(
          {
            event_id: `evt_${randomUUID()}`,
            event_type: input.eventType,
            actor_id: actorId,
            device_id: deviceId,
            client_timestamp: createdAt,
            base_server_sequence: lastVerifiedSequence,
            device_event_counter: BigInt(deviceEventCounter),
            object_type: input.objectType,
            object_id: input.objectId,
            policy_metadata: input.policyMetadata,
            payload_hash: payloadHash(encryptedPayload),
            encrypted_payload: encryptedPayload
          },
          signingSeed
        );
        localPolicy = LocalPolicyEngine.evaluate(
          this.store.readActivePolicy(),
          event,
          riskScore === undefined ? { actorRole } : { actorRole, riskScore }
        );

        return {
          event,
          envelopeBytes: canonicalBytes(event),
          createdAt
        };
      });

      return {
        eventId: signed.event_id,
        deviceEventCounter: signed.device_event_counter.toString(10),
        baseServerSequence: signed.base_server_sequence.toString(10),
        submitState: "queued",
        localPolicy
      };
    } finally {
      sodium.sodium_memzero(encryptionKey);
      sodium.sodium_memzero(signingSeed);
    }
  }
}

function readOptionalRiskScore(value: string | null): number | undefined {
  if (value === null) {
    return undefined;
  }

  const parsed = Number.parseInt(value, 10);

  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 100) {
    throw new Error("Invalid local metadata: device_risk_score");
  }

  return parsed;
}

function signEvent(event: UnsignedClientEventEnvelope, signingSeed: Buffer): ClientEventEnvelope {
  const keyPair = deriveSigningKeyPair(signingSeed);

  try {
    return signClientEvent(event, keyPair.secretKey);
  } finally {
    Buffer.from(keyPair.secretKey, "base64").fill(0);
  }
}

function encryptPayload(payload: CanonicalJson, key: Buffer): string {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ciphertext = Buffer.concat([cipher.update(canonicalBytes(payload)), cipher.final()]);
  const tag = cipher.getAuthTag();

  return canonicalBytes({
    algorithm: "aes-256-gcm",
    ciphertext: ciphertext.toString("base64"),
    nonce: nonce.toString("base64"),
    tag: tag.toString("base64"),
    version: 1
  }).toString("base64");
}
