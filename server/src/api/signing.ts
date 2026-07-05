import {
  canonicalBytes,
  signBytes,
  signCheckpoint,
  type CanonicalJson,
  type Checkpoint,
  type LedgerSnapshot,
  type PolicyDocument,
  type RevocationList
} from "@vorcaro/protocol";

export type SignedEnvelope<T extends CanonicalJson> = T & {
  readonly signature: string;
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

export function signStateResponse(
  body: Omit<StateResponse, "signature">,
  serverSigningSecretKey: string
): StateResponse {
  return {
    ...body,
    signature: signBytes(canonicalBytes(body as CanonicalJson), serverSigningSecretKey)
  };
}

export function signListResponse<T extends Record<string, unknown>>(
  body: T,
  serverSigningSecretKey: string
): T & { readonly signature: string } {
  return {
    ...body,
    signature: signBytes(canonicalBytes(body as CanonicalJson), serverSigningSecretKey)
  };
}

export function signCheckpointResponse(
  checkpoint: Omit<Checkpoint, "signature">,
  serverSigningSecretKey: string
): Checkpoint {
  return signCheckpoint(checkpoint, serverSigningSecretKey);
}

export type SnapshotManifestResponse = {
  readonly snapshot: LedgerSnapshot | null;
  readonly server_timestamp: string;
  readonly signature: string;
};

export type RevocationListResponse = {
  readonly revocation_list: RevocationList | null;
  readonly server_timestamp: string;
  readonly signature: string;
};

export type PolicyDocumentResponse = {
  readonly policy: PolicyDocument | null;
  readonly server_timestamp: string;
  readonly signature: string;
};
