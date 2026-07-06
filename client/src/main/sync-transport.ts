import { request as httpsRequest, type RequestOptions } from "node:https";
import type { IncomingMessage } from "node:http";
import type { ClientEventEnvelope } from "@vorcaro/protocol";

import type {
  CheckpointListResponse,
  EventListResponse,
  PolicyResponse,
  StateResponse,
  SyncTransport
} from "./sync-session.js";
import type { DeviceCredentials, LocalStore } from "./local-store.js";

export type MtlsSyncTransportOptions = {
  readonly baseUrl: string;
  readonly caPem: string;
  readonly clientCertificatePem: string;
  readonly clientPrivateKeyPem: string;
  readonly timeoutMs?: number;
  readonly requestJson?: RequestJson;
};

export type RequestJson = (request: JsonRequest) => Promise<unknown>;

export type JsonRequest = {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly body?: unknown;
};

const protocolBigIntFields = new Set([
  "latest_sequence",
  "after",
  "after_seq",
  "sequence",
  "up_to_sequence",
  "server_sequence",
  "base_server_sequence",
  "device_event_counter",
  "amount_minor_units",
  "local_rate",
  "valid_from_sequence",
  "valid_until_sequence",
  "max_event_counter",
  "activated_at_sequence",
  "as_of_sequence",
  "detected_at_sequence"
]);

export class MtlsSyncTransport implements SyncTransport {
  private readonly baseUrl: URL;
  private readonly caPem: string;
  private readonly clientCertificatePem: string;
  private readonly clientPrivateKeyPem: string;
  private readonly timeoutMs: number;
  private readonly requestJson: RequestJson;

  constructor(options: MtlsSyncTransportOptions) {
    const baseUrl = new URL(options.baseUrl);
    if (baseUrl.protocol !== "https:") {
      throw new Error("Sync transport requires HTTPS");
    }

    this.baseUrl = baseUrl;
    this.caPem = options.caPem;
    this.clientCertificatePem = options.clientCertificatePem;
    this.clientPrivateKeyPem = options.clientPrivateKeyPem;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.requestJson = options.requestJson ?? ((request) => this.performHttpsJsonRequest(request));
  }

  async getState(): Promise<StateResponse> {
    return normalizeProtocolJson(await this.requestJson({ method: "GET", path: "/v1/state" })) as StateResponse;
  }

  async getCheckpoints(after: bigint): Promise<CheckpointListResponse> {
    return normalizeProtocolJson(
      await this.requestJson({ method: "GET", path: `/v1/checkpoints?after=${after.toString(10)}` })
    ) as CheckpointListResponse;
  }

  async getEvents(afterSequence: bigint): Promise<EventListResponse> {
    return normalizeProtocolJson(
      await this.requestJson({ method: "GET", path: `/v1/events?after_seq=${afterSequence.toString(10)}` })
    ) as EventListResponse;
  }

  async getActivePolicy(): Promise<PolicyResponse> {
    return normalizeProtocolJson(await this.requestJson({ method: "GET", path: "/v1/policies/active" })) as PolicyResponse;
  }

  async pushEvents(
    events: readonly ClientEventEnvelope[]
  ): Promise<import("@vorcaro/protocol").ServerAck | { readonly acknowledgements: readonly import("@vorcaro/protocol").ServerAck[] }> {
    const body = events.length === 1 ? events[0] : { events };
    return normalizeProtocolJson(await this.requestJson({ method: "POST", path: "/v1/events", body })) as
      | import("@vorcaro/protocol").ServerAck
      | { readonly acknowledgements: readonly import("@vorcaro/protocol").ServerAck[] };
  }

  buildRequestOptions(request: JsonRequest): RequestOptions {
    const url = new URL(request.path, this.baseUrl);
    if (url.protocol !== "https:" || url.origin !== this.baseUrl.origin) {
      throw new Error("Sync transport path escaped base origin");
    }

    return {
      protocol: "https:",
      hostname: url.hostname,
      port: url.port,
      path: `${url.pathname}${url.search}`,
      method: request.method,
      ca: this.caPem,
      cert: this.clientCertificatePem,
      key: this.clientPrivateKeyPem,
      rejectUnauthorized: true,
      minVersion: "TLSv1.3",
      timeout: this.timeoutMs,
      headers: {
        accept: "application/json",
        ...(request.body === undefined
          ? {}
          : {
              "content-type": "application/json"
            })
      }
    };
  }

  private performHttpsJsonRequest(request: JsonRequest): Promise<unknown> {
    const requestOptions = this.buildRequestOptions(request);
    const body = request.body === undefined ? undefined : JSON.stringify(request.body, jsonReplacer);

    return new Promise((resolve, reject) => {
      const outgoing = httpsRequest(requestOptions, (response) => {
        readResponseBody(response)
          .then((raw) => {
            if ((response.statusCode ?? 500) < 200 || (response.statusCode ?? 500) >= 300) {
              reject(new Error(`Sync request failed with HTTP ${response.statusCode ?? 0}`));
              return;
            }

            resolve(JSON.parse(raw));
          })
          .catch(reject);
      });

      outgoing.on("error", reject);
      outgoing.on("timeout", () => {
        outgoing.destroy(new Error("Sync request timed out"));
      });

      if (body !== undefined) {
        outgoing.setHeader("content-length", Buffer.byteLength(body));
        outgoing.write(body);
      }

      outgoing.end();
    });
  }
}

export function createMtlsSyncTransportFromStore(store: LocalStore, timeoutMs?: number): MtlsSyncTransport {
  const credentials = store.readDeviceCredentials();

  if (credentials === null) {
    throw new Error("Device credentials are not enrolled");
  }

  return createMtlsSyncTransportFromCredentials(credentials, timeoutMs);
}

export function createMtlsSyncTransportFromCredentials(
  credentials: DeviceCredentials,
  timeoutMs?: number
): MtlsSyncTransport {
  return new MtlsSyncTransport({
    baseUrl: credentials.serverBaseUrl,
    caPem: credentials.serverCaPem,
    clientCertificatePem: credentials.clientCertificatePem,
    clientPrivateKeyPem: credentials.clientPrivateKeyPem,
    ...(timeoutMs === undefined ? {} : { timeoutMs })
  });
}

export function normalizeProtocolJson(value: unknown, key = ""): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeProtocolJson(item));
  }

  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value).map(([entryKey, entryValue]) => [entryKey, normalizeProtocolJson(entryValue, entryKey)])
    );
  }

  if (typeof value === "string" && protocolBigIntFields.has(key) && /^-?\d+n?$/.test(value)) {
    return BigInt(value.endsWith("n") ? value.slice(0, -1) : value);
  }

  return value;
}

export function jsonReplacer(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? value.toString(10) : value;
}

function readResponseBody(response: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    response.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
    });
    response.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    response.on("error", reject);
  });
}
