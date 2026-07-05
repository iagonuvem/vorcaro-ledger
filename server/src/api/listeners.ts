import { createServer, type ServerOptions } from "node:https";
import type { Express } from "express";

export type MtlsServerOptions = ServerOptions & {
  readonly key: ServerOptions["key"];
  readonly cert: ServerOptions["cert"];
  readonly ca: ServerOptions["ca"];
  readonly allowUnauthorizedClients?: boolean;
};

export function buildMtlsServerOptions(options: MtlsServerOptions): ServerOptions {
  const { allowUnauthorizedClients: _allowUnauthorizedClients, ...serverOptions } = options;

  return {
    ...serverOptions,
    minVersion: "TLSv1.3",
    requestCert: true,
    rejectUnauthorized: options.allowUnauthorizedClients === true ? false : true
  };
}

export function createMtlsHttpsServer(app: Express, options: MtlsServerOptions) {
  const server = createServer(buildMtlsServerOptions(options), app);
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 64;
  return server;
}
