import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { Server } from "node:https";

import { createAdminApiApp } from "./api/admin-api.js";
import { createDeviceApiApp } from "./api/device-api.js";
import { createMtlsHttpsServer, type MtlsServerOptions } from "./api/listeners.js";
import { openLedgerDatabase, openProjectionsDatabase } from "./db/sqlite.js";
import { LedgerAppender } from "./ledger/appender.js";
import { OpenSslCertificateAuthority } from "./pki/authority.js";
import { PkiService } from "./pki/enrollment.js";
import { PolicyService } from "./policy/service.js";

export type RuntimeConfig = {
  readonly dataDir: string;
  readonly certDir: string;
  readonly devicePort: number;
  readonly adminPort: number;
  readonly host: string;
  readonly serverSigningSecretKeyFile: string;
  readonly deviceServerKeyFile: string;
  readonly deviceServerCertFile: string;
  readonly deviceClientCaFile: string;
  readonly deviceClientCaKeyFile: string;
  readonly adminServerKeyFile: string;
  readonly adminServerCertFile: string;
  readonly adminClientCaFile: string;
  readonly adminUiPath: string | null;
  readonly caRevocationLogFile: string;
  readonly deviceCertificateLifetimeDays: number;
  readonly enrollmentChallengeLifetimeMinutes: number;
};

export class VorcaroServerRuntime {
  private readonly config: RuntimeConfig;
  private readonly lockPath: string;
  private readonly ledgerDatabase;
  private readonly projectionsDatabase;
  private readonly appender: LedgerAppender;
  private readonly deviceServer: Server;
  private readonly adminServer: Server;
  private shuttingDown = false;

  constructor(config: RuntimeConfig) {
    this.config = config;
    mkdirSync(config.dataDir, { recursive: true });
    mkdirSync(join(config.dataDir, "backups"), { recursive: true });
    this.lockPath = join(config.dataDir, ".vorcaro-server.lock");
    VorcaroServerRuntime.acquireLock(this.lockPath);

    try {
      this.ledgerDatabase = openLedgerDatabase({ path: join(config.dataDir, "ledger.db") });
      this.projectionsDatabase = openProjectionsDatabase({ path: join(config.dataDir, "projections.db") });
      const serverSigningSecretKey = VorcaroServerRuntime.readSecret(config.serverSigningSecretKeyFile);
      this.appender = LedgerAppender.create({
        database: this.ledgerDatabase,
        serverSigningSecretKey
      });
      const policyService = new PolicyService({
        database: this.ledgerDatabase,
        appender: this.appender
      });
      const pkiService = new PkiService({
        database: this.ledgerDatabase,
        certificateAuthority: new OpenSslCertificateAuthority({
          caKeyFile: config.deviceClientCaKeyFile,
          caCertFile: config.deviceClientCaFile,
          revocationLogFile: config.caRevocationLogFile
        }),
        serverSigningSecretKey,
        deviceCertificateLifetimeDays: config.deviceCertificateLifetimeDays,
        enrollmentChallengeLifetimeMinutes: config.enrollmentChallengeLifetimeMinutes
      });
      this.deviceServer = createMtlsHttpsServer(
        createDeviceApiApp({
          database: this.ledgerDatabase,
          appender: this.appender,
          serverSigningSecretKey,
          pkiService
        }),
        VorcaroServerRuntime.tlsOptions({
          keyFile: config.deviceServerKeyFile,
          certFile: config.deviceServerCertFile,
          caFile: config.deviceClientCaFile,
          allowUnauthorizedClients: true
        })
      );
      this.adminServer = createMtlsHttpsServer(
        createAdminApiApp({
          database: this.ledgerDatabase,
          policyService,
          pkiService,
          ...(config.adminUiPath === null ? {} : { adminUiPath: config.adminUiPath })
        }),
        VorcaroServerRuntime.tlsOptions({
          keyFile: config.adminServerKeyFile,
          certFile: config.adminServerCertFile,
          caFile: config.adminClientCaFile
        })
      );
    } catch (error) {
      this.releaseLock();
      throw error;
    }
  }

  async start(): Promise<void> {
    await Promise.all([
      VorcaroServerRuntime.listen(this.deviceServer, this.config.devicePort, this.config.host),
      VorcaroServerRuntime.listen(this.adminServer, this.config.adminPort, this.config.host)
    ]);
    process.stdout.write(
      JSON.stringify({
        event: "vorcaro_server_started",
        device_port: this.config.devicePort,
        admin_port: this.config.adminPort,
        data_dir: this.config.dataDir
      }) + "\n"
    );
  }

  async shutdown(signal: string): Promise<void> {
    if (this.shuttingDown) {
      return;
    }

    this.shuttingDown = true;
    process.stdout.write(JSON.stringify({ event: "vorcaro_server_shutdown", signal }) + "\n");
    await this.appender.drain();
    await Promise.all([
      VorcaroServerRuntime.close(this.deviceServer),
      VorcaroServerRuntime.close(this.adminServer)
    ]);
    this.ledgerDatabase.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    this.projectionsDatabase.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    this.ledgerDatabase.close();
    this.projectionsDatabase.close();
    this.releaseLock();
  }

  private releaseLock(): void {
    if (existsSync(this.lockPath)) {
      rmSync(this.lockPath, { recursive: true, force: true });
    }
  }

  static fromEnv(environment: NodeJS.ProcessEnv = process.env): VorcaroServerRuntime {
    const dataDir = environment.VORCARO_DATA_DIR ?? "/var/lib/vorcaro";
    const certDir = environment.VORCARO_CERT_DIR ?? "/etc/vorcaro/certs";
    const secretDir = environment.VORCARO_SECRET_DIR ?? "/etc/vorcaro/secrets";
    return new VorcaroServerRuntime({
      dataDir,
      certDir,
      devicePort: VorcaroServerRuntime.envPort(environment.VORCARO_DEVICE_PORT, 8443),
      adminPort: VorcaroServerRuntime.envPort(environment.VORCARO_ADMIN_PORT, 9443),
      host: environment.VORCARO_HOST ?? "0.0.0.0",
      serverSigningSecretKeyFile:
        environment.VORCARO_SERVER_SIGNING_SECRET_KEY_FILE ?? join(secretDir, "server-signing.key"),
      deviceServerKeyFile:
        environment.VORCARO_DEVICE_SERVER_KEY_FILE ?? join(certDir, "device-server.key.pem"),
      deviceServerCertFile:
        environment.VORCARO_DEVICE_SERVER_CERT_FILE ?? join(certDir, "device-server.cert.pem"),
      deviceClientCaFile:
        environment.VORCARO_DEVICE_CLIENT_CA_FILE ?? join(certDir, "device-client-ca.pem"),
      deviceClientCaKeyFile:
        environment.VORCARO_DEVICE_CLIENT_CA_KEY_FILE ?? join(certDir, "device-client-ca.key.pem"),
      adminServerKeyFile:
        environment.VORCARO_ADMIN_SERVER_KEY_FILE ?? join(certDir, "admin-server.key.pem"),
      adminServerCertFile:
        environment.VORCARO_ADMIN_SERVER_CERT_FILE ?? join(certDir, "admin-server.cert.pem"),
      adminClientCaFile:
        environment.VORCARO_ADMIN_CLIENT_CA_FILE ?? join(certDir, "admin-client-ca.pem"),
      adminUiPath: environment.VORCARO_ADMIN_UI_PATH ?? "/app/admin-ui",
      caRevocationLogFile:
        environment.VORCARO_CA_REVOCATION_LOG_FILE ?? join(dataDir, "device-ca-revocations.log"),
      deviceCertificateLifetimeDays: VorcaroServerRuntime.envPositiveInteger(
        environment.VORCARO_DEVICE_CERTIFICATE_LIFETIME_DAYS,
        7
      ),
      enrollmentChallengeLifetimeMinutes: VorcaroServerRuntime.envPositiveInteger(
        environment.VORCARO_ENROLLMENT_CHALLENGE_LIFETIME_MINUTES,
        10
      )
    });
  }

  static acquireLock(lockPath: string): void {
    try {
      mkdirSync(lockPath);
    } catch (error) {
      throw new Error(`Vorcaro server lock is already held at ${lockPath}`, { cause: error });
    }
  }

  static tlsOptions(input: {
    readonly keyFile: string;
    readonly certFile: string;
    readonly caFile: string;
    readonly allowUnauthorizedClients?: boolean;
  }): MtlsServerOptions {
    return {
      key: readFileSync(input.keyFile),
      cert: readFileSync(input.certFile),
      ca: readFileSync(input.caFile),
      ...(input.allowUnauthorizedClients === undefined
        ? {}
        : { allowUnauthorizedClients: input.allowUnauthorizedClients })
    };
  }

  static readSecret(path: string): string {
    return readFileSync(path, "utf8").trim();
  }

  static envPort(raw: string | undefined, fallback: number): number {
    if (raw === undefined) {
      return fallback;
    }

    const parsed = Number(raw);
    if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65_535) {
      throw new Error(`Invalid port: ${raw}`);
    }

    return parsed;
  }

  static envPositiveInteger(raw: string | undefined, fallback: number): number {
    if (raw === undefined) {
      return fallback;
    }

    const parsed = Number(raw);
    if (!Number.isInteger(parsed) || parsed <= 0) {
      throw new Error(`Invalid positive integer: ${raw}`);
    }

    return parsed;
  }

  static listen(server: Server, port: number, host: string): Promise<void> {
    return new Promise((resolveListen, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => {
        server.off("error", reject);
        resolveListen();
      });
    });
  }

  static close(server: Server): Promise<void> {
    return new Promise((resolveClose, reject) => {
      server.close((error) => {
        if (error !== undefined) {
          reject(error);
          return;
        }

        resolveClose();
      });
    });
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const runtime = VorcaroServerRuntime.fromEnv();
  process.once("SIGTERM", () => {
    void runtime.shutdown("SIGTERM").then(() => process.exit(0));
  });
  process.once("SIGINT", () => {
    void runtime.shutdown("SIGINT").then(() => process.exit(0));
  });
  void runtime.start().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  });
}
