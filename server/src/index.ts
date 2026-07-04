import { errorCodes, eventTypes, objectTypes } from "@vorcaro/protocol";

export {
  configureConnection,
  configureReadOnlyConnection,
  initializeLedgerDatabase,
  initializeProjectionsDatabase,
  openLedgerDatabase,
  openProjectionsDatabase
} from "./db/sqlite.js";
export {
  GENESIS_LEDGER_HASH,
  LedgerAppender,
  type AppendEventRequest,
  type LedgerAppenderOptions
} from "./ledger/appender.js";
export { createAdminApiApp, type AdminApiOptions } from "./api/admin-api.js";
export { createDeviceApiApp, createErrorHandler, type DeviceApiOptions } from "./api/device-api.js";
export {
  buildMtlsServerOptions,
  createMtlsHttpsServer,
  type MtlsServerOptions
} from "./api/listeners.js";
export { LocalCertificateAuthority, type CertificateAuthority } from "./pki/authority.js";
export {
  PkiError,
  PkiService,
  type BeginEnrollmentInput,
  type CompleteEnrollmentInput,
  type CompleteEnrollmentResult,
  type EnrollmentChallenge,
  type IssueEnrollmentTokenInput,
  type IssuedEnrollmentToken,
  type PkiServiceOptions,
  type RevokeDeviceInput
} from "./pki/enrollment.js";
export {
  ProjectionWorker,
  type ProjectionRunResult,
  type ProjectionWorkerOptions
} from "./projections/worker.js";
export {
  MemorySnapshotObjectStore,
  SnapshotWorker,
  type SnapshotObjectStore,
  type SnapshotWorkerOptions
} from "./snapshots/worker.js";

export type ServerBootstrapStatus = {
  protocol_event_type_count: number;
  protocol_object_type_count: number;
  protocol_error_code_count: number;
};

export class ServerBootstrap {
  static getStatus(): ServerBootstrapStatus {
    return {
      protocol_event_type_count: eventTypes.length,
      protocol_object_type_count: objectTypes.length,
      protocol_error_code_count: errorCodes.length
    };
  }
}
