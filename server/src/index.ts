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
  createLedgerAppender,
  type AppendEventRequest,
  type LedgerAppenderOptions
} from "./ledger/appender.js";
export { createAdminApiApp } from "./api/admin-api.js";
export { createDeviceApiApp, createErrorHandler, type DeviceApiOptions } from "./api/device-api.js";
export {
  buildMtlsServerOptions,
  createMtlsHttpsServer,
  type MtlsServerOptions
} from "./api/listeners.js";

export type ServerBootstrapStatus = {
  protocol_event_type_count: number;
  protocol_object_type_count: number;
  protocol_error_code_count: number;
};

export function getServerBootstrapStatus(): ServerBootstrapStatus {
  return {
    protocol_event_type_count: eventTypes.length,
    protocol_object_type_count: objectTypes.length,
    protocol_error_code_count: errorCodes.length
  };
}
