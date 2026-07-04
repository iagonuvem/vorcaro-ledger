import { errorCodes, eventTypes, objectTypes } from "@vorcaro/protocol";

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
