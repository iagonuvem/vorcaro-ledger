import { ipcMain, type IpcMainInvokeEvent } from "electron";
import { z } from "zod";
import {
  createEventRequestSchema,
  createEventResponseSchema,
  emptyRequestSchema,
  executiveWorkspaceSnapshotSchema,
  ipcChannels,
  securityAcknowledgementRequestSchema,
  securityAcknowledgementResponseSchema,
  shellStateSchema,
  vaultPassphraseRequestSchema,
  vaultStatusSchema,
  type ExecutiveWorkspaceSnapshot,
  type CreateEventResponse,
  type ShellState,
  type VaultStatus
} from "../ipc/contract.js";
import type { AuditSink } from "./audit.js";
import type { CreateEventInput } from "./event-creator.js";

type Handler<Input, Output> = (input: Input, event: IpcMainInvokeEvent) => Promise<Output> | Output;

export type VaultIpcHandlers = {
  status: () => Promise<VaultStatus>;
  create: (passphrase: string) => Promise<VaultStatus>;
  unlock: (passphrase: string) => Promise<VaultStatus>;
  lock: () => VaultStatus;
};

export type EventIpcHandlers = {
  create: (input: CreateEventInput) => CreateEventResponse;
};

export function registerIpcHandlers(
  audit: AuditSink,
  getShellState: () => ShellState,
  getExecutiveWorkspaceSnapshot: () => ExecutiveWorkspaceSnapshot,
  vault: VaultIpcHandlers,
  events: EventIpcHandlers
): void {
  registerValidatedHandler(
    ipcChannels.shellGetState,
    emptyRequestSchema,
    shellStateSchema,
    async () => getShellState(),
    audit
  );

  registerValidatedHandler(
    ipcChannels.workspaceGetSnapshot,
    emptyRequestSchema,
    executiveWorkspaceSnapshotSchema,
    async () => getExecutiveWorkspaceSnapshot(),
    audit
  );

  registerValidatedHandler(
    ipcChannels.eventCreate,
    createEventRequestSchema,
    createEventResponseSchema,
    async (request) =>
      events.create({
        eventType: request.eventType,
        objectType: request.objectType,
        objectId: request.objectId,
        policyMetadata: {
          ...request.policyMetadata,
          amount_minor_units:
            request.policyMetadata.amount_minor_units === undefined
              ? undefined
              : BigInt(request.policyMetadata.amount_minor_units),
          local_rate:
            request.policyMetadata.local_rate === undefined ? undefined : BigInt(request.policyMetadata.local_rate)
        },
        payload: request.payload
      }),
    audit
  );

  registerValidatedHandler(ipcChannels.vaultStatus, emptyRequestSchema, vaultStatusSchema, async () => vault.status(), audit);

  registerValidatedHandler(
    ipcChannels.vaultCreate,
    vaultPassphraseRequestSchema,
    vaultStatusSchema,
    async (request) => vault.create(request.passphrase),
    audit
  );

  registerValidatedHandler(
    ipcChannels.vaultUnlock,
    vaultPassphraseRequestSchema,
    vaultStatusSchema,
    async (request) => vault.unlock(request.passphrase),
    audit
  );

  registerValidatedHandler(ipcChannels.vaultLock, emptyRequestSchema, vaultStatusSchema, async () => vault.lock(), audit);

  registerValidatedHandler(
    ipcChannels.securityAcknowledge,
    securityAcknowledgementRequestSchema,
    securityAcknowledgementResponseSchema,
    async (request) => {
      await audit.recordSecurityAcknowledgement(request.kind, request.acknowledgedAt);
      return { recorded: true as const };
    },
    audit
  );
}

function registerValidatedHandler<Input, Output>(
  channel: string,
  inputSchema: z.ZodType<Input>,
  outputSchema: z.ZodType<Output>,
  handler: Handler<Input, Output>,
  audit: AuditSink
): void {
  ipcMain.handle(channel, async (event, payload: unknown) => {
    const input = inputSchema.safeParse(payload);

    if (!input.success) {
      await audit.recordIpcAnomaly(`Rejected invalid payload on ${channel}`);
      throw new Error("IPC payload rejected");
    }

    const output = outputSchema.safeParse(await handler(input.data, event));

    if (!output.success) {
      await audit.recordIpcAnomaly(`Rejected invalid response on ${channel}`);
      throw new Error("IPC response rejected");
    }

    return output.data;
  });
}
