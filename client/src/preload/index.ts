import { contextBridge, ipcRenderer } from "electron";
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
  type VorcaroApi
} from "../ipc/contract.js";

const api: VorcaroApi = {
  async getShellState() {
    const payload = emptyRequestSchema.parse({});
    const response = await ipcRenderer.invoke(ipcChannels.shellGetState, payload);
    return shellStateSchema.parse(response);
  },
  async getExecutiveWorkspaceSnapshot() {
    const payload = emptyRequestSchema.parse({});
    const response = await ipcRenderer.invoke(ipcChannels.workspaceGetSnapshot, payload);
    return executiveWorkspaceSnapshotSchema.parse(response);
  },
  async createEvent(request) {
    const payload = createEventRequestSchema.parse(request);
    const response = await ipcRenderer.invoke(ipcChannels.eventCreate, payload);
    return createEventResponseSchema.parse(response);
  },
  async getVaultStatus() {
    const payload = emptyRequestSchema.parse({});
    const response = await ipcRenderer.invoke(ipcChannels.vaultStatus, payload);
    return vaultStatusSchema.parse(response);
  },
  async createVault(request) {
    const payload = vaultPassphraseRequestSchema.parse(request);
    const response = await ipcRenderer.invoke(ipcChannels.vaultCreate, payload);
    return vaultStatusSchema.parse(response);
  },
  async unlockVault(request) {
    const payload = vaultPassphraseRequestSchema.parse(request);
    const response = await ipcRenderer.invoke(ipcChannels.vaultUnlock, payload);
    return vaultStatusSchema.parse(response);
  },
  async lockVault() {
    const payload = emptyRequestSchema.parse({});
    const response = await ipcRenderer.invoke(ipcChannels.vaultLock, payload);
    return vaultStatusSchema.parse(response);
  },
  async acknowledgeSecurityBanner(request) {
    const payload = securityAcknowledgementRequestSchema.parse(request);
    const response = await ipcRenderer.invoke(ipcChannels.securityAcknowledge, payload);
    return securityAcknowledgementResponseSchema.parse(response);
  }
};

contextBridge.exposeInMainWorld("vorcaro", api);
