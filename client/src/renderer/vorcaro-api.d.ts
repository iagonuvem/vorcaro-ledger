import type { VorcaroApi } from "../ipc/contract.js";

declare global {
  interface Window {
    vorcaro?: VorcaroApi;
  }
}

export {};
