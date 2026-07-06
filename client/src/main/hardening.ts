import type { BrowserWindowConstructorOptions } from "electron";

export const rendererContentSecurityPolicy =
  "default-src app:; script-src app:; style-src app:; img-src app:; font-src app:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'";

export function createHardenedWindowOptions(preloadPath: string): BrowserWindowConstructorOptions {
  return {
    width: 1180,
    height: 760,
    minWidth: 900,
    minHeight: 620,
    title: "Vorcaro Sovereign Finance Ledger",
    backgroundColor: "#000000",
    show: false,
    webPreferences: {
      preload: preloadPath,
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webviewTag: false,
      devTools: false
    }
  };
}
