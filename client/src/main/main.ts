import { app, BrowserWindow, Menu, protocol, session } from "electron";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { createLocalAuditSink } from "./audit.js";
import { isAppProtocolUrl, resolveAppProtocolPath } from "./app-protocol.js";
import { EventCreator } from "./event-creator.js";
import { createHardenedWindowOptions } from "./hardening.js";
import { registerIpcHandlers } from "./ipc.js";
import { LocalStore } from "./local-store.js";
import { resolveRuntimePaths } from "./runtime-paths.js";
import { VaultService } from "./vault.js";
import { getExecutiveWorkspaceSnapshot } from "./workspace-snapshot.js";
import {
  verifyBundledFileManifest,
  VORCARO_RELEASE_PUBLIC_KEY_PEM
} from "./integrity.js";
import type { ShellState } from "../ipc/contract.js";

protocol.registerSchemesAsPrivileged([
  {
    scheme: "app",
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: false,
      corsEnabled: false,
      stream: true
    }
  }
]);

let mainWindow: BrowserWindow | null = null;
let integrityState: ShellState["integrity"] = "development_unsigned";
let vaultService: VaultService | null = null;
let localStore: LocalStore | null = null;
let runtimePaths = resolveRuntimePaths({
  appPath: app.getAppPath(),
  compiledMainUrl: import.meta.url,
  isPackaged: app.isPackaged
});

async function main(): Promise<void> {
  await app.whenReady();
  Menu.setApplicationMenu(null);

  runtimePaths = resolveRuntimePaths({
    appPath: app.getAppPath(),
    compiledMainUrl: import.meta.url,
    isPackaged: app.isPackaged
  });
  await verifyStartupIntegrity(runtimePaths.rendererAssetRoot);
  registerAppProtocol(runtimePaths.rendererAssetRoot);
  applySessionHardening();

  const audit = createLocalAuditSink(app.getPath("userData"), () => localStore);
  vaultService = new VaultService({
    headerPath: path.join(app.getPath("userData"), "vault", "header.json")
  });
  registerIpcHandlers(audit, getShellState, getExecutiveWorkspaceSnapshot, {
    status: () => requireVaultService().status(),
    create: async (passphrase) => {
      const status = await requireVaultService().create(passphrase);
      openLocalStore();
      return status;
    },
    unlock: async (passphrase) => {
      const status = await requireVaultService().unlock(passphrase);
      openLocalStore();
      return status;
    },
    lock: () => {
      closeLocalStore();
      return requireVaultService().lock();
    }
  }, {
    create: (input) =>
      new EventCreator({
        store: requireLocalStore(),
        vault: requireVaultService()
      }).createEvent(input)
  });
  mainWindow = createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      mainWindow = createWindow();
    }
  });
}

function createWindow(): BrowserWindow {
  const window = new BrowserWindow(createHardenedWindowOptions(runtimePaths.preloadPath));

  window.webContents.on("will-navigate", (event, targetUrl) => {
    if (!isAppProtocolUrl(targetUrl)) {
      event.preventDefault();
    }
  });

  window.webContents.setWindowOpenHandler((details) => ({
    action: isAppProtocolUrl(details.url) ? "allow" : "deny"
  }));

  window.once("ready-to-show", () => window.show());
  void window.loadURL("app://index.html");

  return window;
}

function registerAppProtocol(assetRoot: string): void {
  protocol.handle("app", async (request) => {
    try {
      const filePath = resolveAppProtocolPath(request.url, assetRoot);
      const body = await readFile(filePath);
      return new Response(body, {
        headers: {
          "content-type": contentTypeFor(filePath)
        }
      });
    } catch {
      return new Response("Not found", { status: 404 });
    }
  });
}

function contentTypeFor(filePath: string): string {
  switch (path.extname(filePath)) {
    case ".css":
      return "text/css; charset=utf-8";
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".png":
      return "image/png";
    case ".svg":
      return "image/svg+xml";
    case ".woff2":
      return "font/woff2";
    default:
      return "application/octet-stream";
  }
}

function applySessionHardening(): void {
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
    callback(false);
  });

  session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
    const protocolName = new URL(details.url).protocol;
    callback({ cancel: protocolName === "http:" || protocolName === "https:" || protocolName === "file:" });
  });
}

async function verifyStartupIntegrity(assetRoot: string): Promise<void> {
  if (!app.isPackaged) {
    integrityState = "development_unsigned";
    return;
  }

  await verifyBundledFileManifest({
    assetRoot,
    manifestPath: path.join(process.resourcesPath, "integrity", "manifest.json"),
    signaturePath: path.join(process.resourcesPath, "integrity", "manifest.sig"),
    publicKeyPem: VORCARO_RELEASE_PUBLIC_KEY_PEM
  });
  integrityState = "verified";
}

function getShellState(): ShellState {
  return {
    appProtocolUrl: "app://index.html",
    integrity: integrityState,
    navigationPolicy: "app_only",
    rendererNetwork: "disabled",
    vault: localStore ? "unlocked" : "locked"
  };
}

function requireVaultService(): VaultService {
  if (!vaultService) {
    throw new Error("Vault service is not initialized");
  }

  return vaultService;
}

function requireLocalStore(): LocalStore {
  if (!localStore) {
    throw new Error("Vault is locked");
  }

  return localStore;
}

function openLocalStore(): void {
  const databaseKey = requireVaultService().localDatabaseKeyForInternalUse();

  try {
    closeLocalStore();
    localStore = LocalStore.open({
      databasePath: path.join(app.getPath("userData"), "vault", "local.db"),
      databaseKey
    });
  } finally {
    databaseKey.fill(0);
  }
}

function closeLocalStore(): void {
  localStore?.close();
  localStore = null;
}

app.on("window-all-closed", () => {
  closeLocalStore();
  vaultService?.lock();

  if (process.platform !== "darwin") {
    app.quit();
  }
});

void main().catch(() => {
  app.exit(1);
});
