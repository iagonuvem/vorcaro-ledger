import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { resolveAppProtocolPath } from "../dist/main/main/app-protocol.js";
import { createHardenedWindowOptions, rendererContentSecurityPolicy } from "../dist/main/main/hardening.js";
import {
  integrityManifestBytes,
  verifyBundledFileManifest
} from "../dist/main/main/integrity.js";
import { resolveRuntimePaths } from "../dist/main/main/runtime-paths.js";

const clientRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("BrowserWindow options enforce the hardened renderer boundary", () => {
  const options = createHardenedWindowOptions("/tmp/preload.js");

  assert.equal(options.backgroundColor, "#000000");
  assert.equal(options.webPreferences?.contextIsolation, true);
  assert.equal(options.webPreferences?.sandbox, true);
  assert.equal(options.webPreferences?.nodeIntegration, false);
  assert.equal(options.webPreferences?.webviewTag, false);
  assert.equal(options.webPreferences?.devTools, false);
  assert.equal("enableRemoteModule" in (options.webPreferences ?? {}), false);
});

test("app protocol serves only bundled local files", () => {
  const root = path.join(clientRoot, "dist", "renderer");

  assert.equal(resolveAppProtocolPath("app:///index.html", root), path.join(root, "index.html"));
  assert.equal(resolveAppProtocolPath("app://index.html", root), path.join(root, "index.html"));
  assert.equal(resolveAppProtocolPath("app://index.html/", root), path.join(root, "index.html"));
  assert.equal(resolveAppProtocolPath("app:///assets/index.js", root), path.join(root, "assets", "index.js"));
  assert.equal(resolveAppProtocolPath("app://assets/index.js", root), path.join(root, "assets", "index.js"));
  assert.equal(resolveAppProtocolPath("app://index.html/assets/index.js", root), path.join(root, "assets", "index.js"));
  assert.throws(() => resolveAppProtocolPath("https://vorcaro.invalid/index.html", root));
  assert.throws(() => resolveAppProtocolPath("app://assets/../../package.json", root));
  assert.throws(() => resolveAppProtocolPath("app://index.html/remote.exe", root));
});

test("dev runtime paths resolve from the compiled main module", () => {
  const paths = resolveRuntimePaths({
    appPath: path.join(clientRoot, "dist", "main", "main"),
    compiledMainUrl: pathToFileURL(path.join(clientRoot, "dist", "main", "main", "main.js")).toString(),
    isPackaged: false
  });

  assert.equal(paths.rendererAssetRoot, path.join(clientRoot, "dist", "renderer"));
  assert.equal(paths.preloadPath, path.join(clientRoot, "dist", "main", "preload", "index.js"));
});

test("packaged runtime paths preserve the app bundle layout", () => {
  const paths = resolveRuntimePaths({
    appPath: path.join(clientRoot, "packaged-app"),
    compiledMainUrl: pathToFileURL(path.join(clientRoot, "dist", "main", "main", "main.js")).toString(),
    isPackaged: true
  });

  assert.equal(paths.rendererAssetRoot, path.join(clientRoot, "packaged-app", "dist", "renderer"));
  assert.equal(paths.preloadPath, path.join(clientRoot, "packaged-app", "dist", "main", "preload", "index.js"));
});

test("built renderer declares the hardened CSP and no external URL loads", async () => {
  const rendererRoot = path.join(clientRoot, "dist", "renderer");
  const indexHtml = await readFile(path.join(rendererRoot, "index.html"), "utf8");

  assert.match(indexHtml, /Content-Security-Policy/);
  assert.match(indexHtml, /connect-src 'none'/);
  assert.equal(indexHtml.includes(rendererContentSecurityPolicy), true);
  assert.doesNotMatch(indexHtml, /(?:https?|file):\/\//);

  for (const assetPath of loadAttributes(indexHtml)) {
    assert.match(assetPath, /^\/assets\//);
    assert.doesNotMatch(assetPath, /(?:https?|file):\/\//);
  }
});

test("renderer source includes every v1 executive UI surface and truth-state label", async () => {
  const rendererSource = await readFile(path.join(clientRoot, "src", "renderer", "main.tsx"), "utf8");
  const contractSource = await readFile(path.join(clientRoot, "src", "ipc", "contract.ts"), "utf8");
  const snapshotSource = await readFile(path.join(clientRoot, "src", "main", "workspace-snapshot.ts"), "utf8");
  const combinedSource = `${contractSource}\n${snapshotSource}`;

  for (const label of [
    "Dashboard",
    "Approvals",
    "Conflicts",
    "Ledger / Audit",
    "Sync & Device",
    "Exports",
    "Settings"
  ]) {
    assert.match(rendererSource, new RegExp(label.replace("/", "\\/")));
  }

  for (const status of ["accepted", "pending", "rejected", "conflicted", "quarantined"]) {
    assert.match(combinedSource, new RegExp(`"${status}"`));
  }

  assert.match(combinedSource, /AI analysis - advisory/);
  assert.match(combinedSource, /DATA_EXPORTED/);
  assert.match(combinedSource, /CONFLICT_RESOLVED/);
  assert.match(rendererSource, /getExecutiveWorkspaceSnapshot/);
});

test("integrity manifest verifies canonical Ed25519 signatures and file hashes", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "vorcaro-integrity-"));
  const assetRoot = path.join(tempRoot, "assets");
  const manifestPath = path.join(tempRoot, "manifest.json");
  const signaturePath = path.join(tempRoot, "manifest.sig");

  try {
    await mkdir(assetRoot);
    await writeFile(path.join(assetRoot, "index.html"), "<main>locked</main>", "utf8");

    const manifest = {
      version: 1,
      files: [
        {
          path: "index.html",
          sha256: createHash("sha256").update("<main>locked</main>").digest("hex")
        }
      ]
    };
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

    await writeFile(manifestPath, JSON.stringify(manifest, null, 2), "utf8");
    await writeFile(signaturePath, sign(null, integrityManifestBytes(manifest), privateKey).toString("base64"), "utf8");

    await verifyBundledFileManifest({
      assetRoot,
      manifestPath,
      signaturePath,
      publicKeyPem
    });

    await writeFile(path.join(assetRoot, "index.html"), "<main>changed</main>", "utf8");
    await assert.rejects(
      verifyBundledFileManifest({
        assetRoot,
        manifestPath,
        signaturePath,
        publicKeyPem
      }),
      /integrity mismatch/
    );
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});

function loadAttributes(html) {
  return [...html.matchAll(/\s(?:src|href)="([^"]+)"/g)].map((match) => match[1]);
}
