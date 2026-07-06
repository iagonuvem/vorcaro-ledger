import { flipFuses, FuseVersion, FuseV1Options } from "@electron/fuses";

const electronBinaryPath = process.argv[2];

if (!electronBinaryPath) {
  throw new Error("Usage: pnpm fuses:apply <packaged Electron binary path>");
}

await flipFuses(electronBinaryPath, {
  version: FuseVersion.V1,
  [FuseV1Options.RunAsNode]: false,
  [FuseV1Options.EnableCookieEncryption]: true,
  [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
  [FuseV1Options.EnableNodeCliInspectArguments]: false,
  [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
  [FuseV1Options.OnlyLoadAppFromAsar]: true
});
