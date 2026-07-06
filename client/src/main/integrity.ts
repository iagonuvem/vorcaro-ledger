import { createHash, verify as verifySignature } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { canonicalBytes, type CanonicalJson } from "@vorcaro/protocol";
import { z } from "zod";

const manifestFileSchema = z
  .object({
    path: z.string().min(1),
    sha256: z.string().regex(/^[0-9a-f]{64}$/)
  })
  .strict();

const integrityManifestSchema = z
  .object({
    version: z.literal(1),
    files: z.array(manifestFileSchema).min(1)
  })
  .strict();

export type IntegrityManifest = z.infer<typeof integrityManifestSchema>;

export type IntegrityVerificationInput = {
  assetRoot: string;
  manifestPath: string;
  signaturePath: string;
  publicKeyPem: string;
};

export const VORCARO_RELEASE_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAaK3QxTdzGQqtG7t4w4uSvMT4CUnqv0daRIr0TgXjkhU=
-----END PUBLIC KEY-----`;

export function integrityManifestBytes(manifest: IntegrityManifest): Buffer {
  return canonicalBytes(manifest as CanonicalJson);
}

export async function verifyBundledFileManifest(input: IntegrityVerificationInput): Promise<void> {
  const manifest = integrityManifestSchema.parse(JSON.parse(await readFile(input.manifestPath, "utf8")));
  const signature = Buffer.from((await readFile(input.signaturePath, "utf8")).trim(), "base64");
  const verifiedSignature = verifySignature(null, integrityManifestBytes(manifest), input.publicKeyPem, signature);

  if (!verifiedSignature) {
    throw new Error("Application integrity manifest signature is invalid");
  }

  const expected = new Map(manifest.files.map((file) => [file.path, file.sha256]));
  const actual = new Map<string, string>();

  for (const filePath of await listFiles(input.assetRoot)) {
    const relativePath = path.relative(input.assetRoot, filePath).split(path.sep).join("/");
    actual.set(relativePath, await sha256File(filePath));
  }

  const expectedPaths = [...expected.keys()].sort();
  const actualPaths = [...actual.keys()].sort();

  if (expectedPaths.join("\n") !== actualPaths.join("\n")) {
    throw new Error("Application integrity manifest file list does not match bundled assets");
  }

  for (const [filePath, expectedHash] of expected) {
    if (actual.get(filePath) !== expectedHash) {
      throw new Error(`Application integrity mismatch for ${filePath}`);
    }
  }
}

async function listFiles(root: string): Promise<string[]> {
  const entries = await readdir(root);
  const files: string[] = [];

  for (const entry of entries) {
    const fullPath = path.join(root, entry);
    const entryStat = await stat(fullPath);

    if (entryStat.isDirectory()) {
      files.push(...(await listFiles(fullPath)));
    } else if (entryStat.isFile()) {
      files.push(fullPath);
    }
  }

  return files.sort((left, right) => left.localeCompare(right));
}

async function sha256File(filePath: string): Promise<string> {
  const bytes = await readFile(filePath);
  return createHash("sha256").update(bytes).digest("hex");
}
