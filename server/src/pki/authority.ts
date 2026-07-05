import { execFileSync } from "node:child_process";
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { canonicalBytes, sha256Hex, type CanonicalJson } from "@vorcaro/protocol";

export type IssueDeviceCertificateInput = {
  readonly executiveId: string;
  readonly deviceId: string;
  readonly publicKey: string;
  readonly challengeId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
};

export type IssuedDeviceCertificate = {
  readonly certificatePem: string;
  readonly certificateFingerprint: string;
  readonly expiresAt: string;
};

export type RevokeDeviceCertificateInput = {
  readonly deviceId: string;
  readonly certificateFingerprint: string;
  readonly revokedAt: string;
  readonly reason: string;
};

export type CertificateAuthority = {
  issueDeviceCertificate(input: IssueDeviceCertificateInput): IssuedDeviceCertificate;
  revokeDeviceCertificate(input: RevokeDeviceCertificateInput): void;
};

export type OpenSslCertificateAuthorityOptions = {
  readonly caKeyFile: string;
  readonly caCertFile: string;
  readonly revocationLogFile?: string;
};

export class LocalCertificateAuthority implements CertificateAuthority {
  issueDeviceCertificate(input: IssueDeviceCertificateInput): IssuedDeviceCertificate {
    const body = canonicalBytes(input as unknown as CanonicalJson).toString("base64");
    const certificatePem = [
      "-----BEGIN VORCARO LOCAL DEVICE CERTIFICATE-----",
      body,
      "-----END VORCARO LOCAL DEVICE CERTIFICATE-----"
    ].join("\n");

    return {
      certificatePem,
      certificateFingerprint: sha256Hex(certificatePem),
      expiresAt: input.expiresAt
    };
  }

  revokeDeviceCertificate(_input: RevokeDeviceCertificateInput): void {
    return;
  }
}

export class OpenSslCertificateAuthority implements CertificateAuthority {
  private readonly caKeyFile: string;
  private readonly caCertFile: string;
  private readonly revocationLogFile: string | undefined;

  constructor(options: OpenSslCertificateAuthorityOptions) {
    this.caKeyFile = options.caKeyFile;
    this.caCertFile = options.caCertFile;
    this.revocationLogFile = options.revocationLogFile;
  }

  issueDeviceCertificate(input: IssueDeviceCertificateInput): IssuedDeviceCertificate {
    OpenSslCertificateAuthority.assertSafeIdentifier(input.executiveId);
    OpenSslCertificateAuthority.assertSafeIdentifier(input.deviceId);
    const publicKeyDer = OpenSslCertificateAuthority.ed25519PublicKeyDer(input.publicKey);
    const directory = mkdtempSync(join(tmpdir(), "vorcaro-ca-"));
    const publicKeyDerFile = join(directory, "device-public.der");
    const publicKeyPemFile = join(directory, "device-public.pem");
    const requestKeyFile = join(directory, "request.key.pem");
    const requestFile = join(directory, "request.csr.pem");
    const extensionFile = join(directory, "device.ext");
    const certificateFile = join(directory, "device.cert.pem");

    try {
      writeFileSync(publicKeyDerFile, publicKeyDer, { mode: 0o600 });
      OpenSslCertificateAuthority.openssl([
        "pkey",
        "-pubin",
        "-inform",
        "DER",
        "-in",
        publicKeyDerFile,
        "-out",
        publicKeyPemFile
      ]);
      OpenSslCertificateAuthority.openssl([
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        requestKeyFile,
        "-out",
        requestFile,
        "-subj",
        `/O=Vorcaro Enterprises/CN=${input.deviceId}`
      ]);
      writeFileSync(
        extensionFile,
        [
          "basicConstraints = CA:FALSE",
          "keyUsage = digitalSignature",
          "extendedKeyUsage = clientAuth",
          `subjectAltName = URI:urn:vorcaro:device:${input.deviceId},URI:urn:vorcaro:executive:${input.executiveId}`
        ].join("\n"),
        { mode: 0o600 }
      );
      OpenSslCertificateAuthority.openssl([
        "x509",
        "-req",
        "-in",
        requestFile,
        "-force_pubkey",
        publicKeyPemFile,
        "-CA",
        this.caCertFile,
        "-CAkey",
        this.caKeyFile,
        "-set_serial",
        `0x${randomBytes(16).toString("hex")}`,
        "-out",
        certificateFile,
        "-days",
        String(OpenSslCertificateAuthority.certificateDays(input.issuedAt, input.expiresAt)),
        "-sha256",
        "-extfile",
        extensionFile
      ]);
      const certificatePem = readFileSync(certificateFile, "utf8");

      return {
        certificatePem,
        certificateFingerprint: OpenSslCertificateAuthority.fingerprint(certificateFile),
        expiresAt: input.expiresAt
      };
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }

  revokeDeviceCertificate(input: RevokeDeviceCertificateInput): void {
    if (this.revocationLogFile === undefined) {
      return;
    }

    appendFileSync(
      this.revocationLogFile,
      `${JSON.stringify({
        device_id: input.deviceId,
        certificate_fingerprint: input.certificateFingerprint,
        revoked_at: input.revokedAt,
        reason: input.reason
      })}\n`,
      { mode: 0o600 }
    );
  }

  static assertSafeIdentifier(value: string): void {
    if (!/^[A-Za-z0-9._:-]+$/.test(value)) {
      throw new TypeError("Certificate identifiers may contain only letters, numbers, dot, underscore, colon, and hyphen");
    }
  }

  static ed25519PublicKeyDer(publicKeyBase64: string): Buffer {
    const publicKey = Buffer.from(publicKeyBase64, "base64");

    if (publicKey.length !== 32) {
      throw new TypeError("Device public key must be a base64 Ed25519 public key");
    }

    return Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      publicKey
    ]);
  }

  static certificateDays(issuedAt: string, expiresAt: string): number {
    const milliseconds = Date.parse(expiresAt) - Date.parse(issuedAt);

    if (!Number.isFinite(milliseconds) || milliseconds <= 0) {
      return 1;
    }

    return Math.max(1, Math.ceil(milliseconds / 86_400_000));
  }

  static fingerprint(certificateFile: string): string {
    const output = OpenSslCertificateAuthority.openssl([
      "x509",
      "-in",
      certificateFile,
      "-noout",
      "-fingerprint",
      "-sha256"
    ]);
    const value = output.trim().split("=").at(1);

    if (value === undefined) {
      throw new Error("OpenSSL did not return a certificate fingerprint");
    }

    return value.replaceAll(":", "").toLowerCase();
  }

  static openssl(args: readonly string[]): string {
    return execFileSync("openssl", [...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
  }
}
