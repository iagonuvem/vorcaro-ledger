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
