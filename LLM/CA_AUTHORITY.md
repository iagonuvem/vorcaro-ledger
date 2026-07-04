# Vorcaro Certificate Authority

This document describes how the Vorcaro server certificate authority works for
the Sovereign Finance Ledger. It complements `PLAN.md`,
`SERVER_IMPLEMENTATION_PLAN.md`, `APP_IMPLEMENTATION_PLAN.md`, and
`DATABASE_OVERVIEW.md`. Where documents disagree, `PLAN.md` wins.

## 1. Purpose

The Vorcaro CA is the root of device and admin transport identity. It answers one
question before any ledger API request is trusted:

> Is this TLS peer a currently enrolled Vorcaro device or admin identity?

Application identity never comes from headers, JSON bodies, query parameters, or
cookies. Device identity comes from the mTLS peer certificate, then the server
binds the certificate fingerprint to `devices.certificate_fingerprint` in
`ledger.db`.

## 2. Authority Hierarchy

Production uses Vorcaro-owned `step-ca` infrastructure:

- Offline root CA: air-gapped, powered off except for planned intermediate
  signing ceremonies.
- Device intermediate CA: online, issues short-lived device certificates for the
  device listener on port `8443`.
- Admin intermediate CA: online, separate from the device intermediate, issues
  admin certificates for the admin listener on port `9443`.

The server listeners trust only the matching Vorcaro intermediate and enforce:

- TLS 1.3 minimum.
- `requestCert: true`.
- `rejectUnauthorized: true`.
- No bearer-token or cookie fallback for device APIs.

## 3. Device Enrollment Flow

Enrollment is the only planned pre-certificate exception on the device listener.
It is still not anonymous trust.

1. An admin creates a one-time enrollment token for an executive. The server
   stores only `sha256:<hex>` in `enrollment_tokens`; the plaintext token is
   shown once out of band.
2. The device generates a device-binding keypair locally, hardware-backed where
   available.
3. `POST /v1/enroll/begin` receives the token, intended `device_id`, and device
   public key. If the token is valid and unused, the server stores a short-lived
   challenge in `enrollment_challenges`.
4. The device signs canonical bytes of `{challenge_id, challenge, device_id,
   public_key}` with the device-binding key.
5. `POST /v1/enroll/complete` verifies the token, challenge, proof signature,
   and an executive-signed `DEVICE_ENROLLED` ledger event.
6. The CA issues a device certificate bound to the executive, device id, and
   public key.
7. The server stores the device row, appends the accepted `DEVICE_ENROLLED`
   event, consumes the token/challenge, and writes audit evidence in one
   transaction.

The current code exposes a `CertificateAuthority` adapter. Production backs it
with `step-ca`; tests use `LocalCertificateAuthority`, which produces deterministic
local certificate material without claiming production trust.

## 4. Runtime Authentication

After enrollment, normal device API requests require mTLS. The request pipeline is:

1. TLS handshake validates chain, expiry, and revocation state.
2. Express identity middleware reads the peer certificate fingerprint from the
   socket.
3. The fingerprint is matched to an enrolled device row.
4. The bound executive is loaded and must be active.
5. Any identity-shaped headers such as `X-Device-*` are ignored and audited.

Closed error-code mapping:

- Unknown or missing certificate: `CERT_UNKNOWN`.
- Revoked or quarantined device certificate: `CERT_REVOKED`.
- Inactive executive: `EXECUTIVE_INACTIVE`.

## 5. Certificate Lifetime and Renewal

Device certificates are short-lived: seven days by default. Renewal must happen
over existing mTLS and must be refused for revoked or quarantined devices. This
keeps revocation convergence bounded even if a client misses a revocation-list
sync window.

Renewal is not a bypass around ledger identity. A renewed certificate must keep
the same database binding discipline: certificate fingerprint to device row,
device row to executive, executive status checked before route handlers.

## 6. Revocation Flow

Revocation is forward-only.

1. Admin action selects a device to revoke.
2. The server asks the CA adapter to revoke the certificate.
3. The device row moves to `status = 'revoked'` with `revoked_at`.
4. A new signed `RevocationList` document is appended to
   `revocation_list_versions`.
5. Clients pull the latest revocation list on sync and apply local quarantine or
   wipe behavior as policy requires.

Previously accepted events remain valid. Verification always uses the key
version whose authority window covered the event sequence. Revocation blocks
future authority; it does not rewrite history.

## 7. Server Code Boundaries

The CA implementation boundary is deliberately small:

- `server/src/pki/authority.ts`: CA adapter interface and local test adapter.
- `server/src/pki/enrollment.ts`: token issuance, challenge flow, proof
  verification, device materialization, `DEVICE_ENROLLED` append, and revocation
  list creation.
- `server/src/api/identity.ts`: mTLS peer-certificate fingerprint binding.
- `server/src/api/listeners.ts`: TLS listener hardening.

The protocol package remains pure and contains no CA I/O.

## 8. Operational Rules

- Root CA private material is never online during normal operation.
- Online intermediates are Vorcaro-owned and run inside the internal server
  network, not as public dependencies.
- Tokens are one-time, short-lived, and stored only as hashes.
- Challenges are short-lived and consumed on successful enrollment.
- Certificate private keys never enter the server.
- No plaintext token, private key, HSM PIN, or certificate private part is logged.
- Revocation lists are signed server responses and are served on every sync path.

## 9. Current Implementation Status

Implemented baseline:

- One-time enrollment token hashing and storage.
- Enrollment challenge issuance.
- Device possession proof verification.
- Executive-signed `DEVICE_ENROLLED` event validation and append.
- Device materialization with certificate fingerprint binding.
- Revocation-list versioning and server signatures.
- Local CA adapter for deterministic tests.

Deferred to later planned work:

- Real `step-ca` client integration.
- Certificate renewal endpoint.
- Admin console screens and multi-party approval UX.
- Recovery ceremony integration with key rotation and re-wraps.
- Wipe directives and client-side local quarantine behavior.
