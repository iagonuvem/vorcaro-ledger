# How To Enroll A Device

This guide explains how an executive device gets its first Vorcaro mTLS
certificate.

Enrollment is the one intentional exception to normal device mTLS: the device
does not have a certificate yet, so `/v1/enroll/begin` and
`/v1/enroll/complete` are reachable before device identity exists. The flow is
still guarded by a one-time admin-issued token, device proof-of-possession, and
an executive-signed `DEVICE_ENROLLED` ledger event.

## What Enrollment Creates

Successful enrollment creates:

- a `devices` row bound to the executive
- a client certificate fingerprint stored in `devices.certificate_fingerprint`
- an accepted append-only `DEVICE_ENROLLED` ledger event
- a signed server acknowledgement
- a device certificate PEM returned to the client

The server never accepts identity from headers. After enrollment, the device is
identified by the mTLS peer certificate fingerprint on the socket.

## Prerequisites

- The server is running.
- The executive already exists in `executives` and `executive_keys`.
- The admin API is reachable with an admin client certificate.
- The device has generated an Ed25519 keypair and can sign bytes locally.
- The executive client can sign a `DEVICE_ENROLLED` event with the executive
  signing key.

For adding the executive key first, see
[How To Add An Executive Key](HOW_TO_ADD_EXECUTIVE.md).

## 1. Issue A One-Time Enrollment Token

Call the admin API:

```bash
curl --cert /etc/vorcaro/certs/bootstrap-admin-client.cert.pem \
     --key /etc/vorcaro/certs/bootstrap-admin-client.key.pem \
     --cacert /etc/vorcaro/certs/root-ca.pem \
     -H "content-type: application/json" \
     -d '{
       "executive_id": "exec_new_cfo",
       "issued_by": "admin",
       "ttl_minutes": 30
     }' \
     https://localhost:9443/admin/v1/enrollment-tokens
```

On macOS, use `/private/etc/...` paths if needed.

The response includes the only plaintext copy of the token:

```json
{
  "enrollment_token": {
    "token": "one-time-secret-token",
    "tokenHash": "sha256:...",
    "expiresAt": "2026-07-05T15:30:00.000Z"
  }
}
```

Send `token` to the executive out-of-band. Do not store it in tickets, logs, or
chat history. The database stores only `tokenHash`.

## 2. Begin Enrollment From The Device

The device sends the token, its stable device id, and its Ed25519 public key to
the device API:

```bash
curl -k \
     -H "content-type: application/json" \
     -d '{
       "token": "one-time-secret-token",
       "device_id": "dev_cfo_laptop_1",
       "public_key": "DEVICE_PUBLIC_KEY_BASE64"
     }' \
     https://localhost:8443/v1/enroll/begin
```

The response contains a signed enrollment challenge:

```json
{
  "body": {
    "challengeId": "enr_...",
    "challenge": "...",
    "expiresAt": "..."
  },
  "signature": "..."
}
```

The `-k` flag is only for this bootstrap call if the local root CA is not
trusted by the command-line environment. Prefer `--cacert` when the root CA is
available.

## 3. Sign The Device Proof

The device signs the canonical bytes of:

```json
{
  "challenge_id": "enr_...",
  "challenge": "...",
  "device_id": "dev_cfo_laptop_1",
  "public_key": "DEVICE_PUBLIC_KEY_BASE64"
}
```

The signature is `proof_signature`. It proves the device controls the private
key for the public key submitted in step 2.

## 4. Submit The Executive-Signed Enrollment Event

The client creates and signs a `DEVICE_ENROLLED` event with the executive
signing key. The event must match the challenge:

```text
event_type: DEVICE_ENROLLED
actor_id:   executive id from the token
device_id:  device id from the challenge
object_type: device
object_id:   device id from the challenge
```

Then call:

```bash
curl -k \
     -H "content-type: application/json" \
     -d '{
       "token": "one-time-secret-token",
       "challenge_id": "enr_...",
       "proof_signature": "DEVICE_PROOF_SIGNATURE_BASE64",
       "hardware_backed": true,
       "enrollment_event": {
         "event_id": "evt_...",
         "event_type": "DEVICE_ENROLLED",
         "actor_id": "exec_new_cfo",
         "device_id": "dev_cfo_laptop_1",
         "device_event_counter": "1",
         "base_server_sequence": "0",
         "object_type": "device",
         "object_id": "dev_cfo_laptop_1",
         "policy_metadata": {},
         "encrypted_payload": "BASE64_PAYLOAD",
         "payload_hash": "sha256:...",
         "client_signature": "EXECUTIVE_SIGNATURE_BASE64",
         "client_timestamp": "2026-07-05T15:00:00.000Z"
       }
     }' \
     https://localhost:8443/v1/enroll/complete
```

The response contains:

- `certificate.certificatePem`
- `certificate.certificateFingerprint`
- `acknowledgement`

The client stores the certificate with the matching private key and uses it for
all future mTLS calls.

## 5. Verify The Device

From the admin API:

```bash
curl --cert /etc/vorcaro/certs/bootstrap-admin-client.cert.pem \
     --key /etc/vorcaro/certs/bootstrap-admin-client.key.pem \
     --cacert /etc/vorcaro/certs/root-ca.pem \
     https://localhost:9443/admin/v1/devices
```

The enrolled device should appear with:

```text
status: enrolled
hardware_backed: true
certificate_fingerprint: matches the enrollment response
```

## Common Failures

`POLICY_DENIED` during begin enrollment

The token is expired or already consumed. Issue a new one-time token.

`CERT_UNKNOWN` during begin or complete enrollment

The token or challenge id is wrong, or the challenge does not belong to that
token.

`BAD_SIGNATURE` during complete enrollment

Either the device proof signature does not match the submitted device public key,
or the `DEVICE_ENROLLED` event was not signed by the executive key registered in
`executive_keys`.

`BAD_PAYLOAD_HASH`

The event payload hash must equal the protocol `payloadHash(encrypted_payload)`.

TLS fails after successful enrollment

The client must use the returned certificate with the same private key whose
public key was submitted during enrollment. The server matches the mTLS
certificate fingerprint against the `devices` table.

## Safety Notes

- One token enrolls one device.
- Do not reuse tokens.
- Do not send private keys to the server.
- Do not trust identity-shaped HTTP headers.
- Revocation is forward-only: accepted historical events remain valid.
