# How To Add An Executive Key

This guide explains how to register a new executive signing key in the current
Vorcaro server baseline.

An executive key is not a password and not an admin user. It is the Ed25519
public key the server uses to verify signed ledger events from that executive.
The private key must stay on the executive device or in the client vault. The
server stores only the public key.

## Current Status

The current server runtime can read executives from `ledger.db` and can verify
events against `executive_keys`. It does not yet expose a polished admin API for
creating executives in production. Until that flow exists, adding an executive
is an operator bootstrap ceremony:

1. Generate or collect the executive public key.
2. Stop the server.
3. Back up `ledger.db`.
4. Insert the executive row and the first key-version row in one transaction.
5. Restart the server.
6. Verify the executive appears in the admin API.

Do not use this procedure for key recovery or key rotation. Rotating an existing
executive key must go through the recovery ceremony path so the old key window
is closed forward-only and ledger evidence is appended.

## Roles

Choose one role from the server schema:

```text
CEO
CFO
COO
TREASURER
GENERAL_COUNSEL
INTERNAL_AUDIT
SECURITY_RECOVERY_OFFICER
FINANCE_CONTROLLER
```

## 1. Get The Public Key

Preferred production shape:

- Generate the private key on the executive device.
- Export only the public key to the server operator.
- Never copy the private key into the server, shell history, logs, chat, or
  tickets.

For a local drill only, after `pnpm build`, a keypair can be generated from the
protocol package:

```bash
node --input-type=module <<'NODE'
import { generateSigningKeyPair } from "./packages/protocol/dist/src/index.js";

const keys = generateSigningKeyPair();
console.log(JSON.stringify(keys, null, 2));
NODE
```

Give the `secretKey` only to the executive client/vault. Put only `publicKey` in
the server database.

## 2. Stop The Server

Stop the container before editing the identity tables:

```bash
docker compose down
```

## 3. Back Up The Ledger Database

On Linux:

```bash
sudo cp /var/lib/vorcaro/ledger.db /var/lib/vorcaro/backups/ledger.before-executive.$(date -u +%Y%m%dT%H%M%SZ).db
```

On macOS with the standard Compose mounts:

```bash
sudo cp /private/var/lib/vorcaro/ledger.db /private/var/lib/vorcaro/backups/ledger.before-executive.$(date -u +%Y%m%dT%H%M%SZ).db
```

## 4. Insert The Executive And Key

Use one transaction. Replace the example values before running it:

- `exec_new_cfo` with the stable executive id.
- `Vorcaro CFO` with the display name.
- `CFO` with the chosen role.
- `PASTE_PUBLIC_KEY_BASE64_HERE` with the executive public key.

On Linux:

```bash
sudo sqlite3 /var/lib/vorcaro/ledger.db <<'SQL'
BEGIN IMMEDIATE;

INSERT INTO executives (
  id, display_name, role, status, signing_public_key, key_version, created_at
) VALUES (
  'exec_new_cfo',
  'Vorcaro CFO',
  'CFO',
  'active',
  'PASTE_PUBLIC_KEY_BASE64_HERE',
  1,
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

INSERT INTO executive_keys (
  executive_id, key_version, signing_public_key, valid_from_sequence, valid_until_sequence
) VALUES (
  'exec_new_cfo',
  1,
  'PASTE_PUBLIC_KEY_BASE64_HERE',
  COALESCE((SELECT MAX(server_sequence) FROM ledger_events), 0),
  NULL
);

COMMIT;
SQL
```

On macOS, use the real host path:

```bash
sudo sqlite3 /private/var/lib/vorcaro/ledger.db <<'SQL'
BEGIN IMMEDIATE;

INSERT INTO executives (
  id, display_name, role, status, signing_public_key, key_version, created_at
) VALUES (
  'exec_new_cfo',
  'Vorcaro CFO',
  'CFO',
  'active',
  'PASTE_PUBLIC_KEY_BASE64_HERE',
  1,
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

INSERT INTO executive_keys (
  executive_id, key_version, signing_public_key, valid_from_sequence, valid_until_sequence
) VALUES (
  'exec_new_cfo',
  1,
  'PASTE_PUBLIC_KEY_BASE64_HERE',
  COALESCE((SELECT MAX(server_sequence) FROM ledger_events), 0),
  NULL
);

COMMIT;
SQL
```

If `sqlite3` is not installed, install it with your OS package manager. Do not
edit the database with a GUI tool that might issue automatic updates or schema
changes.

## 5. Restore File Permissions

Linux:

```bash
sudo chown -R 10001:10001 /var/lib/vorcaro
sudo find /var/lib/vorcaro -type d -exec chmod 0750 {} \;
sudo find /var/lib/vorcaro -type f -exec chmod 0600 {} \;
```

macOS with Docker Desktop:

```bash
HOST_GROUP="$(id -gn)"

sudo chown -R 10001:"$HOST_GROUP" /private/var/lib/vorcaro
sudo find /private/var/lib/vorcaro -type d -exec chmod 0770 {} \;
sudo find /private/var/lib/vorcaro -type f -exec chmod 0660 {} \;
```

## 6. Restart And Verify

Start the server:

```bash
docker compose up -d
```

Verify the executive is visible through the admin API:

```bash
curl --cert /etc/vorcaro/certs/bootstrap-admin-client.cert.pem \
     --key /etc/vorcaro/certs/bootstrap-admin-client.key.pem \
     --cacert /etc/vorcaro/certs/root-ca.pem \
     https://localhost:9443/admin/v1/executives
```

On macOS:

```bash
curl --cert /private/etc/vorcaro/certs/bootstrap-admin-client.cert.pem \
     --key /private/etc/vorcaro/certs/bootstrap-admin-client.key.pem \
     --cacert /private/etc/vorcaro/certs/root-ca.pem \
     https://localhost:9443/admin/v1/executives
```

You should see the new executive with:

```text
status: active
key_version: 1
```

## 7. Enroll A Device Later

Registering the executive key does not enroll a device by itself. Devices still
need certificate enrollment before they can submit events over mTLS.

The Docker runtime wires the PKI service to the mounted device-client CA, so an
admin can issue a one-time enrollment token and the executive device can use
`/v1/enroll/begin` and `/v1/enroll/complete`.

See [How To Enroll A Device](HOW_TO_ENROLL_DEVICE.md).

## Safety Checklist

- Never put an executive private key in the server.
- Never overwrite an existing `executive_keys` row.
- Never use this procedure to rotate a compromised or lost key.
- Always stop the server before manual identity-table changes.
- Always back up `ledger.db` before the change.
- Always verify through `/admin/v1/executives` after restart.
