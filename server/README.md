# Vorcaro Server

This package is the Vorcaro finance server. It owns the append-only ledger
database, rebuildable projections, device mTLS API, admin mTLS API, policy
activation surface, and the static admin console runtime hook.

Detailed operator guides live in [server/docs](docs).
Start with [How To Add An Executive Key](docs/HOW_TO_ADD_EXECUTIVE.md)
when adding an executive signing key to the server, and
[How To Enroll A Device](docs/HOW_TO_ENROLL_DEVICE.md) when enrolling an
executive device.

The normal deployment shape is:

```text
root bootstrap once -> durable host files -> non-root Docker container
```

The container is disposable. The data, certificates, and secrets under the host
paths below are the durable system.

## Prerequisites

- Node.js 22 or newer.
- pnpm 10 or newer.
- Docker with Compose v2 support.
- `openssl` on the host that runs the first-time bootstrap.
- Root access for the first-time host bootstrap.

To install the required host packages on a supported Linux distribution:

```bash
sudo server/setup.sh
```

`server/setup.sh` also prepares the default Docker-mounted host directories:
`/var/lib/vorcaro`, `/etc/vorcaro/certs`, and `/etc/vorcaro/secrets`.
`server/bootstrap.sh` runs `server/setup.sh` automatically if `openssl`,
Node.js, pnpm, Docker, or Docker Compose v2 is missing. macOS package
installation is not automated from the root setup script; install Node.js 22,
pnpm 10, OpenSSL, and Docker Desktop first.

Install and build the workspace before running the bootstrap if you want the
SQLite files initialized before the container starts:

```bash
pnpm install
pnpm build
```

If `server/dist` is not present, `server/bootstrap.sh` still creates the host
directories, certificates, and signing key. The first container start will then
create the SQLite files.

## Host Layout

Default durable paths:

```text
/var/lib/vorcaro/          ledger.db, projections.db, backups/, lock
/etc/vorcaro/certs/       server certs, CA certs, bootstrap client certs
/etc/vorcaro/secrets/     server signing key file
```

The Docker runtime user is UID/GID `10001:10001`. The bootstrap script creates
the directories for that runtime identity and locks file modes down after
generation.

## First-Time Bootstrap

Run this once from the repository root on the host that will run Docker:

```bash
sudo server/bootstrap.sh
```

The script creates:

```text
/var/lib/vorcaro
/var/lib/vorcaro/backups
/etc/vorcaro/certs/root-ca.key.pem
/etc/vorcaro/certs/root-ca.pem
/etc/vorcaro/certs/device-client-ca.key.pem
/etc/vorcaro/certs/device-client-ca.pem
/etc/vorcaro/certs/admin-client-ca.key.pem
/etc/vorcaro/certs/admin-client-ca.pem
/etc/vorcaro/certs/device-server.key.pem
/etc/vorcaro/certs/device-server.cert.pem
/etc/vorcaro/certs/admin-server.key.pem
/etc/vorcaro/certs/admin-server.cert.pem
/etc/vorcaro/certs/bootstrap-device-client.key.pem
/etc/vorcaro/certs/bootstrap-device-client.cert.pem
/etc/vorcaro/certs/bootstrap-admin-client.key.pem
/etc/vorcaro/certs/bootstrap-admin-client.cert.pem
/etc/vorcaro/certs/healthcheck-client.key.pem
/etc/vorcaro/certs/healthcheck-client.cert.pem
/etc/vorcaro/secrets/server-signing.key
```

If the built server database module exists, it also initializes:

```text
/var/lib/vorcaro/ledger.db
/var/lib/vorcaro/projections.db
```

Existing files are preserved by default. To intentionally regenerate bootstrap
certificates and the server signing key:

```bash
sudo VORCARO_FORCE=1 server/bootstrap.sh
```

Do not use `VORCARO_FORCE=1` against an established ledger unless you have an
operator recovery plan. Regenerating signing and certificate material can strand
existing clients.

## Bootstrap Variables

`server/bootstrap.sh` accepts these environment overrides:

```text
VORCARO_DATA_DIR       default /var/lib/vorcaro
VORCARO_CERT_DIR       default /etc/vorcaro/certs
VORCARO_SECRET_DIR     default /etc/vorcaro/secrets
VORCARO_SERVICE_UID    default 10001
VORCARO_SERVICE_GID    default 10001
VORCARO_CERT_DAYS      default 825
VORCARO_CA_DAYS        default 3650
VORCARO_FORCE          default 0
```

Use non-default paths only when you also update the Docker Compose volume mounts
and runtime environment.

## Run With Docker Compose

After bootstrap:

```bash
docker compose up -d
```

The compose service:

- runs as UID/GID `10001:10001`
- uses a read-only root filesystem
- drops Linux capabilities
- mounts `/var/lib/vorcaro` read-write
- mounts `/etc/vorcaro/certs` read-only
- mounts `/etc/vorcaro/secrets` read-only
- publishes device API port `8443`
- publishes admin API port `9443`

Useful commands:

```bash
docker compose ps
docker compose logs -f ledger-server
docker compose restart ledger-server
docker compose down
```

To rebuild the local image after code changes:

```bash
docker compose build ledger-server
docker compose up -d
```

## Run On macOS

Docker Desktop on macOS can run the standard Linux-oriented Compose file, but
its bind-mount layer maps system paths through `/private`:

```text
/var/lib/vorcaro      -> /private/var/lib/vorcaro
/etc/vorcaro/certs   -> /private/etc/vorcaro/certs
/etc/vorcaro/secrets -> /private/etc/vorcaro/secrets
```

The directories must exist on the macOS host, Docker Desktop must be allowed to
share them, and the directory execute bit must stay enabled. On directories,
`x` means "can traverse/search this path"; without it Docker Desktop cannot
reach the bind-mount source.

1. Open Docker Desktop and verify file sharing.

   Go to `Settings` -> `Resources` -> `File sharing`. The default Docker
   Desktop list usually includes `/private`. If it does not, add:

   ```text
   /private
   ```

   Apply and restart Docker Desktop after changing this setting.

2. Build the workspace once.

   ```bash
   pnpm install
   pnpm build
   ```

3. Prepare the host directories and bootstrap the server.

   ```bash
   sudo server/setup.sh
   sudo server/bootstrap.sh
   ```

   On macOS, `server/setup.sh` prepares the host directories but does not
   install Docker Desktop, Node.js, pnpm, or OpenSSL. Install those separately
   if any are missing.

4. Fix the macOS bind-mount permissions after bootstrap.

   This is the important macOS permission step. Linux only needs the container
   UID/GID `10001:10001`, but Docker Desktop also writes through your macOS
   host group. Keep UID `10001` as owner and give your macOS group write access
   to the data directory:

   ```bash
   HOST_GROUP="$(id -gn)"

   sudo chown -R 10001:"$HOST_GROUP" /private/var/lib/vorcaro
   sudo find /private/var/lib/vorcaro -type d -exec chmod 0770 {} \;
   sudo find /private/var/lib/vorcaro -type f -exec chmod 0660 {} \;

   sudo chown -R 10001:"$HOST_GROUP" /private/etc/vorcaro
   sudo chmod 0750 /private/etc/vorcaro /private/etc/vorcaro/certs /private/etc/vorcaro/secrets
   sudo find /private/etc/vorcaro/certs -type f -exec chmod 0640 {} \;
   sudo find /private/etc/vorcaro/secrets -type f -exec chmod 0640 {} \;
   ```

   Verify the data directory shows group write, usually `drwxrwx---`:

   ```bash
   ls -ld /private/etc/vorcaro \
          /private/etc/vorcaro/certs \
          /private/etc/vorcaro/secrets \
          /private/var/lib/vorcaro
   ```

5. Start the container.

   ```bash
   docker compose up -d
   ```

6. Probe the admin API.

   ```bash
   curl --cert /etc/vorcaro/certs/bootstrap-admin-client.cert.pem \
        --key /etc/vorcaro/certs/bootstrap-admin-client.key.pem \
        --cacert /etc/vorcaro/certs/root-ca.pem \
        https://localhost:9443/admin/v1/status
   ```

If Docker Desktop still reports a `/host_mnt/private/... permission denied`
error after the group-write fix, grant your macOS user explicit ACL access to
traverse the bind-mount sources:

```bash
sudo chmod +a "$(whoami) allow list,search,readattr,readextattr,readsecurity" /private/etc/vorcaro
sudo chmod +a "$(whoami) allow list,search,readattr,readextattr,readsecurity" /private/etc/vorcaro/certs
sudo chmod +a "$(whoami) allow list,search,readattr,readextattr,readsecurity" /private/etc/vorcaro/secrets
sudo chmod +a "$(whoami) allow list,search,readattr,readextattr,readsecurity" /private/var/lib/vorcaro
```

Then restart Docker Desktop and run:

```bash
docker compose up -d
```

For local-only macOS development, project-local mounts under `/Users` are also
valid, but then `docker-compose.yml` and the `VORCARO_*` bootstrap paths must
be changed together. For the standard Compose file, keep the default `/var` and
`/etc` paths and use the steps above.

## Runtime Environment

The server reads these variables at startup:

```text
VORCARO_DATA_DIR                         default /var/lib/vorcaro
VORCARO_CERT_DIR                         default /etc/vorcaro/certs
VORCARO_SECRET_DIR                       default /etc/vorcaro/secrets
VORCARO_DEVICE_PORT                      default 8443
VORCARO_ADMIN_PORT                       default 9443
VORCARO_HOST                             default 0.0.0.0
VORCARO_ADMIN_UI_PATH                    default /app/admin-ui
VORCARO_SERVER_SIGNING_SECRET_KEY_FILE   default $VORCARO_SECRET_DIR/server-signing.key
VORCARO_DEVICE_SERVER_KEY_FILE           default $VORCARO_CERT_DIR/device-server.key.pem
VORCARO_DEVICE_SERVER_CERT_FILE          default $VORCARO_CERT_DIR/device-server.cert.pem
VORCARO_DEVICE_CLIENT_CA_FILE            default $VORCARO_CERT_DIR/device-client-ca.pem
VORCARO_DEVICE_CLIENT_CA_KEY_FILE        default $VORCARO_CERT_DIR/device-client-ca.key.pem
VORCARO_ADMIN_SERVER_KEY_FILE            default $VORCARO_CERT_DIR/admin-server.key.pem
VORCARO_ADMIN_SERVER_CERT_FILE           default $VORCARO_CERT_DIR/admin-server.cert.pem
VORCARO_ADMIN_CLIENT_CA_FILE             default $VORCARO_CERT_DIR/admin-client-ca.pem
VORCARO_CA_REVOCATION_LOG_FILE           default $VORCARO_DATA_DIR/device-ca-revocations.log
VORCARO_DEVICE_CERTIFICATE_LIFETIME_DAYS default 7
VORCARO_ENROLLMENT_CHALLENGE_LIFETIME_MINUTES default 10
```

The default Compose file already supplies the durable path variables.
The device enrollment routes use the mounted device-client CA key and cert to
issue short-lived client certificates.

## Verify The Server

After `docker compose up -d`, check container status:

```bash
docker compose ps
```

Probe the admin status endpoint with the bootstrap admin client certificate:

```bash
curl --cert /etc/vorcaro/certs/bootstrap-admin-client.cert.pem \
     --key /etc/vorcaro/certs/bootstrap-admin-client.key.pem \
     --cacert /etc/vorcaro/certs/root-ca.pem \
     https://localhost:9443/admin/v1/status
```

The admin surface requires mTLS. Requests without a trusted admin client
certificate should fail at TLS authentication.

The container healthcheck runs `node /app/server/dist/healthcheck.js`. By
default it verifies that the database files and runtime lock are accessible.
If these variables are set, it performs an mTLS HTTPS check instead:

```text
VORCARO_HEALTHCHECK_CLIENT_CERT_FILE
VORCARO_HEALTHCHECK_CLIENT_KEY_FILE
VORCARO_HEALTHCHECK_CA_FILE
VORCARO_HEALTHCHECK_HOST                 default localhost
```

## Access The Admin UI

The admin UI is served by the admin mTLS listener:

```text
https://localhost:9443/
```

It is not a public HTTPS site. The browser must trust the local Vorcaro root CA
and present an admin client certificate. A plain request like this is expected
to fail:

```bash
curl https://localhost:9443/admin/v1/status
```

For command-line access, provide both the bootstrap admin client certificate and
the local root CA:

```bash
curl --cert /etc/vorcaro/certs/bootstrap-admin-client.cert.pem \
     --key /etc/vorcaro/certs/bootstrap-admin-client.key.pem \
     --cacert /etc/vorcaro/certs/root-ca.pem \
     https://localhost:9443/admin/v1/status
```

On macOS, use the `/private` paths if needed:

```bash
curl --cert /private/etc/vorcaro/certs/bootstrap-admin-client.cert.pem \
     --key /private/etc/vorcaro/certs/bootstrap-admin-client.key.pem \
     --cacert /private/etc/vorcaro/certs/root-ca.pem \
     https://localhost:9443/admin/v1/status
```

For browser access on macOS:

1. Trust the local root CA.

   ```bash
   sudo security add-trusted-cert \
     -d \
     -r trustRoot \
     -k /Library/Keychains/System.keychain \
     /private/etc/vorcaro/certs/root-ca.pem
   ```

2. Convert the bootstrap admin client certificate to PKCS#12 for Keychain
   import.

   ```bash
   sudo openssl pkcs12 \
     -export \
     -legacy \
     -in /private/etc/vorcaro/certs/bootstrap-admin-client.cert.pem \
     -inkey /private/etc/vorcaro/certs/bootstrap-admin-client.key.pem \
     -certfile /private/etc/vorcaro/certs/admin-client-ca.pem \
     -out /tmp/vorcaro-admin-client.p12 \
     -name "Vorcaro Bootstrap Admin"

   sudo chown "$(id -u):$(id -g)" /tmp/vorcaro-admin-client.p12
   ```

3. Import the PKCS#12 file into Keychain Access.

   ```bash
   open /tmp/vorcaro-admin-client.p12
   ```

4. Open the admin UI.

   ```text
   https://localhost:9443/
   ```

5. Delete the temporary PKCS#12 file after import.

   ```bash
   rm /tmp/vorcaro-admin-client.p12
   ```

When the browser prompts for a certificate, choose `Vorcaro Bootstrap Admin`.

## Run Locally Without Docker

Local execution is useful for development only. It still needs certificate and
secret files.

Create a private local runtime directory:

```bash
mkdir -p /tmp/vorcaro-local/data /tmp/vorcaro-local/certs /tmp/vorcaro-local/secrets
sudo VORCARO_DATA_DIR=/tmp/vorcaro-local/data \
     VORCARO_CERT_DIR=/tmp/vorcaro-local/certs \
     VORCARO_SECRET_DIR=/tmp/vorcaro-local/secrets \
     VORCARO_SERVICE_UID="$(id -u)" \
     VORCARO_SERVICE_GID="$(id -g)" \
     server/bootstrap.sh
```

Then run:

```bash
VORCARO_DATA_DIR=/tmp/vorcaro-local/data \
VORCARO_CERT_DIR=/tmp/vorcaro-local/certs \
VORCARO_SECRET_DIR=/tmp/vorcaro-local/secrets \
VORCARO_ADMIN_UI_PATH=../admin-ui \
pnpm --filter @vorcaro/server start
```

For the local admin status probe, use the same overridden cert paths:

```bash
curl --cert /tmp/vorcaro-local/certs/bootstrap-admin-client.cert.pem \
     --key /tmp/vorcaro-local/certs/bootstrap-admin-client.key.pem \
     --cacert /tmp/vorcaro-local/certs/root-ca.pem \
     https://localhost:9443/admin/v1/status
```

## Development Gates

Before reporting server work complete:

```bash
pnpm build
pnpm test
pnpm lint
```

The protocol golden-byte tests are release gates. Do not skip them.

## Operational Rules

- Do not run two server processes against the same `VORCARO_DATA_DIR`.
- Do not edit `ledger.db` or `projections.db` by hand.
- Do not mount `/var/lib/vorcaro` from NFS or SMB.
- Do not store private keys, HSM PINs, or server signing keys in the image.
- Keep the container root filesystem read-only.
- Keep mTLS client identity as the authority. Do not trust identity-shaped HTTP
  headers.
- Replace the local bootstrap CA/signing-key path with production `step-ca` and
  PKCS#11/HSM wiring before real finance data is used.

## Common Startup Failures

`mkdir /host_mnt/private/var/lib/vorcaro: permission denied`

Docker Desktop on macOS could not reach the bind-mount source path. Follow
`Run On macOS`, then rerun:

```bash
sudo server/setup.sh
sudo server/bootstrap.sh
```

If Docker Desktop still rejects the mount, verify Docker Desktop file sharing
includes:

```text
/private
```

`permission denied, mkdir '/var/lib/vorcaro/.vorcaro-server.lock'`

The top-level error may say the lock is already held, but the nested `EACCES`
cause means the container user cannot create the lock directory. The server runs
as UID/GID `10001:10001`, so the mounted data directory must be writable by
that identity.

On Linux:

```bash
sudo chown -R 10001:10001 /var/lib/vorcaro
sudo chmod 0750 /var/lib/vorcaro
sudo find /var/lib/vorcaro -type d -exec chmod 0750 {} \;
sudo find /var/lib/vorcaro -type f -exec chmod 0600 {} \;
```

On macOS with the standard Compose mounts, fix the real host path:

```bash
HOST_GROUP="$(id -gn)"

sudo chown -R 10001:"$HOST_GROUP" /private/var/lib/vorcaro
sudo find /private/var/lib/vorcaro -type d -exec chmod 0770 {} \;
sudo find /private/var/lib/vorcaro -type f -exec chmod 0660 {} \;
```

If a previous unclean start left a stale lock, first confirm no container is
running:

```bash
docker compose down
```

Then remove only the lock directory:

```bash
sudo rm -rf /private/var/lib/vorcaro/.vorcaro-server.lock
```

`Vorcaro server lock is already held`

Another server process is using the same data directory, or a previous process
left a stale lock after an unclean stop. Confirm no server is running against
that directory before removing `.vorcaro-server.lock`.

`ENOENT` for certificate or signing-key files

The host was not bootstrapped, or Compose points at different mount paths. Run
`sudo server/bootstrap.sh` from the repository root and verify the volume
mounts.

TLS client authentication failure

Use a client certificate signed by the correct trust root for the surface:
device clients must chain to `device-client-ca.pem`; admin clients must chain to
`admin-client-ca.pem`.

`MAC verification failed during PKCS12 import (wrong password?)`

macOS Keychain can reject modern OpenSSL PKCS#12 defaults and report a wrong
password even when the password is correct. Recreate the admin client bundle
with legacy PKCS#12 encryption:

```bash
rm -f /tmp/vorcaro-admin-client.p12

sudo openssl pkcs12 \
  -export \
  -legacy \
  -in /private/etc/vorcaro/certs/bootstrap-admin-client.cert.pem \
  -inkey /private/etc/vorcaro/certs/bootstrap-admin-client.key.pem \
  -certfile /private/etc/vorcaro/certs/admin-client-ca.pem \
  -out /tmp/vorcaro-admin-client.p12 \
  -name "Vorcaro Bootstrap Admin"

sudo chown "$(id -u):$(id -g)" /tmp/vorcaro-admin-client.p12
open /tmp/vorcaro-admin-client.p12
```
