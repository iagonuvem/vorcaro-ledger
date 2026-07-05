# Docker Operations

This is the section 14.1 container baseline for the Vorcaro finance server.

## Host Layout

The container is disposable. These host paths are the durable system:

```text
/var/lib/vorcaro/          ledger.db, projections.db, backups/, lock
/etc/vorcaro/certs/       server certs and trusted client CA bundles
/etc/vorcaro/secrets/     server signing key file and future HSM/KMS config
```

Expected certificate file names:

```text
/etc/vorcaro/certs/root-ca.key.pem
/etc/vorcaro/certs/root-ca.pem
/etc/vorcaro/certs/device-server.key.pem
/etc/vorcaro/certs/device-server.cert.pem
/etc/vorcaro/certs/device-client-ca.key.pem
/etc/vorcaro/certs/device-client-ca.pem
/etc/vorcaro/certs/admin-server.key.pem
/etc/vorcaro/certs/admin-server.cert.pem
/etc/vorcaro/certs/admin-client-ca.key.pem
/etc/vorcaro/certs/admin-client-ca.pem
/etc/vorcaro/certs/bootstrap-device-client.key.pem
/etc/vorcaro/certs/bootstrap-device-client.cert.pem
/etc/vorcaro/certs/bootstrap-admin-client.key.pem
/etc/vorcaro/certs/bootstrap-admin-client.cert.pem
/etc/vorcaro/certs/healthcheck-client.key.pem
/etc/vorcaro/certs/healthcheck-client.cert.pem
```

Expected signing-key file:

```text
/etc/vorcaro/secrets/server-signing.key
```

The signing key file contains the base64 Ed25519 server signing secret used by
the current local baseline. Production should replace this with the PKCS#11
handle boundary introduced in section 11.

## Commands

First-time host bootstrap, run as root:

```bash
sudo server/bootstrap.sh
```

This creates `/var/lib/vorcaro`, `/etc/vorcaro/certs`, `/etc/vorcaro/secrets`,
local bootstrap mTLS certificates, a server signing key, and initializes the
SQLite files when the local server build is already present. Existing files are
preserved unless `VORCARO_FORCE=1` is set.

If required host dependencies are missing, `server/bootstrap.sh` calls
`server/setup.sh` to install Node.js, pnpm, OpenSSL, Docker, and Docker Compose
v2 on supported Linux distributions. `server/setup.sh` also prepares the
default host directories and permissions for Docker bind mounts, including the
macOS `/private/var/lib/vorcaro` and `/private/etc/vorcaro` paths used by
Docker Desktop.

Then run:

```bash
docker compose up -d
docker compose restart ledger-server
docker compose pull && docker compose up -d
```

## Safety Rules

- Never mount `/var/lib/vorcaro` from NFS or SMB.
- Never run more than one `ledger-server` against the same data directory.
- Never store private keys or HSM PINs in the image or compose file.
- Keep `read_only: true`; the data directory and `/tmp` tmpfs are the only
  writable locations.
- Do not edit `ledger.db` or `projections.db` by hand.

## Runtime

The container starts:

- device mTLS listener on `8443`
- admin mTLS listener on `9443`
- static admin console from `/app/admin-ui`
- SQLite databases under `VORCARO_DATA_DIR`
- atomic data-directory lock at `.vorcaro-server.lock`

On `SIGTERM`, the server drains the appender, closes both listeners, runs
`wal_checkpoint(TRUNCATE)` on both databases, releases the lock, and exits.
