# Server Implementation Summary

Checkpoint for future agents implementing `LLM/SERVER_IMPLEMENTATION_PLAN.md` in order.

## Current Status

- Step 1, Protocol package (§4): completed for the initial executable baseline.
- Step 2a, Database schema (§5): completed for the initial executable baseline.
- Step 2b, Ledger append pipeline (§6): completed for the initial executable baseline.
- Step 3a, Network interface and API surface (§7): completed for the initial executable baseline.
- Step 4a, PKI enrollment and revocation baseline (§8): completed for the local executable baseline.
- Step 5a, Conflict detection and resolution (§9): completed for the initial executable baseline.
- Step 6a, Snapshots and projections (§10): completed for the initial executable baseline.
- Step 7a, KMS and recovery ceremony (§11): completed for the local executable baseline.
- Step 8a, Policy engine and admin console (§12): completed for the local executable baseline.
- Step 9a, Containerized deployment (§14.1): completed for the local executable baseline.
- Server app: bootstrapped as the `server` workspace package; device/admin Express apps, mTLS listener factory, PKI service boundary, local CA adapter, enrollment, and revocation-list handling exist. Real `step-ca` deployment wiring remains a later operational integration.

## Completed

- Created the pnpm workspace package `packages/protocol` with strict TypeScript build, lint, and test scripts.
- Implemented strict zod schemas for the shared entities described in `LLM/COMMON_TYPES.md`, including ledger envelopes, acknowledgements, checkpoints, identity, policy, finance views, audit entries, and AI insights.
- Implemented canonical byte generation for client-signed event envelopes, server acknowledgements, and checkpoints.
- Implemented Ed25519 signing and verification helpers using `sodium-native`.
- Implemented SHA-256 helpers, payload hashing, and the server ledger hash rule from `LLM/SERVER_IMPLEMENTATION_PLAN.md` §4.
- Added a pinned golden canonical-bytes fixture for a representative client event.
- Added protocol tests covering golden bytes, event signing/verification, server acknowledgement signing/verification, checkpoint signing/verification, payload hashing, and 10k generated schema-valid event round-trips.
- Created the `server` workspace package and wired it to import `@vorcaro/protocol`.
- Added initial `ledger.db` migration under `server/migrations/ledger/0001_initial.sql`, matching `LLM/DATABASE_OVERVIEW.md` §4 for ledger, identity, PKI state, recovery, policies, audit, AI insights, checkpoints, snapshots, and append-only triggers.
- Added initial `projections.db` migration under `server/migrations/projections/0001_initial.sql`, matching `LLM/DATABASE_OVERVIEW.md` §5 for rebuildable read models.
- Added server database initialization helpers that apply the required SQLite PRAGMAs and migrations.
- Added database tests covering generated routing columns, STRICT-table enforcement, append-only trigger rejection for UPDATE/DELETE, allowed updates for `object_heads` and `devices`, projection schema creation, and read-only `query_only` connections.
- Added `LedgerAppender`, an in-process serialized append worker that implements idempotency, enrolled-device/fingerprint checks, active-executive binding, replay counter checks, key-window signature verification, encrypted payload hashing, conflict detection, gapless sequence assignment, ledger hash chaining, signed server acknowledgements, `object_heads` updates, and device replay-watermark updates.
- Added batch append ordering by `device_event_counter` per device for reconnect flow.
- Persisted nullable `error_code` on `ledger_events` so duplicate `event_id` retries can return the original signed outcome verbatim.
- Added append-pipeline tests covering valid append, duplicate idempotency, captured-counter replay, bad signature rejection, bad payload hash rejection, stale-object conflict marking, independent event convergence after conflict, and batch counter ordering.
- Added device API app factory with strict JSON body guards, 1 MiB default body limit, 10 MiB event submission limit, zod validation at the boundary, closed-enum error responses, per-device token-bucket rate limiting, and no `X-Powered-By` banner.
- Added mTLS identity middleware that reads the certificate fingerprint through a resolver defaulting to the TLS socket, ignores identity-shaped headers, audits their presence, loads device/executive state from SQLite, and maps identity failures to `CERT_UNKNOWN`, `CERT_REVOKED`, or `EXECUTIVE_INACTIVE`.
- Added device routes for `/v1/state`, `/v1/checkpoints`, `/v1/events`, `/v1/snapshots/latest`, `/v1/revocations`, `/v1/policies/active`, and event submission through `LedgerAppender`; enrollment/recovery routes exist as closed-code stubs pending their planned sections.
- Added signed response wrappers for state-bearing API responses and an HTTPS listener factory that forces TLS 1.3, `requestCert: true`, `rejectUnauthorized: true`, and conservative timeout/header settings.
- Added admin API app placeholder on the separate admin surface with closed-code stubs for the planned admin route groups.
- Added API tests covering certificate-fingerprint identity binding, ignored-header audit logging, closed identity error codes, JSON string-to-bigint event normalization, signed state response verification, disabled Express version banners, and mandatory TLS 1.3 mTLS listener options.
- Added `CertificateAuthority` adapter boundary plus deterministic `LocalCertificateAuthority` for tests; production is expected to back the same interface with Vorcaro-owned `step-ca`.
- Added `PkiService` for one-time enrollment-token hashing, short-lived enrollment challenges, device possession proof verification, executive-signed `DEVICE_ENROLLED` event validation, certificate issuance through the CA adapter, device materialization, token/challenge consumption, and audit evidence.
- Added revocation handling that asks the CA adapter to revoke the device certificate, marks the device revoked, and appends a signed `RevocationList` version for clients.
- Added `enrollment_challenges` to the ledger schema and documented it in `DATABASE_OVERVIEW.md`.
- Replaced the enrollment API stubs with working `/v1/enroll/begin` and `/v1/enroll/complete` handlers when a `PkiService` is wired; added an admin revocation route hook for `/admin/v1/devices/:id/revoke`.
- Added `LLM/CA_AUTHORITY.md` describing the Vorcaro CA hierarchy, enrollment flow, runtime authentication, certificate lifetime, revocation, code boundaries, operational rules, and current implementation status.
- Added PKI tests covering hashed-only token storage, challenge proof verification, certificate issuance, `DEVICE_ENROLLED` append, one-time token consumption, bad proof rejection, device revocation, and signed revocation-list creation.
- Added mutable `conflicts` working table in `ledger.db` for open/resolved conflict materialization while keeping conflict truth in append-only ledger events.
- Extended `LedgerAppender` conflict behavior so stale-object events create/update an open conflict record with permanent event ids, conflicted objects reject further writes with `POLICY_DENIED`, and only an accepted signed `CONFLICT_RESOLVED` event clears `object_heads.conflicted`, records `resolution_event_id`, and establishes the new head.
- Added conflict tests covering durable open-conflict records, event-id retention, write blocking while conflicted, successful signed resolution, and closed-code rejection for resolution attempts without an open conflict.
- Added `ProjectionWorker` for `projections.db`, keyed by `proj_meta.last_applied_sequence`, with idempotent batch application, full rebuild support, account projection materialization, cash-position aggregation, and open-conflict projection sync from the ledger `conflicts` table.
- Added `SnapshotWorker` that folds projection state and ledger head into canonical compact snapshot bytes, encrypts the body with AES-256-GCM, stores it through an object-store adapter, and writes a signed append-only manifest to `snapshots`.
- Added `MemorySnapshotObjectStore` for local tests; production MinIO wiring can implement the same object-store boundary without changing snapshot manifest semantics.
- Exported projection and snapshot workers from the server package.
- Added section §10 tests covering projection idempotency, open-conflict mirroring, conflict-resolution projection cleanup, encrypted snapshot object storage, signed snapshot manifests, content-hash verification, and same-sequence snapshot id uniqueness.
- Added a handle-based `KeyManagementService` boundary plus `LocalKeyManagementService` for local drills, covering key wrap, unwrap, rewrap, and signing by key handle.
- Added `RecoveryService` for recovery ceremony initiation, custodian approval verification, threshold transition, target executive/device quarantine, recovery-master rewrap of active key packages, executive key rotation, and signed ledger evidence append for `RECOVERY_PERFORMED` and `KEY_ROTATED`.
- Added recovery audit evidence for ceremony initiation, approvals, threshold crossing, and execution.
- Exported KMS and recovery service types/classes from the server package.
- Added section §11 tests covering KMS wrapping/rewrapping/signing and a full threshold recovery drill with bad-signature rejection, key-package rewrap, old key revocation window, new key activation, signed acknowledgements, append-only ledger evidence, and recovery audit entries.
- Added `PolicyEngine`, a deliberately small pure interpreter for versioned policy documents: role/object/action permissions, a closed condition set, and threshold approval rules.
- Added `PolicyService`, which activates a policy only after a signed `POLICY_CHANGED` event is accepted by `LedgerAppender`, then stores the active document and writes admin audit evidence.
- Wired `LedgerAppender` to evaluate the active policy after signature/payload validation and before conflict handling, appending denied events as `POLICY_DENIED` and approval-required events as `pending` with `APPROVALS_REQUIRED`.
- Expanded the admin API with read surfaces for devices, executives, recovery ceremonies, conflicts, checkpoints, audit log, and policies, plus signed-action hooks for policy activation and recovery ceremonies.
- Added the dependency-free internal `admin-ui/` console using the `DESIGN.md` dark, quiet, typographic system with semantic status treatment and compact tables for devices, executives, recovery, conflicts, checkpoints, audit, and policies.
- Added section §12 tests covering policy allow/deny/approval decisions, signed policy activation, policy hash rejection, and appender policy enforcement.
- Added a production runtime entrypoint (`server/src/main.ts`) that opens host-mounted SQLite databases, acquires an atomic data-directory lock, wires the appender/policy/admin/device services, starts the two TLS 1.3 mTLS listeners, serves the static admin console, and gracefully drains/checkpoints on shutdown.
- Added a container healthcheck command (`server/src/healthcheck.ts`) with mTLS endpoint checking when healthcheck client certs are configured and filesystem readiness fallback for local containers.
- Added `Dockerfile`, `.dockerignore`, and `docker-compose.yml` with a non-root runtime user, read-only root filesystem, `/var/lib/vorcaro` data mount, certificate/secret mounts, published `8443`/`9443` listeners, and optional `step-ca`/MinIO profiles.
- Added `LLM/DOCKER_OPERATIONS.md` with host path layout, expected certificate/secret files, run commands, and safety rules.
- Added `server` start script for `node dist/main.js`; verified the Dockerfile's `pnpm deploy --prod --legacy` packaging command.
- Added `server/bootstrap.sh`, a root-run first-host bootstrap script that creates the durable data/certificate/secret directories, local CA hierarchy, server certificates, bootstrap client certificates, healthcheck client certificate, server signing key, and initial SQLite files when the built server database module is available.
- Added `server/setup.sh`, a root-run dependency installer for supported Linux distributions and host-layout preparer for Docker bind mounts, including macOS `/private/var/lib/vorcaro` and `/private/etc/vorcaro`; `bootstrap.sh` invokes it when Node.js, pnpm, OpenSSL, Docker, or Docker Compose v2 is missing.
- Added `server/README.md` with from-scratch bootstrap, Docker Compose runtime, macOS Docker Desktop bind-mount guidance, local development, environment variable, healthcheck, and common startup failure guidance for the server package.

## Verification

- `pnpm build` passed.
- `pnpm test` passed.
- `pnpm lint` passed.

## Not Started

- Real `step-ca` client integration and certificate renewal endpoint.
- Checkpoints worker, production PKCS#11 adapter, production MinIO adapter, KMS-wrapped snapshot/database keys, hardened admin identity/authorization middleware, broader finance projection event coverage, reporting APIs beyond the admin read surfaces, production React build tooling for the admin console, signed internal registry publishing, backup jobs, observability, ASVS mapping, and server-side AI workers.

## Notes

- The protocol package is intentionally pure and has no filesystem, network, or database I/O.
- The server package is only a compile-time bootstrap at this checkpoint; network listeners should wait until the API/mTLS stage in the build order.
- The database tests use Node's built-in SQLite engine against temporary databases; production SQLCipher key unwrap and HSM/KMS integration remain in the later KMS step.
- The §6 appender currently performs the validation steps available before the later API, KMS, and policy phases. Policy evaluation/decryption and scheduled checkpoint emission remain deferred to their planned sections.
- The §7 API tests avoid opening local sockets because this sandbox blocks `listen`; mTLS listener hardening is verified through the exported server option builder, while identity middleware is tested directly with an injected fingerprint resolver. Production defaults still read the peer certificate from the TLS socket.
- The §8 CA adapter is intentionally local/test-only in this baseline. It preserves the server contract without introducing live CA network calls; production `step-ca` integration must implement the same `CertificateAuthority` interface.
- The §9 implementation blocks all new ledger writes to a conflicted object until `CONFLICT_RESOLVED` lands. The later full policy engine can narrow this to the plan's material-action rule when read/annotation event types exist.
- The §10 snapshot worker currently accepts a 32-byte snapshot encryption key directly. Later KMS work must unwrap/provide that key from the HSM boundary; snapshot bodies are already encrypted before leaving process memory for object storage.
- The §10 projection worker covers account, cash-position, and conflict read models needed by the current implemented event surface. Transaction, budget, approval, and richer account fields should be filled when the corresponding decrypted payload schemas and policy/KMS path exist.
- The §11 KMS implementation is local/test-only. Production must implement the same `KeyManagementService` interface against PKCS#11/SoftHSM or hardware HSM handles.
- The §11 recovery service requires real client-signed `RECOVERY_PERFORMED` and `KEY_ROTATED` envelopes from the executing recovery officer device before it appends recovery evidence. Network route wiring remains with the admin/recovery API work.
- Existing appender, PKI, and snapshot services still accept direct server signing/encryption key material from earlier steps; production HSM retrofit should move those call sites onto the KMS handle boundary introduced in §11.
- The §12 policy interpreter is intentionally not a general-purpose language. Add new condition operators only by extending the closed `PolicyEngine.conditionsAllow` implementation and tests.
- The §12 admin console is static and dependency-free in this baseline to avoid introducing frontend supply-chain dependencies. The admin listener can serve it via `adminUiPath`; production can add React build tooling later while preserving the API and visual system.
- The §12 admin API still relies on the admin listener's mTLS boundary. Fine-grained admin identity binding/role authorization should be added before exposing mutation endpoints beyond controlled local drills.
- The §14.1 runtime requires mounted TLS certs and a server signing key file. It intentionally does not generate development secrets or self-signed certificates at boot.
- The §14.1 lock uses an atomic lock directory under `VORCARO_DATA_DIR`; it makes double-starts against the same mount fail loudly.
- The §14.1 Dockerfile packaging path was verified with `pnpm --filter @vorcaro/server deploy --prod --legacy`; a full Docker image build was not run in this sandbox.
- The §14.1 `server/bootstrap.sh` bootstrap preserves existing keys, certificates, and signing material by default; `VORCARO_FORCE=1` intentionally regenerates them and should not be used against an established ledger without an operator recovery plan.
