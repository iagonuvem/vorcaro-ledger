# App Implementation Summary

Checkpoint for future agents implementing `LLM/APP_IMPLEMENTATION_PLAN.md` in order.

## Current Status

- Step A0, Hardened shell + IPC contract + integrity check (§4): completed for the local executable baseline.
- Step A1, Vault + key hierarchy + unlock/lock (§5-§6): partially implemented for the local executable baseline. Argon2id KEK derivation, wrapped root-key header storage, main-process unlock/lock, key zeroization, typed vault IPC, SQLCipher-compatible local database opening, the initial local schema, monotonic counter allocation, and hash-chained local audit storage exist. Electron `safeStorage`, hardware binding, auto-lock, and real local replica projections remain pending.
- Step A2, Local replica + createEvent + pending queue (§7): partially implemented. The main process now has a single `EventCreator` path that requires an unlocked vault and local enrollment metadata, encrypts payload bytes, hashes encrypted payload bytes, signs protocol envelopes with the vault-derived Ed25519 key, evaluates a local policy preview when an active policy is present, and inserts queued pending events with the counter bump in one local transaction. Sync still needs to populate verified local replica projections and process queued pending rows.
- Step A3, Sync engine + verification + checkpoints (§8): partially implemented. The main process now has a verification core, a one-shot sync session orchestration boundary, an HTTPS mTLS transport boundary, and encrypted enrolled-device credential storage for state advertisements, checkpoint pulls, active-policy pulls, event pulls, pending-event pushes, server acknowledgements, and checkpoints. It verifies signed state/list responses, server signatures, checkpoint signatures, encrypted-payload hashes, ledger hash continuity, chain gaps, and rollback tripwire cases before writing to the encrypted local store. Enrollment ceremony, certificate renewal, durable scheduling, revocation pull, snapshot bootstrap, and two-client convergence remain pending.
- Step A4, Enrollment + revocation + recovery client (§9): not started.
- Step A5, Finance UI surfaces (§10-§11): renderer surfaces completed for the local executable baseline; live vault/store/sync integration remains pending.
- Step A6, Signed updater + release pipeline (§13): not started.
- Step A7, Local AI runtime (§12): not started beyond the required advisory UI containment.
- Client app: bootstrapped as the `client` workspace package with Electron, React, TypeScript, Vite, zod, a hardened `app://` shell, typed preload API, main-process workspace view-model provider, and a DESIGN.md-aligned executive UI. The current workspace data provider is a main-process fixture boundary, not the encrypted local replica.

## Completed

- Created the `client` pnpm workspace package and wired it into the root workspace.
- Added strict client build, dev, lint, and test scripts.
- Added Electron, React, Vite, TypeScript, zod, `better-sqlite3-multiple-ciphers`, and `@electron/fuses` dependencies for the client baseline.
- Added explicit pnpm build-script approval for `better-sqlite3-multiple-ciphers`, `electron`, and `esbuild`.
- Implemented a hardened `BrowserWindow` option factory with `contextIsolation: true`, `sandbox: true`, `nodeIntegration: false`, `webviewTag: false`, no `enableRemoteModule`, black background, and disabled production devtools.
- Registered a privileged `app://` protocol for renderer assets.
- Implemented bundled asset path confinement for the `app://` protocol, including traversal rejection, allowed extension checks, and support for Electron/Vite URL shapes such as `app://index.html/` and `app://index.html/assets/...`.
- Fixed the Electron dev-load failure where the app displayed `Not Found`: the protocol handler now reads bundled files directly and returns typed `Response` objects instead of routing through `net.fetch(file://...)`, which the hardened session blocks.
- Added runtime path resolution for development and packaged layouts so dev resolves renderer assets from `client/dist/renderer` and preload from `client/dist/main/preload/index.js`.
- Added strict session hardening that denies permission requests and blocks `http:`, `https:`, and `file:` requests at the session boundary.
- Added navigation controls so `will-navigate` and `setWindowOpenHandler` deny non-`app://` navigation.
- Added a strict renderer CSP with `connect-src 'none'`, no object/embed surface, no frames, no forms, and no remote asset allowances.
- Added a preload bridge exposing only named methods on `window.vorcaro`; raw `ipcRenderer` and channel access are not exposed.
- Added a single zod IPC contract in `client/src/ipc/contract.ts`.
- Added `shell:get-state`, `workspace:get-snapshot`, and `security:acknowledge` IPC handlers with request and response validation.
- Added a minimal local audit sink for IPC anomalies and security-banner acknowledgements; it writes local NDJSON until the encrypted `local_audit` table exists.
- Added packaged-startup integrity verification for an Ed25519-signed manifest over bundled renderer files.
- Reused `@vorcaro/protocol` canonical bytes for integrity manifest signing input.
- Added a package-time fuse script for `runAsNode=off`, Node CLI inspect disabled, Node options environment disabled, cookie encryption enabled, embedded ASAR integrity validation enabled, and `onlyLoadAppFromAsar=on`.
- Added a main-process executive workspace snapshot provider behind the typed preload API.
- Added strict zod schemas for the executive workspace view model: metrics, accounts, flows, approvals, conflicts, ledger rows, checkpoints, export requests, fact rows, advisory text, and action-consequence copy.
- Implemented the renderer as pure UI consuming validated preload data rather than owning finance fixture arrays.
- Added `VaultService` in the main process for the A1 vault baseline.
- Implemented Argon2id KEK derivation via libsodium `crypto_pwhash`.
- Implemented encrypted vault header creation with a randomly generated executive root key wrapped by AES-256-GCM under the derived KEK.
- Stored only Argon2id parameters and wrapped root-key material in the vault header file; passphrases and unwrapped root keys are not written to the header.
- Kept the unwrapped root key in guarded `sodium_malloc` memory while unlocked and zeroized it on lock/replacement.
- Derived internal signing, encryption-unwrapping, and device-binding child handles from the root key using HKDF labels.
- Derived a separate local database key from the vault root key; it is copied only long enough to open the main-process local store and then zeroized.
- Added failed-unlock tracking and a local lockout timestamp after repeated bad unlock attempts.
- Added typed vault IPC methods for status, create, unlock, and lock; responses expose status only and never key material.
- Added `LocalStore` in the main process using `better-sqlite3-multiple-ciphers` with SQLCipher legacy mode, WAL, `synchronous = FULL`, `foreign_keys = ON`, `busy_timeout = 5000`, and `trusted_schema = OFF`.
- Added the initial encrypted local schema for `meta`, `snapshots`, `ledger_replica`, `pending_events`, `checkpoints`, `sync_state`, `object_cache`, `local_audit`, and `ai_insights_cache`.
- Added append-only triggers for `snapshots`, `ledger_replica`, `checkpoints`, and `local_audit`.
- Added transactional monotonic `device_event_counter` allocation from `meta`.
- Moved local audit recording to encrypted, hash-chained `local_audit` storage after vault unlock while retaining the pre-unlock NDJSON fallback for shell anomalies.
- Added `EventCreator` as the single main-process event creation path for the current baseline.
- `EventCreator` requires `executive_id` and `device_id` in encrypted local metadata; it does not invent identity before enrollment.
- `EventCreator` encrypts canonical payload bytes with AES-256-GCM, stores the encrypted payload as base64 protocol bytes, and hashes those encrypted bytes through `@vorcaro/protocol`.
- `EventCreator` derives the Ed25519 signing key from the vault signing seed and signs client event envelopes through `@vorcaro/protocol` canonical signing helpers.
- Pending event insertion and `device_event_counter` advancement happen in one local transaction through `LocalStore.createPendingEvent`.
- Added a narrow `event:create` IPC/preload method with zod validation; the renderer can request an event creation intent but cannot provide event id, actor id, device id, counter, timestamp, payload hash, encrypted payload, or signature.
- Added `LocalPolicyEngine` for client-side UX preview using the same permission, condition, approval-threshold, document-hash, exchange-rate, and default-currency snapshot semantics as the server policy engine.
- Added encrypted local active-policy storage helpers on `LocalStore`; current tests seed this directly, while A3 sync must become the owner of verified policy population.
- `event:create` responses now return structured local policy outcomes: `not_configured`, `allow`, `deny`, or `require_approvals`. The server remains authoritative at push time.
- Added `SyncEngine` as the first A3 verification core in the main process.
- `SyncEngine` verifies state advertisements against the local verified head and trips local audit on rollback-shaped sequence/hash regressions.
- `SyncEngine` verifies pulled ledger events in order by requiring the next sequence, matching `previous_ledger_hash`, matching canonical `resulting_ledger_hash`, matching encrypted-payload hash, and a valid server acknowledgement signature.
- `SyncEngine` stores only verified pulled events in `ledger_replica` and advances `sync_state.last_verified_sequence`.
- `SyncEngine` verifies checkpoint signatures and checks checkpoint hashes against any locally known ledger hash before storing them in append-only `checkpoints`.
- `SyncEngine` applies server acknowledgements to pending rows only after verifying the server signature, mapping accepted/pending to `acked`, conflicted to `conflicted`, and rejected/quarantined to `rejected`.
- Added `SyncSession` as a one-shot A3 orchestration boundary with states `connecting -> verifying -> pulling -> pushing -> idle`.
- `SyncSession` verifies signed state, checkpoint-list, event-list, and active-policy responses before handing data to `SyncEngine` or `LocalStore`.
- `SyncSession` pulls state, checkpoints, active policy, events, then pushes queued pending events through an injected transport interface.
- `LocalStore` can now read queued pending events for push in `device_event_counter` order.
- Added `MtlsSyncTransport` for the real device API endpoint shape.
- `MtlsSyncTransport` requires `https:`, uses a provided Vorcaro CA, client certificate, client private key, `rejectUnauthorized: true`, and `TLSv1.3` minimum request options.
- `MtlsSyncTransport` calls the planned device API paths: `/v1/state`, `/v1/checkpoints`, `/v1/events`, `/v1/policies/active`, and `POST /v1/events`.
- Added protocol JSON normalization for server decimal-string bigint fields and existing `0n` policy-document bigint strings before schema validation.
- Added encrypted enrolled-device credential storage on `LocalStore` for executive id, role, device id, risk score, sync server URL, server CA PEM, device certificate PEM, device private key PEM, certificate fingerprint, certificate expiry, and hardware-backed flag.
- Stored device credentials populate the local metadata fields used by `EventCreator` and the mTLS transport; renderer access remains unavailable.
- Added `createMtlsSyncTransportFromStore` so sync transport construction can come from encrypted enrolled-device state after vault unlock.
- Surfaced vault status in the shell sidebar through the existing typed preload bridge.
- Implemented the v1 executive navigation surfaces from `APP_IMPLEMENTATION_PLAN.md` §11: Dashboard, Approvals, Conflicts, Ledger / Audit, Sync & Device, Exports, and Settings.
- Implemented the DESIGN.md dark-only visual system: true black canvas, charcoal surfaces, hairline borders, compact tables, 8px radii, system fonts, tabular numerals, and no gradients, shadows, glass, remote fonts, or decorative motion.
- Implemented the truth-state badge system for `accepted`, `pending`, `rejected`, `conflicted`, and `quarantined` with structural dot treatment and exact status vocabulary.
- Implemented the Dashboard UI with accepted cash position, pending delta, accounts, inflows/outflows, sync status, pending approvals, conflicts, and a labeled advisory AI container.
- Implemented the Approvals UI with operation amount, policy consequence, multi-party progress, pending status, and disabled signing action until the signer/vault path exists.
- Implemented the Conflicts UI with accepted and conflicting versions side by side, advisory AI proposal containment, and `CONFLICT_RESOLVED` copy that preserves append-only semantics.
- Implemented the Ledger / Audit UI with event type, object, actor, status, sequence, key version, device id, hash, and exact UTC timestamp fields.
- Implemented the Sync & Device UI with connection state, last verified sequence, pending count, revocation-list version, active policy version, certificate expiry, vault state, integrity state, and checkpoint history.
- Implemented the Exports UI with encrypted export requests, policy requirements, and plaintext export disabled until a signed `DATA_EXPORTED` event is accepted.
- Implemented the Settings UI with auto-lock, suspend lock behavior, hardening state, app protocol origin, integrity state, dark-only appearance, and no network toggles that could weaken verification.
- Implemented a global security banner slot whose acknowledgement calls typed preload IPC and is locally audited.
- Added hardened-shell tests covering BrowserWindow settings, `app://` path confinement, dev/runtime path resolution, CSP/no external HTML loads, v1 UI screen inventory, truth-state vocabulary, and Ed25519 integrity manifest verification.
- Added local-store tests covering encrypted SQLCipher-compatible opening, plaintext open failure, append-only trigger enforcement, monotonic counter persistence, and hash-chained audit entries.
- Added event-creator tests covering protocol signature verification, encrypted-payload hash verification, pending queue insertion, counter persistence, missing identity rejection, locked-vault rejection, local policy allow/deny/approval-required previews, policy hash mismatch handling, and IPC string-integer metadata validation.
- Added sync-engine tests covering verified event application, bad ledger hash rejection, rollback tripwire audit, checkpoint signature/hash validation, and verified pending-ack state updates.
- Added sync-session tests covering successful state/checkpoint/policy/event pull plus pending push orchestration and rejection of unsigned state before pull/push side effects.
- Added sync-transport tests covering HTTPS enforcement, pinned TLS request options, device API path construction, bigint response normalization, and bigint POST serialization.
- Added local-store and sync-transport tests covering enrolled-device credential persistence, HTTPS credential validation, and mTLS transport construction from encrypted local state.

## Verification

- `pnpm --filter @vorcaro/client build` passed.
- `pnpm --filter @vorcaro/client test` passed.
- `pnpm build` passed.
- `pnpm test` passed.
- `pnpm lint` passed.
- `pnpm --filter @vorcaro/client dev` launched the Electron app; the prior `Failed to load URL: app://index.html/` and `Not Found` renderer output did not recur. The remaining EGL warning is Chromium/macOS graphics noise, not a renderer-load failure.

## Not Started

- Electron `safeStorage` convenience unlock.
- Auto-lock timers and suspend/lid-close locking.
- TPM / Secure Enclave device-binding key integration.
- Additive migration runner for future local database schema changes.
- Enrollment wizard and ceremony to generate/provision device identity metadata into encrypted local credentials.
- Verified active-policy population from pulled server policy documents.
- Device certificate/key generation, CSR/proof ceremony, and renewal.
- Connectivity scheduling, revocation pull, durable sync loop, dropped-ack idempotency handling, and snapshot bootstrap.
- Enrollment wizard, device certificate storage, certificate renewal, revocation quarantine screen, remote-wipe handling, and recovery-client flow.
- Replacement of the main-process fixture workspace provider with encrypted local replica projections.
- Playwright-driven Electron e2e flows for unlock, offline create/sign, reconnect/converge, approval, and conflict resolution.
- electron-builder packaging, OS code-signing, internal file-manifest generation/signing, packaged fuse assertions, and signed Vorcaro-only updater.
- Local AI runtime process using `node-llama-cpp`, no-network utility process isolation, AI cache persistence, and zero write paths into signing or ledger mutation.

## Notes

- The renderer remains a pure UI process: it receives view models through typed preload methods and has no direct network, filesystem, database, signer, or raw IPC access.
- The current workspace snapshot is fixture data in the main process. This is intentional until the encrypted vault, local replica, projection, and sync milestones exist.
- Local audit entries recorded after vault unlock now land in the encrypted, hash-chained `local_audit` table. The file-backed fallback remains only for pre-unlock shell anomalies.
- The security banner acknowledgement is wired and audited locally, but it does not yet represent a real checkpoint-tripwire or quarantine condition from the sync engine.
- The integrity verifier enforces signed renderer assets only in packaged builds. Release packaging must add manifest generation, signing, and fuse verification.
- The client dev command currently runs a production renderer build before launching Electron. Hot reload is not implemented; preserving the hardened `app://` boot path took priority.
- The EGL warning seen during Electron launch is emitted by Chromium's graphics stack on this host. It did not coincide with a failed renderer load after the runtime path/protocol fix.
- The disabled action buttons are deliberate: no UI path should pretend to sign, export, approve, or resolve until the vault, signer, policy, and ledger paths exist.
- Green is currently limited to accepted-state markers and primary disabled/enabled action styling per `DESIGN.md`; no heading or decorative green usage has been introduced.
