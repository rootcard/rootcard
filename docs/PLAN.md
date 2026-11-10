# rootcard: setup plan

This is the plan for agents that set up the monorepo and build the first release. Work through the phases in order. A
phase is done when every acceptance criterion is checked, with tests where possible. Record deviations under the phase.

**Current phase: 6 (hardening and release).** Phases 0 to 5 are done, with the deviations recorded under each. Released:
0.1.0, 0.2.0, 0.2.1, 0.3.0 (its review items below), 0.3.1 and 0.3.2.

Design: [docs/DESIGN.md](DESIGN.md). It started in the Xigna game and is application-neutral here (labels `rootcard/...`,
`realm`, *host*). Xigna's own integration plan lives in the Xigna repository.

---

## Decisions needed from the owner (before phase 6)

| # | Question | Proposal |
|---|---|---|
| D1 | License | ✅ **MIT OR Apache-2.0** (decided; 0.1.0 was MIT only, the dual license applies from the next release) |
| D2 | Reserve the names now with placeholder releases? | Yes: `rootcard`, `rootcard-cli`, `rootcard-host` on crates.io and `rootcard` on npm, version `0.0.0`, published by the owner |
| D3 | npm scope as well (`@rootcard/*`)? | Create the `rootcard` org on npm to block look-alikes, publish the main package unscoped |
| D4 | Minimum supported Rust version | Latest stable minus two releases, checked in CI |
| D5 | Minimum browsers | Those with WebCrypto `Ed25519` and `X25519`. No weaker fallback |
| D6 | Security contact and disclosure policy | `SECURITY.md` with a private advisory address on GitHub |
| D7 | Unicode dependency for passwords (NFC) | ✅ **`unicode-normalization`** in Rust, behind the core's `vault` feature so hosts do not build it; JS uses `String.prototype.normalize` (decided) |
| D8 | Scope of v1 | ✅ **Good for servers first** (decided): hosts are simple, multi-server safe and need no password handling; forks are detected, not resolved, and fork resolution waits for a later format version |
| D9 | Recovery key and passwords | ✅ **The user keeps the recovery key**, generated at registration (decided). No escrow and no reset by the host. Passwords can be changed in the browser with the old password; a forgotten password is reset with the recovery key in the key tool |

---

## Versioning and stability

Three version numbers move independently. None of them may break what an earlier one promised.

| What | Now | Rule |
|---|---|---|
| **Packages** (all crates and the npm package, one tag `vX.Y.Z`) | 0.x | Semantic versioning. Breaking changes are allowed between 0.x releases and recorded in the changelogs. `1.0.0` after phase 6's acceptance and the external review |
| **Format** (`v` of every structure, labels `rootcard/<purpose>/v<n>`) | 1 | SPEC §22: anything hashed or signed changes only by a new `v` or label, and `v: 1` is accepted forever. Ids, logs and signatures made by 0.1.0 stay valid in every later release |
| **HTTP binding** (path segment after the base URL, HOST_PROTOCOL.md §1.3) | `v0` | `/v0` until 1.0.0 and may change between 0.x releases. At 1.0.0 the binding is frozen as `/v1`; a later breaking change gets `/v2`, served beside `/v1` for an announced transition |

- The API version never enters a base URL, `home.url` or a signed message, so moving the binding from `v0` to `v1` needs
  no new instance and no format change. Peer request signatures cover the versioned path, so they do not cross
  versions.
- New capabilities (sign-in at other services, passkeys, post-quantum keys, witnesses) arrive as new labels, kinds,
  key types or format versions beside the old ones (SPEC [EXT-1]–[EXT-3]), never by changing the meaning of what exists.
- Licensing: MIT OR Apache-2.0 from the release after 0.1.0 (D1).

---

## 0.3.0 (review of 0.2.0) ✅

A review of 0.2.0 found two bugs that could lose a recovery key or break the key tool, fixed in 0.2.1 (the key tool
saved new cards only after sending; `keytool.html` lacked `binding.js`; `POST /events` dropped a rotation's vault).
These findings remain. None needs a format change unless stated. Each item gets the tests and, where bytes change,
the vectors that AGENTS.md asks for.

**Release pipeline (a separate pull request).** RELEASING.md §3 keeps the release workflow out of release pull requests,
so this was not part of 0.2.1. It was meant to land before 0.2.1 was published and did not: 0.2.1 was published with
unpinned actions (the run was green, nothing suggests a compromise). The review of 0.2.x recorded this.
- [x] Pin every third-party action in `.github/workflows/release.yml` and `ci.yml` to a full commit SHA, with the tag
  in a comment: `actions/checkout`, `actions/setup-node`, `dtolnay/rust-toolchain` (with an explicit `toolchain`),
  `rust-lang/crates-io-auth-action`, `Swatinem/rust-cache`, `EmbarkStudios/cargo-deny-action`. Checkouts no longer
  keep the job token in `.git/config` (`persist-credentials: false`).
- [x] `npm install -g npm@11.21.2` in the npm job, an exact version.
- [x] `xtask repo-check` (in CI and in `release-check`) fails on an unpinned `uses:` or an npm install without an exact
  version, so the pins cannot erode.

**Hosts**
- [x] Handle squatting by propagation. **Decided** ([HST-4], [HDL-5]): only identities registered at a host reserve a
  handle there; identities that arrive any other way reserve nothing and are told apart by extended tags.
  `IdentityStore::handle_claimed`; tested in both directions (`only_registered_identities_reserve_a_handle`);
  THREAT_MODEL.md T42. The original finding: `POST /id/{account}/events` stores an unknown account's log, even one of only
  the inception, and the stored identity reserves its handle (`insert(.., false)` still enters the handle index), so
  registration of a colliding handle fails with `handle_taken`. About 2^20 cheap requests cover every tag of one
  username at a host without rate limits. [HST-4] allows this today; decide in the spec, for example that an identity
  without a current instance reserves no handle, or that only identities a host registered or received from a peer
  do, and test it in both directions.
- [x] Reject-case tests for the host rules, through `http::route`, in `crates/rootcard-host/tests/rejects.rs` (with the
  e2e helpers moved to `tests/common`). Writing them found no host bug; two expectations were corrected instead: a data
  change cannot be told apart in a password change (the contents are encrypted, [CHG-2] allows a new `ct`), so the
  `stale_locks` case is a vault that also changes the grant; and a retirement sent with a vault is adopted
  (`account_retired`). `bad_signature` at fetch and login stays in `e2e.rs`. The original item: `handle_taken`, `username_policy`,
  `realm_not_accepted`, `bad_locks` (registration without a slot), `fork` and `stale_version` on `/events` and
  `/instance`, `bad_signature` at fetch and login (wrong password), every `unauthorized` and `stale_locks` case of
  [HST-12] and [CHG-2] (a session that changes locks, a stolen session changing a password), session idle expiry
  ([HST-11]), and retries ([HST-20]) of `/instance` and `/events`.
- [x] `merge` answered `fork` when an overlapping event differed, without verifying the submitted events. It now
  verifies them on top of the stored prefix first, so garbage gets its own code and only a valid diverging log is
  `fork` ([HST-14]). **Decided:** events whose first `prev` is not a stored event still answer `stale_version`: they
  cannot be verified without the events before them, and the answer carries the host's version so the sender can
  fetch and compare.
- [x] (Fixed with `i64::abs_diff` at both sites, with a regression test.) `peer::verify_peer_request` computes `(headers.time - now).abs()`, which overflows in debug builds for an extreme
  header time (anyone can send a peer's public key from the descriptor). Use a saturating difference. The receipt check
  (`Host::receipt`, [HST-6]) has the same expression; it is safe today only because `verify_pending` bounds `time` to
  `0..=2^53-1` first, and gets the same fix.
- [x] (Purged on insert, keeping a just-expired challenge one more lifetime; the duty is in the `ChallengeStore` docs
  and ARCHITECTURE.md §3.1 with the SQL.) `MemoryChallengeStore` never dropped expired challenges, and `POST /id/{account}/challenge` needs no
  authentication, so the example host's memory grows without bound. Purge on insert; document the same duty for the
  SQL schema (ARCHITECTURE.md §3.1).

**Format and both cores**
- [x] `check_base_url` ([HST-22]) accepted `.` and `..` path segments, so a version segment could enter a base URL as
  `https://example.com/v0/..`. **Decided:** path segments have only unreserved characters (RFC 3986 §2.3), so no
  percent-encoding at all (which also closes `/%76%30`), and are never `.` or `..`. Both cores and seven new vectors
  in `proof.json`; THREAT_MODEL.md T43.
- [x] **Decided:** the cores enforce [LCK-8] in every function that creates a password lock (`new_password_lock` and
  therefore `add_slot`, `instance_vault` and `new_instance`; and `change_password`), not only `register`. `NewSlot`
  gains `username`, `change_password` a `username` parameter; `new_instance` refuses a slot for another username
  (`bad_field`) and checks the password before drawing anything. Vectors in `vault.json`; THREAT_MODEL.md T44.
- [x] Rust `aes_gcm_encrypt` turned an encryption failure into an empty vector (`unwrap_or_default`); it returns
  `Result` now (`too_large`; unreachable within the format's size limits).

**Testing and tools**
- [x] Run the shared vectors in browsers in CI (Playwright: Chromium, Firefox, WebKit): `tests/browser`, the CI job
  `browser`. The page runs the same `ops.mjs` as Node; the deterministic test stream's SHA-256 is precomputed with
  WebCrypto. Chromium 153 passes every vector locally; Firefox and WebKit run in CI. WebKit's first run found a
  bug: its WebCrypto rejects an X25519 secret with a zero first byte (about 1 in 256 secrets; a password whose box
  secret starts with one could never unlock in Safari). The JS core gives such secrets to WebCrypto as the same
  scalar after clamping, with regression vectors for secrets and seeds with a zero byte at either end. WebKit also
  rejects such Ed25519 seeds and then cannot compute their public keys, but signs with one imported as a JWK with
  its public key. **Decided:** new keys avoid them (account seed, recovery key, password salt are drawn again,
  [CRY-9]), and the JS core signs with an older one through a public key on record that it was checked against
  ([IMP-6]); THREAT_MODEL.md T45 holds the residual case. The key tool no longer says "Done." while a rotation is
  still being sent (the browser job caught this race).
- [x] Drive `keytool.html` end to end in a browser against the example host in CI (`tests/browser/keytool.mjs`, from
  `file://` as users open it): create, load, add a password, rotate with the send failing (the card is downloaded
  first, the page says to keep both) and with the host up, load the new card (the old one answers
  `wrong_recovery_key`), retire. It fails on the 0.2.0 page.
- [x] Make `keytool.html` clear about hosts and card-only identities. **Decided:** the page uses the rootcard.org
  theme and shows which actions work offline and which need a host, disabling the rest with the reason ([KT-1]). A
  card-only identity can show its card and make root proofs, and "Start at a host" ([KT-3] fresh) puts it on one.
  Host addresses are checked while typed ([HST-22]), and `https://` is added when no scheme is given. The browser
  test also covers the card-only flow (create without a host, open it, start it at the host).
- [x] An end-to-end test of the CLI against a host (`new --host`, `rotate-recovery`, `restore`), beside the offline
  tests of `crates/rootcard-cli/tests/key_tool.rs`: `tests/against_host.rs` runs `http::route` behind a minimal HTTP
  server in the test process and checks what the host stores after each command, including that the vault still
  verifies after a rotation (the 0.2.0 `/events` bug).

**Documentation**
- [x] SPEC §5: the `rootcard/fetch/v1` row of the label table was indented and might not render in the table; SPEC
  §11.1: `"locks"` was indented one level too deep.
- [x] Documents that name the current version (README status, SECURITY.md supported versions) were left at 0.1.0 by
  0.2.0 and 0.2.1. They are updated, and `xtask repo-check` now fails when they do not match the workspace version.

---

## Phase 0: repository skeleton ✅

- [x] `Cargo.toml` workspace with `crates/rootcard`, `crates/rootcard-cli`, `crates/rootcard-host`, `crates/xtask`
  (`resolver = "3"`, edition 2024, shared `[workspace.package]`: version, license, repository, rust-version)
- [x] `[workspace.lints]`: `unsafe_code = "forbid"`, `clippy::unwrap_used = "deny"`, `missing_docs = "warn"` for the libraries
- [x] `rustfmt.toml` (`max_width = 120`), `deny.toml` for `cargo deny`
- [x] `packages/rootcard/package.json`: `"type": "module"`, `exports` map (`.`, `./keytool`), `"files"` whitelist,
  `"sideEffects": false`, `engines.node >= 20`, no dependencies, `"test": "node --test"`
- [x] `spec/SPEC.md` (stub), `spec/vectors/` (empty), `CHANGELOG.md` per package, `SECURITY.md` (placeholder)
- [x] CI (`.github/workflows/ci.yml`): fmt, clippy, test on Linux, macOS and Windows, MSRV, `cargo deny`, npm test on Node 20
  and 22, and a job that runs the JS tests against the Rust-generated vectors
- [x] Every crate and the npm package builds and tests green with empty modules

**Acceptance:** a fresh clone passes all commands in AGENTS.md, and CI is green.
- [x] All commands pass locally (stable 1.97 and MSRV 1.95, Node 22, `cargo deny check`)
- [x] CI green on GitHub (first run on the phase-0 pull request; green on every release since)

**Deviations**
- The `./keytool` export is left out of `package.json` until the page exists (phase 5).
- The license is MIT OR Apache-2.0 (D1; 0.1.0 was published under MIT alone). The published crates carry `license = "MIT OR
  Apache-2.0"`, the npm package `"(MIT OR Apache-2.0)"`, and `LICENSE-MIT` and `LICENSE-APACHE` are in every package. `xtask` stays `publish = false`. Nothing is published before the release workflow (phase 6), except
  the placeholder releases the owner may make for D2.
- MSRV (D4) is set to 1.95, the stable release two versions back at the time of writing.
- The parity mechanism is in place from the start: `xtask vectors` writes `spec/vectors/meta.json` (format version and labels),
  and the JS tests read it. Every later phase adds its vectors the same way.

## Phase 1: specification and threat model ✅

- [x] `spec/SPEC.md`: turn DESIGN.md into a normative, application-neutral specification (MUST/SHOULD):
  canonical JSON, base32 and the recovery-key format, inception and id, handle and extended tags, log events (`incept`,
  `instance`, `rotate_recovery`, `retire`), versions, the vault and locks, the public profile and
  namespaces, login, receipts and proofs, the account file and the recovery card, size limits, error codes
- [x] `docs/THREAT_MODEL.md`: the threat table, the secure-and-feasible decisions and the accepted risks from DESIGN.md §2 and §10,
  expanded (attacker capabilities, assets, trust boundaries)
- [x] `docs/HOST_PROTOCOL.md`: the HTTP endpoints as a recommended (not required) binding

**Acceptance:** the spec can be implemented without reading DESIGN.md, and every rule has a number that tests can
refer to.
- [x] Every normative rule has a stable identifier (`[LOG-12]`) and names its error code; algorithms are numbered steps
  checked in order, so reject vectors can require the same code from both implementations (SPEC [CNV-3])
- [x] The label registry (SPEC §5) is checked against `spec/vectors/meta.json` by both test suites and by `xtask vectors`

**Deviations**
- The spec changes the design where it was ambiguous or unsafe; SPEC Appendix B lists every change. The ones that matter
  most for later phases:
  - every hashed or signed input is `label ‖ 0x00 ‖ canonical JSON` (login and proof messages are JSON objects);
  - the vault is released only after a **lock proof** (`rootcard/fetch/v1`, signed by a per-lock `auth` key derived from the
    same Argon2id output), because the design's public `GET /id/<account>/vault` allowed offline guessing by anyone;
  - **who may unlock is set by the recovery key** (a signed grant of password slots), because the design let the account
    key (low power) sign locks;
  - recovery key derivation is bound to realm and username, so identities from one key are unlinkable;
  - versions are ordered by extension only; forks are detected (`fork`) and not resolved in v1 (D8, SPEC Appendix A);
  - hosts can rotate keys and change addresses without new instances, login and fetch messages are bound to the address
    the client uses, sessions are checked against the current instance on every use, storage updates are
    compare-and-swap and retries are idempotent (SPEC [HST-17]–[HST-21]); handles are unique per realm;
  - vault and profile revisions are `rev`; "version" means only the log version.
- Phase 2 needs Unicode NFC for passwords (SPEC [LCK-7]): `unicode-normalization` in Rust (D7), only with the `vault`
  feature. The dependency budget per package is in [ARCHITECTURE.md](ARCHITECTURE.md) §5.
- Phase 2's JS `crypto.js` must perform the strict Ed25519 pre-checks itself (SPEC [CRY-3] steps 1–4), since WebCrypto
  verifiers differ on them.

## Phase 2: primitives in both languages ✅

- [x] Rust: `canon`, `base32` (Crockford + checksum), thin wrappers over the crypto crates with strict verification
- [x] JS: `canon.js`, `base32.js`, `crypto.js` (WebCrypto wrappers), `blake2b.js`, `argon2.js`
- [x] `xtask vectors`: generates `spec/vectors/primitives.json`. Both suites check it. RFC 8032, RFC 7748, RFC 5869 and RFC
  9106 vectors pass in both languages
- [ ] JS Argon2id benchmark (`m = 64 MiB, t = 3`) recorded: Node and a desktop browser done (see Deviations), a
  mid-range phone still open (needs a real device; the owner)

**Acceptance:** identical bytes for every vector in both languages. Argon2id in JS within about 3 s on a mid-range phone, or
a documented parameter change in the spec.

**Deviations**
- The modules are named by area (`json`, `encoding`, `crypto`, `keys`, `recovery` in Rust; the same files in JS) rather
  than `canon` and `base32`.
- The crypto crates are the current majors: `ed25519-dalek` 3, `x25519-dalek` 3, `sha2` 0.11, `hkdf` 0.13, `aes-gcm` 0.11,
  `argon2` 0.6, without their `getrandom` features: the core draws no randomness ([IMP-1]).
- Argon2id in JS takes about 1.7 s at the minimum lock parameters and 3 s at the default in Node 22 on the development
  machine. Measured again on a 4-core 2.1 GHz Xeon cloud VM (median of three runs after a warm-up): Node 22 1.6 s at
  `KDF_MIN` (46 MiB, `t = 2`) and 3.1 s at `KDF_DEFAULT` (64 MiB, `t = 3`); Chromium 153 1.5 s and 3.0 s. A phone is
  not measured yet; if it is well over 3 s, the default may need to move towards the minimum.
- The RFC 9106 vector (with a secret and associated data) is checked by unit tests in both languages; the shared vectors
  use rootcard's own parameters (no secret, no associated data).
- `testing::TestRandom` (Rust) and `testRandom` (JS) are a deterministic byte stream for vectors: every function that
  draws random bytes documents the order of its draws, so creation is checked byte for byte too.

## Phase 3: identity log and versions ✅

- [x] Deterministic inception from recovery key + username + realm, account id, handle, extended tags
- [x] Events, `verify_log` (including self-signature of every new public key), `extend_log` (incremental, equal to
  `verify_log` on the whole log), `verify_pending`, current instance, `compare_logs` (extension, fork)
- [x] Reject cases: wrong `prev`, wrong signer, wrong realm, future time, after `retire`, forged inception, tag collision
- [x] Vectors: `spec/vectors/log.json`

**Acceptance:** both languages accept and reject exactly the same logs with the same error codes, and compare the same
logs the same way.

**Deviations**
- `extend_log` checks the total length before the events, so that it reports the same code as `verify_log` on the whole
  log (SPEC [LOG-15] now says so).
- Tag collisions are a host concern ([HST-4]); the vectors cover extended tags ([HDL-6]) and the host tests cover the
  unique index.

## Phase 4: vault, public profile, login and proofs ✅

- [x] Vault: create, unlock with a password or the recovery key, add a lock, revoke (new instance, rewrap to remaining
  locks by their public keys), `restore` and `fresh` instances, private data, recovery-signed grants (`gen`), password change with the old password, login lock proofs, lock
  `auth` keys and fetch messages
- [x] Public profile: key and value rules, namespaces, versions, signing
- [x] Login message, receipts, proofs (`prove`, `verify_proof`), account file and recovery card (text and QR payload)
- [x] Power-level tests: nothing reachable with the account key can change the log or the locks
- [x] Vectors: `spec/vectors/vault.json`, `profile.json`, `proof.json`, `file.json`

**Acceptance:** an account created in JS is unlocked, revoked and re-instanced in Rust and the other way round.

**Deviations**
- Interoperability is proven by the vectors rather than a separate cross-language test: vaults created by Rust from a
  random stream are re-created byte for byte by JS from the same stream, and both unlock, change, revoke and re-instance
  the other's output.
- The power levels are enforced by the format: every log event and grant needs the recovery key ([LCK-3], [LOG-13]);
  the reject vectors cover a grant or an event signed by anything else, and `vault_change` classifies every replacement
  under [VLT-4].

## Phase 5: key tool and host helpers ✅

- [x] `rootcard-cli`: `new`, `card`, `add-password`, `revoke-password`, `reset-password`, `restore`, `fresh`,
  `rotate-recovery`, `retire`, `inspect`, `verify`, `prove`. Reads and writes account files and cards, talks to a host only when asked
- [x] `packages/rootcard/keytool.html`: the same operations as one standalone page with no network access unless the user picks
  a host. Works from `file://`
- [x] `rootcard-host` (design in [ARCHITECTURE.md](ARCHITECTURE.md) §3): `ChallengeStore` (atomic take, 60 s),
  `IdentityStore` with compare-and-swap and an in-memory implementation, stored log states with `extend_log`, host keys
  with retired keys, accepted addresses, `stale_version` and `fork`, idempotent retries, `LoginResult` and
  `session_valid` (sessions bound to an instance), handlers independent of any HTTP framework, built on the core without
  the `vault` feature
- [x] A documented SQL schema for the store, and a concurrency test: two handlers on one store racing the same update
- [x] An example host and an end-to-end test: register, log in, export, new instance on a second host, the first host
  answers `not_home`; a host key rotation and an address change with existing identities logging in

**Acceptance:** the full flow runs end to end in CI with two example hosts.

**Deviations**
- The example host is `crates/rootcard-host/examples/host.rs` on `std::net` (development only, no TLS), not axum: it
  needs no dependency beyond `getrandom`. The end-to-end test (`crates/rootcard-host/tests/e2e.rs`) runs two hosts
  through `http::route` in-process; the key tool and `keytool.html` were also run against two example hosts over HTTP.
- The traits are synchronous. An async store can wrap them.
- The router answers `GET /peer/changes` and `POST /peer/push` with signed peer requests; pulling from peers and pushing
  new instances to the previous primary host is the application's loop (the key tool tells the previous host itself).
- `keytool.html` is generated by `tools/build-keytool.mjs`, which inlines the package's own modules (a page opened from
  `file://` cannot import modules); `npm test` fails if it is stale.
- The CLI's HTTP client is `ureq` with `rustls` (and Mozilla's root list through `webpki-roots`, a per-crate license
  exception in `deny.toml`); passwords are read without echo with `rpassword`.

## Phase 6: hardening and release

- [x] Fuzz targets for every parser and verifier, run in CI for a fixed time. `fuzz/` (its own workspace, not
  published): `json`, `text`, `log`, `log_signed`, `documents` and `host`, seeded from `spec/vectors` by
  `cargo run --bin seeds`, two minutes each in the CI job `fuzz` on a dated nightly ([fuzz/README.md](../fuzz/README.md)).
  `log_signed` re-signs mutated logs with known keys, so the fuzzer gets past the signatures to the checks of
  [LOG-12]; `host` drives `http::route` with a sequence of requests against the vectors' host key. `xtask repo-check`
  also requires exact versions and `--locked` for `cargo install` and a date for a nightly toolchain. The first runs
  found no bug in the cores; one assertion was too strict (a host pointer may differ in the case of the host,
  [HST-23]).
- [x] Differential fuzzing of the JS core against the Rust core (same inputs, same result or error code), at least for
  canonical JSON, the encodings and `verify_log`: `cargo fuzz` reaches only Rust. Decided: `cargo run -p xtask --
  differential` mutates the shared vectors' inputs with a seeded generator, runs them through the vector operations of
  both cores (`ops.rs`, `ops.mjs`, with `tests/differential/run.mjs` for Node) and requires the same output or error
  code, for 32 operations from canonical JSON to proofs and account files. Logs are re-signed with the fuzz target's
  re-signer (moved to `crates/xtask/src/resign.rs`). CI job `differential`, 100 000 cases with a new seed per run
  ([fuzz/README.md](../fuzz/README.md)). The first runs found a Rust panic in `extended_tags` on ids shorter than a tag
  or with multi-byte characters, and JS counting UTF-16 units there; both cores now count characters ([HDL-6],
  regression vectors). JS also limited a login request's `lock` to 16 UTF-16 units instead of 16 bytes; it counts
  bytes now, and SPEC [LGN-1] step 5 states the limit. Other signed documents are not re-signed, so their mutations mostly stop at the signature
- [x] `cargo deny`, `cargo audit`, `npm audit` (empty tree), reproducible npm tarball check. Decided: `cargo deny` (CI
  job `deny`, every pull request) is the advisory check, and the workflow `advisories.yml` runs its RustSec check daily,
  so an advisory published after a merge is noticed; `cargo audit` reads the same database and is not run as well.
  `npm audit` has no tree to audit: `xtask repo-check` fails if `packages/rootcard/package.json` or
  `tests/browser/package.json` gains a dependency key, `overrides` or an install script, or the package a lock file.
  Reproducible packages: the `.crate` files and the npm tarball do not depend on file times or on npm 10 or 11
  (CI job `package` packs a second checkout with other file times and compares), and the release's `assets` job fails
  unless what it builds from the tag is byte for byte what crates.io and npm serve (docs/RELEASING.md §4–5). 0.3.2
  rebuilt from its tag matches both registries. npm records file modes, so a reproduction needs a checkout made with
  `umask 022`
- [x] Release workflow: tag `vX.Y.Z` → crates published in dependency order with crates.io trusted publishing, npm published
  with trusted publishing and `--provenance`, GitHub release with checksums (`.github/workflows/release.yml`, prepared
  ahead of phase 6; the owner's one-time setup is docs/RELEASING.md §2)
- [x] Release preparation for agents (docs/RELEASING.md, AGENTS.md rule 10) and `xtask release-check` (versions,
  changelogs, tag, vectors); CI packages every crate and the npm package on each pull request (dry run)
- [x] Documentation: crate docs, `README` per package, a "getting started" for apps and for hosts. Done:
  [GETTING_STARTED.md](GETTING_STARTED.md) with code for an application client (registration and login in JS, run
  against the example host), a host (configuration, routing, sessions on the application's own endpoints, a
  production checklist that says rate limits are the application's, [HST-16]), a relying party and the key tool; a
  compiled tour in the crate docs of `rootcard` (registration, receipt, unlock, proof) and `rootcard-host` (configure
  and route); a README per package that links the guide. Also `CONTRIBUTING.md` (the rules of AGENTS.md for people),
  issue templates that send security reports to private reporting, a pull request template, a code of conduct
  (Contributor Covenant 2.1) and funding information (`.github/FUNDING.yml` and `funding` in the npm package, GitHub
  Sponsors)
- [ ] External review of the spec and the crypto use before `1.0.0`
- [x] Host pointer: a host on a path of a shared domain (`https://example.com/rootcard`) can be named by the bare domain.
  Decided: `GET <origin>/.well-known/rootcard` → `{ v, base, api }` ([HST-23]); resolved only for a typed origin, only
  to a base URL on the same origin (`wrong_host` otherwise), without redirects, at most 4 096 bytes; never stored, so
  `home.url` and signed messages keep the resolved base URL ([LGN-4]) and addresses from logs are not resolved.
  `well_known_base` / `wellKnownBase` and `is_origin` / `isOrigin` in both cores with vectors, `http::well_known` in
  `rootcard-host`, used by `--host` and `--from` in the key tool and by the host fields of `keytool.html`
  (THREAT_MODEL.md T46). Cross-origin pointers (a domain that delegates to another host) are not allowed; they would
  need the client to show the target before registering
- [ ] HTTP binding: freeze `/v0` as `/v1` for `1.0.0` (HOST_PROTOCOL.md §1.3) and decide how long hosts keep serving
  `/v0`
- [ ] Decide which "Later" items, if any, are in `1.0.0` (the sign-in flow of docs/proposals/signin.md adds a label and
  can also come after `1.0.0` without breaking it)

**Acceptance:** `1.0.0` published on crates.io and npm from CI, with provenance, and the docs build on docs.rs. The
publishing part was first met by `0.1.0` and has held for every release since.

## Later

- Passkeys (WebAuthn PRF) as a lock type
- Sign-in at other services (relying parties): the flow, the `rootcard/signin/v1` label and `rootcard signin` in the key
  tool, from [proposals/signin.md](proposals/signin.md); an agent for other command line programs after that
- Linked accounts, from [proposals/links.md](proposals/links.md). Decided there (§12): the profile key `user.links`, a
  service-neutral spec with a registry of declarative descriptors in `spec/links/` (`github`, `dns`, `web` first),
  no root-signed link list, and no e-mail, which cannot be proved publicly
- Standard profile keys (a display name, a small avatar image) with display rules: raster images only, never SVG or
  URLs to load (SPEC [DAT-8] needs a clarification for images)
- An additional host secret (OPAQUE or a pepper) as a lock layer against offline guessing (THREAT_MODEL.md AR1), and a
  signed client not served by the host (AR2)
- Witnesses and pre-rotation (`v: 2`) against a stolen recovery key, together with deterministic fork resolution (SPEC
  Appendix A)
- Host helpers for JavaScript servers (`rootcard/host`), if there is demand; the JS core already verifies everything a
  host checks
- Post-quantum key types (ML-DSA, ML-KEM) by new type tags
- Federation of public logs between hosts
- First application: Xigna (its integration plan is in the Xigna repository)
