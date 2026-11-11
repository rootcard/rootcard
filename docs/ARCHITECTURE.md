# rootcard: architecture

How the packages fit together, what runs where, and how a server uses rootcard. The format is
[spec/SPEC.md](../spec/SPEC.md); the HTTP binding is [HOST_PROTOCOL.md](HOST_PROTOCOL.md); the threat model is
[THREAT_MODEL.md](THREAT_MODEL.md). This document is informative and describes the target of [PLAN.md](PLAN.md).

---

## 1. Components

```
                 ┌──────────────────────────── one monorepo ────────────────────────────┐
 spec/SPEC.md ──►│ crates/rootcard        core (Rust)    pure: formats, verification, crypto │
 spec/vectors ──►│ packages/rootcard      core (JS)      the same functions, byte for byte   │
                 │ crates/rootcard-host   host library   storage traits + handlers (Rust)    │
                 │ crates/rootcard-cli    key tool       binary `rootcard`                   │
                 │ packages/rootcard/keytool.html        key tool page, works from file://   │
                 │ crates/xtask           vectors, repo checks, JS/Rust differential test    │
                 │ fuzz/                  fuzz targets: parsers, verifiers, host router      │
                 └────────────────────────────────────────────────────────────────────────┘
```

| Component | Runs on | Holds | Power |
|---|---|---|---|
| Application client (uses `packages/rootcard`) | Browser, app | Password, unlocked account key | Low |
| Key tool (`rootcard-cli`, `keytool.html`) | The user's machine | Recovery key | High |
| Host (uses `rootcard-host` or the core directly) | Server | Logs, its identities' vaults, sessions, host key | None over identities |
| Relying party (uses the core) | Any server or client | Logs it fetched | None |

Both cores are **pure** ([IMP-1]): no I/O, no clock, no randomness. Everything around them (HTTP, storage, time, random
bytes, user interaction) belongs to the host library, the key tool or the application.

---

## 2. What a server does with rootcard

A server meets rootcard in one of two roles.

**Host** (stores identities and accepts logins, SPEC §17). Per request it parses strict JSON, checks sizes, verifies a
few Ed25519 signatures, compares hashes and does one atomic storage update. It never sees a password, never runs
Argon2id and never decrypts a vault, so it needs only the verification half of the core (§4). It can run on many servers
in front of one shared store ([HST-19]), and it can rotate its key and change its address without touching any identity
([HST-17], [HST-18]).

**Relying party** (any server that wants to know "is this rootcard user who they say?", SPEC §14). It gives the user a
fresh challenge and its own `recipient`, receives a proof and the user's log, fetches the newest log from the identity's
home if it wants to be sure it is current, and calls `verify_proof`. It stores at most the newest log per identity it
deals with ([VER-4]). An application that runs its own host does not need proofs for its own users: the login result
([LGN-1] step 6) already is the answer.

### 2.1 Workflows

The application is a website whose server uses `rootcard-host` and whose pages use `packages/rootcard`. The user sees a
normal account: a username and a password. rootcard shows itself only twice: the recovery card to save at registration,
and the key tool for the rare actions that need it. Requests are listed in HOST_PROTOCOL.md §7.

| Workflow | What the user does | What the browser does | What the server does |
|---|---|---|---|
| **Register** | Picks a username and a password; saves the recovery card (file or print) | Generates the recovery key, builds the inception, the first instance (home = this server), a vault with one password slot and an empty profile; erases the recovery key ([CLT-1]) | Checks and stores them, claims the username, adds its receipt ([HST-3]) |
| **Log in** | Types username and password | Fetches and unlocks the vault (one Argon2id run), signs the challenge with the account key and the password's lock key ([LGN-1]) | Checks both signatures and the version, returns the login result; the application opens its session ([HST-10]) |
| **Change password** | Types the current and the new password | Builds the new lock and vault, signs a change proof with the old password ([CHG-1]) | Checks the session and the proof, stores the vault ([CHG-2]); the old password stops working at once |
| **Download the account** | Clicks "download" | – | Returns the account file: log, profile and vault ([FIL-2]) |
| **Move to another server** | Opens the key tool with the account file and the recovery card, picks the new server; then logs in there with the same password | The key tool mints a new instance at the new server, carrying data, profile and passwords over ([KT-3]) | The new server receipts it and becomes home; the old one deletes the vault and answers `not_home` ([HST-7]) |
| **Forgot password** | Opens the key tool with the recovery card, chooses a new password | The key tool mints a new instance on the same server with only the new password ([KT-8]) | Receipts it; every old password, vault copy and session stops working |

Consequences an application should state plainly:

- **The recovery card is the only way back.** Without it a forgotten password loses the account: no server, the
  application's included, can reset it ([PWR-5]). An account whose card is lost keeps working with its password, but can
  no longer be reset or moved.
- **A password change is not a revocation.** It stops the old password at once, but someone who already unlocked the
  vault with it keeps a copy of the account key until a new instance ([CHG-3]). After a suspected leak, the user resets
  with the recovery card instead.
- **The application may show just the username** inside its own realm ([CLT-7]).

### 2.2 A login, seen from the host

Paths are relative to the API root `<base URL>/v0` (HOST_PROTOCOL.md §1.3).

```
client                                   host                                       storage
  │ GET /id/{a}/log                        │──── read events, state ───────────────────►│
  │ POST /id/{a}/challenge {login} ───────►│──── put nonce (60 s, purpose, account) ───►│
  │ POST /id/{a}/login {nonce, version,    │──── take nonce (atomic) ──────────────────►│
  │      url, lock, sig, lock_sig} ───────►│     check home, url, version, signatures   │
  │ ◄──── login result + session ──────────│──── put session {account, instance} ─────►│
  │ GET /session/vault (bearer) ──────────►│──── session.instance == current? ─────────►│
```

---

## 3. `rootcard-host`

A library, not a server: it owns the rules of SPEC §17 and leaves HTTP, storage and secrets to the application.

```rust
pub struct Host<S: IdentityStore, C: ChallengeStore, T: SessionStore> { pub config: HostConfig, pub store: S, pub challenges: C, pub sessions: T }

pub struct HostConfig {
    pub key_seed: Zeroizing<[u8; 32]>,   // current host key                                 [HST-17]
    pub retired_keys: Vec<[u8; 32]>,     // public parts of earlier host keys
    pub urls: Vec<String>,               // accepted base URLs                               [HST-18]
    pub realms: Vec<RealmConfig>,        // realm + UsernamePolicy                           [RLM-3], [USR-3]
    pub peers: Vec<[u8; 32]>,            // peer host keys                                   [HST-15]
}

pub trait IdentityStore {               // shared by all servers of the host
    fn load(&self, account: &str) -> Result<Option<Stored>, StoreError>;          // events, state, vault, profile
    fn insert(&self, new: &Stored, claim: bool) -> Result<Insert, StoreError>;    // atomic handle claim   [HST-3]
    fn swap(&self, account: &str, expected: &Expected, new: &Stored) -> Result<bool, StoreError>;  //     [HST-19]
    fn by_handle(&self, key: &HandleKey) -> Result<Vec<String>, StoreError>;      // (realm, lower username, tag)
    fn handle_claimed(&self, key: &HandleKey) -> Result<bool, StoreError>;        // registered here only  [HST-4]
    fn changes(&self, since: u64, limit: usize) -> Result<(u64, Vec<String>), StoreError>;          // peers
}
pub trait ChallengeStore { fn put(..); fn take(..) }      // atomic get-and-delete, 60 s       [CHL-2]
pub trait SessionStore { fn put(..); fn get(..); fn touch(..); fn remove(..) }   // SHA-256 of tokens [HST-10]

impl Host<S, C, T> {
    pub fn register(&self, body: &Value, now: i64) -> HostResult<Value>;
    pub fn instance(&self, account: &str, body: &Value, now: i64) -> HostResult<Value>;
    pub fn events(&self, account: &str, body: &Value, now: i64) -> HostResult<Value>;
    pub fn challenge(&self, account: &str, purpose: Purpose, now: i64, nonce: [u8; 32]) -> HostResult<Value>;
    pub fn login_result(&self, req: &LoginRequest, now: i64) -> HostResult<LoginResult>;   // own sessions
    pub fn session_valid(&self, session: &Session, now: i64) -> HostResult<bool>;          // [HST-11]
    // lookup, log, public, locks, fetch, login (opaque tokens), session endpoints, put_vault, peer_push ...
}
pub fn http::route(host, &Request, now, random) -> Response;       // the binding of HOST_PROTOCOL.md
```

- **Time and randomness are parameters**, like in the core, so handlers are deterministic in tests. The host application
  passes its clock ([HST-21]) and random bytes from `getrandom`.
- **Errors are the spec's codes** ([SPEC §20]); the HTTP mapping is in HOST_PROTOCOL.md §1.1. Each error that needs
  extra data (`not_home`, `stale_version`, `fork`) carries it.
- **Storage holds the verified log state** next to the events ([LOG-16]), so a request with new events runs `extend_log`
  on the stored state and verifies only the new events ([LOG-15]).
- **Sessions are the application's.** `login` returns a `LoginResult { account, handle, instance, version }`; the
  application creates a session in whatever form it uses and calls `session_valid` (one indexed read, cacheable for 10
  s) on every use. Optional helpers create and check opaque tokens stored as SHA-256 hashes ([HST-10]).
- **Retries** are recognized by the handlers ([HST-20]); the store only needs compare-and-swap.
- **Rate limits are the application's.** They are keyed by network address, which only the server in front of the
  handlers knows, so the crate limits nothing itself; the application applies HOST_PROTOCOL.md §6 before `http::route`
  and answers `rate_limited` ([HST-16], THREAT_MODEL.md T11, T26).
- **In-memory implementations** of the traits ship with the crate for tests and the example host; §3.1 is a SQL schema.
- **No framework, no async runtime.** Handlers are plain functions over JSON values; `http::route` maps the binding onto
  them under the API version `http::API_VERSION` (`v0` until 1.0.0, HOST_PROTOCOL.md §1.3) and `examples/host.rs`
  serves it with `std::net` for development. `HostConfig::check` refuses addresses that are not base URLs or that end
  in a version segment ([HST-22]), since they go into signed logs as `home.url`. `http::well_known` answers the host
  pointer at `<origin>/.well-known/rootcard` ([HST-23]); it lies outside the base URL, so the application routes it
  (the example host does). The traits are synchronous; async storage can wrap them.

### 3.1 A SQL schema for the store

One row per identity is enough, because every change of an identity is one compare-and-swap ([HST-19]):

```sql
CREATE TABLE identities (
  account     TEXT PRIMARY KEY,               -- 52-character id
  realm       TEXT NOT NULL,
  username_lc TEXT NOT NULL,                  -- ASCII lower case
  tag         TEXT NOT NULL,                  -- first 4 characters of the id
  claimed     BOOLEAN NOT NULL,               -- registered here (false: any other arrival reserves nothing, [HST-4])
  events      JSONB NOT NULL,                 -- the newest valid log
  state       JSONB NOT NULL,                 -- LogState::to_value, only ever written after verify/extend_log [LOG-16]
  version_seq INTEGER NOT NULL,               -- the compare-and-swap columns of Expected
  version     TEXT NOT NULL,
  vault       JSONB, vault_rev BIGINT,        -- only while this host is home [VLT-5]
  public      JSONB, public_rev BIGINT,
  changed     BIGSERIAL                       -- cursor for GET /peer/changes
);
CREATE UNIQUE INDEX identities_handle ON identities (realm, username_lc, tag) WHERE claimed;   -- [HST-4]
CREATE INDEX identities_lookup ON identities (realm, username_lc, tag);

-- swap: UPDATE identities SET ... WHERE account = $1 AND version = $2 AND vault_rev IS NOT DISTINCT FROM $3
--       AND public_rev IS NOT DISTINCT FROM $4   (one row updated = success)

CREATE TABLE challenges (nonce BYTEA PRIMARY KEY, account TEXT NOT NULL, purpose TEXT NOT NULL, expires BIGINT NOT NULL);
-- take: DELETE FROM challenges WHERE nonce = $1 RETURNING account, purpose, expires
CREATE TABLE sessions (token_hash BYTEA PRIMARY KEY, account TEXT NOT NULL, instance BYTEA NOT NULL, last_used BIGINT NOT NULL);
```

A session check reads the session and the identity's `state` (or a 10 s cache of the current instance hash, [HST-11]);
challenges and sessions past their expiry must be deleted, by a periodic job or on insert: anyone can request a
challenge without authentication, so a store that keeps expired ones grows without bound (`MemoryChallengeStore` drops
them on insert, keeping a just-expired one for one more lifetime so that it still answers `challenge_expired`):

```sql
DELETE FROM challenges WHERE expires < $now - 60;
DELETE FROM sessions WHERE last_used < $now - 86400;
```

---

## 4. The cores

The same functions exist in both languages with the same names (snake_case in Rust, camelCase in JS) and are checked by
the shared vectors ([CNV-4]).

| Area | Functions | Needs | Feature |
|---|---|---|---|
| Encodings | `canonical`, `parse_json`, `base64url_*`, `base32_*`, key and signature parsing | – | always |
| Recovery key | `parse_recovery_key`, `format_recovery_key`, `derive_recovery_keys` | SHA-256, HKDF | always |
| Identity | `inception`, `account_id`, `handle`, `parse_handle`, `extended_tags` | SHA-256, Ed25519 | always |
| Log | `verify_log`, `extend_log`, `verify_pending`, `compare_logs`, `current_instance` | SHA-256, Ed25519 | always |
| Messages | `login_message`, `fetch_message`, `change_message`, `receipt_message` and their verification | Ed25519 | always |
| Proofs | `prove`, `verify_proof`, `statement_challenge` | Ed25519 | always |
| Public data | `verify_public`, `PublicProfile::set` (namespace-checked) | Ed25519 | always |
| Vault checks | `verify_vault` (signatures, locks, limits; no decryption) | Ed25519 | always |
| Vault crypto | `Vault::create`, `unlock`, `change_password`, `add_slot`, `new_instance`, contents | X25519, HKDF, AES-GCM, Argon2id, NFC | `vault` |
| Files | `AccountFile::export` / `import`, `RecoveryCard` | as above | always (vault parts with `vault`) |

Hosts and relying parties use the core **without** the `vault` feature (Rust: `default-features = false`), which removes
Argon2id, X25519, AES-GCM and Unicode normalization from their build. Clients and the key tool use the default features.
In JavaScript, the vault functions live in their own module, so a server bundle that does not import it never loads
them.

---

## 5. Dependencies

Few dependencies, each justified (AGENTS.md rule 6). The budget:

| Package | Runtime dependencies |
|---|---|
| `rootcard` (always) | `ed25519-dalek`, `sha2`, `hkdf` (for `derive_recovery_keys`), `zeroize` |
| `rootcard` (`vault`) | + `x25519-dalek`, `aes-gcm`, `argon2`, `unicode-normalization` (passwords only, SPEC [LCK-7]) |
| `rootcard-host` | `rootcard` without `vault`, `zeroize`; random bytes and time come from the application |
| `rootcard-cli` | `rootcard`, `getrandom`, `zeroize`, `ureq` with `rustls` (HTTPS to hosts), `rpassword` (no-echo input) |
| `packages/rootcard` | none (WebCrypto, `String.prototype.normalize`; own Argon2id and BLAKE2b) |
| `crates/rootcard-host/examples/host.rs` (not published) | `getrandom` (development dependency) |
| `tests/browser` (not published, CI only) | `playwright` at an exact version, installed in the CI job only: the vectors and `keytool.html` in Chromium, Firefox and WebKit |
| `crates/rootcard-cli/tests` (not published) | `rootcard-host` by path only, so `cargo publish` drops it: the key tool's end-to-end test runs a host in the test process |
| `xtask` (not published) | `rootcard`, `zeroize`; `curve25519-dalek`, `sha2`: only to construct the rejected signature classes of the vectors. The differential test runs Node on `tests/differential/run.mjs`, which imports the npm package and its vector operations and has no dependencies |
| `fuzz` (not published, its own workspace) | `libfuzzer-sys` (with `arbitrary`, and `cc` to build libFuzzer): the fuzz targets, run with `cargo fuzz` on a dated nightly toolchain in CI. Outside the main workspace, so `cargo deny` and the MSRV job do not cover it; nothing from it is shipped |

The budget is enforced, not only written down. `cargo deny` (`deny.toml`, the CI job `deny`) checks the main
workspace's licenses, sources, duplicates and RustSec advisories on every pull request, and `advisories.yml` repeats the
advisory check daily. `xtask repo-check` fails if the npm package (or `tests/browser`) gains a dependency, `overrides`
or an install script, and pins every tool CI installs. The published packages are reproducible: the release checks that
crates.io and npm serve exactly what CI builds from the tag (RELEASING.md §4).

None of the core's dependencies is built with its `getrandom` or `rand_core` features: the core draws no randomness.
Canonical JSON,
base64url and base32 are implemented in the cores themselves: they are small, they must be strict in ways general
libraries are not (duplicate members, number forms, canonical padding), and they are covered by reject vectors. No
`serde_json` in the core.

---

## 6. Documentation map

| Document | Kind | Content |
|---|---|---|
| [AGENTS.md](../AGENTS.md) | Rules | How to work in this repository |
| [docs/PLAN.md](PLAN.md) | Plan | Phases, acceptance criteria, decisions, deviations |
| [docs/DESIGN.md](DESIGN.md) | Motivation | Requirements and the original design (superseded where SPEC differs) |
| [spec/SPEC.md](../spec/SPEC.md) | **Normative** | The format and the rules for every party |
| [spec/vectors/](../spec/vectors/) | **Normative** | Shared test vectors |
| [docs/GETTING_STARTED.md](GETTING_STARTED.md) | Guide | Code for each role: application client, host, relying party |
| [docs/CONCEPTS.md](CONCEPTS.md) | Guide | The log, vault, recovery card, proofs and verification, citing SPEC rules |
| [docs/THREAT_MODEL.md](THREAT_MODEL.md) | Security | Goals, attackers, threats, accepted risks |
| [docs/HOST_PROTOCOL.md](HOST_PROTOCOL.md) | Binding | Recommended HTTP endpoints for hosts |
| docs/ARCHITECTURE.md | Overview | This document: components, server usage, dependencies |
| [docs/RELEASING.md](RELEASING.md) | Process | Preparing, publishing and reproducing releases |
| [docs/proposals/](proposals/) | Drafts | Proposals that are not normative yet (sign-in at other services, linked accounts) |
| [fuzz/README.md](../fuzz/README.md) | Process | The fuzz targets and how to run them |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Rules | AGENTS.md's rules for people, the checks, pull requests |
| [SECURITY.md](../SECURITY.md) | Policy | Reporting vulnerabilities, supported versions |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Policy | Contributor Covenant 2.1 |

A change to the format updates SPEC (and vectors), then THREAT_MODEL if a threat changes, HOST_PROTOCOL if an endpoint
changes, and this document if a component or dependency changes, in the same commit.
