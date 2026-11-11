# rootcard: getting started

This guide shows how to add rootcard to an application and how to run a host. It is informative: the rules are in
[spec/SPEC.md](../spec/SPEC.md) (cited as `[LGN-1]`), the endpoints in [HOST_PROTOCOL.md](HOST_PROTOCOL.md), and the
ideas behind the log, the vault and the recovery card in [CONCEPTS.md](CONCEPTS.md). Read the
[threat model](THREAT_MODEL.md) before you put real accounts on it.

---

## 1. Which part do you need?

| You are building… | You use | Section |
|---|---|---|
| A sign-up and login page (browser or app) | the npm package `rootcard` and `rootcard/vault` | §2 |
| The server that stores identities and accepts logins (a *host*) | the crate `rootcard-host` (Rust) | §3 |
| A server that only checks "is this rootcard user who they say?" (a *relying party*) | the core, `verify_proof` / `verifyProof` | §4 |
| Recovery, moving hosts, resetting a forgotten password | nothing: users run the key tool (`rootcard` CLI or `keytool.html`) | §5 |

Most applications need §2 and §3: a page where users register and log in, and a host on the application's own server.

Two rules shape everything below:

- **Low power in the application, high power in the key tool** (SPEC §16). The password unlocks the account key, which
  can log in, edit the profile and the private data, export and prove. Everything that changes who can access the
  account or where it lives needs the **recovery key**, and an application never asks for it ([PWR-6]). Users enter it
  only in the key tool.
- **The cores are pure** ([IMP-1]). They make no requests, read no clock and draw no randomness. You pass the time
  (Unix seconds) and a source of random bytes (`systemRandom` in JS, `getrandom` in Rust), and you do the HTTP.

## 2. An application client (JavaScript)

```sh
npm install rootcard
```

The package has no dependencies and no build step. It runs in browsers with WebCrypto Ed25519 and X25519 and in Node 20
or later. Call `await checkSupport()` once and show a clear message where it returns `false`; there is no weaker
fallback (PLAN.md D5).

```js
import * as rc from "rootcard";                                   // verification, messages, encodings
import { register, deriveLockSecrets, unlockVault } from "rootcard/vault"; // passwords, Argon2id, vaults

const base = "https://id.example.com";      // the host's base URL, never ending in /v0 ([HST-22])
rc.checkBaseUrl(base);                       // throws RootcardError("bad_field") otherwise
const api = `${base}/${rc.API_VERSION}`;     // endpoints live under <base URL>/v0 (HOST_PROTOCOL.md §1.3)
const realm = "global";                      // or your application's own realm ([RLM-1])
const now = () => Math.floor(Date.now() / 1000);

async function call(method, path, body) {
  const res = await fetch(`${api}${path}`, {
    method,
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : rc.canonicalString(body),
    credentials: "omit",                     // rootcard never uses cookies (HOST_PROTOCOL.md §1)
  });
  const text = await res.text();
  const value = text ? rc.parseJson(text) : null;
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${value?.error}`);
  return value;
}
```

Errors from the host are `{ "error": "<code>" }` with the codes of SPEC §20; errors from the core are `RootcardError`
with the same `code`. Map the codes to your own messages.

### 2.1 Registration ([CLT-1])

```js
const host = await call("GET", "/host");                              // the host key and its realms
const recoveryKey = await rc.newRecoveryKey(realm, username, rc.systemRandom); // never 32 bytes of your own ([CRY-9])
const reg = await register(recoveryKey, realm, username, password, "Password",
  { key: host.key, url: base }, now(), rc.KDF_DEFAULT, rc.systemRandom);
recoveryKey.fill(0);

// Hand reg.card to the user (a download, rc.cardText(reg.card) to print) BEFORE anything is sent: once the host has
// the identity, the card is the only copy of the recovery key.
await saveRecoveryCard(reg.card);

const done = await call("POST", "/id/register", { log: reg.log, vault: reg.vault, public: reg.public });
// done.handle is the user's handle, such as "Astra#3F9C"; done.account is the account id to store.
```

`register` checks the password first (`weak_password`: at least 12 characters, not the username, [LCK-8]) and the
username (`bad_username`). The host answers `handle_taken` when the username and tag are already registered there, and
`username_policy` when the host's policy refuses the username.

Store the **account id**, never the handle, as the key of your own user records, and compare full account ids
([HDL-2]).

### 2.2 Login ([LGN-1])

```js
const found = await call("GET", `/id/lookup?realm=${realm}&handle=${encodeURIComponent(handle)}`);
const { events } = await call("GET", `/id/${found.account}/log`);
const state = await rc.verifyLog(events, { realms: [realm], now: now() }); // never trust the host's word
const home = state.instance.home.url;   // the primary host; continue there if it is not `base` ([HST-9])

// Prove the password to the host without sending it, and get the encrypted vault ([FET-1]).
const { locks } = await call("GET", `/id/${state.account}/locks`);
const lock = locks[0];                  // or let the user pick by lock.label
const { authSeed } = await deriveLockSecrets(state.account, lock.id, password, lock.kdf,
  rc.base64urlDecode(lock.kdf.salt));   // Argon2id: about 3 s on a laptop, show progress
const fch = rc.parseChallenge(await call("POST", `/id/${state.account}/challenge`, { purpose: "fetch" }));
const fsig = await rc.ed25519Sign(authSeed, rc.fetchMessage(state.account, fch.host, lock.id, fch.nonce, home));
const { vault } = await call("POST", `/id/${state.account}/fetch`,
  { lock: lock.id, nonce: fch.nonce, url: home, sig: rc.base64urlEncode(fsig) });
authSeed.fill(0);

// Unlock it locally and log in with the account key ([VLT-8], [LGN-1] steps 4–6).
const unlocked = await unlockVault(vault, state, { lock: lock.id, password });
const lch = await call("POST", `/id/${state.account}/challenge`, { purpose: "login" });
const login = await rc.signLogin(state, lch, home, lock.id, unlocked.contents.accountSeed, unlocked.lockSeed);
const session = await call("POST", `/id/${state.account}/login`, login);
// session.token is a bearer token for /session/* and for your own endpoints (§3.3); session.handle is the handle.
```

A wrong password fails at the `fetch` step (`bad_signature`: the lock key derived from it is not the one on record), and every failure counts against the rate limits
([FET-3]). The unlocked vault holds the account key (`unlocked.contents.accountSeed`) and the private data
(`unlocked.contents.data`); keep it in memory only, overwrite the bytes on logout, and never send it anywhere
([LGN-2], [LGN-3]).

The `url` in the fetch and login messages is the base URL the client talks to, exactly as configured ([LGN-4]): the
host refuses a message made for another address (`wrong_host`), so a phishing site cannot relay a login.

### 2.3 After login

- **Private data and the profile.** `updateContents` (private data, `PUT /session/vault`), `setData` / `signPublic`
  (public profile, `PUT /session/public`). An application writes only its own namespace `app.<name>.` and `user.` ([DAT-4], [DAT-7]).
- **Change the password.** `changePassword` builds the new lock and vault; sign the change proof with the old lock's
  key and send it to `POST /session/password` ([CHG-1]).
- **Export.** `GET /session/export` returns the account file for the user to keep ([FIL-2]).
- **Logout.** `POST /session/logout`, then overwrite `unlocked.contents.accountSeed` and `unlocked.vaultKey`.

The flows with every request are in HOST_PROTOCOL.md §7; the key tool's source (`packages/rootcard/tools/keytool.app.js`)
is a complete client for the high-power ones.

### 2.4 Serving the page

A page that handles passwords is the most valuable target of the whole system (THREAT_MODEL.md T19). Serve it with a
strict Content Security Policy (no inline script, no third-party script), `X-Content-Type-Options: nosniff` and HSTS,
and bundle `rootcard` yourself rather than loading it from a CDN.

## 3. A host (Rust)

```sh
cargo add rootcard --no-default-features   # verification only: no Argon2id, X25519 or AES-GCM in the build
cargo add rootcard-host getrandom zeroize
```

`rootcard-host` is a library, not a server. `Host` holds the rules of SPEC §17 over three storage traits, and
`http::route` turns a request of the HTTP binding into a response. You supply the HTTP server, the storage, the clock,
random bytes and the host key.

### 3.1 Configure

```rust
use rootcard_host::store::{MemoryChallengeStore, MemoryIdentityStore, MemorySessionStore};
use rootcard_host::{Host, HostConfig, RealmConfig, UsernamePolicy};
use zeroize::Zeroizing;

let config = HostConfig {
    key_seed: Zeroizing::new(load_host_key()),          // 32 bytes from your secret store ([HST-17])
    retired_keys: Vec::new(),                           // public keys of earlier host keys, after a rotation
    urls: vec!["https://id.example.com".into()],        // base URLs; the first is preferred ([HST-18])
    realms: vec![RealmConfig { realm: "global".into(), policy: UsernamePolicy::DEFAULT }],
    peers: Vec::new(),                                  // host keys of peer hosts ([HST-15])
};
config.check()?;                                         // every address a base URL without /v0 ([HST-22])
let host = Host::new(config, MemoryIdentityStore::new(), MemoryChallengeStore::new(), MemorySessionStore::new());
```

The addresses go into the users' signed logs as `home.url`, so choose them once. On a domain of its own the domain is
the base URL. On a domain shared with the application, give the host a path (`https://example.com/rootcard`) and answer
`GET https://example.com/.well-known/rootcard` with `http::well_known(&host.config, "https://example.com")`, so users can
type the bare domain ([HST-23]).

### 3.2 Serve

Map your framework's request onto `http::Request` and the `http::Response` back. The path is relative to the base URL
and starts with the API version (`/v0/host`):

```rust
use rootcard_host::http::{route, Request, MAX_BODY};

// in your handler, after checking Content-Length against MAX_BODY (413 before reading the body):
let req = Request {
    method: method.to_string(),                       // GET, POST, PUT, OPTIONS
    path: path_below_base_url.to_string(),            // "/v0/id/lookup?realm=global&handle=Astra%233F9C"
    bearer: authorization.and_then(|v| v.strip_prefix("Bearer ")).map(str::to_string),
    peer: None,                                       // the Rootcard-Peer-* headers, if you have peers
    body,
};
let now = unix_seconds();                             // a synchronized clock ([HST-21])
let res = route(&host, &req, now, &mut |b| getrandom::fill(b).expect("random"));
// res.status, res.body (canonical JSON, Content-Type: application/json) and res.headers (CORS, Cache-Control)
```

`examples/host.rs` in the repository does exactly this on `std::net`, in about 140 lines, and is the reference for the
header mapping. Run it to try things locally (§6). The handlers are synchronous; call them from a blocking task in an
async server.

### 3.3 Know who is logged in on your own endpoints

A login through the host returns an opaque bearer token. Your application's own endpoints check it with
`Host::session`, which also ends the session when the identity moves to another instance or is retired ([HST-11]):

```rust
let (session, stored) = host.session(&token, now)?;   // unauthorized if unknown, idle, moved or retired
let account = &session.account;                        // your user key: the account id, not the handle ([HDL-2])
let handle = &stored.state.handle;                     // for display
```

An application that issues its own sessions (a cookie with its own CSRF protection) calls `Host::login_result` instead
of `login` and checks `Host::session_valid` on every use (ARCHITECTURE.md §3).

### 3.4 Before production

The in-memory stores and the example host are for development. A production host also needs:

- **Shared storage** with compare-and-swap: implement `IdentityStore`, `ChallengeStore` and `SessionStore` over your
  database. ARCHITECTURE.md §3.1 has a SQL schema, and the traits' documentation states each method's duty (atomic
  claims, atomic take of challenges, expiry). With that, any number of servers can share one store ([HST-19]).
- **Rate limits.** `rootcard-host` does not limit anything itself: the limits are keyed by network address, which only
  your server knows. Apply those of HOST_PROTOCOL.md §6 in front of `route` and answer `429 rate_limited` with
  `Retry-After` ([HST-16]). Without them, the vault fetch is an unlimited online password guess (THREAT_MODEL.md T11).
- **TLS** on every address (plain `http://` is accepted only on loopback addresses), and the security headers of §2.4
  on any page you serve.
- **The host key** in a secret store or a signing service. Rotating it keeps old receipts valid as long as the old
  public key stays in `retired_keys` ([HST-17]).
- **Peers**, only if you run more than one host for a realm: add each other's keys to `peers` and forward the
  `Rootcard-Peer-*` headers ([HST-15], HOST_PROTOCOL.md §5).

A host never sees a password, never runs Argon2id and never decrypts a vault; a request costs a few signature checks.

## 4. A relying party (proofs)

A service that does not host an identity can still check that a user controls it, with a proof (SPEC §14,
CONCEPTS.md §4). Give the user a fresh 32-byte challenge and your own `recipient` string, receive the proof and the
user's log, and verify both together:

```rust
use rootcard::log::VerifyOptions;
use rootcard::proof::verify_proof;

// `log` as received (parsed with rootcard::parse_json); fetch the newest from the identity's home to be sure.
let state = verify_proof(&proof, &log, &challenge, "example.org", &VerifyOptions::new(["global"]).at(now))?;
// state.account is who it is; keep the newest log per account you deal with ([VER-4]).
```

```js
const state = await rc.verifyProof(proof, log, challenge, "example.org", { realms: ["global"], now: now() });
```

The user's side is `prove(state, "account", accountSeed, challenge, recipient)` after login, or the key tool's `prove`
with the recovery key. An application that runs its own host does not need proofs for its own users: the login already
is the answer.

## 5. Recovery and the key tool

Applications never handle the recovery key ([PWR-6]), so they never offer recovery themselves. Point users to the key
tool for everything high power:

| The user wants to… | Key tool |
|---|---|
| reset a forgotten password | `rootcard reset-password --card <card> --from <host>`, or "Reset password" in `keytool.html` |
| move to another host, or restore after the host lost data | `rootcard restore --card <card> --account <file> --host <new host>` |
| add a password for another device | `rootcard add-password` |
| replace a recovery key that may be exposed | `rootcard rotate-recovery` |

`keytool.html` is one file that works from the user's own disk (`file://`) and ships in the npm package; point users to
that published copy rather than serving it from your host, so a compromised host cannot change the page that asks for the recovery key
(THREAT_MODEL.md AR2). The CLI's options are in `crates/rootcard-cli/README.md` and `rootcard help`.

## 6. Try it locally

```sh
# A development host on http://127.0.0.1:8787 (in memory, no TLS, no rate limits).
cargo run -p rootcard-host --example host

# An identity on it with the key tool, then inspect the account file.
cargo run -p rootcard-cli -- new --realm global --username Astra --host http://127.0.0.1:8787
cargo run -p rootcard-cli -- inspect Astra-*.rootcard.json
```

The code of §2.1 and §2.2 runs as it stands in Node 20 or later against this host, with `base =
"http://127.0.0.1:8787"`.
