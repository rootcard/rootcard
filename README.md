# rootcard

**A portable, self-certifying identity for online logins — an ID card you own.**

> Status: **0.3.3, pre-1.0.** Published on crates.io and npm. The format (format version 1) is a draft and has not had
> an external security review yet ([docs/PLAN.md](docs/PLAN.md), phase 6). Do not rely on it for high-value accounts
> before `1.0.0`.

Accounts today are rows in someone else's database: the server owns your identity, stores a copy of your password secret,
and when it leaks or shuts down, you are gone. rootcard turns that around. Your identity is a **card you hold**: an
account id that only your own key can stand behind, a public signed history, and an encrypted vault. Servers can check that you
are you, but they can never become you, never learn your password, and never keep you from moving. One offline
**recovery key** can always rebuild everything, on any server, forever.

## Two ways to use it

### 1. A safer username-and-password login for your own service

In its simplest form rootcard is a **standardized username-and-password login** that you add to your own server. Users
see what they already know: a username, a password and, once, a recovery card to save. Under the hood:

- The password **never leaves the user's device**. It unlocks an encrypted vault in the browser, and the browser signs
  a one-time challenge. The server stores **no password hash** and has nothing it could replay.
- A stolen session or a captured login message is useless elsewhere: every login is bound to the server, its address,
  the realm and the account's exact version.
- A forgotten password is reset with the recovery card in the key tool. There is no e-mail reset that an attacker could
  take over.

You need nothing but the libraries: your server is the **host** (`rootcard-host`, Rust), your web pages use the npm
package. There is no redirect and no third party. An application that runs its own host gets the login result directly
and needs none of the cross-service machinery below.

### 2. An ID card for many websites and services

The same identity can be your login at other services:

- You choose a **home**: any host that serves your realm, run by someone you trust or **hosted by yourself**. It keeps
  your vault and is the only place your password is typed.
- Any other service checks who you are **by itself**: it asks you to sign a fresh challenge addressed to it and verifies
  the signature against your public log. It does not call a central API and does not trust your home's word.
- Your account at those services is keyed by your **account id**, which never changes. Move to another home, or reset
  your password, and every service still knows you.

The proofs that make this work (`prove`, `verify_proof`) are in the core. A standard sign-in flow for websites and command
line tools, built on them, is a **proposal**: [docs/proposals/signin.md](docs/proposals/signin.md).

### You are in control

Only the **recovery key** can change who can access the identity, where it lives or whether it exists. It is shown once
at registration and is then kept offline, on the card. Pages that look an identity up may show its *recovery public
key*: that is public and safe to see. The secret is never shown on, or typed into, a website. The password has low
power: log in, edit your data, export.

| You have | If you forget the password | If your home server disappears |
|---|---|---|
| Password only | The identity is lost | The identity is lost |
| Account file, no recovery card | Lost: the file is locked with the same password | Data readable with the password; no new home without the card |
| Recovery card | Reset in the key tool; data and profile carry over | Your id and handle survive on a new host; private data and profile are lost |
| Recovery card and account file | Reset | Everything moves to a new host |

**Save the recovery card.** Nobody, not even your home, can recover an identity without it. That is the point: there
is no backdoor.

## Questions and answers

**Does the server keep a copy of my account?** Yes, your home keeps the complete account: the public log, the public
profile and the encrypted vault. It cannot decrypt the vault or reset your password. You can download the whole account
as one file at any time.

**Is my account tied to one server?** Your *login* is: exactly one host, your home, holds the vault and accepts
logins. Your *identity* is not: it belongs to the recovery card. With the card you can move to another host in a few
minutes; the old one then refuses logins.

**Can other servers identify me?** Yes. Hosts that serve the same realm share the public log and profile (never the
vault) and anyone can verify a proof from you. Vaults are never copied, so a password can be guessed offline only by
whoever holds your home's storage or one of your account files.

**Can I use one identity at several services at the same time?** Yes. Each service gets its own proof, valid only for
that service. If you do not want services to link your accounts, create several identities from the **same recovery
key**: they cannot be linked by their public data.

**Can I log in without a browser?** Yes. The protocol is plain HTTP and signatures: a command line client can log in to
its own host with the libraries. For other services the proposal adds `rootcard signin <url>` to the key tool, which
derives the recipient from the address it connects to itself.

**Can my ID card have a picture?** You can put a small image in your public profile (a `user.` key; the whole profile is
at most 16 KiB, so think a 10 KiB avatar). There is no standard key or display rule for images yet; it is on the
roadmap. Remember that the public profile is **public and cannot be taken back** once copied.

**Which languages?** Rust and JavaScript implement the same functions and produce the same bytes, checked against
shared test vectors. The JavaScript package runs in browsers and in Node 20 or later and verifies everything a host
checks. The ready-made host helpers (`rootcard-host`) are Rust only for now; JavaScript host helpers are on the roadmap.

## How it compares

| | Password + hash on the server | Passkeys (WebAuthn) | "Sign in with …" (OAuth / OIDC) | rootcard |
|---|---|---|---|---|
| Server learns the password | At every login | No password | The provider does | Never sent. The page your home serves could capture it (THREAT_MODEL AR2) |
| Server database stolen | Offline guessing of hashes | Nothing useful | Provider's database | Offline guessing of the vault, Argon2id 64 MiB, home only (AR1) |
| Phishing | Vulnerable | **Resistant** | Vulnerable at the provider's login | Relayed logins fail (address binding), but a fake page can still capture the password |
| Replay of a login | Session theft | No | Token theft | No: one-time, bound signatures |
| Forgotten password | E-mail reset | Platform recovery | The provider decides | Recovery card only; no backdoor |
| Who controls the identity | The service | The site and your sync provider | The provider, who can lock you out or sign in as you | **You**, through the recovery key |
| Move to another provider | New account | New credential per site | New account | Same id, one key tool operation |
| Second factor | Add-on | Built in | Provider's | None yet (passkeys as a lock type are planned) |
| Maturity | Decades | Standardized, widely deployed | Standardized, widely deployed | New, not yet externally reviewed |

In short: against database leaks, replay and lock-in, rootcard does better than classic password logins and
social logins. It does not yet match passkeys against phishing, and it is young. The plan is to add passkeys as a way to
unlock the vault, which combines both.

For the user it stays simple: a username and a password every day, and a card in a drawer. For a developer it is two
libraries and one HTTP binding. The cryptography is standard (Ed25519, X25519, SHA-256, HKDF, AES-GCM, Argon2id) and comes
from audited crates and WebCrypto.

## Built to last

- **Versioned from the start.** Every structure has a `v`, every key a type tag and every signature a versioned label
  (SPEC §22). New formats are added beside the old ones, and ids, logs and signatures made with `v: 1` stay valid
  forever.
- **New algorithms without a new identity.** Post-quantum keys (for example ML-DSA, ML-KEM) and passkeys arrive as new
  key types and lock kinds, adopted by a recovery-key rotation or a new instance. The account id stays the same.
- **A versioned HTTP API.** Endpoints live under `<base URL>/v0` until 1.0.0, then under a frozen `/v1`. Addresses
  stored in identities never contain the version, so the API can evolve without touching any identity.
- **Not tied to a company or a transport.** The HTTP binding is a recommendation, any host can be your home, and the
  key tool works offline from a file on your own disk.
- **Known limits.** Ed25519 and X25519 are not quantum-safe: the move to post-quantum keys has to happen before a
  quantum attacker exists, and stored vaults could be attacked later (THREAT_MODEL T37). Forks of a log are detected but
  not resolved in format version 1, and a stolen recovery key gives control until witnesses and pre-rotation arrive in a
  later format version (AR3, AR11). Before `1.0.0` the packages and the `v0` API can still change; changes to the format
  follow §22.

## How it works

1. **Create.** Pick a username, a realm (`global` or an application) and a password. You get a recovery key, printed as a
   recovery card. Your account id is the SHA-256 of a statement signed by that key, so nobody can forge it; people see
   it as `Astra#3F9C`.
2. **Instance.** The recovery key signs an *instance*: a fresh account key and the server that is your **home**. The
   account key and your private data go into a **vault**, encrypted on your device and locked with your password (and
   with the recovery key).
3. **Log in.** Your device proves the password to get the vault, unlocks it locally, and signs the home server's
   one-time challenge with the account key. The password never leaves your device, and the server has nothing it could replay.
4. **Prove.** Anyone, on any server, can ask you to sign a challenge and check the signature against your public log.
5. **Change, download, move.** Change your password in the browser with the old one. Download your whole account as one
   file at any time, and move it to another server with the recovery card; your password comes along.
6. **Recover.** Forgot the password, or lost a device or a whole server? The recovery card signs a new instance, on the
   same server or another one. Every old password, vault and session stops working at once. Your id and handle stay.
   No server can do this for you, so keep the card.

The log, the vault, the recovery card, proofs and verification are explained in more depth in
[docs/CONCEPTS.md](docs/CONCEPTS.md). To add rootcard to an application or run a host, start with
[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md).

## The map

```
      recovery card  RCR-…-CCCC                              password  ••••••••••••
      offline · high power · key tool only                   in your head · low power · app client
                 │ signs the log, mints instances                        │ unlocks the vault
                 ▼                                                       ▼
 ╭──────────────────────────────────────── rootcard ───────────────────────────────────────────╮
 │  Astra#3F9C        id 3F9C… = SHA-256( inception signed by the recovery key )               │
 │                                                                                             │
 │  LOG      public · append-only · every event signed by the recovery key                     │
 │           incept ──► instance ──► rotate_recovery ──► instance ──► …         version = last │
 │                      account key + home host + the host's receipt                           │
 │                                                                                             │
 │  VAULT    encrypted · one per instance        PROFILE  public · signed by the account key   │
 │           locks: password … recovery                   user.*   app.<name>.*                │
 │           holds: account key, private data                                                  │
 ╰───────────────────┬──────────────────────────────────┬──────────────────────────┬───────────╯
                     │ log · vault · profile            │ log · profile            │ log + proof
                     ▼                                  ▼                          ▼
 ┌─ home host ─────────────────────────┐  ┌─ other hosts ─────────────┐  ┌─ relying party ────────┐
 │ the only vault copy, the only login │  │ verify everything         │  │ any server or user     │
 │ challenge ─► answer ─► session      │  │ share the public log      │  │ challenge ─► proof     │
 │ never sees a password               │  │ answer not_home           │  │ verify against the log │
 └─────────────────────────────────────┘  └───────────────────────────┘  └────────────────────────┘
```

## What you get

- **Self-certifying id.** The account id is a hash of a signed inception that names the recovery public key. It cannot
  be forged without breaking SHA-256 or Ed25519 or stealing a private key. Shown to humans as `Name#XXXX`.
- **No password verifiers on servers.** The password only unlocks an encrypted vault on the client. Login is a fresh
  challenge signed by the account key, bound to the host, the realm and the current version.
- **Two power levels.** The password gives *low power* (log in, edit your data, export). Everything that changes who can
  access the account, where it lives or whether it exists needs the **recovery key**, kept offline.
- **The recovery key is the root.** It can always mint a fresh, complete instance of the account, even if every host and
  backup is gone.
- **One latest version.** A log only grows. Anyone who has seen a newer verified version rejects the old one, and forks are
  detected and refused.
- **Built for servers.** Hosts never see a password or run Argon2id, verify logs incrementally, run on many servers over
  one compare-and-swap store, and can rotate keys and change addresses without touching identities.
- **Arbitrary data.** A signed public profile and private data inside the vault, with per-application namespaces.
- **Realms.** An identity is bound to a realm string (an app, a world, or `global`).

## Packages

| Registry | Package | What |
|---|---|---|
| crates.io | `rootcard` | Core library: formats, verification, vault, proofs. Pure, no I/O |
| crates.io | `rootcard-cli` | The key tool (`rootcard` binary): recovery-key operations |
| crates.io | `rootcard-host` | Helpers for hosts (servers): challenges, stores, HTTP-agnostic handlers |
| npm | `rootcard` | The same core in plain ES modules, zero dependencies, browser and Node (WebCrypto), and the standalone key tool page `keytool.html` |

The specification in [`spec/`](spec/) and its test vectors are the source of truth. Rust and JavaScript must produce the same
bytes for the same inputs.

## Roadmap

Planned (details in [docs/PLAN.md](docs/PLAN.md)):

- **Before 1.0:** getting-started guides and an external review. The Rust parsers, verifiers and host router are
  fuzzed in CI, and the JS core is tested against the Rust core on mutated inputs ([fuzz/](fuzz/README.md)).
- **Sign-in at other services:** the relying-party flow and `rootcard signin` ([proposal](docs/proposals/signin.md)).
- **Linked accounts in the key tool:** `rootcard link` and a links panel in `keytool.html`. The format and both cores
  already check links to GitHub accounts and domains (SPEC §12.3, [CONCEPTS.md §6](docs/CONCEPTS.md)).
- **Standard profile keys** such as a display name and a small avatar image, with safe display rules.
- **Passkeys** as a lock type, for phishing resistance.
- **Host helpers for JavaScript servers.**
- **Stronger roots** (witnesses and pre-rotation), and post-quantum key types, in later format versions.

## Documentation

| | |
|---|---|
| [spec/SPEC.md](spec/SPEC.md) | The normative specification, with [test vectors](spec/vectors/) |
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | Adding rootcard to an application, running a host, checking proofs: code for each role |
| [docs/CONCEPTS.md](docs/CONCEPTS.md) | The log, the vault, the recovery card, proofs and verification: how and when they are used |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, server usage, dependencies |
| [docs/HOST_PROTOCOL.md](docs/HOST_PROTOCOL.md) | Recommended HTTP binding for hosts |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Goals, attackers, threats, accepted risks |
| [spec/links/](spec/links/) | The registry of linked services (`github`, `dns`, `web`), bundled with both cores |
| [docs/proposals/](docs/proposals/) | Proposals: [sign-in at other services](docs/proposals/signin.md) (draft), [linked accounts](docs/proposals/links.md) (adopted in SPEC §12.3) |
| [CONTRIBUTING.md](CONTRIBUTING.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [SECURITY.md](SECURITY.md) | How to contribute · the code of conduct · how to report a vulnerability |
| [docs/RELEASING.md](docs/RELEASING.md) | How releases are prepared and published |
| [docs/DESIGN.md](docs/DESIGN.md) · [docs/PLAN.md](docs/PLAN.md) | Motivation · setup plan |

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. Release 0.1.0 was
published under MIT alone.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in rootcard by you, as
defined in the Apache-2.0 license, is dual licensed as above, without any additional terms or conditions.

## Origin

rootcard started as the account design of the game Xigna and is developed here as an application-neutral library. The
design is [docs/DESIGN.md](docs/DESIGN.md). How Xigna uses rootcard is documented in the Xigna repository.
