# rootcard: design

This document is the design of rootcard: what an identity is, how it is verified, which version is current, how passwords
are added and revoked, how arbitrary data is stored, how an identity is exported, and how the recovery key can always mint
a fresh, complete instance. It is the motivation; the normative format is [spec/SPEC.md](../spec/SPEC.md), which corrects
this design in several places (listed in its Appendix B: framing, vault fetch, recovery-signed locks, extension-only versions, host operation,
sizes and more). Where they differ, the specification wins. Section numbers are stable.

Terms: an **application** uses rootcard (a game, a web service). A **host** is a server that stores identities and accepts
logins for an application. A **realm** is the string an identity is bound to (an application, a world, or `global`).

---

## 1. Requirements

| # | Requirement | Where |
|---|---|---|
| R1 | A user chooses a **username**, a **realm** and a **password**, and receives a **recovery key** | §6.1 |
| R2 | An identity is **bound to one realm** | §4.1, §5.1 |
| R3 | The account id is **unique** | §4.1 |
| R4 | The displayed id is always **`Username#XXXX`**, the first four characters of the account id | §4.2 |
| R5 | The recovery key can **add a password** and **revoke an old one** | §6.3, §6.4 |
| R6 | The profile is **encrypted** and is what a login unlocks. At login **the password is enough** | §5.2, §6.2 |
| R7 | An identity can **only be verified while the user is online and has unlocked it** | §2.2, §6.2 |
| R8 | A logged-in user can **download** the identity | §6.6 |
| R9 | The **complete identity is not propagated automatically**. It lives on the **primary host** and with the user | §5.4, §7 |
| R10 | An identity can **live forever** | §9 |
| R11 | **The recovery key can always mint a fresh version of a complete instance** | §6.8, §9.1 |
| R12 | There is always **one latest version**. Whoever has seen a newer verified version **rejects the old one for login** | §5.5 |
| R13 | A user can **prove who they are** to others, also across hosts | §6.9 |
| R14 | It is **impossible to forge an identity with the same id**. The identity proves possession of the **private key** for the **public key** the id builds on | §4.4, §6.9 |
| R15 | **Arbitrary data**, public and private, can be stored and updated in the identity | §5.6 |
| R16 | The library is **application-neutral**: a global, secure identity (like an ID card) usable by any application | §8 |
| R17 | **The password gives low power.** All higher power needs the recovery key | §5.7 |

---

## 2. Model, threats and decisions

### 2.1 Model
An identity is the user's own key pair, not a row in a host's database. The **complete identity** has three parts:

1. **The identity log** (§5.1): public, signed, a hash chain of events with public keys only. It says who the identity is,
   which instance is current (account key and primary host) and which recovery key controls it. Its last event is the
   identity's **version** (§5.5).
2. **The vault** (§5.2): encrypted, bound to one instance, holding the private account key and private data. Unlocked with a
   password or the recovery key, only on the user's side.
3. **The public profile** (§5.6): arbitrary public data signed by the identity.

The complete identity lives only on the **primary host** and in account files the user has downloaded (§5.4). Only the
primary host accepts logins. The log and the public profile may be shared freely: they hold no secrets, and the log is what
lets everyone agree on the latest version.

A host can check that someone *is* the identity but can never *become* it. Whoever holds the recovery key can mint a new
instance at any time, which invalidates every earlier instance, vault, password and session.

### 2.2 Verification only online and unlocked (R7)
- Hosts store **no password verifier**: no hash, no salt, no public value derived from the password.
- Every login answers a **fresh challenge** (single use, 60 s) with a signature by the account key, which exists only in the
  unlocked vault in the client's memory. The signature is bound to the host, the realm and the **version** (§5.5).
- There are no stored signatures or long-lived proofs to replay. A session belongs to one host, one connection and one
  instance.

### 2.3 Threat model

| Threat | Protection | Remaining |
|---|---|---|
| Someone creates an identity with the same id | The id is the hash of a signed inception naming the recovery key. Forging needs the private key or a break of SHA-256 or Ed25519 (§4.4) | – |
| Someone impersonates a user (same name) | The full id always differs. Signature proofs (§6.9) | The 4-character tag can collide (§4.3) |
| A host database leaks | Only public logs and profiles, and vaults only for identities with that primary host. No password hashes | The primary host's vaults can be guessed offline (§10.1) |
| Online password guessing | The password is never sent. Vault downloads are rate limited | – |
| Offline guessing against a stolen vault | Vaults exist only on the primary host and with the user. Argon2id and password rules (§3.3) | A weak password falls to whoever has the vault (§10.1) |
| A password is stolen | Low power only (§5.7), only on the primary host, only in the current instance. Revocation is immediate (§6.4) | The thief can log in until the owner revokes |
| An account file and a password are stolen | Not enough to move the identity. An old file is invalid once a newer version exists (§5.5) | – |
| An old version is used (old file, old host, replay, old profile) | Total order of versions, logins bound to the version, newer versions carried onwards (§5.5) | A party that *never* sees the newer version (§10.4) |
| A host replays a login | Bound to the host key, the realm, the version and a nonce | – |
| A host alters a public profile | Signed by the account key, versioned (§5.6) | A host can withhold it |
| A malicious host serves a malicious web client | The password is typed only at the primary host the user chose. The recovery key is never typed into an application client (§6.5) | The primary host sees passwords typed into its client (§10.2) |
| The recovery key is stolen | Kept offline, used only in the key tool | The thief owns the identity (§10.3) |
| Quantum computers | Typed keys, algorithm agility (§9.2) | – |

### 2.4 Secure and feasible: decisions

| Part | Secure? | Feasible? | Decision |
|---|---|---|---|
| Ed25519, X25519, SHA-256, HKDF, AES-GCM | Yes, standard and reviewed | Yes: WebCrypto in current browsers, RustCrypto and dalek | **Used** |
| Argon2id for passwords | Yes (RFC 9106) | Yes in Rust. Not in WebCrypto: a plain JS implementation tested against the RFC vectors, slower than WASM, so parameters target about 1–3 s on a mid-range phone | **Used**, own JS implementation, parameters stored per lock |
| Self-certifying id (hash of a signed inception) | Yes, no registry needed | Yes | **Used** (§4.1, §4.4) |
| Hash chain with versions and rollback protection | Yes | Yes | **Used** (§5.1, §5.5) |
| Vault only on the primary host | Yes | Yes | **Used** (§5.4) |
| Identity re-derivable from the recovery key | Yes, it is the root | Yes, with a deterministic inception (§4.1) | **Used** (§9.1) |
| Arbitrary data: signed public profile and private vault data | Yes, with size limits and data-only display | Yes | **Used** (§5.6) |
| OPAQUE | Yes | Needs a per-host secret and heavy JS. Conflicts with portability | **Not now.** Possible extra layer on the primary host (§10.1) |
| Passkeys (WebAuthn PRF) as a lock | Yes, strongly phishing-resistant | Yes in newer browsers, but bound to the host's domain | **Later**, as a lock type (§9.2) |
| Witnesses and pre-rotation (KERI) | Yes, against a stolen recovery key | More complex, two secrets to keep | **Later**, in `v: 2` without changing the id (§10.3) |
| Global uniqueness of handles (consensus, blockchain) | – | Unreasonable | **No.** Unique per host, visible extended tags on collision (§4.3) |
| Protection against a host serving a malicious web client | – | Impossible for a client served by that host | **Accepted.** The password gives low power, the identity can move (§10.2) |
| Recovery without the recovery key | Would need a backdoor | – | **No, by design** (§9.1) |

---

## 3. Cryptography

### 3.1 Algorithms

| Purpose | Algorithm | Rust | JS |
|---|---|---|---|
| Signatures | Ed25519 (RFC 8032), deterministic, strict verification | `ed25519-dalek` (`verify_strict`) | WebCrypto `Ed25519` |
| Key agreement (vault locks) | X25519 (RFC 7748) | `x25519-dalek` | WebCrypto `X25519` |
| Hash | SHA-256 | `sha2` | WebCrypto `SHA-256` |
| Key derivation | HKDF-SHA256 (RFC 5869) | `hkdf` | WebCrypto `HKDF` |
| Password to key | Argon2id (RFC 9106) | `argon2` | own `argon2.js` with `blake2b.js` |
| Encryption | AES-256-GCM, random 96-bit nonce, fresh key per instance | `aes-gcm` | WebCrypto `AES-GCM` |
| Randomness | OS CSPRNG | `getrandom` | `crypto.getRandomValues` |

- No home-made cryptography on hosts. In JS everything but Argon2id comes from WebCrypto, so the package has no
  dependencies. Argon2id is checked against RFC 9106 and against Rust.
- Strict verification everywhere: small-order keys and non-canonical signatures are rejected.
- Browsers without WebCrypto `Ed25519` and `X25519` get `unsupported_browser`. There is no weaker fallback.

### 3.2 Domain separation
Every signature and derivation has its own label, so a signature for one purpose never works for another:

```
rootcard/id/v1            id from the inception
rootcard/event/v1         identity log events
rootcard/vault/v1         vault header
rootcard/public/v1        public profile
rootcard/login/v1         answer to a login challenge
rootcard/proof/v1         proof of identity (§6.9)
rootcard/receipt/v1       host receipt for a new instance
rootcard/recovery/sign/v1, rootcard/recovery/box/v1   keys from the recovery key
rootcard/password/box/v1  key from a password
rootcard/wrap/v1          wrapping of the vault key
```

### 3.3 Passwords
- Argon2id, defaults `m = 64 MiB, t = 3, p = 1`, 32-byte output, 16-byte random salt per lock. Parameters are stored per lock
  and can be raised for new locks. Floor `m ≥ 46 MiB, t ≥ 2` (OWASP minimum), enforced by clients and the key tool.
- Passwords are normalized with Unicode NFC.
- Rules are enforced by the client, since hosts never see the password: at least 12 characters, not the username, not in a
  common-password list, with a strength meter that suggests a passphrase.

### 3.4 Canonical encoding
Everything hashed or signed is **canonical JSON**: sorted keys, no whitespace, only strings, integers (at most 2⁵³),
booleans, arrays and objects, **no floats**. Byte strings are unpadded base64url. Rust and JS produce identical bytes,
checked by shared vectors (§11).

### 3.5 The recovery key
- 32 random bytes, written `RCR-` + 52 characters Crockford base32 + 4 characters checksum (SHA-256), in groups of 4.
- Signing key `HKDF(key, "rootcard/recovery/sign/v1") → Ed25519`, lock key `HKDF(key, "rootcard/recovery/box/v1") → X25519`.
  No Argon2id: the key already has full entropy.

---

## 4. Account id and displayed id

### 4.1 The account id (R2, R3)
The inception is derived **deterministically** from the recovery key, the username and the realm:

```
inception  = { v: 1, kind: "incept", seq: 0, realm: "<realm>", username: "<name>", recovery: "ed25519:<public>" }
             signed by the recovery key (Ed25519 signatures are deterministic)
account id = SHA-256("rootcard/id/v1" ‖ canonical(inception without signatures))
```
- 256 bits, written in Crockford base32 (52 characters, upper case, no `I L O U`).
- The realm is part of the inception, so the identity is bound to it. A host accepts only realms it is configured for.
- The same recovery key, username and realm always give the same inception and id again (§9.1). This is the basis of R11.
- The id never changes, even when instances, passwords and the recovery key change.
- Hosts map the account id to their own internal ids. Internal ids never leave the host.

### 4.2 Displayed id (R4)
```
handle = username + "#" + first four characters of the account id      e.g.  Astra#3F9C
```
- Usernames follow a `UsernamePolicy` given by the application. The default: 2–20 characters `A–Z a–z 0–9 _ -`, starting
  with a letter, ASCII only (no look-alike Unicode).
- The username is part of the inception and **cannot change**, so the handle is as stable as the id.
- Applications always show the handle and always compare the **full** id.

### 4.3 Tag collisions
Four base32 characters are 20 bits. Anyone can try about a million recovery keys and get someone else's *tag*, never their
*id* (§4.4). **The tag is a human aid, not a security proof.** Therefore:

1. **A host never allows two identities with the same handle** (case-insensitive). First come, first served, and a
   colliding registration gets `handle_taken`. The client then creates a new recovery key.
2. **Collisions revealed by propagation** are always visible: both identities are shown with an **extended tag** with as many
   characters as needed (`Astra#3F9C-K2`).
3. **Clients remember the full id** of people they have dealt with (in the vault) and warn when a handle shows up with another
   id. Anyone who wants certainty asks for a proof (§6.9).

*Rejected:* a memory-hard proof of work in the inception. It would slow registration, give hosts an expensive check per
unknown identity (a DoS vector) and still not stop a determined attacker.

### 4.4 Why an identity with the same id cannot be forged (R14)
The id is **self-certifying**: it is the hash of the inception, and the inception names the recovery key's public key and is
signed by its private key. To present an identity with a given id one must

1. present an inception whose hash is the id, which only the genuine inception has (second-preimage resistance of SHA-256), and
2. prove possession of the **private key** for the public key that inception names. The inception is signed by the recovery
   key, every later event by the recovery key current at that point, and every login and proof by the current instance's
   account key, which was signed in by the recovery key.

The chain *id → inception → recovery key → instance → account key → signature over a fresh challenge* is checked with public
data only, and every link needs a private key only the owner has. No host, peer or user can create an identity with the same
id, alter an existing one or replay an old proof without breaking Ed25519 or SHA-256 or stealing a private key. Only the tag
can be made to match (§4.3).

Every new public key entering the log (`incept`, `instance`, `rotate_recovery`) must **sign itself** (proof of possession),
so nobody can claim someone else's public key.

---

## 5. Parts of an identity

### 5.1 The identity log

```
Event {
  v: 1, account: "<account id>" (absent in the inception), seq: n, prev: "<hash of event n-1>" (absent in the inception),
  kind: ..., time: <unix seconds, owner's clock>, body: { ... },
  sigs: [{ key: "ed25519:<public>", sig: "<base64url>" }]
}
event hash = SHA-256("rootcard/event/v1" ‖ canonical(event without sigs))
```

| `kind` | Body | Signed by | Effect |
|---|---|---|---|
| `incept` | `realm`, `username`, `recovery` (§4.1) | recovery key | The identity exists. No instance yet |
| `instance` | `account` (new public account key), `home` (primary host's public key and address), `reason` (`register`, `revoke`, `restore`, `fresh`) | recovery key, the new account key **and** the primary host (receipt, `rootcard/receipt/v1`) | **A new complete instance.** All earlier instances, vaults, passwords not carried over, and sessions become invalid |
| `rotate_recovery` | new `recovery` | the old **and** the new recovery key | New recovery key. The instance stays |
| `retire` | – | recovery key | The identity is closed forever |

Rules every host and client checks (`verify_log`):
- The inception has `seq = 0`, a valid username and a realm the verifier accepts. The account id matches.
- Every later event has `seq = n`, `prev` equal to the hash of event `n−1`, and is signed by **the recovery key current after
  event `n−1`**. **Only the recovery key can change the log.**
- `time` may not be more than 10 minutes in the future for the receiving host and may not go backwards in the chain.
- The **current instance** is the latest `instance`. Its `account` is the only valid account key, its `home` the primary host.
- After `retire` no events are accepted and nobody can log in.

### 5.2 The vault
A vault always belongs to **one** instance.

```
Vault {
  v: 1, account: "<account id>", instance: "<hash of the instance event>", version: n,
  locks: [
    { id: "<8 bytes>", kind: "password", label: "laptop",
      kdf: { alg: "argon2id", m: 65536, t: 3, p: 1, salt: "<16 bytes>" },
      box: "x25519:<public>",                          derived from the password
      wrap: { epk: "<ephemeral X25519>", nonce, ct } },  vault key wrapped to box
    { id: "recovery", kind: "recovery", box: "x25519:<public>", wrap: {...} }
  ],
  revoked: ["<lock id>", ...],
  nonce, ct,                                           AES-256-GCM(vault key, contents), header as AAD
  sig: { key: "ed25519:<instance account key>", sig }
}
```

- **Contents** (encrypted): the private account key, the highest seen version of this and known identities, the full ids of
  known identities (§4.3) and the **private data** (§5.6). Never the recovery key.
- **Locks:** `Argon2id → HKDF("rootcard/password/box/v1") → X25519` from the password. The 32-byte random vault key is wrapped to
  the lock's public key with an ephemeral key: `ECDH → HKDF("rootcard/wrap/v1") → AES-GCM`. The recovery lock works the same way.
- Because every lock has a **public** key, the recovery key can wrap a new vault key to the remaining passwords **without
  knowing them** (§6.4).
- A vault is valid only if `instance` is the current instance and it is signed by that instance's account key.
- `version` increases with every change within the instance. The primary host keeps only a higher `version`.

### 5.3 Keys and what they may do

| Key | Where | May |
|---|---|---|
| **Recovery key** | Only with the user, on paper or in a file, offline | Sign every log event, mint instances (always, §6.8), unlock the vault, add and revoke passwords, rotate itself, retire the identity |
| **Account key** (one per instance) | Encrypted in the vault, unlocked only in client memory | Answer login challenges, sign the vault and the public profile within the instance, give proofs (§6.9) |
| **Password** (one per lock) | In the user's head | Unlock the vault of the current instance, and with it low power (§5.7) |
| **Host key** (Ed25519, one per host) | On the host | Bind challenges, receipt new instances, sign host-to-host requests (§7) |

### 5.4 Where the complete identity lives

| Place | Log | Public profile | Vault | Password login |
|---|---|---|---|---|
| **Primary host** (`home` of the current instance) | Yes | Yes | Yes, the only vault on any host | Yes |
| **The user's account file** (§6.6) | Yes | Yes | Yes (encrypted) | – (backup, used for new instances) |
| **The user's browser** | Yes (highest seen version) | Yes | Optionally, encrypted | – |
| **Other hosts in the realm** | The public log (§7) | Yes (§7) | Never | No, they answer `not_home` |

### 5.5 Versions: what is latest (R12)
An identity's **version** is its last log event, `(seq, hash)`. All valid versions have a **total order**:

1. **Extension:** if B extends A (A is a prefix of B), B is newer.
2. **Branch:** two valid events with the same `seq` and `prev` can only come from the recovery key, that is from the owner
   (for example a new instance made without reaching the hosts, §6.8). The branch whose last event has the **latest `time`**
   wins, and on equal time the lower hash. The rule is deterministic, so everyone converges without freezing the identity. The
   losing branch is invalid. The owner is warned and offered a new instance on top of the winner.

Within an instance the vault and the public profile each have a `version` that only increases.

**Whoever has seen a newer version rejects the old one:**
- **Hosts** only move forward in this order. A new `instance` revokes every session of earlier instances, and a host that is no
  longer `home` deletes its vault and answers `not_home`.
- **Clients** store the highest verified version per identity and never log in with an older one or accept a vault or profile
  of a non-current instance.
- **Logins are bound to the version** (§6.2). A host accepts a signature only if its version is exactly the host's current
  version. A client that has seen a newer version sends the missing events first. A host with a newer version returns it, and
  the client updates before retrying.
- **Everyone carries newer versions onwards.** The log is public, so every client and host that has seen a newer version sends
  it to the hosts it talks to (`POST /id/<account>/events`).

### 5.6 Arbitrary data (R15)

| | **Public profile** | **Private data** |
|---|---|---|
| Where | A signed document next to the log | Inside the vault contents (§5.2) |
| Who sees it | Everyone with the log (shared like the log, §7) | Only whoever unlocks the vault |
| Signed by | The current instance's account key (`rootcard/public/v1`) | The current instance's account key (vault `sig`) |
| Updated by | A logged-in, unlocked client | A logged-in, unlocked client and the key tool |
| Size | At most 16 KiB | At most 48 KiB (vault at most 64 KiB) |

```
PublicProfile { v: 1, account, instance: "<hash of the instance event>", version: n,
                data: { "<key>": <value>, ... }, sig: { key: "ed25519:<account key>", sig } }
```

- Keys are at most 64 characters `a–z 0–9 . _ -`, values canonical JSON without floats.
- **Namespaces:** `user.` belongs to the user, every application has `app.<name>.`. An application writes only its own namespace
  and `user.`, and may read everything.
- An update sends the whole document with `version + 1`, signed, to the primary host, which checks the signature, instance and
  version and shares it.
- The profile is valid only for the current instance and the highest seen `version`. On a new instance the key tool re-signs
  it (`restore`) or clears it (`fresh`).
- Hosts and clients show the data only as **text or data**, never as HTML or code, and enforce the size limits. Shared copies can
  outlive updates, which the client says before saving.

### 5.7 Low and high power (R17)

| | **Low power**: the password (unlocked account key) | **High power**: the recovery key |
|---|---|---|
| Use | Log in at the primary host | – |
| Data | Read and change private data and the public profile within the current instance | Clear or replace everything with a new instance |
| Identity | Download the account file, give proofs within the instance (§6.9) | Everything in the log |
| Passwords | – (not even changing one's own) | Add, revoke and replace passwords |
| Instances | – | Mint instances (`restore`, `fresh`), replace the account key |
| Primary host | – | Choose and change it |
| Root | – | Rotate the recovery key, retire, give instance-independent proofs |

- **The rule:** anything that changes *who can access the identity*, *where it lives* or *whether it exists* is high power. The
  format enforces it: only the recovery key signs log events (§5.1) and vault locks (§6.3). In doubt, a feature is high power.
- A stolen password gives low power only, until the owner mints a new instance.
- Application clients have low power only. High power is only in the key tool (§6.5).

---

## 6. Flows

### 6.1 Registration (R1)
1. The user picks a **username**, a **realm** (the host lists the realms it serves) and a **password**.
2. The client creates the **recovery key** and shows it **once** as text and as a printable/downloadable **recovery card**
   (§6.7). The user retypes two random groups. Alternatively the user pastes a key created in the key tool (safest).
3. The client derives the inception (§4.1), gets a challenge from the host and creates the first instance
   `instance { account, home: this host, reason: "register" }`, a vault with a password lock and a recovery lock, and an empty
   public profile.
4. `POST /id/register { log: [inception, instance], vault, public, challenge_sig }`. The host checks the log (including
   self-signatures, §4.4), the vault, the limits and that the handle is free, receipts the instance and answers
   `{ account, handle, version }`.

Rate limit: at most 3 registrations per IP and hour.

### 6.2 Login (R6, R7, R12)
Only **at the primary host**, with the handle and the password.
```
1  GET  /id/lookup?handle=Astra%233F9C               → { account, version, home }
2  compare versions (§5.5); if the client's is newer: POST /id/<account>/events first
3  GET  /id/<account>/vault                          → vault (skipped if the client has the current instance's vault)
4  unlock the vault with the password                → account key in memory
5  POST /auth/challenge { account }                  → { nonce, host, realm, version, expires }
6  sign "rootcard/login/v1" ‖ realm ‖ host ‖ nonce ‖ account ‖ version
7  POST /auth/login { account, nonce, version, sig } → { token, handle }
```
- In step 4 the client checks that the vault belongs to the current instance and holds that instance's account key.
- A host that is not `home` answers `not_home` with the primary host's address.
- The nonce is 32 random bytes, valid once and for 60 s. If the host's version changed meanwhile, the login fails with
  `stale_version`.
- The account key is imported into WebCrypto as **non-extractable** and the raw bytes are overwritten.
- Sessions belong to one host and one instance, expire after 24 h idle and are revoked on logout and on a new instance.
- Rate limits: vault downloads at most 10 per identity and hour and 30 per IP and hour; challenges at most 10 per IP and minute.

### 6.3 Adding a password (R5)
In the **key tool** with the recovery key: load the identity, check it is the latest version, unlock with the recovery lock,
add a lock with a new salt, increase `version`, sign with the instance account key, `PUT /id/<account>/vault` to the primary
host. The log is unchanged.

A password **cannot** be changed with only the old password (§5.7). Changing a password means adding a new one and revoking
the old one with the recovery key.

### 6.4 Revoking a password (R5)
Whoever has an old password may have taken the account key and the vault key, so revocation is **a new instance**: the key
tool creates a new account key and vault key, re-encrypts the contents, wraps the new vault key to the remaining locks and the
recovery lock, re-signs the public profile and creates `instance { account: new, home: same, reason: "revoke" }`. The primary
host receipts it, stores it, **revokes every session** and shares it. Since only the primary host accepts logins, revocation is
immediate.

### 6.5 The key tool
The recovery key is **never typed into an application client**.
- `rootcard` CLI (crate `rootcard-cli`): `new`, `card`, `add-password`, `revoke-password`, `restore`, `fresh`,
  `rotate-recovery`, `retire`, `inspect`, `verify`, `prove`.
- `keytool.html` (npm package): the same as one standalone page that works from `file://` and makes no network request unless
  the user picks a host.
- Applications link to the key tool and warn: "Only enter your recovery key in the key tool."

### 6.6 Downloading the identity (R8)
A logged-in user can always download the identity (`GET /account/export` with the session token, or straight from client
memory), as `Astra-3F9C.rootcard.json`:
```
{ format: "rootcard-account", v: 1, realm, account, handle, version,
  log: [...], public: <public profile>, vault: <current instance's vault>, host_data?: { ... read-only } }
```
- No plaintext secrets. It is a backup, but it can be guessed offline like the vault (§10.1).
- It is current only while its version is the latest. After a new instance its log still serves as evidence, its vault no
  longer logs in.

### 6.7 Recovery card, recovery key rotation, retiring
- The **recovery card** (text, file, QR) holds the recovery key, the username, the realm and, after rotations, the chain of
  `rotate_recovery` events (a few hundred bytes). It is everything needed to mint a new instance (§9.1).
- `rotate_recovery`: a new recovery key signed by the old and the new, the vault's recovery lock replaced, a new card printed.
- `retire`: closed forever. Hosts keep the inception and the event so the id can never be reused, delete the vault and the
  public profile and stop showing the username.

### 6.8 A fresh complete instance (R11)
**The recovery key can always mint a new instance**, on any host serving the realm:
1. Enter the recovery card in the key tool, which derives the inception and the id (§4.1).
2. The tool looks for the latest version (the chosen host, its peers, an account file) and picks the latest (§5.5).
3. The user chooses **restore** (unlock an existing current vault with the recovery lock: data, profile and passwords carry
   over) or **fresh** (a new empty vault with the recovery lock and a password chosen now, an empty profile).
4. The tool gets a challenge from the new primary host and creates `instance { account: new, home: that host, reason }` **on top
   of the latest version it found** (or on the inception if none).
5. `POST /id/<account>/instance`. The host checks everything. If it knows a newer version it answers `stale_version` with the
   missing events and the tool rebuilds on top of them. Then it receipts the instance and becomes the primary host.
6. The instance is shared (§7). Every party that sees it rejects earlier instances. The old primary host revokes its sessions,
   deletes its vault and answers `not_home`.
7. The user logs in with the password and downloads a new account file.

If the tool built on an older version because it could not reach the latest, a branch appears, resolved by §5.5: the later
instance wins, which is what the owner just did.

### 6.9 Proving who you are (R13, R14)
```
verifier → challenge: 32 random bytes
prover   → sig = Ed25519(account key, "rootcard/proof/v1" ‖ account id ‖ version ‖ challenge ‖ recipient)
verifier → verify_log(log) → current instance → its public account key → verify_strict(sig)
```
- Checked against the log and the latest version the verifier knows. Proofs from older instances are rejected. Fresh challenge
  plus recipient prevents replay and forwarding.
- A statement without a challenge can be signed with `challenge` = hash of the statement. It is valid while the instance is.
- With the recovery key the owner can give an instance-independent proof, for example that two identities in different realms
  share an owner.

---

## 7. Sharing between hosts

**The complete identity is never propagated automatically.** Only the public log and the public profile are shared.

- **Connected hosts** serve the same realm and have added each other's host keys. Hosts never trust each other's claims and
  always verify themselves (§4.4, §5.5). No vaults and no passwords pass between hosts.
- **Push:** a new event or profile goes to connected hosts (signed with the host key). A new `instance` always also goes to the
  previous primary host. **Pull:** every 30 s each host asks its peers what changed and fetches what is missing. **Clients** carry
  newer versions too (§5.5).
- Nothing goes backwards. Branches are resolved by the same rule everywhere. Handle collisions give extended tags (§4.3).
- Limits: an event at most 4 KiB, a public profile 16 KiB, a vault 64 KiB, at most 16 locks, at most 1 000 events per identity.

---

## 8. Shape of the library

- **Crates:** `rootcard` (pure core), `rootcard-cli` (key tool), `rootcard-host` (challenge store, `IdentityStore` trait,
  framework-independent handlers). **npm:** `rootcard` (the same core in plain ES modules, zero dependencies) with `keytool.html`.
- **Pure core:** no I/O, no clock, no randomness of its own. Time and random bytes are passed in.
- **Everything application-specific is a parameter:** `realm`, `UsernamePolicy`, the application's profile namespace, the HTTP
  binding (the paths above are the recommended binding in `docs/HOST_PROTOCOL.md`, not a requirement).
- **API** (same names in Rust and JS): `Identity::create`, `Identity::from_recovery`, `verify_log`, `newer`, `current_instance`,
  `Vault::unlock`, `Vault::add_lock`, `Vault::revoke`, `Vault::new_instance`, `PublicProfile::set`, `login_message`, `prove`,
  `verify_proof`, `AccountFile::export` / `import`.
- **Error codes** (strings, for applications to translate): `handle_taken`, `not_home`, `stale_version`, `account_retired`,
  `challenge_expired`, `too_large`, `unsupported_browser`, plus a code per failed verification rule.
- The spec and the vectors are the contract, so other languages can implement rootcard and be checked against the same vectors.

---

## 9. An identity that lives forever (R10, R11)

### 9.1 Why it does not die
- **The root is the recovery card**, which the user owns. From it the inception and id are derived (§4.1), and a new instance can
  always be minted on a host serving the realm (§6.8), even if every host, file and password is gone. Only the vault contents
  and the public profile are lost then.
- **The id belongs to the root, not to an instance.** Instances, keys, passwords and hosts change; the id and handle stay.
- **Nothing expires.** Only `retire` closes an identity.
- **No backdoor:** whoever loses the card and every password has lost the identity, and registration says so.

### 9.2 Algorithm and format agility
- Every key has a type tag (`ed25519:`, `x25519:`) and every structure a `v`. New algorithms (for example ML-DSA and ML-KEM) are
  new tags and a `rotate_recovery` or `instance` switching to them. History stays valid.
- New lock types (passkeys with WebAuthn PRF) are new lock `kind`s.
- New Argon2 parameters apply to new locks. Clients suggest re-locking below the floor.
- Verifiers always read `v: 1`.

---

## 10. Accepted risks

1. **Offline guessing against the vault** by whoever has it (the primary host's operator, a thief of its database or of a current
   account file). Mitigated by never sharing vaults, Argon2id and password rules. A primary host may add its own secret later
   (OPAQUE or a pepper in the locks) without losing portability.
2. **The primary host sees passwords typed into its own client.** The user chooses the primary host. The password gives low power,
   the recovery key is used only in the key tool, the identity can move. Later: a signed client not served by the host.
3. **A stolen recovery key gives control.** Owner and thief can keep minting instances and neither wins over time. Witnesses and
   pre-rotation can come in `v: 2` without changing the id.
4. **A party that never sees the newer version** may believe an old instance is current. Only the previous primary host could let
   an old password in, and that account key is valid nowhere else.
5. **The owner's clock decides branches.** Hosts reject times more than 10 minutes ahead, and the tool shows the current instance
   afterwards.
6. **Public profiles cannot be taken back** once shared.

---

## 11. Tests

| What | Where |
|---|---|
| Ed25519 (strict), X25519, HKDF, Argon2id against RFC vectors | both implementations |
| Rust ↔ JS parity: canonical JSON, inception from the recovery key, id, handle, logs, version order, vaults, profiles, login, proofs | `spec/vectors/*.json` from `xtask vectors` |
| Forgery: other inception with the same tag, someone else's public key without its signature, altered event, proof from an old instance or for another recipient | both |
| Log rules: wrong `prev`, signer, realm, future time, after `retire` | both |
| Versions: extension, later branch wins, equal time lowest hash, no rollback | both |
| Vault: unlock with password and recovery key, add lock, revoke (old password and old vault stop working), fresh instance | both |
| Arbitrary data: key rules, sizes, versions only increase, old instance rejected, re-signed on `restore` | both |
| Power levels: nothing reachable with the account key changes the log or the locks | both |
| Hosts: register, handle collision, login, old nonce, wrong host, `not_home`, `stale_version`, revocation revokes sessions, export, rate limits, new instance on a second host | `rootcard-host` + example host |

---

## 12. Open questions

- Several primary hosts at the same time? Today no: one at a time, moving with a new instance.
- Should hosts share logs automatically, or only clients?
- Which reserved profile keys does rootcard itself need, if any?
- When does a signed client that is not served by the host become available (§10.2)?
