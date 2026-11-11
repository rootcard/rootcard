# rootcard: threat model

This document states what rootcard protects, against whom, where the trust boundaries are, and which risks are accepted.
Rule identifiers (`[LOG-12]`) refer to [spec/SPEC.md](../spec/SPEC.md). Design background is in [DESIGN.md](DESIGN.md)
§2 and §10. Every threat has an identifier (`T1`) and every accepted risk one (`AR1`); both are stable.

---

## 1. Security goals

| # | Goal |
|---|---|
| G1 | **Unforgeable identity.** Nobody but the holder of the recovery key can create an identity with a given account id, add an event to its log, or change who can unlock its vault |
| G2 | **Authentic login.** A host accepts a login only from someone who unlocked the current instance's vault just now and knows a password (or the recovery key) valid now, for this host, this address, this realm and this exact version |
| G3 | **No password exposure.** No host, peer or network attacker learns a password or anything that allows checking a password guess, except the primary host's own storage (AR1) |
| G4 | **Confidential private data.** Private data and the account key are readable only by whoever unlocks the vault |
| G5 | **Integrity of public data.** The log and the public profile cannot be altered by anyone but the owner, only withheld |
| G6 | **One latest version.** Every party that has seen a version rejects older ones and never switches to a fork; all parties detect forks the same way |
| G7 | **Bounded low power.** A stolen password or account key gives only low power ([PWR-1]–[PWR-4]), only in the current instance, and is revoked by one high-power action |
| G8 | **Always recoverable.** The recovery key can always mint a new, complete instance, without any host's cooperation except the new primary host's receipt |
| G11 | **Operable hosts.** A host can run on many servers, rotate its key, change its address and retry requests without weakening G1–G7 |
| G9 | **Unlinkability across identities.** Two identities made from one recovery key are not linkable by their public data ([RK-4]) |
| G10 | **Application neutrality.** No application can use rootcard data to act in another application's namespace or realm |
| G12 | **Two-sided links.** A link to an external account is shown as verified only if the identity's current profile names the account and the account names the identity, both checked by the viewer itself (SPEC §12.3) |

Non-goals: anonymity towards the primary host (it sees logins and network addresses), hiding that an identity exists
(handles and logs are public by design), availability against a host that refuses service (the owner can move, G8), and
protection of a device that the attacker controls while the user unlocks on it.

---

## 2. Assets

| # | Asset | Where it lives | Protected by |
|---|---|---|---|
| A1 | Recovery key (and its derived seeds) | Recovery card, offline; the key tool's memory during use | User custody, [PWR-6], [IMP-2] |
| A2 | Password | The user's head; the client's memory during unlock | Never sent ([LGN-3]), Argon2id ([LCK-6]) |
| A3 | Account key (private) | Vault contents; client memory while unlocked | AES-256-GCM, non-extractable import ([LGN-2]) |
| A4 | Vault key | Wrapped to each lock; memory during unlock | X25519 + HKDF + AES-GCM wraps ([LCK-9]) |
| A5 | Vault (ciphertext and locks) | Primary host; account files | Fetch gating ([FET-1]), never shared ([HST-13]) |
| A6 | Private data | Vault contents | As A4, A5 |
| A7 | Identity log | Everywhere | Signatures, hash chain ([LOG-12]) |
| A8 | Public profile | Hosts, clients | Account-key signature ([DAT-2]) |
| A9 | Host key | The host | Host operations security |
| A10 | Session tokens | Client memory; host stores the hash ([HST-10]) | TLS, bearer header, idle expiry |
| A11 | Account id ↔ person mapping | Hosts, clients | Not secret; tags are not identifiers ([HDL-2]) |

---

## 3. Actors and attacker capabilities

| # | Actor | Capabilities assumed |
|---|---|---|
| X1 | **Network attacker** | Reads, drops, replays and modifies traffic, but cannot break TLS to a host whose certificate the client checks |
| X2 | **Other user** | Registers identities, chooses usernames, brute-forces tags (≈ 2²⁰ work), sends arbitrary data to hosts and clients |
| X3 | **Peer host** (malicious or compromised) | Sends arbitrary logs, profiles and events; withholds data; lies about versions |
| X4 | **Non-primary host** a user talks to | As X3, and serves the client code the user runs on its pages |
| X5 | **Primary host** (malicious operator or full compromise) | Everything the host stores: vaults, sessions, logs; serves the client code; sees every login |
| X6 | **Database thief** of a host | A copy of the host's storage at one point in time |
| X7 | **Password thief** (phishing, shoulder surfing, reuse) | One password of the user |
| X8 | **Account-file thief** | A downloaded account file, possibly old |
| X9 | **Recovery-card thief** | The recovery key (current or rotated out) |
| X10 | **Malicious application** in the same realm or another | Its own client code, its own namespace, the user's trust in it |
| X11 | **Supply-chain attacker** | Tries to ship modified packages or a modified key tool page |
| X12 | **Quantum adversary** (future) | Breaks Ed25519 and X25519 given public keys |
| X13 | **Linked service or domain** (or whoever controls its answers: its operator, a taken-over account, a new domain owner, a DNS resolver) | Answers a verifier's link checks with anything, slowly, hugely or with redirects |

Not in scope: an attacker who controls the user's device or browser while the user enters the password or recovery key,
and side channels on the user's device beyond constant-time comparisons ([IMP-4]).

---

## 4. Trust boundaries

```
 ┌───────────────────────── user's device ─────────────────────────┐
 │  key tool (CLI / keytool.html)      application client          │
 │  sees: recovery key, password       sees: password, account key │
 │  high power                         low power                   │
 └────────────┬──────────────────────────────┬─────────────────────┘
              │ TLS (B1)                     │ TLS (B1)
 ┌────────────▼──────────────┐      ┌────────▼──────────────────────┐
 │ primary host (home)       │◄────►│ other hosts in the realm      │
 │ vault, log, profile,      │ (B2) │ log, profile only             │
 │ sessions, logins          │      │ answer not_home               │
 └───────────────────────────┘      └───────────────────────────────┘
        B3: the primary host serves the application client code
```

- **B1 (client ↔ host):** everything crossing it is either public (log, profile, lock hints), a signature over a fresh
  challenge, or the vault after a lock proof. Secrets never cross it.
- **B2 (host ↔ host):** only public logs and profiles cross it ([HST-13]), and the receiver verifies everything itself
  ([HST-14]).
- **B3 (code served by the host):** a client served by a host can do whatever that host wants with what the user types
  into it. This boundary is the reason for power levels: what is typed into a host-served client (the password) gives
  low power; what gives high power (the recovery key) is typed only into the key tool, which the host does not serve
  (AR2).
- **B4 (key tool):** the key tool is trusted with the recovery key. It is distributed through package registries with
  provenance (CLI, npm) and works offline from a local file (`keytool.html`), so no host can change it after the user
  obtained it.

---

## 5. Assumptions

1. SHA-256 is collision and second-preimage resistant; Ed25519 with strict verification is existentially unforgeable;
   X25519 is a secure key agreement; HKDF-SHA256 is a secure KDF; AES-256-GCM with unique nonces is a secure AEAD;
   Argon2id is memory-hard.
2. Random number generators of operating systems and browsers are secure.
3. TLS protects client ↔ host traffic, and users reach the host they intend (they choose the primary host).
4. The user keeps the recovery card offline and does not type it outside the key tool.
5. Host clocks are within a few minutes of real time; the owner's clock is honest (AR5).

---

## 6. Threats and mitigations

| # | Threat | Actor | Mitigation | Rules | Remaining |
|---|---|---|---|---|---|
| T1 | Create an identity with someone else's account id | X2, X3 | The id is the hash of the signed inception; a second inception with the same hash needs a SHA-256 second preimage; an inception naming the victim's recovery key needs its signature | ID-1, ID-3, LOG-12 | – |
| T2 | Impersonate by handle: same username and a brute-forced tag | X2 | Applications compare full ids; hosts refuse colliding handles; collisions from propagation get extended tags; clients remember full ids and warn | HDL-2, HDL-5, HDL-6, CLT-4 | A user who only reads the plain tag can be fooled once (AR7) |
| T3 | Look-alike usernames (Unicode homographs) | X2 | Usernames are ASCII only; similarity is case-insensitive | USR-1, USR-2, HDL-4 | `l`/`I`, `0`/`O` look-alikes in some fonts; applications may tighten their policy |
| T4 | Add an event without the recovery key (claim an instance, rotate, retire) | X3–X8 | Every event is signed by the current recovery key; new keys self-sign; instances need the home's receipt | LOG-7, LOG-8, LOG-12, PWR-1 | – |
| T5 | Name someone else's public key (as account key, recovery key or home) | X2, X3 | Proof of possession: every key that enters the log signs that event | LOG-7 | – |
| T6 | Replay a login to the same or another host | X1, X3–X5 | Login signs host key, address, realm, exact version and a single-use 60 s nonce bound to account and purpose; single use holds across all servers of a host | CHL-2, LGN-1, HST-19 | – |
| T7 | Relay a login or fetch through a phishing site | X1, X4 | The signed message names the address the client actually connected to, and the real host accepts only its own addresses | LGN-4, HST-18 | A host-served client that the user reached by phishing is a malicious client (T19) |
| T8 | Cross-protocol signature reuse (a login signature as a proof, an event signature as a receipt) | all | Every signed message is framed with its own label and is a canonical JSON object with the context | DS-1–DS-3 | – |
| T9 | Parser differentials (duplicate members, number forms, Unicode escapes, unknown members) that make two implementations see different content under one signature | X2, X3 | Strict parser, canonical re-serialization before every hash, strict schemas with unknown members rejected, shared reject vectors, and a differential test of the two cores on mutated inputs in CI | CJ-1–CJ-13, CNV-3 | – |
| T10 | Signature malleability and weak keys (small-order points, non-canonical encodings) | X2, X3 | Strict verification with explicit checks, identical in both languages | CRY-3, KEY-3 | – |
| T11 | Download a vault and guess the password offline | X2, X3, X4 | The vault is released only after a lock proof or with a session; lock hints carry no verifier; fetches are rate limited; Argon2id and password rules | FET-1–FET-3, VLT-5, LCK-6, LCK-8 | Online guessing within the rate limits |
| T12 | Steal a host's database and guess passwords offline | X5, X6 | Only the primary host stores vaults, only of its own identities; Argon2id with high memory cost | HST-2, HST-13, LCK-6 | Weak passwords fall (AR1) |
| T13 | Use a stolen password | X7 | Low power only, only at the primary host, only in the current instance; the owner can change it with the old password (logins stop at once) or reset with the recovery key (a new instance ends every session and copied account key) | PWR-1–PWR-5, LGN-5, CHG-3, HST-7, KT-8 | The thief can log in and read or change private data until the owner changes or resets the password |
| T14 | A password thief adds their own password, or re-adds a revoked one, to keep access | X7 | Password slots are fixed by a recovery-signed grant with a generation counter; low power can only replace the material of an existing slot, with its old password | LCK-3, LCK-10, VLT-4, HST-12 | – |
| T15 | Use an old account file (with a password) after revocation | X8 | A new instance invalidates the old vault, account key and sessions; hosts and clients that saw the newer version reject the old one | VER-4, VER-6, HST-7 | A party that never sees the newer version (AR4) |
| T16 | Roll an identity back to an older version (replay an old log, profile or vault) | X3–X5 | Extension order; monotonic storage; logins bound to the exact version; revisions only increase | VER-2, VER-4, VLT-4, DAT-3, LGN-1 | Withholding (AR4) |
| T17 | A host alters or forges a public profile | X3–X5 | Signed by the account key, bound to the instance and revision | DAT-2 | A host can withhold it or serve an older copy of the current instance until the client sees a newer one |
| T18 | A host forks the log | X3–X5 | A host cannot sign events; only a recovery-key holder can fork, and every party detects and rejects forks the same way | VER-2, VER-3 | – |
| T19 | The primary host serves a malicious client that captures the password | X5, X4 | The password gives low power only; the recovery key is never typed into an application client; the owner can move to another host | PWR-6, CLT-5, KT-3 | The primary host can capture passwords typed into its own client (AR2) |
| T20 | Phishing for the recovery key with a fake key tool or a fake host page | X4, X11 | Application clients never ask for it, and applications warn; pages that show the recovery public key label it as public, so a "recovery key" on a website is never normal; the key tool is installed from registries with provenance or kept as a local file | PWR-6, CLT-5, CLT-8, KT-1 | A user who types the key into a phishing page loses the identity (AR3) |
| T21 | Stolen recovery key | X9 | Kept offline; used only in the key tool | RK-3, PWR-6 | The thief controls the identity (AR3) |
| T22 | A rotated-out recovery key is used to fork the log from before the rotation | X9 | Parties that saw the rotation keep their log and reject the fork | VER-3, VER-4 | Parties that never saw the rotation may adopt the thief's branch first (AR3, AR11) |
| T23 | A recovery-key thief retires the identity, or extends it first | X9 | – | VER-3 | Retirement is final; a thief's events adopted first by a host stay there (AR3) |
| T24 | Back- or future-dated events | X9, owner | Time decides nothing in format version 1; hosts reject events more than 600 s ahead and receipt instances only within ± 600 s of their clock | LOG-12, HST-6 | – |
| T25 | Denial of service with expensive inputs (huge or deep JSON, long logs, extreme Argon2id parameters, many signatures) or with state that anyone can create (challenges) | X2, X3 | Size limits checked before parsing; depth limit; event and lock limits; Argon2id bounds; rate limits; expired challenges are deleted (ARCHITECTURE.md §3.1); extreme times are compared without overflow | CJ-5, CJ-8, LOG-1, LOG-2, LCK-6, HST-16, CHL-2, §19 | Verifying a maximal log costs about 3 000 signature checks (also when a host checks a claimed fork, [HST-14]) |
| T26 | Lock out the owner by exhausting fetch or login rate limits | X2 | Rate limits per identity and per network address; a cached vault skips the fetch | HST-16, LGN-1 | Partial (AR8) |
| T27 | Stored cross-site scripting through profile or private data | X2, X10 | Data is displayed only as text; keys are restricted; sizes are bounded | DAT-4, DAT-8 | – |
| T28 | An application writes into another application's namespace | X10 | Write functions are restricted to the application's namespace and `user.` | DAT-7 | A malicious client can ignore the library and sign anything with the account key it holds (low power, own identity only) |
| T29 | Linking identities of one person across realms by their recovery public key | X2–X5 | Recovery keys are derived per realm and username | RK-4 | Network addresses, timing and the primary host link them (non-goal) |
| T30 | AES-GCM nonce reuse | – | Random 96-bit nonces, a fresh vault key per instance, a fresh wrap key per wrap, at most 2³² encryptions per key | CRY-7, LCK-9, VLT-4 | Negligible collision probability |
| T31 | Secret material left in memory or exported from WebCrypto | malware after the fact | Zeroization; non-extractable keys | IMP-2, LGN-2 | Garbage-collected copies in JavaScript cannot be fully controlled |
| T32 | Supply-chain compromise of the packages | X11 | Zero npm dependencies and no install scripts, enforced by `xtask repo-check`; audited Rust crates; `cargo deny` on every pull request and a daily RustSec advisory check; reproducible packages, and the release checks that the registries serve exactly the packages built from the tag; releases only from CI with trusted publishing and provenance; every third-party action pinned to a commit SHA and npm to an exact version, enforced by `xtask repo-check` | AGENTS.md rule 6 | Compromise of the CI or registry accounts, or of a pinned action's own repository before a pin is updated |
| T33 | Session theft | X1, X5 | Random tokens stored hashed (or the host's own session mechanism), bound to host, account and instance; checked against the current instance on every use; idle expiry | HST-10, HST-11 | A thief with a session has low power until it expires or the owner makes a new instance |
| T34 | A host claims an instance that names it without the owner (or names another host) | X3–X5 | The instance must be signed by the recovery key; the receipt must be by `home.key` itself | LOG-8, LOG-12 | – |
| T35 | A host's key leaks, or the host rotates it | X5 | Host keys sign nothing that creates or changes an identity without the recovery key; hosts rotate by making a new key current and keeping the old one as retired | HST-17, LOG-8 | A leaked key lets an attacker impersonate the host towards its peers until it rotates |
| T36 | Malicious lock hints (wrong salt, maximal Argon2id cost) | X5 | Hints are only for the primary host's own identities; Argon2id bounds limit the cost | FET-2, LCK-6 | The primary host can make a login fail or cost up to the bound |
| T37 | Quantum attacks on Ed25519 and X25519 | X12 | Typed keys and versioned structures allow a migration by a later format version | EXT-1, EXT-3 | Recorded traffic and vaults could be attacked later; harvest-now attacks on X25519 wraps of stored vaults |
| T38 | Concurrent requests on several servers of a host lose an update or move an identity backwards | – | Every change is a compare-and-swap on the stored version, `rev` or `gen`; handle claims and nonce use are atomic | HST-19 | – |
| T39 | A retried request after a lost response fails, or creates a second receipt or session | X1 | Identical resubmissions return the original answer | HST-20 | – |
| T40 | A password thief changes the password and locks the owner out | X7 | – (a password change needs only the old password, by design) | CHG-1 | The owner resets with the recovery card, which ends the thief's access (AR12) |
| T41 | A stolen session (without the password) changes the password | X1, X5 | A change needs a proof by the old password's lock key, and every login a current lock proof | CHG-2, LGN-5 | – |
| T42 | Handle squatting: push cheap inception-only logs to a host's public `/events` until every tag of a username is taken there, so the real user cannot register it | X2 | Only identities registered at a host reserve a handle there; pushed and propagated identities may collide and are told apart by extended tags (found in the review of 0.2.0, fixed in 0.3.0) | HST-4, HDL-5, HDL-6 | – |
| T43 | A host address that reaches another path after normalization (`/v0/..`, `/%76%30`) puts an API version or a foreign path into `home.url` | X2, X4 | Base URLs have only unreserved characters in their path and no dot segments; hosts, clients and the key tool check every address | HST-22 | Verifiers of a log do not apply the check (LOG-4 alone defines `home.url`) |
| T44 | A weak password is set after registration (a change, an added slot, a reset), where no host can check it | owner, X10 | Every core function that creates a password lock enforces the password rules, not only registration (0.3.0) | LCK-8 | A modified client can skip the library (low power, own identity only) |
| T45 | A browser's WebCrypto cannot use some keys: WebKit (Safari) rejects an Ed25519 seed or X25519 secret whose first byte is zero (about 1 key in 256), so registration, rotation or login fails at random and a password whose login key is such a seed never works there | platform | X25519 secrets are passed as the same scalar after clamping; new Ed25519 seeds (account seed, recovery key, password salt) are drawn again until usable; a JavaScript client signs with an older such seed by importing it with its public key on record (found by the WebKit browser job, fixed in 0.3.0) | CRY-2, CRY-9, IMP-6 | An identity made before 0.3.0 whose recovery signing seed starts with zero cannot be opened in Safari's key tool from the typed recovery key alone (the inception is recomputed before any key is on record); the card file, the CLI or another browser work |
| T46 | A forged or hijacked host pointer (`/.well-known/rootcard`) sends a user who typed a domain to another host, or one that answers with a redirect or a huge body | X2, X4 | The pointer is resolved only for a typed origin, only to a base URL on that same origin (`wrong_host` otherwise), without redirects and with a 4 096-byte limit; it is never stored: `home.url` and signed messages carry the resolved base URL, and addresses from a verified log are not resolved | HST-23, LGN-4 | Whoever controls the origin's server controls its pointer, as it controls the host itself; an origin without a pointer is used as the base URL |
| T47 | An identity claims an external account it does not control | X2 | The token must be at a location only the account's owner can write; missing → `token_missing` | LNK-6, LNK-7, LNK-10 | – |
| T48 | An external account claims an identity by posting its token | X2, X13 | Verifiers start from the identity's signed, current profile and show only links listed there | LNK-3, LNK-10 | – |
| T49 | A service name is renamed, deleted and registered again by someone else, who posts the token | X2, X13 | Descriptors of such services require the stable `uid` and every check compares both `uid` and `name` with the answer | LNK-18, LNK-22 | – |
| T50 | Profile data steers a verifier's requests: another host, another path (`..`, `%2e%2e`), a query, a `javascript:` link | X2 | URLs come only from descriptor templates with literal hosts or `domain` fields; values are percent-encoded, fill whole path segments and are never `.` or `..`; no URL from profile data is fetched or displayed (the dot-segment case was found while adopting the proposal, before release) | LNK-8, LNK-12, LNK-21, LNK-22 | – |
| T51 | A server-side verifier is made to reach internal addresses (SSRF) through a `domain` field (`intranet.example`, a name resolving to `10.0.0.1`) | X2 | `domain` names are never IP addresses and never single labels; a server-side verifier connects only to public addresses, checked after resolution; answers are only searched for the token | LNK-9, LNK-21 | A verifier that ignores [LNK-9] can be made to send `GET` requests without credentials to internal names |
| T52 | A changed or injected descriptor makes false links verify | X11, X10 | Descriptors are bundled and reviewed like code, never loaded at run time; the format's rules bind every descriptor and are checked by the parser and by `xtask` | LNK-19, LNK-22 | A site that adds its own descriptors is trusted for them, and labels them as its own |
| T53 | A service or domain answers with huge, slow, redirecting, deeply nested or active content | X13 | No redirects, 64 KiB, 10 s, the strict reader with a depth limit, text only searched, never rendered | LNK-9, DAT-8 | – |
| T54 | A website, badge or host says "verified" without checking | X4, X10 | Viewers check themselves; others' results are labelled as theirs, with a time | LNK-11 | – |
| T55 | The token is placed in a comment, issue or other field someone else can write | X2 | Only owner-writable locations are read: the descriptor names exact pointers (`/bio`, `/files/*/content`) | LNK-7, LNK-22 | – |
| T56 | Look-alike names (`examp1e.org`, Unicode domains, `Alice` vs `alice`) | X2 | Domains in ASCII only, names shown as text; names are compared as the service compares them | LNK-12, LNK-21, LNK-2 | Viewers still compare names themselves (as AR7) |
| T57 | An unknown service, form or version breaks old verifiers, or is shown as verified | – | Unknown is `unsupported`, never invalid and never verified | LNK-13 | – |
| T58 | The JSON reader of answers differs between the cores, so one verifies what the other rejects | X13 | One strict-but-lenient reader per core (null and other numbers dropped, duplicates rejected), shared vectors, the differential test and the `links` fuzz target | LNK-9 | – |

---

## 7. Secure and feasible: decisions

| Part | Decision | Reason |
|---|---|---|
| Ed25519, X25519, SHA-256, HKDF, AES-GCM | **Used** | Standard, reviewed, available in WebCrypto and in audited Rust crates |
| Argon2id in plain JavaScript | **Used**, tested against RFC 9106 and the shared vectors | WebCrypto has no memory-hard KDF; WASM would add a build step and a dependency |
| Strict Ed25519 with explicit pre-checks | **Used** | Platform verifiers differ on edge cases; both languages must reject the same signatures |
| Self-certifying id from a deterministic inception | **Used** | No registry, and the recovery key can always re-derive the identity |
| Hash chain, extension order, forks detected | **Used** | Rollback protection without consensus; hosts only ever append |
| Deterministic fork resolution | **Later** | A time-based rule was drafted but lets a rotated-out recovery key win and makes hosts switch instances; it belongs with witnesses (Appendix A of the spec) |
| Vault only at the primary host, released after a lock proof | **Used** | Restricts offline guessing to the primary host's storage and account files |
| Recovery-signed grants | **Used** | Makes "who can unlock" high power in the format, not by policy |
| Password change with the old password | **Used** | Users expect it in the browser; it replaces one slot's material and cannot add slots. Reset of a forgotten password stays with the recovery key |
| Reset by e-mail or by the host (escrow) | **No** (decided) | Would give the host power over the identity |
| OPAQUE or a server pepper | **Not now** | Needs per-host secrets and heavy client code; conflicts with portability. A primary host may add one later without a format change to the log (AR1) |
| Passkeys (WebAuthn PRF) as a lock | **Later** | Strong against phishing but bound to a host's domain; a new lock `kind` ([EXT-3]) |
| Witnesses and pre-rotation (KERI style) | **Later**, format version 2 | Would make rotation effective against a stolen key (AR3); more complex and two secrets to keep |
| Global handle uniqueness by consensus | **No** | Infeasible; per-host uniqueness and extended tags instead |
| Proof of work in the inception against tag brute force | **No** | Slows registration, gives hosts an expensive check per unknown identity (a DoS vector) and does not stop a determined attacker |
| Protection against the primary host's own client | **Accepted risk** (AR2) | Impossible for code served by that host |
| Recovery without the recovery key | **No, by design** | Would be a backdoor |

---

## 8. Accepted risks

- **AR1: Offline guessing by whoever holds a vault.** The primary host's operator, a thief of its storage, or a thief of
  a current account file can run Argon2id guesses against the vault's locks. *Mitigations:* vaults are never shared or
  handed out without a lock proof, Argon2id at 64 MiB by default with a 46 MiB floor, at least 12 characters and a
  common-password check. *Future:* a primary host may add its own secret (OPAQUE or a pepper) as an additional lock
  layer.
- **AR2: The primary host sees passwords typed into its own client.** The user chooses the primary host; the password
  gives low power; the recovery key is used only in the key tool; the identity can move with one high-power action.
  *Future:* a signed client that is not served by the host.
- **AR3: A stolen recovery key gives control.** The thief can add events, mint instances and retire the identity (which
  is final). A rotated-out key in format version 1 can still fork the log from before the rotation; parties that saw the
  rotation reject that fork, but a party that never saw it may adopt the thief's branch and then keeps it (AR11).
  *Advice:* rotate to replace a worn or exposed card, submit the rotation to the primary host and its peers at once,
  destroy old cards, and treat a suspected compromise as the loss of the identity. *Future:* witnesses and pre-rotation
  in a later format version without changing the id.
- **AR4: A party that never sees the newer version** may believe an old instance is current. Only the previous primary
  host could let an old password in, it is told first ([HST-15]), and the old account key is valid nowhere else. Clients
  and hosts carry newer versions forward ([VER-5]).
- **AR5: (withdrawn)** In an earlier draft the owner's clock decided between branches. In format version 1 time decides
  nothing (T24).
- **AR6: Public profiles cannot be taken back** once shared.
- **AR7: The tag is not a security feature.** Users who compare only the 4-character tag can be fooled by a collision
  made with about a million attempts. Applications compare full ids and show extended tags; users who need certainty ask
  for a proof (§14 of the spec).
- **AR8: Lock-out by rate limits.** An attacker can exhaust per-identity fetch limits for a while. A client with a
  cached vault is unaffected; hosts should combine per-identity and per-address limits.
- **AR9: Metadata.** Handles, logs (including the primary host and the times of events) and public profiles are public.
  Lookups reveal that an identity exists. The primary host sees when and from where the user logs in.
- **AR10: Lock labels are visible** to anyone who asks the primary host for lock hints.
- **AR11: Forks are not resolved.** If a recovery-key holder forks a log (by mistake from an old account file, or as a
  thief), hosts keep whichever branch they saw first, so different hosts can disagree until the owner extends the branch
  the primary host holds. The key tool gathers every reachable log before signing to avoid this ([KT-2]).

- **AR12: A password holder can change the password.** A thief who knows the password can replace it and lock the owner
  out until the owner resets with the recovery card ([KT-8]), which also ends the thief's access. A password change by
  the owner, in turn, does not revoke an account key someone already copied ([CHG-3]); after a suspected leak the owner
  resets instead.
- **AR13: A lost recovery card cannot be replaced** in format version 1: rotation needs the old key. The account keeps
  working with its password, but can no longer be reset, moved or retired.
- **AR14: A password thief edits links** (SPEC [LNK-4]). Adding a link to the thief's own account makes the identity
  appear to be that account; removing links hides the owner's. Low power like every profile edit, ended by a reset with
  the recovery card (AR12). Links signed by the recovery key would prevent it and are not planned.
- **AR15: A link is as strong as the external account.** Its side is the service's word: a compromised GitHub account,
  a dishonest service, or the new owner of an expired domain (`dns` and `web` have no stable id) controls it. A domain
  that changes hands confirms a link that a stale profile still lists. *Advice:* remove links before letting a domain
  expire.
- **AR16: DNS answers without DNSSEC** can be forged by an attacker on the verifier's path or at its resolver, and a
  browser verifier reads DNS through a DNS-over-HTTPS resolver it trusts. Verifiers show the resolver and whether
  DNSSEC was validated.
- **AR17: Stale profiles and link privacy.** A verifier that cannot reach the home may show a link from an older profile
  the owner has since changed (DAT-9); the owner removes the token too, which ends the link for every check. Links are
  public and link the identity to the external accounts; each check tells the service the viewer's address and that
  someone looked. A user who does not want this uses another identity (G9).

---

## 9. Review checklist

For every change, reviewers check:

1. Does it add anything that is hashed or signed? Then it is a format change (spec §22) with a new label or `v`, and
   vectors.
2. Does it add a way to change who can access the identity, where it lives or whether it exists? Then it needs the
   recovery key (spec §16).
3. Does any new input reach a parser or verifier? Then it has limits, reject vectors and (before 1.0) a fuzz target.
4. Does any secret cross a trust boundary (§4)? It must not.
5. Is the threat table still true? Update it in the same change. A review finding that is not fixed at once is recorded
   here as a threat with its residual risk, or as an accepted risk (§8), in the same pull request that records it in
   docs/PLAN.md.
