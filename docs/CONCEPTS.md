# rootcard: concepts

An informative guide to the five things an identity is built from: the **log**, the **vault**, the **recovery card**,
**proofs** and **verification**. For each one it covers what it is, how it works and when it is used. The rules
themselves live in [spec/SPEC.md](../spec/SPEC.md). This guide only explains them and cites them by id
(`[LOG-12]`, `§11`). Where the two differ, the spec wins. Threats and accepted risks are in
[THREAT_MODEL.md](THREAT_MODEL.md), and the HTTP endpoints are in [HOST_PROTOCOL.md](HOST_PROTOCOL.md).

## The big picture

An identity has one root secret, the **recovery key**: 32 random bytes the user keeps offline and types only into the
key tool ([PWR-6]). (In about 1 case in 256 the bytes are drawn again, so that the signing key derived from them works
in every browser: [CRY-9].) Everything else is derived from it or signed by it (SPEC §1):

```
recovery key ─HKDF─► recovery signing key ─signs─► inception ─SHA-256─► account id ─► handle Astra#3F9C
                              └─signs─► instance { account_key, home } ─► account key ─signs─► login, proof, vault, profile
password ─Argon2id─HKDF─► lock keys ─unwrap─► vault key ─decrypts─► account key, private data
```

- The **log** is public and says who the identity is and which key is valid now.
- The **vault** is private and holds the key that does everyday work.
- The **recovery card** is the backup of the root secret. Its public part, the **recovery public key**, is in the log
  for anyone to see; software labels it as public and never calls it "recovery key" alone ([CLT-8]).
- **Proofs** and **verification** are how other people and hosts check all of it.

The power split (SPEC §16) runs through all of them. The password unlocks the vault, which is low power. Only the
recovery key changes the log or the vault's grant, which is high power.

## 1. The identity log (SPEC §9, §10)

**What it is.** A public, append-only hash chain of signed events. It holds public keys only.

| Event | What it does | Signed by |
|---|---|---|
| `incept` (seq 0) | Creates the identity: realm, username, recovery public key | recovery key |
| `instance` | Names a new account key and the primary host (`home`). Every earlier instance becomes invalid | recovery key, the new account key, and the host's receipt |
| `rotate_recovery` | Replaces the recovery key | old and new recovery keys |
| `retire` | Closes the identity for good | recovery key |

**How it works.**
- The inception is deterministic ([ID-2]). The account id is its hash ([ID-3]). The id can therefore be re-derived
  from the recovery card alone, and it never changes ([ID-4]).
- Each later event links to the previous one by hash (`prev`). Every key that enters the log signs the event that
  introduces it ([LOG-7]).
- An `instance` event is valid only with the primary host's receipt ([LOG-8]), so no instance exists without the host's
  consent. Clients submit a *pending instance* without the receipt ([LOG-9]).
- Only the current recovery key can add events ([LOG-13], [PWR-1]).
- A log's **version** is its last event. Log `b` is newer than log `a` only if `a` is a strict prefix of `b` ([VER-2]).
  Every party keeps the newest log it has seen and never moves back or switches to a fork ([VER-4]). Forks are detected,
  not resolved, in format version 1 ([VER-3]).

**When it is used.** The log is written at registration and afterwards only by the key tool: restore, revoke, password
reset, moving hosts, rotation and retirement. It is read at every login, at every vault, profile and proof check, and
whenever hosts share identities ([HST-13]–[HST-15]).

## 2. The vault (SPEC §11)

**What it is.** An encrypted blob bound to exactly one instance. It holds:
- the instance's private account key (`account_seed`);
- the private data (§12.2);
- `known`: the identities the user has dealt with, so a client can warn about look-alike handles ([VLT-7], [CLT-4]).

It never holds the recovery key ([VLT-9]). It is stored only at the primary host and in account files the user
downloads ([VLT-5]).

**How it works.**
- **Encryption.** The contents are encrypted under a random **vault key**, which is wrapped once for each **lock**
  ([LCK-9], [VLT-6]).
- **Locks.** There are up to 15 password locks, derived with Argon2id, and one recovery lock, derived from the recovery
  key ([LCK-7], [RK-4]). Password locks do not depend on the instance, so they carry over to a new instance ([KT-3]).
- **Grant and list.** The **grant** says who may unlock: the slots and the recovery lock key. Only the recovery key signs
  it ([LCK-3]), so a password holder cannot add a slot of their own. The **list** holds each lock's key material. A
  password change replaces one slot's material, using the old password ([LCK-10], §13.4).
- **Signature and rollback.** The account key signs the whole vault ([VLT-2]). `rev` and `grant.gen` only increase,
  which stops rollback ([VLT-4]).
- **Unlocking.** Unlocking happens on the client and ends by checking that the decrypted account key is the one the log
  names ([VLT-8]). A host never decrypts a vault and never runs Argon2id (§17).

**When it is used.**
- **Registration:** created with one password slot and the recovery lock ([CLT-1]).
- **Login:** fetched by proving a lock ([FET-1]), then unlocked locally (§13.3).
- **Data edits:** replaced with a session ([HST-12] case 1).
- **Password change:** replaced with a session and a proof made with the old password ([CHG-1]).
- **Adding a password slot:** a new grant from the key tool ([KT-4]).
- **Revoke, reset, restore and fresh:** a new instance gets a new vault ([KT-3], [KT-8]).

## 3. The recovery card (SPEC §6, §15.2)

**What it is.** Everything needed to mint a new instance when nothing else is left ([CRD-1]): the recovery key in its
written form `RCR-…` ([RK-1]), the realm, the username, and the account id as a check.

**How it works.**
- The written key carries a checksum, so typos are caught ([RK-2]).
- The keys are derived with the realm and the username ([RK-4]), so identities made from the same recovery key cannot be
  linked.
- `read_card` re-derives the inception and checks that its id equals the card's account id ([CRD-3]).
- After a rotation, the inception can no longer be derived from the new key, so the card also carries the log up to the
  `rotate_recovery` event ([CRD-2]).
- The canonical JSON doubles as the QR payload ([CRD-4]).

**When it is used.**
- **Creation:** generated once at registration, shown to the user and erased from the application client ([CLT-1]). It
  is reissued after every rotation ([KT-5]).
- **Use:** entered only in the key tool ([PWR-6]), for every high-power operation:
  - resetting a forgotten password ([KT-8]);
  - adding or revoking passwords ([KT-4]);
  - restoring or moving to another host ([KT-3]);
  - rotating the recovery key ([KT-5]);
  - retiring the identity ([KT-6]);
  - root proofs ([PRF-2]).

  There is no reset by e-mail or by the host ([PWR-5]). Without the card, a forgotten password cannot be recovered.

## 4. Proofs (SPEC §14)

**What it is.** A signed statement that shows a verifier, another user or another host, that the prover controls an
identity now.

| Kind | Signed by | Valid while | Made in |
|---|---|---|---|
| Account proof ([PRF-1]) | the account key of the named instance | that instance is current | any client, with the password |
| Root proof ([PRF-2]) | the recovery signing key | that key is the current recovery key | the key tool only |

**How it works.**
- `recipient` names the verifier, so a proof cannot be forwarded to a third party ([PRF-3]).
- An interactive proof signs a fresh challenge from the verifier.
- A statement proof signs the hash of a statement. It is replayable by design, so the statement should say what it is
  for and until when ([PRF-5]).

**When it is used.** Whenever someone other than the primary host needs to know "is this really `Astra#3F9C`, now?"
Examples are a service keyed by the account id, linking two identities, or a host checking a peer's user. Logins are
not proofs: they have their own message and happen only at the primary host (§13.3). A standard sign-in flow at other
services built on proofs is a proposal ([proposals/signin.md](proposals/signin.md)). Showing that an identity owns a
GitHub account or a domain needs no proof at all: it is a linked account (§6).

## 5. Verification

Every party verifies everything itself. A host never trusts another host's claim ([HST-14]), and every check is
strict Ed25519, a hash or a size ([CRY-3], §17).

- **Logs:** `verify_log` ([LOG-12]) checks the inception, then each event in order: chain, sequence, time, the exact
  signers, key reuse, signatures and receipt. It returns a **log state** with the current recovery public key, the
  current instance and the version. `extend_log` ([LOG-15]) does the same for new events only, starting from a stored
  state, so a host never re-checks old signatures.
- **Everything else** is checked against a log state:

  | Function | Checks | Rule |
  |---|---|---|
  | `verify_vault` | the vault | [VLT-3] |
  | `verify_public` | the public profile | [DAT-2] |
  | `verify_proof` | a proof, after merging the log the prover sent | [PRF-4] |
  | `import_account` | an account file | [FIL-3] |
  | `read_card` | a recovery card | [CRD-3] |

- **Logins** are checked by the primary host ([LGN-1] step 6):
  - a single-use challenge ([CHL-2]);
  - the address the client actually connected to ([LGN-4]);
  - the exact version;
  - two signatures, one by the account key and one by the lock that was unlocked ([LGN-5]).
- **Freshness:** vaults, profiles and account proofs are valid only for the current instance of the newest log the
  verifier knows ([VER-6]). A new instance minted with the recovery key therefore ends every old vault copy, password,
  session and account proof at once ([HST-7], [HST-11]).

## 6. Linked accounts (SPEC §12.3)

**What it is.** A statement that the identity and an account elsewhere have the same owner: "`Astra#3F9C` is `alice`
on GitHub and owns `example.org`". It has two sides, and neither alone is a link:

| Side | Where | Who can write it | Says |
|---|---|---|---|
| Identity side | `user.links` in the signed public profile ([LNK-1]) | the account key (low power, [LNK-4]) | "I am GitHub `alice` (id 583231)" |
| External side | the link token `rootcard:<account id>` ([LNK-5]) in a place only the account's owner can write ([LNK-7]): a GitHub bio or gist, a DNS TXT record at `_rootcard.<domain>`, the file `https://<domain>/.well-known/rootcard-link` | the external account's owner | "I belong to this account id" |

**How it works.**
- Services are data, not code: one **descriptor** per service in the registry `spec/links/` ([LNK-22]), bundled with
  both cores ([LNK-19]). A descriptor names the account's fields, the requests that check it and what the answers must
  say. The spec names no service, so a new one is a reviewed data change.
- A verifier reads the links of the current profile (`parse_links`), asks the core what to fetch (`link_requests`),
  fetches it under strict rules (HTTPS, no redirects, 64 KiB, 10 s, [LNK-9]) and lets the core decide (`check_link`):
  verified, `wrong_owner`, `token_missing`, or `fetch_failed` when the service could not be read ([LNK-10]).
- Services whose names can change hands are checked by a stable id as well as the name ([LNK-18]), so a GitHub account
  that was renamed and whose name someone else took is `wrong_owner`, not verified.
- The token holds only the account id, which never changes, so links survive password resets, moves and recovery
  rotations; the profile is carried to each new instance.
- Whatever the verifier does not know (a service, a `ref` form, a version) is `unsupported`: never verified, and never
  breaking the other links ([LNK-13]).

**When it is used.** An identity page shows who someone is elsewhere; a service can show "also GitHub `alice`" next to a
handle. Each viewer checks for itself, and shows "verified" only for what it checked, with the time ([LNK-11]). A link
is as strong as the external account (THREAT_MODEL.md AR15), and e-mail addresses are not links: no place in a mailbox
can be read by everyone and written only by its owner.

## The flows at a glance

| Flow | Log | Vault | Card | Checked by |
|---|---|---|---|---|
| Register ([CLT-1], [HST-3]) | inception + `instance` (`register`) | created: one password slot + recovery lock | generated, shown once | host: `verify_log`, `verify_pending`, `verify_vault` |
| Log in ([LGN-1]) | synced to the newest | fetched with the password, unlocked locally | — | host: challenge, version, two signatures |
| Edit data or profile ([HST-12]) | unchanged | `rev + 1` | — | `verify_vault`, `verify_public` |
| Change password ([CHG-1]) | unchanged | one slot's lock replaced | — | host: proof with the old password |
| Forgot password, revoke, move ([KT-3], [KT-4], [KT-8]) | new `instance` | new vault for the new instance | required | old sessions and vaults end |
| Rotate the recovery key ([KT-5]) | `rotate_recovery` | new grant signed by the new key | new card with `log` | — |
| Prove to a third party ([PRF-4]) | read | — | root proofs only | `verify_proof` |
| Link an account ([LNK-4]) | unchanged | — | — | each viewer: `verify_public`, `parse_links`, `check_link` |
| Retire ([KT-6]) | `retire` | deleted by hosts ([HST-8]) | required | everything answers `account_retired` |
