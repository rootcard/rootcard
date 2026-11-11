# Changelog: rootcard (npm)

All notable changes to this package are recorded here.

## Unreleased

- The README links the new getting-started guide, whose registration and login code uses this package.
- `parseLoginRequest` and `verifyLogin` limit `lock` to 16 bytes of UTF-8, not 16 UTF-16 units, as the Rust crate
  does and SPEC [LGN-1] now states. Lock ids are ASCII, so real requests are unaffected.
- `extendedTags` and `tag` count characters (code points), not UTF-16 units, as [HDL-6] says and as the Rust crate
  does. Account ids are ASCII, so their tags do not change.
- `package.json` has a `funding` link (GitHub Sponsors), shown by `npm fund`.

## 0.3.2 - 2026-11-06

- Host pointers ([HST-23]): `wellKnownBase(origin, document)`, `isOrigin(url)`, `WELL_KNOWN_PATH`,
  `WELL_KNOWN_LIMIT` and `MAX_WELL_KNOWN_APIS`, equal to the Rust crate's (shared vectors).
- `keytool.html` resolves a bare domain typed into a host field through `<domain>/.well-known/rootcard`, and says so
  while the address is typed.

## 0.3.1 - 2026-11-05

- The package metadata (`homepage`, `repository`, `bugs`) and the README links point to `github.com/rootcard/rootcard`,
  the repository it is built and published from, so npm provenance matches.

## 0.3.0 - 2026-11-05

- `keytool.html` is redesigned in the rootcard.org theme, with the same operations and checks. It has tabs (open,
  create, verify a proof). An opened identity is shown as a card with its host, and each action says whether it
  works offline, sends to the primary host or to a host you enter. Actions the identity cannot do yet are disabled,
  with the reason: a card-only identity (no instance) can show its card and make root proofs, and "Start at a host"
  puts it on one. Before, reset, revoke, rotate and retire failed with a script error for such an identity. Host
  addresses are checked as you type and show what will be contacted. `https://` is added when no scheme is given
  (`http://` for `localhost`, `127.0.0.1` and `[::1]`), and a trailing `/v0` is refused with an explanation
  ([HST-22]). Creating an identity offers "At a host" or "Only on this computer", and asks for a password only
  for a host. "Could not reach the host" replaces the browser's bare fetch error.
- **Breaking:** every function that creates a password lock enforces the password rules of SPEC [LCK-8]
  (`weak_password`), not only `register`: `newPasswordLock` (and so `addSlot`, `instanceVault`, `newInstance`) and
  `changePassword`. Slots (`{ label, password, kdf }`) need `username`, and `changePassword` has a new parameter
  `username` after `password`. `newInstance` refuses a slot whose `username` is not the identity's (`bad_field`).
- **Breaking:** `checkBaseUrl` ([HST-22]) refuses dot segments and anything but unreserved characters in the path
  (no percent-encoding), as in the Rust crate. `keytool.html` is rebuilt with both changes.
- Fixed: in Safari (WebKit), about 1 in 256 X25519 secrets failed with a `DataError`: WebKit's WebCrypto rejects a
  secret whose first byte is zero. Creating locks, wrapping the vault key and unlocking could fail at random, and a
  password whose box secret started with a zero byte could never unlock there. X25519 secrets are now given to
  WebCrypto with a zero first byte as 1 and a zero last byte as 0x40, the same scalar after clamping (RFC 7748 §5),
  so no key, result or vector changes. New vectors in `spec/vectors/primitives.json` cover secrets and seeds with a
  zero byte at either end. `keytool.html` is rebuilt.
- Ed25519 seeds whose first byte is zero (SPEC [CRY-9], [IMP-6]): WebKit cannot import them at all.
  - New keys never use one: `register` and `newInstance` draw the account seed again, `newPasswordLock`,
    `changePassword` and `addSlot` draw the salt again, and **breaking:** `register` and `rotateRecovery` refuse a
    recovery key whose signing seed is unusable (`bad_key`). The new `newRecoveryKey(realm, username, random)`
    generates a usable one; `checkNewRecoveryKey` and `usableSeed` are exported. Draws change only when a first draw
    is unusable, with vectors for each case.
  - Older such keys keep working: `checkRecoveryKey`, `unlockVault` and `prove` check a seed against its public key on
    record with the new `ed25519PublicIs`, and signing with that seed then imports it as a JWK with that key where
    the platform refuses it. A key on record that is not the seed's is refused.
- `keytool.html`: generates recovery keys with `newRecoveryKey`, and no longer reports "Done." while a rotation is
  still being sent (the status stays "Working…" until it ends).

## 0.2.1 - 2026-11-05

- **Fixed:** `keytool.html` 0.2.0 refused every host address ("not a host base URL"), because the page did not include
  `checkBaseUrl` and `API_VERSION`. A test now checks that the page has every function the package exports.
- **Fixed (loss of the recovery key):** the key tool page sent a recovery key rotation before it downloaded the new
  card, and registered at a host before it downloaded the card. Both cards are now downloaded and shown first; if a
  rotation cannot be sent, the page says to keep both cards.

## 0.2.0 - 2026-11-05

- License: MIT OR Apache-2.0, at the user's option (0.1.0 was MIT only). The package now ships `LICENSE-MIT` and
  `LICENSE-APACHE`.
- **Breaking (HTTP binding):** `keytool.html` calls hosts under `<base URL>/v0` (HOST_PROTOCOL.md §1.3). The core
  library makes no requests and is unchanged.
- `API_VERSION` (`"v0"`), `checkBaseUrl` and `isVersionSegment`, equal to the Rust crate's ([HST-22], shared vectors).
- `keytool.html` checks every host address as a base URL; a trailing slash is still removed from typed addresses.
- README points to the project README.

## 0.1.0 - 2026-11-04

- First release of the JavaScript implementation of format version 1, byte for byte equal to the Rust crate on every
  shared vector. Zero dependencies; WebCrypto for Ed25519, X25519, SHA-256, HKDF and AES-GCM; its own BLAKE2b and
  Argon2id (RFC 9106).
- `rootcard`: verification (JSON, encodings, keys, recovery keys, identities, logs, vault and profile checks,
  messages, proofs, account files, cards). `rootcard/vault`: password locks, vault encryption, registration, password
  change, new instances and rotation. `rootcard/testing`: the deterministic stream of the vectors.
- `keytool.html`: the standalone key tool page, works from `file://`.
