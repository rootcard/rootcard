# Changelog: rootcard

All notable changes to this package are recorded here.

## Unreleased

- The crate documentation starts with a compiled tour (registration, a receipt, unlocking the vault, a proof) and points
  to the new `docs/GETTING_STARTED.md`; the README adds the crate with `cargo add` instead of naming an old version.
- `id::extended_tags` no longer panics on ids shorter than a tag or with characters of more than one byte, and
  `id::tag` takes the first 4 characters of any string: both count characters, as [HDL-6] says (found by the new
  differential test against the JS core; regression vectors in `spec/vectors/log.json`). Account ids are ASCII, so
  their tags do not change.

## 0.3.2 - 2026-11-06

- Host pointers ([HST-23]): `well_known_base(origin, document)` resolves `<origin>/.well-known/rootcard` to the host's
  base URL on that origin (`bad_field`, `unsupported_version`, `wrong_host`), `is_origin(url)`, and the constants
  `WELL_KNOWN_PATH`, `WELL_KNOWN_LIMIT` and `MAX_WELL_KNOWN_APIS`. Shared vectors in `spec/vectors/proof.json`.

## 0.3.1 - 2026-11-05

- The crate metadata (`repository`, `homepage`) and the README links point to `github.com/rootcard/rootcard`.

## 0.3.0 - 2026-11-05

- New Ed25519 keys never use a seed whose first byte is zero (SPEC [CRY-9]; WebKit's WebCrypto cannot import one):
  `account::register` and `account::new_instance` draw the account seed again, `vault::new_password_lock`,
  `change_password` and `add_slot` draw the salt again, and **breaking:** `register` and `rotate_recovery` refuse a
  recovery key whose signing seed is unusable (`bad_key`). New: `recovery::new_recovery_key` generates a usable
  recovery key, `recovery::check_new_recovery_key`, `crypto::usable_seed`, `crypto::ed25519_public_is` and
  `crypto::DRAW_ATTEMPTS`. Draws change only when a first draw is unusable; existing keys and signatures stay valid.
- **Breaking:** `crypto::aes_gcm_encrypt` returns `Result<Vec<u8>>` (`too_large` beyond AES-GCM's input limits)
  instead of an empty vector on failure. No output changes.
- **Breaking:** every function that creates a password lock enforces the password rules of SPEC [LCK-8]
  (`weak_password`), not only `register`: `new_password_lock` (and so `add_slot`, `instance_vault`, `new_instance`)
  and `change_password`. `NewSlot` has a new field `username`, and `change_password` a new parameter `username` after
  `password`. `new_instance` refuses a slot whose `username` is not the identity's (`bad_field`). New vectors in
  `spec/vectors/vault.json`.
- **Breaking:** `check_base_url` ([HST-22]) refuses path segments that are `.` or `..` or contain anything other than
  unreserved characters (`A`–`Z`, `a`–`z`, `0`–`9`, `-`, `.`, `_`, `~`), so a base URL has no percent-encoding and
  cannot reach a version segment after normalization (`https://example.com/v0/..`, `https://example.com/%76%30`). New
  vectors in `spec/vectors/proof.json`. No format change: log verification is unchanged.

## 0.2.1 - 2026-11-05

No changes.

## 0.2.0 - 2026-11-05

- License: MIT OR Apache-2.0, at the user's option (0.1.0 was MIT only). The package now ships `LICENSE-MIT` and
  `LICENSE-APACHE`.
- `API_VERSION` (`"v0"`), the version segment of the HTTP binding, and `check_base_url` / `binding::is_version_segment`:
  host addresses are base URLs without a trailing version segment (SPEC [HST-22]), with shared vectors in
  `spec/vectors/proof.json` and the API version in `meta.json`. No format change: log verification is unchanged.
- README points to the project README.

## 0.1.0 - 2026-11-04

- First release of the core, implementing format version 1 of `spec/SPEC.md` (no format change: everything is `v: 1`).
- Canonical JSON (`parse_json`, `parse_limited`, `canonical`), unpadded base64url, Crockford base32, key strings.
- Strict Ed25519 verification with the pre-checks of [CRY-3] (canonical points, no small order, `S < L`, cofactorless).
- Recovery keys: written form, parsing, derivation of the signing and lock keys.
- Identities: deterministic inception, account id, handles, `parse_handle`, `extended_tags`, realm and username rules.
- The identity log: `verify_log`, `extend_log`, `verify_pending`, `compare_logs`, event builders and receipts.
- Vaults: `verify_vault` and `vault_change` (always); with the default `vault` feature, password locks (Argon2id,
  NFC), wrapping, contents, `unlock_vault`, `change_password`, `add_slot`, `regrant`, `instance_vault`.
- Public profiles and data keys, login, fetch and change messages, challenges, proofs and statement challenges,
  account files and recovery cards.
- High-level flows (`account`, feature `vault`): `register`, `new_instance`, `rotate_recovery`.
- `testing::TestRandom`, the deterministic stream the shared vectors are generated with.
