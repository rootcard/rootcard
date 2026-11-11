# Changelog: rootcard-cli

All notable changes to this package are recorded here.

## Unreleased

## 0.3.3 - 2026-11-11

No changes.

## 0.3.2 - 2026-11-06

- `--host` and `--from` accept a bare domain (`https://example.com`) and resolve it through the host pointer
  `/.well-known/rootcard` ([HST-23]) to the host's base URL on that domain (`https://example.com/rootcard`); without a
  pointer the domain itself is the base URL, as before.

## 0.3.1 - 2026-11-05

- The crate metadata (`repository`, `homepage`) and the README links point to `github.com/rootcard/rootcard`.

## 0.3.0 - 2026-11-05

- `new` and `rotate-recovery` generate recovery keys with `new_recovery_key`, so the signing key works in every
  browser ([CRY-9]).
- Host addresses with dot segments or percent-encoding in their path are refused ([HST-22]), and new passwords are
  checked by the core as well as by the tool ([LCK-8]).

## 0.2.1 - 2026-11-05

- **Fixed (loss of the recovery key):** `rotate-recovery` sent the rotation to the primary host before it wrote the new
  card. If the card could not be written (a missing `--dir`, a full disk) or the host's answer was lost, the host had
  the rotation, the old card no longer worked and the new key was gone. The new card is now written and printed first;
  if sending fails, the tool says to keep both cards and how to check which one is current.
- **Fixed:** `new --host` wrote the card only after the registration and a further request had succeeded. The card is
  now written before anything is sent.

## 0.2.0 - 2026-11-05

- License: MIT OR Apache-2.0, at the user's option (0.1.0 was MIT only). The package now ships `LICENSE-MIT` and
  `LICENSE-APACHE`.
- **Breaking (HTTP binding):** the key tool calls hosts under `<base URL>/v0` (HOST_PROTOCOL.md §1.3). Host addresses
  are given and stored without the version segment, as before.
- Every host address given to the tool, or read from a log, is checked as a base URL before use ([HST-22]); an address
  ending in `/v0` or with a trailing slash is refused with a hint.
- README points to the project README.

## 0.1.0 - 2026-11-04

- First release of the key tool `rootcard`: `new`, `restore`, `fresh`, `reset-password`, `add-password`,
  `revoke-password`, `rotate-recovery`, `retire`, `card`, `inspect`, `prove`, `verify`.
- Gathers the newest log from the card, the account file and the hosts before signing, and stops on a fork.
