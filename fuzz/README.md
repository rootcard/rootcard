# Fuzz targets

`cargo fuzz` targets for the Rust parsers, verifiers and the host's router (AGENTS.md rule 7, PLAN.md phase 6). This
crate is its own workspace and is never published: it needs libFuzzer and a nightly toolchain, which the main workspace
must not.

| Target | Input | What it checks |
|---|---|---|
| `json` | bytes | Canonical JSON (SPEC §2): the parser never panics; an accepted value serializes canonically, parses back to itself and serializes to the same bytes |
| `text` | UTF-8 | base64url, base32 (strict and lenient), hex, typed recovery keys, `ed25519:`/`x25519:` keys, handles, account ids, realms, usernames, `home.url`, base URLs ([HST-22]), origins, data keys, app names and lock labels. Decoders that accept round-trip through their encoders |
| `log` | JSON | `verify_log`, `verify_pending`, `compare_logs`, `LogState::from_value`. An accepted log keeps the invariants of `check_accepted`: its prefixes are accepted, `extend_log` on a prefix gives the same state ([LOG-15]), the state survives its own serialization, and the log compares `same` with itself |
| `log_signed` | control byte + JSON | The same, behind the signatures: `resign` maps every key to one of eight known keys (equal keys stay equal) and, as the control byte asks, recomputes `account`, `prev` and the signatures (a receipt when the signer is the event's `home.key`). Mutated logs reach the checks on kinds, sequence, key reuse, reasons, receipts, rotations and retirement |
| `documents` | selector byte + JSON | `verify_public`, `verify_vault`, `vault_change`, `import_account`, `read_card` and `card_text`, `verify_proof`, `well_known_base` (the result is always on the origin and a valid base URL), statements, challenges, login requests and vault contents. The logs, challenges and recipients they are checked against come from the shared vectors |
| `links` | selector byte + bytes or JSON | Linked accounts ([LNK-*]): `parse_response_json` (an accepted value is rootcard JSON), `parse_descriptor` and the requests of sample links, `parse_links` of profile data with the bundled registry followed by `link_requests`, `link_display` and `check_link` with answers from the input, and `find_link_token`. Every URL a check would fetch or display is `https://`, has a valid host name and a path without a query, a fragment or a dot segment ([LNK-8]) |
| `host` | requests | `rootcard_host::http::route` with the in-memory stores and the vectors' host key: up to 16 requests per input, separated by `\n\0\n`, each a line `METHOD PATH [bearer=<token>] [peer=<key>,<time>,<sig>]` and a body. The state persists across the requests of one input. Every answer has a status of HOST_PROTOCOL.md and a canonical JSON body |

Every target asserts only what the spec promises: a panic is a finding.

## Running

```bash
cd fuzz
cargo run --bin seeds                                    # corpus/<target>/ from spec/vectors (not committed)
cargo +nightly fuzz run -O -a log_signed -- -max_total_time=300
cargo +nightly fuzz run -O -a log_signed artifacts/log_signed/crash-…   # reproduce a finding
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings   # stable is enough for these
```

`-a` matters: `-O` alone builds without overflow checks, and an overflow in a time comparison was a real host bug
(`(time - now).abs()`, fixed with `abs_diff` in the 0.3.0 review). `cargo install cargo-fuzz --version 0.13.2 --locked`
installs the tool. CI (`fuzz` in `.github/workflows/ci.yml`) runs
every target for two minutes on each push and pull request, on the dated nightly named there, starting from the seeds,
and keeps a failing input as a build artifact.

The seed writer also checks itself: the re-signer must keep every accepted log of the vectors accepted, and it prints
the statuses of the host seeds (a registration answers `201`, pushed logs `200`), so a vector change that silently
empties a target is noticed.

## A finding

1. Reproduce it with the file from `artifacts/<target>/` and minimize it (`cargo fuzz tmin`).
2. If it is a bug in a core, fix both cores (AGENTS.md rule 2) and add a regression vector (rule 7), with the rule id.
3. If the assertion was wrong, fix the assertion and say why in the commit. The first run found one: `well_known_base`
   returns `https://example.cOm/rootcard` for the origin `https://example.com`, which [HST-23] allows (the host is
   compared without regard to ASCII case).

## The JS core: differential test

`cargo fuzz` reaches only Rust, so the JS core is checked against the Rust core instead (AGENTS.md rule 2):

```bash
cargo run --release -p xtask -- differential --cases 100000 --seed 7   # needs Node >= 20
```

`xtask` takes the inputs of the shared vectors, mutates them with a seeded generator and runs each through the vector
operations of `crates/xtask/src/ops.rs`; `tests/differential/run.mjs` runs the same cases through
`packages/rootcard/test/ops.mjs` and requires the same output or the same error code. The mutations follow how the core
reads each member: bytes for canonical JSON (with JSON-aware edits and boundary tokens such as `\ud800` and
`9007199254740992`), signatures, keys and ciphertexts; text with boundary characters (controls, combining marks,
look-alikes of base32, separators) for the encodings, names, handles and addresses; JSON edits and values spliced from
other vectors for documents; and event lists for logs, re-signed with the re-signer of `log_signed`
(`crates/xtask/src/resign.rs`, included here by path) so the mutations reach the checks behind the signatures. 32
operations are covered: canonical JSON, the decoders, keys, recovery keys, Ed25519 verification, X25519, AES-GCM
decryption, names, handles, extended tags, `verify_log`, `extend_log`, `verify_pending`, `compare_logs`, vaults,
`vault_change`, password rules, base URLs, host pointers, data keys, `set_data`, public profiles, logins, proofs,
account files and recovery cards.

A case the operation's harness cannot read (a member it needs is gone) is dropped; a Rust panic is a finding
(`target/differential/rust-panics.jsonl`), and so is a JS exception that is not a `RootcardError`. Disagreements go to
`target/differential/mismatches.jsonl`. The same seed gives the same cases. CI (`differential` in
`.github/workflows/ci.yml`) runs 100 000 cases on each push and pull request with a new seed each run, named in the
log, and keeps the disagreements as a build artifact.

Limits: documents other than logs (vaults, profiles, proofs, login requests, cards) are not re-signed, so a mutated
document mostly stops at its signature. The order of the checks before it is still compared, and accepting paths are
covered by the vectors. The first runs found a Rust panic in `extended_tags` on ids shorter than a tag or with
characters of more than one byte, and a JS core that counted UTF-16 units there; both now count characters
([HDL-6], regression vectors in `log.json`). They also found that the JS core limited a login request's `lock` to 16
UTF-16 units where Rust allows 16 bytes; both now count bytes ([LGN-1], regression vector in `proof.json`).

## Not covered here

- `unlock_vault` and the other functions that run Argon2id: one call takes about a second, too slow to fuzz. Their
  inputs are parsed by functions the targets cover (`verify_vault`, `Contents`).
- The host's checks after a lock proof or login signature (`fetch`, `login`, the session endpoints): the fuzzer cannot
  sign with a lock key, so it reaches them only up to the signature. The handlers are covered by the reject-case tests
  in `crates/rootcard-host/tests`.
- `cargo deny` and the MSRV job check the main workspace only. This crate adds `libfuzzer-sys`, `arbitrary`, `cc` and
  `jobserver` for testing; nothing from it is shipped.
