# rootcard: guide for agents

rootcard is a portable, self-certifying identity library ("an ID card for online logins") published as Rust crates on
crates.io and an npm package on npmjs, from one monorepo. Security is the product. Read before changing anything:

1. [docs/PLAN.md](docs/PLAN.md): the setup plan, phases, current phase and acceptance criteria
2. [docs/DESIGN.md](docs/DESIGN.md): the design (requirements, threat model, formats, flows)
3. [spec/SPEC.md](spec/SPEC.md): the normative format. Where it differs from DESIGN.md, the spec wins (Appendix B)
4. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): goals, attackers, trust boundaries, threats and accepted risks
5. [docs/HOST_PROTOCOL.md](docs/HOST_PROTOCOL.md): the recommended HTTP binding for hosts
6. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): components, server usage, the `rootcard-host` design and the dependency
   budget. Keep it, SPEC, THREAT_MODEL and HOST_PROTOCOL consistent in the same commit
7. [docs/RELEASING.md](docs/RELEASING.md): how a release is prepared (by agents) and published (by the owner, through CI)
8. [docs/CONCEPTS.md](docs/CONCEPTS.md): an informative guide to the log, vault, recovery card, proofs and verification.
   It cites SPEC rule ids; update it when a rule it explains changes
9. [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md): code for applications, hosts and relying parties. Its examples
   call the public API; update it when a function it shows or a flow it walks through changes

## Layout

```
Cargo.toml              workspace
crates/rootcard         core (pure): json, encoding, crypto, keys, recovery, id, log, vault, profile, links, messages,
                        binding, proof, account, file, testing
crates/rootcard-cli     the key tool, binary `rootcard`
crates/rootcard-host    host-side helpers: store (challenge and identity stores), http (router), peer
crates/xtask            vector generation, label registry, repo and release checks, differential test of the JS core
fuzz                    cargo fuzz targets for parsers, verifiers and the host router (own workspace, not published)
packages/rootcard       npm package: plain ES modules with the core's module names, zero dependencies, WebCrypto
packages/rootcard/keytool.html   standalone key tool page (works from file://), built by tools/build-keytool.mjs
tests/browser           the vectors and keytool.html in real browsers (Playwright, CI only, not published)
tests/differential      the JS side of the differential test (`xtask differential`, not published)
spec/SPEC.md            normative specification
spec/vectors/*.json     shared test vectors (the facit for every implementation)
spec/links/*.json       the registry of linked services; `xtask vectors` generates it into both cores
docs/                   plan, design, concepts, getting started, architecture, threat model, host protocol, releasing
docs/proposals/         proposals: sign-in (a draft, not normative), linked accounts (adopted in SPEC §12.3)
.github/workflows       ci.yml (every push and PR), release.yml (publishes on a GitHub release), advisories.yml (daily)
.github/ISSUE_TEMPLATE  issue templates; security reports go to private reporting (SECURITY.md)
CONTRIBUTING.md         the rules below, for people; CODE_OF_CONDUCT.md, SECURITY.md
```

## Commands

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p xtask -- vectors --check     # Rust output matches spec/vectors
cargo run -p xtask -- repo-check          # pinned workflow dependencies, npm without dependencies, documents that name the version
(cd packages/rootcard && npm test)        # node --test, Node >= 20, no dependencies
(cd tests/browser && node run.mjs chromium)   # vectors and keytool.html in a browser (needs Playwright; CI runs all three)
cargo run --release -p xtask -- differential --cases 20000   # JS core against Rust core on mutated inputs; fuzz/README.md
(cd fuzz && cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings)   # the fuzz crate (stable)
(cd fuzz && cargo run --bin seeds && cargo +nightly fuzz run -O -a log -- -max_total_time=60)   # after changing a parser or verifier; fuzz/README.md
```

For a release pull request, also `cargo run -p xtask -- release-check --tag vX.Y.Z` and the dry runs in
[docs/RELEASING.md](docs/RELEASING.md) §3.

Run all of them before every commit. CI runs them too.

## Rules

### 1. The spec is the source of truth
- Every format, label, encoding and rule is in `spec/SPEC.md`. Code follows the spec, never the other way round.
- A change to anything that is hashed or signed is a **format change**: bump the structure's `v`, keep reading the old
  version forever, add vectors, and say so in the commit message. Ids and signatures made with `v: 1` must stay valid.
- Domain-separation labels start with `rootcard/` and end with a version (`rootcard/id/v1`). Never reuse a label for
  another purpose. A new label goes into the registry (SPEC §5) and `xtask`'s `LABEL_PURPOSES` in the same commit; the
  vector check fails otherwise.
- The HTTP binding is versioned by a path segment (`<base URL>/v0`, HOST_PROTOCOL.md §1.3), separately from the format.
  `v0` until 1.0.0, then `v1` (`API_VERSION` in both cores). The segment never goes into a base URL, `home.url` or
  anything signed and stored; `check_base_url` ([HST-22]) enforces this wherever an address is configured or typed.
- Rules have stable identifiers (`[LOG-12]`). Tests and vectors name the rules they exercise; a removed rule leaves a gap.

### 2. Rust and JS must agree byte for byte
- `crates/rootcard` and `packages/rootcard` implement the same functions with the same names (snake_case / camelCase).
- Every function that produces or checks bytes has vectors in `spec/vectors/`, generated by Rust (`xtask vectors`) and
  checked by both test suites. Changing one implementation means changing the other in the same commit.

### 3. Cryptography
- **No home-made cryptography**, with one exception: Argon2id (and BLAKE2b inside it) in JS, because WebCrypto lacks it. It
  must pass the RFC 9106 vectors and the shared vectors.
- Rust uses audited crates only: `ed25519-dalek` (with `verify_strict`), `x25519-dalek`, `sha2`, `hkdf`, `aes-gcm`, `argon2`,
  `getrandom`, `zeroize`, plus `unicode-normalization` for password NFC. Password and vault cryptography sits behind the
  core's `vault` feature, so hosts build without it (ARCHITECTURE.md §4–5). JS uses WebCrypto (`Ed25519`, `X25519`, `SHA-256`, `HKDF`, `AES-GCM`, `getRandomValues`).
- Strict verification everywhere: reject small-order keys and non-canonical signatures.
- Secrets are zeroized (Rust `zeroize`, JS overwrite buffers) and JS keys are imported non-extractable.
- `#![forbid(unsafe_code)]` in every crate. No `unwrap()`/`expect()` outside tests (`clippy::unwrap_used`).

### 4. The core is pure and generic
- `crates/rootcard` and `packages/rootcard` do no I/O, read no clock and draw no randomness themselves: time and random bytes
  are passed in. This keeps them testable and deterministic.
- Nothing application-specific belongs in the core. Applications choose a `realm` string, a `UsernamePolicy` and their own
  profile namespace (`app.<name>.`).

### 5. Power levels are enforced by the format
- The password (unlocked account key) has **low power**: log in, edit the profile and private data in the current instance,
  export, prove. Everything that changes who can access the account, where it lives or whether it exists needs the
  **recovery key**. Only the recovery key signs log events and vault locks. A new feature that is unclear is high power.
- The recovery key is never entered in an application client. Only the key tool (CLI or `keytool.html`) asks for it.

### 6. Dependencies and supply chain
- The npm package has **zero runtime and zero dev dependencies** and no install scripts (`xtask repo-check` enforces
  it). Tests use `node --test`.
- New crates need a justification in the PR and must pass `cargo deny` (licenses, advisories, duplicates).
- Releases are built and published only from CI with trusted publishing (crates.io and npm OIDC) and npm provenance. No
  long-lived tokens in the repository or in CI secrets once trusted publishing is set up.
- Every third-party action in `.github/workflows` is pinned to a full commit SHA with its tag in a comment
  (`uses: actions/checkout@<40 hex> # v4.4.0`), and tools installed in CI have exact versions. `xtask repo-check` fails
  otherwise. To update a pin, resolve the tag with `git ls-remote` and change SHA and comment together.

### 7. Tests
- Every rule in the spec has a test that proves it is enforced (accept and reject cases).
- Parsers and verifiers get fuzz targets (`cargo fuzz`, [fuzz/README.md](fuzz/README.md)); a new parser or verifier gets one
  in the same commit, and an entry in the differential test's `OPS` (`crates/xtask/src/differential.rs`) if it has a
  vector operation.
- Security-relevant fixes get a regression vector.

### 8. Language and style
- Code, comments, docs, commits: **English**.
- Nothing application-specific in this repository. Applications (such as Xigna) document their own use of rootcard in their
  own repositories.
- `rustfmt` (`max_width = 120`), `clippy -D warnings`. Small, focused commits.
- Public API changes are recorded in `CHANGELOG.md` (one per package), under `## Unreleased` until a release.

### 9. Documentation is part of the change
A change is not done until every document that describes it says so, in the same commit. The 0.2.0 and 0.2.1 releases
shipped with a README that still said 0.1.0, a `SECURITY.md` that said nothing was released, and review findings in
PLAN.md that THREAT_MODEL.md did not know about. So, for every change:

| If the change touches… | …also update |
|---|---|
| a public function, type or CLI command | the package's `CHANGELOG.md` (`## Unreleased`), its README and docs/GETTING_STARTED.md if they show it |
| a spec rule, label or error code | SPEC (and §20 for codes), vectors, THREAT_MODEL.md if a threat or its mitigation changes |
| an endpoint, status or header | HOST_PROTOCOL.md, and the router's tests |
| a component, store trait, schema or dependency | ARCHITECTURE.md (§3.1 for the SQL schema, §5 for the budget) |
| a plan item | tick it in PLAN.md and say what was decided, with the rule ids |
| a review finding that is not fixed now | PLAN.md **and** THREAT_MODEL.md (a threat with its residual risk, or an accepted risk) |
| the released version | README status line and `SECURITY.md` supported versions (RELEASING.md §3 step 4) |

- Prose does not name versions ("in 0.1.0", "planned after 0.1.0") except in changelogs, history notes and the two
  places `xtask repo-check` verifies. Write "in the core" or "in 0.3.0 (planned)" and let the plan carry the schedule.
- When a plan item says it must happen before something else ("before 0.2.1 is published"), the agent preparing that
  something checks it first and tells the owner if it is still open (RELEASING.md §3 step 1).
- Before finishing, search the docs for what you changed (`grep -rn` the function, rule id or old behaviour) and fix
  every stale mention.

### 10. Releases
- All packages are released together with one version and a tag `vX.Y.Z`. Follow [docs/RELEASING.md](docs/RELEASING.md)
  exactly, and only when the owner asks for a release.
- Agents prepare the release pull request and stop. They never tag, create a GitHub release, publish (`cargo publish`
  or `npm publish` without `--dry-run`), handle registry tokens, or yank. Publishing happens only in
  `.github/workflows/release.yml` when the owner publishes a GitHub release.
