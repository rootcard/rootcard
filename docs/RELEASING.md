# rootcard: releasing

How a release is prepared, published and checked. **Agents prepare releases; only the owner publishes them**, by
pushing the tag `vX.Y.Z` or making a GitHub release with that tag (which makes the tag). Publishing is done by CI ([`.github/workflows/release.yml`](../.github/workflows/release.yml))
with trusted publishing, never from a laptop and never with a registry token (AGENTS.md rule 6).

---

## 1. What a release is

- One version for everything: the crates `rootcard`, `rootcard-host` and `rootcard-cli` and the npm package `rootcard`
  are released together, in lockstep, with the same `MAJOR.MINOR.PATCH` (optionally `-rc.N`, `-alpha.N`, `-beta.N`).
- The git tag is `v` + the version (`v0.1.0`) on the release commit on `main`.
- Before `1.0.0`: a minor bump (`0.1 → 0.2`) for any breaking API change or any **format change** (SPEC §22); a patch
  bump for everything else. From `1.0.0`: semantic versioning, and a format change never removes the reading of `v: 1`.
- A version with a `-` is a pre-release: its GitHub release is marked pre-release, and npm publishes it under the `next`
  tag instead of `latest`.
- Every release also has, on its GitHub release: the key tool `rootcard` as binaries for Linux (static, x86_64 and
  arm64), macOS (Apple silicon and Intel) and Windows (x86_64), the key tool page `keytool.html`, the packages exactly
  as the registries serve them, `SHA256SUMS`, and a signature of every file (a GitHub artifact attestation, §4). The
  release notes are generated from the changelogs.

## 2. One-time setup (owner)

1. **Names exist** (PLAN D2): trusted publishing can only be configured for packages that already exist, so the owner
   publishes the `0.0.0` placeholders once by hand.
2. **crates.io:** for each of the three crates, add a trusted publisher: repository `rootcard/rootcard`, workflow
   `release.yml`, environment `release`.
3. **npm:** for `rootcard`, add a trusted publisher: GitHub Actions, repository `rootcard/rootcard`, workflow
   `release.yml`, environment `release`. Then disallow token publishing in the package settings.
4. **GitHub:** create the environment `release` with the owner as required reviewer and deployments limited to tags
   `v*`. Protect `main` and the tag pattern `v*`, so that only the owner can make a release tag. Artifact attestations
   need nothing to be set up for a public repository.

No secret is added to the repository for any of this.

## 3. Preparing a release (agents)

An agent prepares a release only when the owner asks for one. Do exactly these steps, in one pull request that contains
nothing else.

1. **Start from a green `main`.** Fetch `main`, check that CI is green on it, and branch from it (use the branch you were
   given, otherwise `release/vX.Y.Z`). Read the open items of docs/PLAN.md: if one must land before this release (it says
   "before X.Y.Z", "before the release" or "before it is published"), tell the owner before continuing. 0.2.1 went out
   without the release-pipeline pins that were planned for it because nobody checked.
2. **Choose the version** by §1 from the changelogs' `Unreleased` sections. If any entry is a format change or breaking,
   say so in the pull request. If unsure between minor and patch, choose minor and ask.
3. **Bump the version** in all three places:
   - `Cargo.toml`: `[workspace.package] version` and the `version` of `rootcard` in `[workspace.dependencies]`;
   - `packages/rootcard/package.json`: `version`;
   - `Cargo.lock`: run `cargo update --workspace` (it changes only the workspace's own entries).
4. **Update the documents that name the version:** the status line of `README.md` (`Status: **X.Y.Z, ...**`) and, for a
   new minor (or major) version, the supported versions table of `SECURITY.md` (the new line `Yes`, the previous one
   `No`). `xtask repo-check`, which `release-check` runs, fails until both match. Then search the docs for the previous
   version number and fix any mention that is not history.
5. **Write the changelogs.** In each of the four `CHANGELOG.md` files, move the `Unreleased` entries under a new heading
   `## X.Y.Z - YYYY-MM-DD` (today's date, UTC) and leave an empty `## Unreleased` above it. A package without changes gets
   the line `No changes.` Entries describe user-visible changes; format changes say which structure and `v`.
6. **Run every check:**
   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo test --workspace --locked
   (cd packages/rootcard && npm test)
   cargo run -p xtask -- release-check --tag vX.Y.Z     # versions, changelogs, tag, vectors, label registry, repo-check
   cargo publish --workspace --locked --dry-run         # packages every crate and builds it from its tarball
   (cd packages/rootcard && npm publish --dry-run)      # lists exactly the files that would be published
   ```
   Read the file lists of both dry runs: nothing outside `src/`, the README, the changelog and the license may be in them.
7. **Commit** as `Release vX.Y.Z` and open a pull request with the same title. Its description has the changelog
   entries, the result of every check above, and whether the release contains a format change.
8. **Check the release notes.** Make a `SHA256SUMS` with the names of the release files and render the notes the
   workflow will write, to see that every package's section reads well on its own:
   ```bash
   v=X.Y.Z
   for f in rootcard-$v.crate rootcard-cli-$v-x86_64-unknown-linux-musl.tar.gz rootcard-keytool-$v.html; do
     printf '%064d  %s\n' 0 "$f"; done > /tmp/SHA256SUMS
   cargo run -q -p xtask -- release-notes --tag v$v --sums /tmp/SHA256SUMS
   ```
9. **Stop.** Tell the owner the pull request is ready and that, after merging, they either push the tag `vX.Y.Z` on the
   merge commit (`git tag vX.Y.Z <merge commit> && git push origin vX.Y.Z`) or make a GitHub release with that tag
   on the merge commit. Its text may be left empty, and the pre-release flag need not be set: CI writes the notes and
   sets the flag (§4). Text the owner writes in the release stays, after the generated notes.

Agents never: create or push tags, create or publish GitHub releases, run `cargo publish` or `npm publish` without
`--dry-run`, add registry tokens or secrets, yank crates or deprecate npm versions, or edit the release workflow in a
release pull request.

## 4. What CI does when a release tag is pushed

`.github/workflows/release.yml`, triggered by a pushed tag `v*` (a GitHub release made by hand makes its tag, which
counts as a push):

1. **verify**: format, clippy, all tests, `xtask release-check --tag <tag>`, `cargo publish --dry-run` and
   `npm publish --dry-run`. Nothing is published if any step fails.
2. **binaries**, next to verify: the key tool `rootcard` built from the tag with `--locked` for
   `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (static, with `cargo zigbuild`; ring needs a C compiler
   for the target), `aarch64-apple-darwin`, `x86_64-apple-darwin` and `x86_64-pc-windows-msvc`. Where the runner can
   run the binary, it must print the tag's version. Each is archived as `rootcard-cli-<version>-<target>.tar.gz`
   (`.zip` for Windows) with its README, changelog and licenses. The publishing jobs wait for every build, so a
   platform that does not build stops the release before anything is published. CI builds the static Linux binaries
   on every pull request too (job `binaries`).
3. **crates** (environment `release`): a short-lived crates.io token from OIDC (`rust-lang/crates-io-auth-action`), then
   `cargo publish --workspace`, which publishes `rootcard` first and then the crates that depend on it.
4. **npm** (environment `release`): `npm publish --provenance` with trusted publishing; the package gets a provenance
   statement that links it to this workflow run and commit.
5. **release**, after both registries have the packages:
   - builds the `.crate` files and the npm tarball from the tag and checks that each is byte for byte the file the
     registry serves (the `cksum` in the crates.io index, npm's `dist.integrity`). A mismatch fails the job before
     anything is attached: the published package was not built from the tag as checked, and the owner investigates
     before anything else is released;
   - adds the binaries and the key tool page (`packages/rootcard/keytool.html` at the tag, as
     `rootcard-keytool-<version>.html`) and writes `SHA256SUMS` of every file;
   - **signs** every file listed in `SHA256SUMS` with a GitHub artifact attestation
     (`actions/attest-build-provenance`): a Sigstore-signed SLSA build provenance statement, made with the workflow's
     short-lived OIDC identity, that names the repository, the workflow, the commit and the tag. There is no signing
     key to keep or to lose. The attestation is stored by GitHub and also attached as `rootcard-<version>.sigstore.json`;
   - writes the notes with `xtask release-notes`: each package's changelog section for the version (packages without
     changes on one line), a table of the files, how to verify them, and the checksums, between two marks
     (`<!-- release-notes: … -->`). If the release exists (made by hand, or by an earlier run), its files are replaced,
     its title kept, and its text kept after the notes, without any block an earlier run wrote; otherwise the job
     creates the release, titled `rootcard <version>`. Either way the pre-release flag is set from the version (§1).

Run by hand (Actions → Release → Run workflow, with the tag), the workflow publishes nothing: it runs verify and the
builds, checks the registries again, and replaces the release's files, signatures and notes. Use it when the release
job failed after the packages were published, or to rewrite the notes after a changelog fix (the notes are taken from
the tag, so a fix on `main` does not change them; edit the release's text by hand instead). It works for tags that
contain `xtask release-notes`.

**Verifying a download** (anyone; the release notes say the same):

```sh
gh attestation verify rootcard-cli-X.Y.Z-x86_64-unknown-linux-musl.tar.gz --repo rootcard/rootcard
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify <file> --repo rootcard/rootcard --bundle rootcard-X.Y.Z.sigstore.json   # without the GitHub API
```

The binaries are not reproducible (the packages are, §5): the signature is what ties them to the tag.

## 5. After the release

The owner, or an agent asked to check, confirms:

- the workflow run is green;
- the three crates show the new version on crates.io and their docs build on docs.rs;
- `npm view rootcard@X.Y.Z` shows the version, the `latest` or `next` tag as intended, and provenance
  (`npm audit signatures` in a project that installs it);
- the release has the binaries for every platform, the key tool page, the packages, `SHA256SUMS` and
  `rootcard-X.Y.Z.sigstore.json`; the release job printed a matching checksum for every package; and
  `gh attestation verify` accepts a downloaded file;
- the release notes have every package's section and no leftover text from a draft.

Anyone can repeat the reproducibility check: check out the tag in a fresh clone made with `umask 022` (npm records file
modes in the tarball, so a clone with other permissions packs other bytes), then
`cargo package --workspace --exclude xtask --locked --no-verify` and `(cd packages/rootcard && npm pack)`, and compare
the files with `SHA256SUMS` and the registries. The tarballs do not depend on file times or on the npm 10 or 11 that
packs them. CI checks on every pull request that a second checkout with other file times packs the same bytes.

## 6. When something goes wrong

- **verify or a binary build failed:** nothing was published. Fix on `main` with a normal pull request, delete the
  GitHub release (if one was made) and the tag (owner), and prepare the release again.
- **The release job failed** after both registries had the packages (a registry was slow, GitHub had an outage): the
  owner runs the workflow by hand with the tag (§4). A checksum mismatch is not retried: see §4.
- **A publish job failed after another succeeded** (for example the crates are out and npm is not): never change or
  re-tag a published version. If the failed job published nothing (its log shows no upload), the owner re-runs it. If
  it published part of its packages (the crates job stopped after `rootcard`), a re-run fails on the published ones, so
  fix forward with the next patch version for all packages.
- **A bad version is out:** release a fixed patch version. Yanking a crate or deprecating an npm version is the owner's
  decision; a security problem additionally follows `SECURITY.md`.
