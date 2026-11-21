# rootcard-cli

The key tool for [rootcard](https://github.com/rootcard/rootcard) identities, binary `rootcard`. It is the only place
besides `keytool.html` where a recovery key is entered (SPEC [PWR-6]).

> **New to rootcard?** Start with the [project README](https://github.com/rootcard/rootcard#readme): what rootcard is,
> the two ways to use it (a safer username-and-password login for your own service, or an ID card across services),
> how it compares with other login methods, and the roadmap.

## Install

Every [GitHub release](https://github.com/rootcard/rootcard/releases) has the binary for Linux (static, x86_64 and
arm64), macOS (Apple silicon and Intel) and Windows (x86_64), built from the release tag in CI and signed with a GitHub
artifact attestation. Check the download before you run it:

```sh
gh attestation verify rootcard-cli-<version>-<target>.tar.gz --repo rootcard/rootcard
sha256sum -c SHA256SUMS --ignore-missing
```

Or build it: `cargo install rootcard-cli --locked`. More in
[docs/HOSTING.md §2](https://github.com/rootcard/rootcard/blob/main/docs/HOSTING.md#2-release-files-and-how-to-check-them).

## Use

```sh
rootcard new --realm global --username Astra --host https://id.example.com
rootcard restore --card Astra-3F9C.card.json --account Astra-3F9C.rootcard.json --host https://other.example
rootcard reset-password --card Astra-3F9C.card.json --from https://other.example
rootcard add-password --card Astra-3F9C.card.json --from https://other.example --label Phone
rootcard rotate-recovery --card Astra-3F9C.card.json --from https://other.example
rootcard inspect Astra-3F9C.rootcard.json
rootcard help
```

Before it signs anything, the tool gathers the newest log from the card, the account file and every host given, and
stops on a fork (SPEC [KT-2], [KT-7]). It talks only to the hosts you name, over HTTPS.

Host addresses are base URLs without the API version (`https://id.example.com` or `https://example.com/rootcard`, never
`…/v0`); the tool calls `<base URL>/v0/…` itself (HOST_PROTOCOL.md §1.3, SPEC [HST-22]). A bare domain
(`https://example.com`) is looked up at `https://example.com/.well-known/rootcard` first: if that names a base URL on the
domain (`https://example.com/rootcard`), the tool uses it and says so; otherwise the domain is the base URL (SPEC
[HST-23]).

## License

Licensed under either of MIT or Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`).
