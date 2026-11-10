# rootcard

The core of [rootcard](https://github.com/rootcard/rootcard): a portable, self-certifying identity for online logins. This
crate holds the formats of `spec/SPEC.md` and everything that verifies them: canonical JSON, keys, the recovery key,
inceptions and account ids, handles, the identity log (`verify_log`, `extend_log`, `compare_logs`), vault checks, public
profiles, login, fetch and change messages, proofs, account files and recovery cards.

> **New to rootcard?** Start with the [project README](https://github.com/rootcard/rootcard#readme): what rootcard is,
> the two ways to use it (a safer username-and-password login for your own service, or an ID card across services),
> how it compares with other login methods, and the roadmap.
> To build with it, the [getting-started guide](https://github.com/rootcard/rootcard/blob/main/docs/GETTING_STARTED.md)
> has code for each role.

It is pure: no I/O, no clock and no randomness of its own. Time and random bytes are parameters. It produces and checks
exactly the bytes of the npm package `rootcard`; both are tested against the shared vectors in `spec/vectors/`.

```sh
# A host or relying party: verification only, no Argon2id, X25519 or AES-GCM in the build.
cargo add rootcard --no-default-features
# A client or the key tool: vault cryptography as well (the default).
cargo add rootcard
```

```rust
use rootcard::log::{verify_log, VerifyOptions};
use rootcard::proof::verify_proof;

// `events` is an identity's log as received (parsed with rootcard::parse_json, never trusted as bytes).
let state = verify_log(&events, &VerifyOptions::new(["global"]).at(now))?;
println!("{} is at version {}", state.handle, state.version.seq);
// A proof that the holder controls the identity now, for this verifier and this challenge.
verify_proof(&proof, &events, &challenge, "example.org", &VerifyOptions::new(["global"]).at(now))?;
```

Errors are the stable codes of SPEC §20 (`rootcard::Error::code`). Status: `0.x`; nothing is stable before `1.0.0`, but
everything hashed or signed follows the format versioning of SPEC §22.

## License

Licensed under either of MIT or Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`).
