# rootcard-host

Helpers for hosts (servers) that store [rootcard](https://github.com/rootcard/rootcard) identities and accept their
logins (SPEC §17). A library, not a server: the handlers are plain functions over three storage traits, so a host can
run on any number of servers in front of one shared store and with any HTTP framework.

> **New to rootcard?** Start with the [project README](https://github.com/rootcard/rootcard#readme): what rootcard is,
> the two ways to use it (a safer username-and-password login for your own service, or an ID card across services),
> how it compares with other login methods, and the roadmap.
> To build with it, the [getting-started guide](https://github.com/rootcard/rootcard/blob/main/docs/GETTING_STARTED.md#3-a-host-rust)
> has code for each role.

- `Host::register`, `instance`, `events`, `lookup`, `log`, `locks`, `challenge`, `fetch`, `login`, the session endpoints
  and `peer_push` implement the rules of SPEC §17: receipts, idempotent retries, fork and staleness answers, address
  binding, sessions bound to an instance and checked on every use, compare-and-swap updates.
- `store::{IdentityStore, ChallengeStore, SessionStore}` with in-memory implementations for tests and development.
- `http::route` maps the recommended HTTP binding (`docs/HOST_PROTOCOL.md`) onto the handlers: a request in, a response
  out. `examples/host.rs` in the repository wires it to `std::net` for local development.

It builds on the core without its `vault` feature: a host never runs Argon2id, never sees a password and never decrypts a
vault. Time and random bytes are parameters, as in the core.

```rust
let res = rootcard_host::http::route(&host, &request, now, &mut |b| getrandom::fill(b).expect("random"));
```

## HTTP binding and addresses

`http::route` serves every endpoint under the API version, `<base URL>/v0/…` until 1.0.0 (`http::API_VERSION`,
HOST_PROTOCOL.md §1.3). Requests reach it with paths relative to the base URL (`/v0/host`). Call
`HostConfig::check` at startup: every address must be a base URL without a version segment (SPEC [HST-22]), because the
address goes into the identities' signed logs as `home.url`. On a domain of its own, use the domain as the base URL
(`https://id.example.com`); on a domain shared with an application, give the host a path of its own
(`https://example.com/rootcard`), so its endpoints cannot collide with the application's, and route
`GET /.well-known/rootcard` on that domain to `http::well_known(&host.config, "https://example.com")` (SPEC [HST-23]):
users can then type `https://example.com`, and the key tool finds `https://example.com/rootcard` from it.

## License

Licensed under either of MIT or Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`).
