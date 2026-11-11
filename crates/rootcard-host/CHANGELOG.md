# Changelog: rootcard-host

All notable changes to this package are recorded here.

## Unreleased

## 0.3.3 - 2026-11-11

- The crate documentation shows a host configured and routed (a compiled example) and states that rate limits are the
  application's ([HST-16]); `docs/GETTING_STARTED.md` §3 walks through a host.

## 0.3.2 - 2026-11-06

- `http::well_known(config, origin)` answers the host pointer `GET <origin>/.well-known/rootcard` ([HST-23]) with the
  first configured address on that origin; the application routes the path to it. The example host serves it.

## 0.3.1 - 2026-11-05

- The crate metadata (`repository`, `homepage`) and the README links point to `github.com/rootcard/rootcard`.

## 0.3.0 - 2026-11-05

- **Fixed:** `POST /id/{account}/events` and `/instance` answered `fork` for any event that differed from a stored
  one, valid or not. The submitted events are now verified first: garbage gets its own error code, and only a valid
  diverging log is a `fork` ([HST-14]).
- **Fixed:** `verify_peer_request` and the receipt time check computed `(time - now).abs()`, which overflows (a panic
  in debug builds) for an extreme peer header time. They use `abs_diff`.
- **Fixed:** `MemoryChallengeStore` kept every challenge forever, and challenges need no authentication. It drops
  expired ones on insert. The `ChallengeStore` documentation and ARCHITECTURE.md §3.1 state the same duty for other
  stores. New: `MemoryChallengeStore::len` and `is_empty`.
- **Fixed (handle squatting):** an identity stored from `POST /id/{account}/events` (anyone can push an inception-only
  log) reserved its handle, so about 2^20 cheap requests could block every tag of a username at a host. Only
  identities registered at the host now reserve a handle ([HST-4], [HDL-5]); the others may collide and are shown with
  extended tags ([HDL-6]).
- **Breaking:** `IdentityStore` has a new method `handle_claimed`: whether an identity stored with `claim` holds the
  handle key. The SQL schema of ARCHITECTURE.md §3.1 already had this (`WHERE claimed`); `MemoryIdentityStore`
  implements it.
- Host addresses follow the stricter `check_base_url` of the core ([HST-22]).

## 0.2.1 - 2026-11-05

- **Fixed:** `POST /id/{account}/events` with a rotation and the new vault answered success without storing the vault
  when the host already had the rotation (for example from a peer). The stored vault then no longer verified and nobody
  could log in. The vault is now stored as a new grant ([HST-12] case 3) or refused, and a retry of the same
  submission gets the same answer ([HST-20]).

## 0.2.0 - 2026-11-05

- License: MIT OR Apache-2.0, at the user's option (0.1.0 was MIT only). The package now ships `LICENSE-MIT` and
  `LICENSE-APACHE`.
- **Breaking (HTTP binding):** `http::route` serves every endpoint under the API version segment `/v0`
  (`<base URL>/v0/host`, `<base URL>/v0/id/…`, HOST_PROTOCOL.md §1.3) and answers paths without it, or with another
  version, with `404`. New constant `http::API_VERSION`. Peer request signatures cover the versioned path. Base URLs,
  `home.url` and every signed message are unchanged; no format change.
- `HostConfig::check`: every configured address must pass `rootcard::check_base_url` ([HST-22]); call it at startup.
  `http::API_VERSION` is now the core's constant.
- The example host accepts a base URL with a path (`ROOTCARD_HOST_URL=http://127.0.0.1:8787/rootcard`) and checks its
  configuration.
- README: the HTTP binding, choosing a base URL, and a pointer to the project README.

## 0.1.0 - 2026-11-04

- First release: the host rules of SPEC §17 as framework-independent handlers (registration, new instances, log
  propagation, lookup, lock hints, challenges, vault fetch, login, sessions, vault and profile updates, password
  change, export, peer pushes) over `IdentityStore`, `ChallengeStore` and `SessionStore`, with in-memory stores.
- `http::route`: the recommended HTTP binding of `docs/HOST_PROTOCOL.md`; `peer`: signed peer requests.
- Builds on the core without its `vault` feature.
