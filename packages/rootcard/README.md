# rootcard (npm)

[rootcard](https://github.com/rootcard/rootcard) in plain ES modules: a portable, self-certifying identity for online
logins. Zero dependencies, no build step, WebCrypto only; runs in browsers and Node 20 or later. It produces and checks
exactly the bytes of the Rust crate `rootcard`; both are tested against the shared vectors of the specification.

> **New to rootcard?** Start with the [project README](https://github.com/rootcard/rootcard#readme): what rootcard is,
> the two ways to use it (a safer username-and-password login for your own service, or an ID card across services),
> how it compares with other login methods, and the roadmap.
> To build with it, the [getting-started guide](https://github.com/rootcard/rootcard/blob/main/docs/GETTING_STARTED.md#2-an-application-client-javascript)
> has code for each role.

```js
import { verifyLog, verifyProof } from "rootcard";             // verification: hosts, relying parties, clients
import { register, unlockVault, changePassword } from "rootcard/vault"; // passwords, Argon2id, vault encryption

const state = await verifyLog(events, { realms: ["global"], now: Math.floor(Date.now() / 1000) });
```

- `rootcard` is the verification core: canonical JSON, keys, recovery keys, identities and handles, logs
  (`verifyLog`, `extendLog`, `compareLogs`), vault and profile checks, login and fetch messages, proofs, account files
  and recovery cards.
- `rootcard/vault` adds password locks (Argon2id implemented in this package, the only primitive not taken from
  WebCrypto), vault encryption and the high-level flows: registration, password change, new instances and rotation.
  A server bundle that does not import it never loads it.
- `keytool.html` is the standalone key tool page: open it from your own disk (`file://`). It talks only to the hosts you
  enter. It is generated from these modules by `npm run build`.

Functions that need randomness take `random(n)`; pass `systemRandom` (WebCrypto `getRandomValues`). Make a new
recovery key with `newRecoveryKey(realm, username, systemRandom)`, not with 32 bytes of your own: `register` refuses
the rare key whose signing key some browsers cannot use (SPEC [CRY-9]). Errors are `RootcardError` with the stable
`code` of SPEC §20.

## HTTP binding

The core makes no requests. Application clients that talk to a host build URLs as `` `${base}/${API_VERSION}/…` ``
(`API_VERSION` is `"v0"` until 1.0.0, HOST_PROTOCOL.md §1.3) and check host addresses with `checkBaseUrl` (SPEC
[HST-22]) before using them or putting them into an instance. `keytool.html` does both; a `keytool.html` from 0.1.0
does not reach hosts of 0.2.0. When the user types a bare domain (`isOrigin`), fetch `` `${origin}${WELL_KNOWN_PATH}` ``
without following redirects and resolve it with `wellKnownBase` (SPEC [HST-23]); without a `200` answer, use the
domain itself.

## License

Licensed under either of MIT or Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`).
