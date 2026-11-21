# rootcard: hosting

How to get the key tool and run a rootcard host in production: the release files and how to check them, addresses,
the reverse proxy, storage and backups, the host key, several servers, and updates. The code that makes a server a
host is in [GETTING_STARTED.md §3](GETTING_STARTED.md#3-a-host-rust); the endpoints are in
[HOST_PROTOCOL.md](HOST_PROTOCOL.md). This guide is informative: where it and SPEC differ, SPEC wins.

---

## 1. What you run

- **A host** is your own server program, built with the crate `rootcard-host` (Rust). rootcard ships no ready-made
  server: the host lives inside your application, which owns HTTP, storage, rate limits and secrets
  (ARCHITECTURE.md §3). `cargo run -p rootcard-host --example host` is a development host (in memory, no TLS, no rate
  limits), not something to deploy.
- **The key tool** runs on the users' own machines, never on the host: the binary `rootcard` (`rootcard-cli`) and the
  page `keytool.html`. They are the only places a recovery key is typed ([PWR-6]).
- **The application client** is your web page or app, built with the npm package `rootcard`. It is where the password
  is typed (§7).

## 2. Release files and how to check them

Every release on GitHub (`https://github.com/rootcard/rootcard/releases`) has:

| File | What |
|---|---|
| `rootcard-cli-<version>-x86_64-unknown-linux-musl.tar.gz` | Key tool, Linux x86_64, static: runs on any distribution |
| `rootcard-cli-<version>-aarch64-unknown-linux-musl.tar.gz` | Key tool, Linux arm64, static |
| `rootcard-cli-<version>-aarch64-apple-darwin.tar.gz` | Key tool, macOS on Apple silicon |
| `rootcard-cli-<version>-x86_64-apple-darwin.tar.gz` | Key tool, macOS on Intel |
| `rootcard-cli-<version>-x86_64-pc-windows-msvc.zip` | Key tool, Windows x86_64 |
| `rootcard-keytool-<version>.html` | The key tool page, the same file as `keytool.html` in the npm package |
| `rootcard-<version>.crate`, `rootcard-host-<version>.crate`, `rootcard-cli-<version>.crate`, `rootcard-<version>.tgz` | The packages, byte for byte as crates.io and npm serve them |
| `SHA256SUMS` | The SHA-256 of every file above |
| `rootcard-<version>.sigstore.json` | The signature of every file above (a Sigstore bundle) |

**Signatures.** The release workflow signs every file with a GitHub artifact attestation: a Sigstore-signed build
provenance statement that says which workflow run of `rootcard/rootcard` built the file, from which commit and tag.
It is made with the workflow's short-lived identity, so there is no long-lived signing key that could leak
(RELEASING.md §4). Check a file before you run it or open it, with the GitHub CLI:

```sh
gh attestation verify rootcard-cli-0.4.0-x86_64-unknown-linux-musl.tar.gz --repo rootcard/rootcard
sha256sum -c SHA256SUMS --ignore-missing         # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
```

`gh attestation verify` must say that the file was built by `.github/workflows/release.yml` in `rootcard/rootcard`
for the tag you expect. To verify without the GitHub API, download `rootcard-<version>.sigstore.json` too and add
`--bundle rootcard-<version>.sigstore.json`. On Windows, `Get-FileHash <file>` prints the SHA-256 to compare with
`SHA256SUMS`. The checksums are also in the release notes.

The packages are reproducible: anyone can rebuild them from the tag and compare (RELEASING.md §5). The binaries are
not; their signature is what ties them to the tag.

### 2.1 Installing the key tool

Linux and macOS:

```sh
tar -xzf rootcard-cli-0.4.0-x86_64-unknown-linux-musl.tar.gz
sudo install -m 755 rootcard-cli-0.4.0-x86_64-unknown-linux-musl/rootcard /usr/local/bin/rootcard
rootcard --version                                # rootcard 0.4.0 (format v1)
```

macOS marks files downloaded with a browser as quarantined, and the binaries are not notarized by Apple: download
with `curl -LO` or `gh release download`, or remove the mark with `xattr -d com.apple.quarantine rootcard` after
checking the signature. On Windows, unpack the zip and run `rootcard.exe` from a terminal.

From source instead: `cargo install rootcard-cli --version 0.4.0 --locked`.

### 2.2 The key tool page

`rootcard-keytool-<version>.html` is one file without external resources. Users save it, check it as above, and open it
from their own disk (`file://`). Point your users to the release file (or the copy in the npm package) and do not
serve the page from your host: a page your host serves can be changed by whoever controls the host, and this page asks
for the recovery key (THREAT_MODEL.md AR2, GETTING_STARTED.md §5). The page talks to hosts with plain `fetch`, which
the CORS headers of the binding allow (HOST_PROTOCOL.md §1).

## 3. Addresses

A host has one or more **base URLs** ([HST-18], [HST-22]): `https://id.example.com`, or a path on a shared domain,
`https://example.com/rootcard`. The endpoints are below `<base URL>/v0` (HOST_PROTOCOL.md §1.3).

- **Choose once.** The base URL goes into every user's signed log as `home.url` when the host receipts their instance.
  A host can add addresses and announce a new one at an old address without any new event ([HST-18]), but the old
  address should keep answering `GET /host` for as long as logs name it.
- **A shared domain** needs a path of its own (preferably `/rootcard`) and the host pointer at
  `https://example.com/.well-known/rootcard` (`http::well_known`), so that users can type the bare domain ([HST-23]).
  The pointer is outside the base URL: your application routes it.
- `HostConfig::check` refuses an address that is not a base URL or that ends in a version segment. Plain `http://`
  works only on loopback, for development.

## 4. Reverse proxy and TLS

The host is your server; put TLS in front of it the way you do for the rest of your application. What the proxy must
do for the rootcard endpoints:

- **TLS** on every address, with HSTS. Clients refuse `http://` except on loopback.
- **Request bodies up to 6 MiB** (`http::MAX_BODY`, identity logs with vaults): the proxy must allow them, and your
  server must answer `413` before reading a larger body.
- **The client address** in `X-Forwarded-For` (or your proxy's equivalent), trusted only from your proxies. The rate
  limits of HOST_PROTOCOL.md §6 are keyed by it (§6).
- **Pass the response headers through.** The router sets CORS (`Access-Control-Allow-Origin: *` on every endpoint except
  `/peer/*`) and `Cache-Control: no-store` on responses with vaults, tokens, lock hints and challenges. Do not cache
  rootcard responses in the proxy or a CDN, and do not add cookies: no rootcard endpoint uses them.
- **Pass `Authorization`** (session endpoints) and, if you run peers, the `Rootcard-Peer-*` headers.
- **Do not redirect the host pointer:** clients do not follow redirects for it ([HST-23]).

Caddy, with the host on `127.0.0.1:8080` and its base URL `https://example.com/rootcard`:

```text
example.com {
	request_body {
		max_size 6MiB
	}
	handle /rootcard/* {
		reverse_proxy 127.0.0.1:8080
	}
	handle /.well-known/rootcard {
		reverse_proxy 127.0.0.1:8080
	}
	# ... the rest of the application
}
```

nginx (certificate already set up, for example by certbot):

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name id.example.com;
    # ssl_certificate …; ssl_certificate_key …;
    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 6m;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## 5. Storage, the host key and backups

### 5.1 What to keep

| What | Where | Back up? |
|---|---|---|
| Identities: events, log state, vault, profile per account | your `IdentityStore` (ARCHITECTURE.md §3.1, table `identities`) | **Yes** |
| The host key (32-byte seed) and the public parts of retired keys | your secret store ([HST-17]) | **Yes**, separately and encrypted |
| Challenges | `ChallengeStore` (60 s) | No |
| Sessions | `SessionStore`, or your own sessions | No: users log in again |
| The configuration: base URLs, realms, username policies, peers | your deployment | Yes, with the code |

The store needs compare-and-swap on one identity at a time and an atomic take of challenges ([HST-19]); with that, any
number of servers share it. Delete expired challenges and sessions with a periodic job (ARCHITECTURE.md §3.1), or the
tables grow without bound: anyone can request a challenge.

A backup of the identities holds every vault the host is home for. Vaults are encrypted, but whoever holds them can
guess passwords offline (Argon2id, 64 MiB; THREAT_MODEL.md AR1). Keep backups as secret as the database, and not
longer than you need them.

### 5.2 Restoring

Restore the identities and the host key together, from a consistent backup (a database snapshot or point-in-time
recovery, never a file copy of a running database). Prefer point-in-time recovery: what a restore loses is everything
since the backup, and a restored host is **behind** for every identity that changed since then.

- **Revoked instances come back at this host.** Hosts keep only the newest log they have seen ([VER-4]). A restored
  host has forgotten what happened after the backup, so until it sees the newer log again it treats an instance that
  was replaced since (a password reset, a move to another host, a retirement) as current, and accepts that instance's
  old password and account key. This is THREAT_MODEL.md AR4 for every such identity. The newer log comes back whenever
  a party that holds it talks to the host ([VER-5]): peers ([HST-15]), clients that saw it, and the key tool when it
  is given an account file or another host that has the newer log ([KT-2]). So after a restore, start the host with an
  empty session store, let peers push to it first if you have any, and tell your users which period was lost, so that
  those who reset a password or moved in that period know that the old password may work here again until the newer
  log arrives.
- **Vaults** replaced after the backup (a new password slot, private data) are the older vault again. The user resets
  the password with the recovery card or restores from an account file (`rootcard restore --card <card> --account
  <file> --host <base URL>`, GETTING_STARTED.md §5).
- **Identities registered after the backup** are gone from this host. Their owners register them again with `rootcard
  restore` from the account file or the recovery card; the account id stays the same.

A host that lost its data completely is the same case for every identity: the recovery card can always mint a new
instance, on this host or another one. That is the design's last resort, not a backup strategy.

### 5.3 The host key

The host key signs receipts and peer requests, and identifies the host as the home of its instances ([HST-17]). It
signs nothing that could create or change an identity without the owner's recovery key. Keep it in a secret store or a
signing service, readable by the host process only.

- **Lost:** give the host a new key and put the old public key (in every log the host receipted, and in the host
  descriptor of `GET /host`) into `retired_keys`. The host is still the home of every instance with the old key
  ([HST-17]), so they keep working; new instances get receipts from the new key. Tell your peers the new key.
- **Leaked:** an attacker can impersonate the host towards peers. Rotate: make a new key current, keep the old public
  key in `retired_keys`, destroy the old private key, and tell your peers the new key.
- **Rotation** needs no event from any user: instances receipted by a retired key stay valid as long as its public key
  is in `retired_keys`.

## 6. Running it safely

- **Rate limits** are yours: `rootcard-host` limits nothing, because only your server knows the client's address.
  Apply HOST_PROTOCOL.md §6 (per address and per account) in front of `http::route` and answer `429 rate_limited` with `Retry-After` ([HST-16]).
  Without them, the vault fetch is an unlimited online password guess (THREAT_MODEL.md T11).
- **The clock** must be synchronized (NTP; [HST-21]): receipt times are checked within ± 600 s ([HST-6]), and
  challenges expire after 60 s.
- **Several servers** share one store and one host key: they are one host. **Peers** are separate hosts of the same
  realm that share public logs: exchange host keys (`peers`), route `/peer/*` only between them, and forward the
  `Rootcard-Peer-*` headers (HOST_PROTOCOL.md §5).
- **Logs.** Do not log request bodies: they contain vaults and login messages. Log the status, the endpoint and the
  account id if you need them.
- **Handlers are synchronous.** In an async server, call `http::route` from a blocking task.

## 7. The application page

The page where users type their password is the most valuable target (THREAT_MODEL.md T19). Serve it from your own
origin with a strict Content Security Policy (no inline script, no third-party script), `X-Content-Type-Options:
nosniff` and HSTS, and bundle the npm package `rootcard` yourself instead of loading it from a CDN. The npm package
has provenance (`npm audit signatures` in your project), and its tarball is also on the GitHub release (§2).

## 8. Updates

- **Watch the releases** on GitHub (Watch → Custom → Releases). The notes of every release list the changes of each
  package; a format change or a breaking change says so.
- **Update the crates** with `cargo update -p rootcard -p rootcard-host` (or a new version in `Cargo.toml` for a new
  minor version before 1.0.0, which may change the API: read the changelog). Rebuild and deploy as for any change to
  your server.
- **Formats stay readable.** Ids, logs and signatures made with format version 1 stay valid in every later release
  (SPEC §22), so an update of the host does not touch the stored identities.
- **The HTTP binding** is versioned by its path: `/v0` until 1.0.0, then `/v1` (HOST_PROTOCOL.md §1.3). Base URLs and
  `home.url` never contain the version, so moving to `/v1` changes no identity.
- **The key tool** is updated by its users: a new binary from the release, checked as in §2.
- **Security fixes** are released as a patch version of every package together (SECURITY.md); only the newest minor
  line gets them before 1.0.0.

## 9. Checklist

- [ ] Base URLs chosen for good; the host pointer served on a shared domain ([HST-22], [HST-23])
- [ ] TLS and HSTS on every address; the proxy allows 6 MiB bodies and passes CORS, `Authorization` and
  `Cache-Control` through
- [ ] A shared store with compare-and-swap, atomic challenge takes and expiry jobs ([HST-19])
- [ ] The host key in a secret store, backed up separately; retired keys kept
- [ ] Backups of the identities, as secret as the database, and a restore tried once
- [ ] Rate limits of HOST_PROTOCOL.md §6 keyed by the real client address ([HST-16])
- [ ] A synchronized clock ([HST-21])
- [ ] The application page with CSP, `nosniff` and HSTS; `rootcard` bundled, not from a CDN
- [ ] Users pointed to the signed key tool from the release (binary or page), not a copy on the host
- [ ] Releases watched
