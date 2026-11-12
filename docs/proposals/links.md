# Proposal: linked accounts (GitHub, domains and other services)

Status: **adopted** into [spec/SPEC.md](../../spec/SPEC.md) §12.3; the spec is normative and wins where this document
differs. This document keeps the motivation, the evaluation of the alternatives and the decisions (§5.1, §8, §10, §12).
Differences from the draft below, decided while adopting it (docs/PLAN.md phase 6):

- A value in a URL path fills a whole path segment and is never `.` or `..` ([LNK-8], [LNK-22]): browsers treat
  `%2e%2e` as a dot segment, so percent-encoding alone did not keep a name from reaching another path.
- A `domain` is never an IP address or a single label ([LNK-21]), and a verifier that runs on a server connects only to
  public addresses ([LNK-9]), so links cannot be used to reach internal hosts.
- Descriptors have a `v` and an exact format ([LNK-22]): forms are `{ "type": "none" }` or a token field (no
  `prefix`), a `uid` field means the uid is required, and checks are keyed by form.
- The answer reader is `parse_response_json` ([LNK-9]): `null` and non-integer numbers are dropped, duplicate members
  rejected. Answers of the wrong kind or number are `bad_field`, and the token is searched in bytes ([LNK-6]).
- Rules [LNK-15] (the token never changes) and [LNK-16] (the identity side follows the profile) became part of [LNK-5]
  and the text of §12.3; [LNK-20] (the codes) is SPEC §20. The three ids are not assigned. T-L* threats are
  THREAT_MODEL.md T47–T58 and AR14–AR17.

---

## 1. Goal

A user wants to show that their rootcard identity and an account elsewhere belong to the same person: "`Astra#3F9C`
is `alice` on GitHub and owns `example.org`". Anyone, for example a visitor of an identity page on rootcard.org, should
be able to check this **by themselves** and see a status per link. Requirements:

1. **Two-sided.** A link is verified only when the identity names the external account *and* the external account
   names the identity. Neither side alone can create a link: an identity cannot claim someone else's GitHub account,
   and a GitHub user cannot attach themselves to someone else's identity.
2. **Verified by the viewer.** The verifier checks the identity side with the public log and profile ([LOG-12],
   [DAT-2]) and the external side at the service itself. It never trusts a host's or a website's word that a link is
   verified ([HST-14]).
3. **Low maintenance.** A link survives password resets, moves to another host and recovery key rotation. The text
   the user posts at the service is short enough for a bio or a DNS record and never needs to change.
4. **Revocable.** The user removes a link by editing the profile; verifiers that see the newer profile stop showing it.
5. **No format change.** No new label, no change to any hashed or signed structure. The identity side is a public
   profile key ([DAT-4]); the external side is plain text. Ids, logs, profiles and proofs made so far stay valid.
6. **Pure core.** The core does no I/O (AGENTS.md rule 4): it builds the requests and checks the responses; the
   caller fetches.
7. **Service-neutral format.** The spec names no third-party service. Services are described in a shared registry, so
   every site shows and checks them the same way (§5).

Non-goals: e-mail addresses (left out, §8), proving facts other than account ownership (age, name, employer),
a reverse index ("which identity is GitHub `alice`?", §7.4), and anonymity: a link is public by design.

## 2. Overview

```
 identity side (signed by the account key)              external side (written by the account owner)
 ───────────────────────────────────────────            ───────────────────────────────────────────────
 PublicProfile of Astra#3F9C                            https://gist.github.com/alice/5b1c…
   data["user.links"] = { "v": 1, "links": [            "rootcard:3F9CQ…(52 characters)…"
     { "service": "github", "name": "alice",
       "uid": "583231", "ref": "gist:5b1c…" } ] }

 verifier: verify log ─► fetch newest profile ─► verify_public ─► for each link:
           request = link_requests(link, descriptor) ─► fetch ─► check_link(link, account, descriptor, responses)
           ─► verified | failed (code) | unsupported | not checked
```

The **identity side** is the signed public profile: it says which external accounts the identity claims *now*. The
**external side** is a **link token**, `rootcard:<account id>`, placed where only the external account's owner can
write. The token names the account id, which never changes ([ID-4]), so the external side stays valid across
instances; the profile is re-signed in every instance anyway.

## 3. The identity side

### 3.1 The `user.links` profile key

- **[LNK-1]** An identity's links are the value of the public profile data key `user.links` ([DAT-4]):
  ```
  { "v": 1, "links": [ Link, ... ] }          at most 16 links

  Link { "service": "<service name>",          1–32 characters a–z 0–9 -, beginning with a–z
         "name":    "<account name at the service>",   1–256 bytes, rules per service (§5)
         "uid"?:    "<stable account id at the service>", 1–64 characters A–Z a–z 0–9 . _ : -, rules per service
         "ref"?:    "<where the token is>",    1–256 bytes, rules per service }
  ```
  No other members. → `bad_link`
- **[LNK-2]** A verifier checks `user.links` as a whole (schema, at most 16 links) and then each link on its own. A
  `v` it does not know makes the whole value `unsupported`, not invalid ([LNK-13]). An invalid value or link is reported as `bad_link` **for that value or link only**: the profile stays valid
  ([DAT-2] does not change), and other links are still checked. Two links with the same `service` and `name`
  (compared as the service defines) → `bad_link` for the second.
- **[LNK-3]** The identity side of a link is valid only in the newest valid profile the verifier has for the current
  instance ([DAT-3], [VER-6]). A link that is not in that profile is not shown, whatever the external side says.

*Rationale.* The profile is already signed by the account key of the current instance, ordered by `rev` and replaced
at every new instance. Putting links there gives signing, freshness and revocation without a new structure. The key
is in the `user.` namespace because the user owns it and because a new prefix would make today's verifiers reject
profiles that use it ([DAT-4]). Decided (§12): links do not wait for a namespace for standard keys (PLAN.md "Standard
profile keys"); if one comes, [LNK-16] moves them.

### 3.2 Power level

- **[LNK-4]** Adding, changing and removing links is a profile edit: **low power** ([PWR-1]). A client that writes
  `user.links` SHOULD verify the link (§4.3) before it publishes the profile, and MUST show the user the service, the
  name and that the link is public ([DAT-9]).

A password thief can therefore add a link to an external account the thief controls, or remove the owner's links
(T-L4, §9.2). The owner's reset with the recovery card ends this, as for every other profile edit (AR12).

## 4. The external side

### 4.1 Link token

- **[LNK-5]** The **link token** of an identity is the string `rootcard:` followed by its account id in strict form
  ([ID-3]): `link_token(account) = "rootcard:" + account`, 61 ASCII characters.
- **[LNK-6]** `find_link_token(text, account)` is true if and only if `link_token(account)` occurs in `text` (compared
  byte for byte, case-sensitive) at a position where the character before it, if any, and the character after it, if
  any, are not ASCII letters or digits. Only the first **64 KiB** of `text` are searched. One text MAY hold the tokens
  of several identities (a user with several identities, [RK-4]).

*Rationale.* A token without a signature is enough because each side is authoritative only for itself: the service
decides who may write at the location, and the profile signature decides what the identity claims. A signature on
the external side would add nothing an attacker could not copy, and it would tie the token to an instance or a
recovery key (§10).

### 4.2 Locations

- **[LNK-7]** A service descriptor (§5) names locations where **only the account's owner can write**: a profile
  field, a file the owner publishes, a DNS record. Places where others can write (comments, issues, replies, wikis)
  are never read, even if they are on the owner's page.

### 4.3 Creating a link (client flow)

1. The user chooses a service and types the name. The client checks it against the service's rules and, for services
   with a `uid`, resolves the stable id at the service (§5) and shows the account it found.
2. The client shows the token and where to put it (a gist, a bio, a DNS record).
3. When the user says it is done, the client runs the check of §6 against a profile that would contain the link. On
   `verified` it adds the link to `user.links`, increments `rev` and publishes the profile ([DAT-3]).
4. To remove a link the client removes it from `user.links` and publishes the profile. It tells the user to remove the
   token too, because older copies of the profile still exist ([DAT-9], T-L7).

When the user starts a new instance (password reset, move), the client carries `user.links` over with the rest of the
public profile; the tokens at the services stay as they are.

## 5. Services: a shared convention, not part of the format

### 5.1 Evaluation: services in the spec or in a convention?

| | Service definitions in the spec | Spec stays service-neutral, services in a shared convention |
|---|---|---|
| Spec stability | The spec changes whenever GitHub changes its API or a new service is wanted | The spec changes only when the link structure or the security rules change |
| Neutrality (AGENTS.md rules 4 and 8) | The core names third-party services | The core names none; it only interprets descriptors |
| Adding a service | A spec change and a release of both cores | A reviewed descriptor; verifiers pick it up with their next update |
| Same result everywhere | Guaranteed by vectors | Kept by one shared registry with vectors and one interpreter in both cores; a site that adds its own descriptors gets its own results |
| Security | Fixed in the spec | The security rules stay normative (§5.2); a descriptor can only do what they allow |

**Decision: the convention.** The spec defines what a link is, the token, how a link may be checked and what a
status means. It names no service. A **service registry** next to the spec holds one descriptor per service, as data,
and both cores contain a small, pure interpreter for descriptors. Sites such as rootcard.org bundle the registry, so
they show and check the same services in the same way, and a new service is a reviewed data change rather than a
format change. The cost is a little more machinery (the descriptor format and its interpreter) than hard-coded
checks; the gain is a spec that does not age with third-party APIs.

### 5.2 What stays normative

These rules bind every descriptor and every verifier, whatever the registry says:

- **[LNK-7]** (§4.2) Only locations that only the account's owner can write.
- **[LNK-8]** Every URL a verifier fetches or displays is built from a descriptor's template and validated link fields
  only. A verifier never fetches or displays a URL taken from profile data ([DAT-8]).
- **[LNK-9]** Fetches use HTTPS with certificate checks, follow **no redirects**, send no credentials or cookies, read
  at most **64 KiB**, and give up after **10 s**. A failure of any kind (network, status, size, time, a response that
  does not parse) → `fetch_failed`. JSON responses are parsed with an ordinary JSON parser, not as rootcard JSON
  ([CJ-6] is for signed data only); text is only searched for the token, never rendered as markup.
- **[LNK-18]** A descriptor for a service that lets names be renamed or reused MUST require a `uid` and check it
  against the response (T-L3). A descriptor without a `uid` is allowed only where the name is the account itself (a
  domain), and the registry states its residual risk (T-L10).
- **[LNK-19]** Verifiers use descriptors **bundled with their code** and reviewed like code, never loaded at run time
  from a URL, a host or profile data: whoever controls a descriptor decides what "verified" means for that service. A
  verifier that adds descriptors of its own MUST NOT present their results as the shared registry's, and the
  registry's descriptor wins for a service name it defines.
- **[LNK-20]** The result codes are service-neutral: `wrong_owner` (the account or the location is not the one the
  link names), `token_missing`, `fetch_failed`, `unsupported` and `bad_link`.

### 5.3 Descriptor format

```
Descriptor { "service": "github", "rev": n, "status": "active" | "retired",
  "fields": { "name": Field, "uid"?: Field, "ref"?: { "<form>": Field, ... } },
  "display": "<URL template>",
  "checks": { "<ref form, or * without ref>": [ Step, ... ] } }

Field   { "type": "token" | "domain", "chars"?: "<character set>", "min": n, "max": n, "prefix"?: "<literal>",
          "compare": "exact" | "ascii-ci", "required"?: true }
Step    { "kind": "http-json", "url": "<template>",
          "equal"?: { "<JSON pointer>": "<template>", ... },         mismatch → wrong_owner
          "token_in"?: [ "<JSON pointer, * for any member>", ... ] }  no token → token_missing
      | { "kind": "http-text", "url": "<template>" }                  no token → token_missing
      | { "kind": "dns-txt", "name": "<template>" }                   no token → token_missing
```

- Fields are checked by character set and length (the `domain` type has the rules of a lower-case ASCII host name:
  labels of 1–63 characters `a–z 0–9 -`, at least two labels, at most 253 characters), never by regular expressions,
  so both cores implement them without a dependency and agree byte for byte.
- Templates hold literal hosts; the only placeholders are `{name}`, `{uid}` and `{ref}` (the part after a form's
  prefix). A placeholder in the host part is allowed only for a field of type `domain`, whose characters need no
  encoding. Everywhere else a value is percent-encoded (every byte outside the unreserved characters of RFC 3986), so
  it cannot change the host, add a path segment or start a query ([LNK-8]).
- Steps run in order and stop at the first failure. `equal` compares a value in the response with a filled template,
  as a string or, where the response holds an integer, as its decimal form.
- A descriptor or step kind the interpreter does not know makes that service `unsupported` ([LNK-13]). A new step
  kind is the only spec change a new service can need, and it comes with vectors.

### 5.4 Initial registry entries

**`github`.** `name`: the login, 1–39 characters `A–Z a–z 0–9 -`, compared case-insensitively. `uid`: required, the
numeric user id. `ref`: `bio`, or `gist:` followed by 1–64 characters `0–9 a–f`. Display `https://github.com/{name}`.

```
"checks": {
  "bio":  [ { "kind": "http-json", "url": "https://api.github.com/user/{uid}",
              "equal": { "/id": "{uid}", "/login": "{name}" }, "token_in": [ "/bio" ] } ],
  "gist": [ { "kind": "http-json", "url": "https://api.github.com/user/{uid}",
              "equal": { "/id": "{uid}", "/login": "{name}" } },
            { "kind": "http-json", "url": "https://api.github.com/gists/{ref}",
              "equal": { "/owner/id": "{uid}" }, "token_in": [ "/files/*/content" ] } ] }
```

The first step catches a renamed account and a name that someone else registered later (T-L3); the gist step reads
the files, never the comments ([LNK-7]). The GitHub REST API answers browsers cross-origin; unauthenticated callers
are rate-limited, which shows as "not checked".

**`dns`.** `name`: a domain; no `uid` or `ref`. One step: `dns-txt` at `_rootcard.{name}`; the strings of one record,
concatenated, hold the token. The verifier SHOULD show its resolver and whether DNSSEC was validated (T-L13).
Display `https://{name}/`, as text.

**`web`.** `name`: a domain; no `uid` or `ref`. One step: `http-text` at
`https://{name}/.well-known/rootcard-link`. Browser verifiers need `Access-Control-Allow-Origin: *` on that file. The
path is separate from the host pointer `/.well-known/rootcard` ([HST-23]), which says where a host is, not who owns
the domain.

### 5.5 Candidates

| Service | Name and stable id | Location of the token | Fits the descriptor format? |
|---|---|---|---|
| GitLab, Codeberg (Forgejo) | login, numeric user id | bio | Yes, as `github`; a self-hosted instance is a descriptor of its own |
| Bluesky | handle, DID as `uid` | profile description | Yes: one `http-json` step on the public API by DID |
| Mastodon | `@user@instance` | profile note or field | Not yet: needs a name split into user and instance domain, a new field type |

## 6. Verification and status

### 6.1 Algorithm

**[LNK-10]** `verify_links(profile, log, now)` and the per-link check, in order:
1. The verifier has the newest log it can gather for the account ([VER-4]) and verifies it ([LOG-12]); the identity
   is not retired → `account_retired`. It fetches the current public profile from `home.url` of the current instance
   (`GET /id/{account}/public`), keeps the newest valid one it knows ([DAT-3]) and verifies it ([DAT-2]).
2. It reads `user.links` ([LNK-1], [LNK-2]). No key → no links.
3. For each link: a `service` without a bundled descriptor → `unsupported`; otherwise `link_requests(link,
   descriptor)` gives the requests ([LNK-8]), the caller performs them ([LNK-9]) and `check_link(link, account,
   descriptor, responses)` gives `verified` or the code of the first failing step (§5.3).

The core provides steps 2 and 3 without I/O: `parse_links`, `link_token`, `find_link_token`, `link_requests` and
`check_link` (snake_case in Rust, camelCase in JS), with vectors that include recorded service responses.

### 6.2 Status values

| Status | Meaning | Shown as |
|---|---|---|
| `verified` | Both sides checked by this verifier at time `t` | "verified", with the time of the check |
| `failed` | Checked, and a step failed: `wrong_owner` or `token_missing` ([LNK-20]) | "not verified", with the reason |
| `not checked` | `fetch_failed`: the service could not be reached, rate-limited, refused a browser | "not checked", with a retry |
| `unsupported` | The verifier does not know the service, the `ref` form or the `v` ([LNK-13]) | "unsupported", name as text only |
| `invalid` | `bad_link` | not shown, or "invalid link" for the owner |

- **[LNK-11]** A verifier shows a link as verified only if **it** checked both sides, and says when. A result that
  someone else checked (a server's cache, a badge image, a host) is shown as that party's statement, with its name
  and time, never as the viewer's own result. A verifier SHOULD re-check a result older than **24 h** before showing it
  as verified.
- **[LNK-12]** Names, uids and references are displayed as plain text ([DAT-8]). Domain names are shown in their
  ASCII form. The displayed URL is the descriptor's (§5), never one from the profile.

### 6.3 Evolution and compatibility

Links are meant to outlive the services' APIs, the verifiers deployed today and the core's current key types. These
rules keep old links valid and old verifiers safe when something new appears.

- **[LNK-13]** **Unknown means unsupported, never invalid.** A verifier reports `unsupported` (not `bad_link`) for a
  `user.links` value with a `v` it does not know, for a `service` it does not know, and for a `ref` form a known
  service may have gained later (for example `repo:` next to `bio` and `gist:`). Nothing unknown is shown as verified,
  and nothing unknown makes other links or the profile fail. This lets a newer client add services and forms without
  breaking older verifiers.
- **[LNK-14]** **Stored fields are stable; checks may change.** The meaning of `service`, `name`, `uid` and the existing
  `ref` forms never changes once its descriptor is in the registry. How a verifier checks them (endpoints, response fields,
  API versions) MAY change when the service changes its API, with new vectors, as long as the same stored link means
  the same account. A change of meaning needs a new service name or a new `v`, and the old one stays readable
  (AGENTS.md rule 1).
- **[LNK-15]** **The token never changes.** `rootcard:<account id>` names only the account id, which never changes
  ([ID-4]), and holds no key, signature or instance. Password resets, moves, recovery rotation and later key types
  (post-quantum, PLAN.md "Later") leave every posted token valid. If a later format introduces account ids of another
  form, the token is still `rootcard:` followed by that id in its strict form; [LNK-6] matches whole tokens, so the
  length of the id does not matter.
- **[LNK-16]** **The identity side follows the profile.** Links are signed only through the public profile. When the
  profile gets a new version or key type, links come along with no change here. If standard profile keys later get
  their own namespace, verifiers read the new key and `user.links` for at least one major version, and prefer
  the new key when both are present.
- **[LNK-17]** **Services may disappear.** A service that shuts down or stops answering anonymous reads makes its links
  `not checked` (`fetch_failed`), not `failed`. Its descriptor is then marked `retired` in the registry; verifiers keep
  reporting its links as `unsupported` rather than reusing the name.
- **Extensions without a format change.** New services (§5.5) and new `ref` forms are additions to the registry. A
  separate structure, should one ever be needed, is combined with `user.links` by verifiers that know it and ignored
  by the rest, as [LNK-13] requires.

## 7. Displaying links: an identity page such as rootcard.org

An identity page is a verifier like any other. A static page that checks everything in the viewer's browser is the
strongest form, because then the page's server is trusted only for the code it serves, as for `keytool.html` (B3, B4).

### 7.1 Finding the identity

The page takes a full account id (`/id/<account id>`) or a typed handle. A handle is looked up at hosts the page
trusts (`GET /id/lookup`), the id is checked to start with the typed tag ([HDL-1]), and the page shows the **full**
account id and the extended handle where tags collide ([HDL-2], [HDL-6]). Hosts answer cross-origin (HOST_PROTOCOL.md
§1), so the browser fetches the log and profile directly.

### 7.2 What the page shows

```
 Astra#3F9C                       3F9CQ…  (full account id, copyable)
 home: https://id.example         current instance since 2026-10-02, not retired
 ───────────────────────────────────────────────────────────────────────────────
 ✓ github  alice        verified now                 https://github.com/alice
 ✓ dns     example.org  verified now (resolver: …)   https://example.org/
 ? web     astra.dev    not checked: the site does not allow browser checks   [retry]
 ✗ github  astra-old    not verified: wrong_owner (renamed or reassigned)
```

- The status comes from the checks of §6, run when the page opens. Results MAY be cached in the browser for the 24 h
  of [LNK-11], labelled with their time.
- A server-side cache (to save rate limits) is allowed only if the page says that the result is the server's and when
  it was made ([LNK-11]), and offers a check in the browser.
- The page never shows `verified` for a link it could not check, and never offers an "is verified" API that other
  parties are expected to trust: they run the same check.
- Embeddable badges are images served by a server, so they are that server's statement; they link to the page, where
  the viewer's own check runs.

### 7.3 Starting from the external side

A visitor who finds a token on GitHub can paste it (or the account id in it) into the page. The page then runs the
same check from the identity side, so a token copied to someone else's account is never shown as a link (T-L2).

### 7.4 Search by external account

"Which identity is GitHub `alice`?" needs an index of profiles, which is a server's statement. It is out of scope;
an index MAY exist, and every hit is checked as in §6 before it is shown.

## 8. E-mail addresses: left out

**Decision: e-mail addresses are not part of linked accounts, now or as a planned extension.** Nothing about
e-mail goes into the spec, the cores or the key tool.

- **It cannot be proved publicly.** A link is two-sided (§1): the external account must say which identity it
  belongs to, at a place anyone can read and that only the owner can write. A mailbox has no such place. Without it, a
  viewer cannot check an address, so an identity page could only show the address as an unverified claim. That is
  worse than nothing: it looks like a credential and is not one.
- **The check that does work is useless as a standard.** A site can send a code to an address and ask the user to
  answer. That shows the site, and only the site, that the identity's owner reads the mailbox. Every site already does
  this with its own e-mail confirmation, keyed to its own account, and gains nothing from a rootcard format. A user
  who wants it can already sign the answer with a statement proof ([PRF-5]); this needs no rule.
- **Attestations would be a different product.** A third party that checks addresses and signs "account X controls
  a@b.com" makes viewers trust that party: a certificate authority for e-mail, with keys, expiry and revocation of its
  own. That conflicts with requirement 2 (verified by the viewer), and is not proposed.
- **DKIM does not fit either.** A domain's DKIM signature on a message holding the token vouches for the domain's
  mail system, not for one mailbox, and domains rotate and withdraw DKIM keys, so a check cannot be repeated later.

What a user can prove instead: **a domain they own**, with `dns` or `web` (§5.4). For a personal domain that is
the useful part of "this is my address": whoever controls `example.org` controls mail for it.

If e-mail is raised again, it needs a design in which a viewer can check the address without trusting a third party.
None is known.

## 9. Security analysis

### 9.1 Threats addressed

| # | Threat | Mitigation |
|---|---|---|
| T-L1 | An identity claims an external account it does not control | The token must be at a location only the account's owner can write ([LNK-7]); missing → `token_missing` |
| T-L2 | An external account claims an identity (copies its token) | Verifiers start from the identity's signed profile and show only links listed there ([LNK-3]) |
| T-L3 | A service name is renamed, deleted and registered again by someone else, who then posts the token | Descriptors of such services require the stable `uid` and check the current name ([LNK-18], §5.4) |
| T-L5 | Profile data used to fetch or link to other hosts or paths (URL injection, `javascript:` links) | Literal hosts in templates, percent-encoded values, `domain` fields for host names; URLs never come from the profile ([LNK-8], [LNK-12], §5.3) |
| T-L14 | A changed or injected descriptor makes false links verify | Descriptors are bundled and reviewed like code, never loaded at run time; the normative rules bind every descriptor ([LNK-19], §5.2) |
| T-L6 | A service or domain answers with huge, slow, redirecting or active content | No redirects, 64 KiB, 10 s, text only ([LNK-9], [DAT-8]) |
| T-L8 | A website or host says "verified" without checking, or lies | Viewers check themselves; others' results are labelled as theirs ([LNK-11]) |
| T-L11 | The token is placed in a comment or issue on the owner's page by someone else | Only owner-writable locations are read ([LNK-7]) |
| T-L12 | Look-alike names (`examp1e.org`, Unicode domains) | ASCII forms only, shown as text ([LNK-12]); viewers still compare names themselves |

### 9.2 Residual risks (would become accepted risks)

- **T-L4: A password thief edits links.** Adding a link to the thief's own account makes the identity appear to be
  that account; removing links hides the owner's. Low power, ended by a reset ([PWR-1], AR12). A later option is
  links signed by the recovery key, which is not planned (§12).
- **T-L7: Stale profiles.** A verifier that cannot reach the home may show a link from an older profile copy that the
  owner has since removed ([DAT-9]). The owner removes the token as well (§4.3 step 4), which ends such links for
  everyone who checks.
- **T-L9: The service is trusted for its side.** A link is as strong as the external account's security and the
  service's honesty. A compromised GitHub account can post a token for an attacker's identity; that only creates a
  link if the attacker also lists the account in a profile, and it shows the attacker's identity, not the victim's.
- **T-L10: Domains change hands.** `dns` and `web` have no stable id: whoever registers an expired domain controls its
  side. Combined with a stale profile listing the domain, the new owner can confirm a link they were not meant to
  have. The owner removes links before letting a domain expire.
- **T-L13: DNS answers without DNSSEC** can be forged by an attacker on the verifier's path or at its resolver.
  Verifiers show the resolver and whether DNSSEC was validated.
- **Privacy.** Links are public and make the identity linkable to the external accounts; a user who does not want
  this uses another identity ([RK-4], G9). Each check tells the service (GitHub, the DNS resolver, the domain) the
  viewer's network address and that someone looked at the link.

### 9.3 What stays unchanged

- No secret crosses any boundary: the verifier reads only public data.
- No new label, no change to the log, the profile, proofs or any signed bytes.
- Power levels: links are profile data (§3.2). Nothing here touches the log or the vault.

## 10. Alternatives considered

| Alternative | Verdict |
|---|---|
| A signed statement proof ([PRF-5]) at the service instead of a token | **Rejected for the first version.** About 400 bytes (too long for a bio or a single DNS string). An account proof ([PRF-1]) dies with the instance, so every reset or move would break every link; a root proof ([PRF-2]) lasts longer but needs the recovery card for every link and dies at `rotate_recovery`. It adds no security: the service decides who writes at the location, and the profile signature already covers the identity side |
| A new log event for links | **Rejected.** Links would need the recovery key, and the log would grow with data that is not about keys or hosts |
| Links signed by the recovery key (a root-signed link list) | **Not planned** (§12). Stronger against a password thief (T-L4), but needs a new structure and label for a risk that every profile edit already carries |
| A central verification service | **Not needed.** Every verifier checks for itself; a service would be one more party to trust (§7.2) |
| A new profile namespace (`link.` or a standard-key prefix) | **Rejected** (§12). Today's verifiers reject profiles with unknown prefixes ([DAT-4]), so it would need a profile `v: 2` for no security gain |

## 11. Work if adopted

1. SPEC: a section "Linked accounts" with the [LNK-*] rules, the descriptor format and its step kinds, §19 limits (16
   links, 64 KiB, 10 s), §20 codes ([LNK-20]), §21 vectors. No service is named in the spec. THREAT_MODEL: the T-L*
   threats and accepted risks. ARCHITECTURE: the link functions, the interpreter, and that the core does no fetching.
   CONCEPTS: a section on links.
2. The service registry in `spec/links/`: one descriptor file per service (`github.json`, `dns.json`, `web.json`), each
   with recorded responses (accept and reject for every step) as vectors.
3. `spec/vectors/link.json` from `xtask`: tokens, token search (boundaries, several tokens, the 64 KiB limit), valid and
   invalid `user.links` values, field checks, template filling, and the registry's recorded responses. `xtask` also
   checks every descriptor against the format.
4. Both cores: `parse_links`, `link_token`, `find_link_token`, `link_requests`, `check_link` / `parseLinks`,
   `linkToken`, `findLinkToken`, `linkRequests`, `checkLink`. No new dependency.
5. The key tool: `rootcard link add|remove|check` and a links panel in `keytool.html`; `rootcard-host` MAY check links
   for its own identity pages.
6. CHANGELOGs under `## Unreleased`.

## 12. Decisions

1. **The profile key is `user.links`.** It works with every verifier deployed today, the user owns it, and [LNK-16]
   covers a move if standard keys ever get a namespace of their own. A new prefix would need a profile `v: 2` and gives
   no security: a client with the password can sign any profile whatever the key is called.
2. **Services are a convention (§5).** The spec is service-neutral, the registry holds declarative descriptors, and
   both cores interpret them without I/O. Hard-coded checks in a separate module were rejected: two implementations
   would drift, and every site would have to trust that module's code per service instead of reviewing data.
3. **The registry lives in this repository, in `spec/links/`,** and is released with the packages. Verifiers must
   bundle descriptors anyway ([LNK-19]), so a separate repository would not let services change faster where it
   matters; it would only add a second review process, and `xtask` could not check descriptors and vectors together.
   A service whose API changes is fixed in a patch release.
4. **The first registry has `github`, `dns` and `web`.** GitHub is the case that motivated the proposal; `dns` and
   `web` cover domains, the answer to e-mail (§8), and need only the `dns-txt` and `http-text` steps. Other services
   (§5.5) are added later as descriptors only, without a spec change, except Mastodon, which first needs a new field
   type.
5. **E-mail is left out (§8),** and not kept as a later item: no design is known in which a viewer can check an address
   without trusting a third party.
6. **No root-signed link list.** A password thief who edits links has the same low power as one who edits any other
   profile data, and the recovery card ends it (AR12). An identity with only a card has no host and no profile to show,
   so links would not help it. If the threat model changes, a separate structure can still be added without breaking
   anything ([LNK-13]).
