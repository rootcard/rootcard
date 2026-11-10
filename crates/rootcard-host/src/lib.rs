//! # rootcard-host
//!
//! Host-side helpers for [`rootcard`] identities (SPEC §17): registration, new instances, log propagation, lock hints,
//! challenges, vault fetch, login, sessions, vault and profile updates, export and peer pushes. It is a library, not a
//! server: handlers are plain functions over storage traits ([`store`]), independent of any HTTP framework, and
//! [`http::route`] maps the recommended HTTP binding (docs/HOST_PROTOCOL.md) onto them.
//!
//! Time and random bytes are parameters ([HST-21], [IMP-1]): the application passes its clock and bytes from its secure
//! generator. The host never sees a password and never decrypts a vault; it builds on the core without the `vault`
//! feature.
//!
//! ## Getting started
//!
//! Configure a [`Host`] over three stores and hand each request of the binding to [`http::route`]. Paths are relative
//! to the base URL and start with the API version ([`http::API_VERSION`]):
//!
//! ```
//! use rootcard_host::http::{Request, route};
//! use rootcard_host::store::{MemoryChallengeStore, MemoryIdentityStore, MemorySessionStore};
//! use rootcard_host::{Host, HostConfig, RealmConfig, UsernamePolicy};
//! use zeroize::Zeroizing;
//!
//! let config = HostConfig {
//!     key_seed: Zeroizing::new([0xa1; 32]), // from the host's secret store ([HST-17])
//!     retired_keys: Vec::new(),
//!     urls: vec!["https://id.example.com".into()], // base URLs, never ending in /v0 ([HST-22])
//!     realms: vec![RealmConfig { realm: "global".into(), policy: UsernamePolicy::DEFAULT }],
//!     peers: Vec::new(),
//! };
//! config.check()?;
//! let host = Host::new(config, MemoryIdentityStore::new(), MemoryChallengeStore::new(), MemorySessionStore::new());
//!
//! let req = Request { method: "GET".into(), path: "/v0/host".into(), ..Request::default() };
//! let now = 1_800_000_000; // the system clock in real code ([HST-21])
//! let res = route(&host, &req, now, &mut |b| getrandom::fill(b).expect("random"));
//! assert_eq!(res.status, 200);
//!
//! // On the application's own endpoints, a bearer token from a login names the user ([HST-11]).
//! assert_eq!(host.session("not-a-token", now).err().map(|e| e.status()), Some(401));
//! # Ok::<(), rootcard::Error>(())
//! ```
//!
//! The in-memory stores are for tests and development. A production host implements the [`store`] traits over shared
//! storage (docs/ARCHITECTURE.md §3.1) and applies the rate limits of docs/HOST_PROTOCOL.md §6 in front of the router:
//! this crate limits nothing itself ([HST-16]). `examples/host.rs` wires the router to `std::net`, and
//! docs/GETTING_STARTED.md §3 walks through a host step by step.

#![forbid(unsafe_code)]

pub mod http;
pub mod peer;
pub mod store;

use rootcard::Error;
use rootcard::crypto::{ed25519_public, ed25519_sign, ed25519_verify, sha256};
use rootcard::encoding::{base64url_decode, base64url_encode};
use rootcard::id::{check_username, extended_tags, handle, parse_handle};
use rootcard::json::{Map, Value, canonical};
use rootcard::keys::{KeyType, format_key, parse_key};
use rootcard::log::{
    LogState, VerifyOptions, Version, event_hash, extend_log, receipt_message, verify_log, verify_pending,
};
use rootcard::messages::{Challenge, LoginRequest, Purpose, change_message, fetch_message};
use rootcard::profile::verify_public;
use rootcard::vault::{VaultChange, vault_change, verify_vault};
use store::{ChallengeStore, HandleKey, IdentityStore, Insert, Issued, Session, SessionStore, StoreError, Stored};
use zeroize::Zeroizing;

/// The format version this host crate speaks, re-exported from the core.
pub const FORMAT_VERSION: u32 = rootcard::FORMAT_VERSION;
/// The receipt time window ([HST-6]).
pub const RECEIPT_WINDOW: i64 = 600;
/// The longest session idle time ([HST-11]).
pub const SESSION_IDLE: i64 = 24 * 3600;

/// A username policy with the descriptor fields of HOST_PROTOCOL.md §2 ([USR-3]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsernamePolicy {
    /// Minimum length.
    pub min: usize,
    /// Maximum length.
    pub max: usize,
    /// Whether the first character must be a letter.
    pub first_letter: bool,
}

impl UsernamePolicy {
    /// The default policy: 3 to 20 characters, beginning with a letter ([USR-3]).
    pub const DEFAULT: UsernamePolicy = UsernamePolicy {
        min: 3,
        max: 20,
        first_letter: true,
    };

    /// Whether `username` satisfies [USR-1] and this policy.
    pub fn allows(&self, username: &str) -> bool {
        check_username(username).is_ok()
            && (self.min..=self.max).contains(&username.len())
            && (!self.first_letter || username.as_bytes()[0].is_ascii_alphabetic())
    }
}

/// A realm the host serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmConfig {
    /// The realm ([RLM-1]).
    pub realm: String,
    /// Its username policy.
    pub policy: UsernamePolicy,
}

/// The host's configuration.
pub struct HostConfig {
    /// The seed of the current host key ([HST-17]).
    pub key_seed: Zeroizing<[u8; 32]>,
    /// The public parts of retired host keys.
    pub retired_keys: Vec<[u8; 32]>,
    /// The host's addresses (base URLs); the first is preferred ([HST-18]).
    pub urls: Vec<String>,
    /// The realms it serves ([RLM-3]).
    pub realms: Vec<RealmConfig>,
    /// The host keys of its peers ([HST-15]).
    pub peers: Vec<[u8; 32]>,
}

impl HostConfig {
    /// The current host key.
    pub fn key(&self) -> [u8; 32] {
        ed25519_public(&self.key_seed)
    }

    /// Check the configuration before serving: at least one address, and every address a base URL of the HTTP binding
    /// ([HST-22], [`rootcard::check_base_url`]). → `bad_field`
    pub fn check(&self) -> Result<(), Error> {
        if self.urls.is_empty() {
            return Err(Error::BadField);
        }
        self.urls.iter().try_for_each(|u| rootcard::check_base_url(u))
    }

    /// Whether `key` is one of the host's keys, current or retired ([HST-17]).
    pub fn is_own_key(&self, key: &[u8; 32]) -> bool {
        *key == self.key() || self.retired_keys.contains(key)
    }

    fn realm(&self, realm: &str) -> Option<&RealmConfig> {
        self.realms.iter().find(|r| r.realm == realm)
    }

    fn options(&self, now: i64) -> VerifyOptions {
        VerifyOptions::new(self.realms.iter().map(|r| r.realm.clone())).at(now)
    }
}

/// A host error: a code of SPEC §20 and the extra members of HOST_PROTOCOL.md §1.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostError {
    /// The error code.
    pub error: Error,
    /// Extra members of the answer.
    pub extra: Map,
    /// A storage failure, answered as `500` (then `error` is meaningless).
    pub storage: Option<String>,
}

impl From<Error> for HostError {
    fn from(error: Error) -> Self {
        HostError {
            error,
            extra: Map::new(),
            storage: None,
        }
    }
}

impl From<StoreError> for HostError {
    fn from(e: StoreError) -> Self {
        HostError {
            error: Error::BadField,
            extra: Map::new(),
            storage: Some(e.0),
        }
    }
}

impl HostError {
    fn with(error: Error, extra: Map) -> Self {
        HostError {
            error,
            extra,
            storage: None,
        }
    }

    /// The HTTP status of HOST_PROTOCOL.md §1.1.
    pub fn status(&self) -> u16 {
        if self.storage.is_some() {
            return 500;
        }
        match self.error {
            Error::Unauthorized | Error::ChallengeUnknown | Error::ChallengeExpired => 401,
            Error::RealmNotAccepted => 403,
            Error::UnknownAccount => 404,
            Error::StaleVersion
            | Error::Fork
            | Error::HandleTaken
            | Error::AmbiguousHandle
            | Error::StaleRev
            | Error::StaleLocks
            | Error::NotHome => 409,
            Error::AccountRetired => 410,
            Error::TooLarge => 413,
            Error::RateLimited => 429,
            _ => 400,
        }
    }

    /// The JSON answer `{ "error": code, ... }`.
    pub fn to_value(&self) -> Value {
        let mut m = self.extra.clone();
        match &self.storage {
            Some(s) => {
                m.insert("error", "storage".into());
                m.insert("message", s.as_str().into());
            }
            None => {
                m.insert("error", self.error.code().into());
            }
        }
        m.into()
    }
}

/// The result of a handler.
pub type HostResult<T> = Result<T, HostError>;

fn version_answer(st: &LogState) -> Map {
    Map::new().with("version", st.version.to_value())
}

/// `stale_version` or `fork` with the host's version and the events from `from` ([VER-5], HOST_PROTOCOL.md §1.2).
fn behind(error: Error, stored: &Stored, from: usize) -> HostError {
    let events = stored
        .events
        .get(from.min(stored.events.len())..)
        .unwrap_or(&[])
        .to_vec();
    HostError::with(
        error,
        version_answer(&stored.state).with("events", Value::Array(events)),
    )
}

fn home_value(st: &LogState) -> Option<Value> {
    st.instance.as_ref().map(|i| i.home.to_value())
}

fn obj(v: &Value) -> HostResult<&Map> {
    Ok(v.as_object().ok_or(Error::BadField)?)
}

fn field<'a>(m: &'a Map, k: &str) -> HostResult<&'a Value> {
    Ok(m.get(k).ok_or(Error::BadField)?)
}

fn members(m: &Map, required: &[&str], optional: &[&str]) -> HostResult<()> {
    let ok =
        required.iter().all(|k| m.get(k).is_some()) && m.keys().all(|k| required.contains(&k) || optional.contains(&k));
    if ok { Ok(()) } else { Err(Error::BadField.into()) }
}

fn string<'a>(m: &'a Map, k: &str) -> HostResult<&'a str> {
    Ok(field(m, k)?.as_str().ok_or(Error::BadField)?)
}

fn bytes<const N: usize>(m: &Map, k: &str) -> HostResult<[u8; N]> {
    let v = base64url_decode(string(m, k)?).map_err(|_| Error::BadField)?;
    Ok(v.try_into().map_err(|_| Error::BadField)?)
}

fn events_of(m: &Map, k: &str) -> HostResult<Vec<Value>> {
    Ok(field(m, k)?.as_array().ok_or(Error::BadField)?.clone())
}

fn seq_of(e: &Value) -> HostResult<usize> {
    let s = obj(e)?.get("seq").and_then(Value::as_int).ok_or(Error::BadField)?;
    usize::try_from(s).map_err(|_| Error::BadField.into())
}

fn without_receipt(e: &Value) -> HostResult<Value> {
    let mut m = obj(e)?.clone();
    let mut sigs = m
        .get("sigs")
        .and_then(Value::as_array)
        .cloned()
        .ok_or(Error::BadField)?;
    sigs.truncate(2);
    m.insert("sigs", Value::Array(sigs));
    Ok(m.into())
}

fn receipt_of(e: &Value) -> Option<Value> {
    e.as_object()?
        .get("sigs")?
        .as_array()?
        .get(2)?
        .as_object()?
        .get("sig")
        .cloned()
}

/// A login result ([LGN-1] step 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResult {
    /// The account id.
    pub account: String,
    /// The handle.
    pub handle: String,
    /// The current instance hash.
    pub instance: [u8; 32],
    /// The version the login was made with.
    pub version: Version,
}

/// A host: its configuration and its storage.
pub struct Host<S, C, T> {
    /// The configuration.
    pub config: HostConfig,
    /// Identity storage.
    pub store: S,
    /// Challenge storage.
    pub challenges: C,
    /// Session storage (opaque tokens, [HST-10]).
    pub sessions: T,
}

impl<S: IdentityStore, C: ChallengeStore, T: SessionStore> Host<S, C, T> {
    /// A host over the given stores.
    pub fn new(config: HostConfig, store: S, challenges: C, sessions: T) -> Self {
        Host {
            config,
            store,
            challenges,
            sessions,
        }
    }

    /// The host descriptor (`GET /host`, [HST-17], [HST-18]).
    pub fn descriptor(&self) -> Value {
        let realms: Vec<Value> = self
            .config
            .realms
            .iter()
            .map(|r| {
                let policy = Map::new()
                    .with("min", r.policy.min as i64)
                    .with("max", r.policy.max as i64)
                    .with("first", if r.policy.first_letter { "letter" } else { "any" });
                Map::new()
                    .with("realm", r.realm.as_str())
                    .with("username_policy", policy)
                    .into()
            })
            .collect();
        let keys = |ks: &[[u8; 32]]| Value::Array(ks.iter().map(|k| format_key(KeyType::Ed25519, k).into()).collect());
        let mut m = Map::new()
            .with("v", 1i64)
            .with("key", format_key(KeyType::Ed25519, &self.config.key()))
            .with("urls", Value::Array(self.config.urls.iter().map(Value::from).collect()))
            .with("realms", Value::Array(realms));
        if !self.config.retired_keys.is_empty() {
            m.insert("retired_keys", keys(&self.config.retired_keys));
        }
        if !self.config.peers.is_empty() {
            m.insert("peers", keys(&self.config.peers));
        }
        m.into()
    }

    fn load(&self, account: &str) -> HostResult<Stored> {
        self.store.load(account)?.ok_or_else(|| Error::UnknownAccount.into())
    }

    /// This host is the primary host of `stored` ([HST-9]). → `account_retired`, `not_home`
    fn require_home(&self, stored: &Stored) -> HostResult<()> {
        if stored.state.retired {
            return Err(HostError::with(Error::AccountRetired, version_answer(&stored.state)));
        }
        match &stored.state.instance {
            Some(i) if self.config.is_own_key(&i.home.key) => Ok(()),
            _ => {
                let mut extra = Map::new();
                if let Some(h) = home_value(&stored.state) {
                    extra.insert("home", h);
                }
                Err(HostError::with(Error::NotHome, extra))
            }
        }
    }

    fn check_url(&self, url: &str) -> HostResult<()> {
        if self.config.urls.iter().any(|u| u == url) {
            Ok(())
        } else {
            Err(Error::WrongHost.into())
        }
    }

    fn take_challenge(&self, nonce: &[u8; 32], account: &str, purpose: Purpose, now: i64) -> HostResult<()> {
        let issued = self.challenges.take(nonce)?.ok_or(Error::ChallengeUnknown)?;
        if issued.account != account || issued.purpose != purpose {
            return Err(Error::ChallengeUnknown.into());
        }
        if now > issued.expires {
            return Err(Error::ChallengeExpired.into());
        }
        Ok(())
    }

    /// The receipt checks of [HST-6] for a pending instance, then the receipted event and the new state.
    fn receipt(&self, state: &LogState, pending: &Value, now: i64) -> HostResult<(Value, LogState)> {
        verify_pending(state, pending, now)?;
        let m = obj(pending)?;
        let body = obj(field(m, "body")?)?;
        let home = obj(field(body, "home")?)?;
        let key = parse_key(string(home, "key")?, KeyType::Ed25519)?;
        if key != self.config.key() || self.check_url(string(home, "url")?).is_err() {
            return Err(Error::WrongHost.into());
        }
        let time = field(m, "time")?.as_int().ok_or(Error::BadField)?;
        if time.abs_diff(now) > RECEIPT_WINDOW.unsigned_abs() {
            return Err(Error::BadTime.into());
        }
        if self.config.realm(&state.realm).is_none() {
            return Err(Error::RealmNotAccepted.into());
        }
        let mut e = m.clone();
        let sig = ed25519_sign(&self.config.key_seed, &receipt_message(&e));
        let mut sigs = e.get("sigs").and_then(Value::as_array).cloned().unwrap_or_default();
        sigs.push(
            Map::new()
                .with("key", format_key(KeyType::Ed25519, &self.config.key()))
                .with("sig", base64url_encode(&sig))
                .into(),
        );
        e.insert("sigs", Value::Array(sigs));
        let ev: Value = e.into();
        let st = extend_log(state, std::slice::from_ref(&ev), &self.config.options(now))?;
        Ok((ev, st))
    }

    /// `POST /id/register` ([HST-3]).
    pub fn register(&self, body: &Value, now: i64) -> HostResult<Value> {
        let m = obj(body)?;
        members(m, &["log", "vault"], &["public"])?;
        let log = events_of(m, "log")?;
        if log.len() != 2 {
            return Err(Error::BadField.into());
        }
        let inc_body = obj(field(obj(&log[0])?, "body")?)?;
        let realm = string(inc_body, "realm")?;
        let rc = self
            .config
            .realm(realm)
            .ok_or_else(|| HostError::with(Error::RealmNotAccepted, self.realms_extra()))?;
        let username = string(inc_body, "username")?;
        check_username(username)?;
        if !rc.policy.allows(username) {
            return Err(Error::UsernamePolicy.into());
        }
        let st0 = verify_log(&log[..1], &self.config.options(now))?;
        verify_pending(&st0, &log[1], now)?;
        if let Some(stored) = self.store.load(&st0.account)? {
            return self.registration_retry(&stored, &log);
        }
        let (ev, st) = self.receipt(&st0, &log[1], now)?;
        if self.store.handle_claimed(&HandleKey::of(&st))? {
            return Err(Error::HandleTaken.into());
        }
        let vault = field(m, "vault")?;
        let info = verify_vault(vault, &st)?;
        let public = match m.get("public") {
            Some(p) => {
                verify_public(p, &st)?;
                Some(p.clone())
            }
            None => None,
        };
        if info.slots.is_empty() {
            return Err(Error::BadLocks.into());
        }
        let stored = Stored {
            events: vec![log[0].clone(), ev.clone()],
            state: st.clone(),
            vault: Some(vault.clone()),
            public,
        };
        match self.store.insert(&stored, true)? {
            Insert::Done => Ok(self.registration_answer(&st, &ev)),
            Insert::HandleTaken => Err(Error::HandleTaken.into()),
            Insert::Exists => {
                let stored = self.load(&st.account)?;
                self.registration_retry(&stored, &log)
            }
        }
    }

    fn realms_extra(&self) -> Map {
        Map::new().with(
            "realms",
            Value::Array(
                self.config
                    .realms
                    .iter()
                    .map(|r| Value::from(r.realm.as_str()))
                    .collect(),
            ),
        )
    }

    fn registration_answer(&self, st: &LogState, ev: &Value) -> Value {
        let mut m = version_answer(st)
            .with("account", st.account.as_str())
            .with("handle", st.handle.as_str());
        if let Some(r) = receipt_of(ev) {
            m.insert("receipt", r);
        }
        m.into()
    }

    /// [HST-3], [HST-20]: a registration of an identity the host already stores is a retry if the stored log is
    /// exactly the submitted one.
    fn registration_retry(&self, stored: &Stored, log: &[Value]) -> HostResult<Value> {
        if stored.events.len() == 2
            && stored.events[0] == log[0]
            && without_receipt(&stored.events[1])? == without_receipt(&log[1])?
        {
            return Ok(self.registration_answer(&stored.state, &stored.events[1]));
        }
        Err(behind(Error::StaleVersion, stored, 0))
    }

    /// Combine the stored log with submitted events ([HST-14], HOST_PROTOCOL.md `POST /id/{account}/events`).
    /// Returns `None` when the submitted events add nothing (a retry), or the new events and state.
    /// With `allow_older`, a consistent submission that ends before the stored log is not an error.
    fn merge(
        &self,
        stored: &Stored,
        events: &[Value],
        now: i64,
        allow_older: bool,
    ) -> HostResult<Option<(Vec<Value>, LogState)>> {
        let Some(first) = events.first() else {
            return Ok(None);
        };
        let s = seq_of(first)?;
        let have = stored.events.len();
        if s > have {
            return Err(behind(Error::StaleVersion, stored, have));
        }
        if s > 0 {
            let prev = obj(first)?.get("prev").and_then(Value::as_str).ok_or(Error::BadField)?;
            if prev != base64url_encode(&event_hash(obj(&stored.events[s - 1])?)) {
                return Err(behind(Error::StaleVersion, stored, s - 1));
            }
        }
        // The overlap must be identical; a difference is a fork.
        for (k, e) in events.iter().enumerate() {
            let i = s + k;
            if i >= have {
                let new = &events[k..];
                let st = extend_log(&stored.state, new, &self.config.options(now))?;
                let mut all = stored.events.clone();
                all.extend_from_slice(new);
                return Ok(Some((all, st)));
            }
            if canonical(e) != canonical(&stored.events[i]) {
                // Only a valid diverging log is a fork: the submitted events are verified on top of the stored prefix
                // they extend, so that garbage gets its own code ([VER-3]).
                let candidate: Vec<Value> = stored.events[..s].iter().chain(events).cloned().collect();
                verify_log(&candidate, &self.config.options(now))?;
                return Err(behind(Error::Fork, stored, i));
            }
        }
        if s + events.len() == have || allow_older {
            Ok(None)
        } else {
            Err(behind(Error::StaleVersion, stored, s + events.len()))
        }
    }

    /// What the host keeps when it adopts a new log ([HST-7], [HST-8], [DAT-3]).
    fn adopt(&self, old: &Stored, events: Vec<Value>, state: LogState) -> Stored {
        let same_instance = old.state.instance.as_ref().map(|i| i.hash) == state.instance.as_ref().map(|i| i.hash);
        let home = state
            .instance
            .as_ref()
            .is_some_and(|i| self.config.is_own_key(&i.home.key));
        Stored {
            events,
            vault: if state.retired || !same_instance || !home {
                None
            } else {
                old.vault.clone()
            },
            public: if state.retired || !same_instance {
                None
            } else {
                old.public.clone()
            },
            state,
        }
    }

    fn swap(&self, old: &Stored, new: &Stored) -> HostResult<()> {
        if self.store.swap(&old.state.account, &old.expected(), new)? {
            Ok(())
        } else {
            let cur = self.load(&old.state.account)?;
            Err(behind(Error::StaleVersion, &cur, old.events.len()))
        }
    }

    /// `POST /id/{account}/events` ([VER-5], [HST-14]).
    pub fn events(&self, account: &str, body: &Value, now: i64) -> HostResult<Value> {
        let m = obj(body)?;
        members(m, &["events"], &["vault"])?;
        let events = events_of(m, "events")?;
        let vault = m.get("vault");
        let Some(stored) = self.store.load(account)? else {
            let st = verify_log(&events, &self.config.options(now))?;
            if st.account != account {
                return Err(Error::AccountMismatch.into());
            }
            if vault.is_some() {
                return Err(Error::Unauthorized.into());
            }
            let new = Stored {
                events,
                state: st.clone(),
                vault: None,
                public: None,
            };
            if self.store.insert(&new, false)? == Insert::Exists {
                return self.events(account, body, now);
            }
            return Ok(version_answer(&st).into());
        };
        let rotated = events
            .iter()
            .any(|e| e.as_object().and_then(|m| m.get("kind")).and_then(Value::as_str) == Some("rotate_recovery"));
        let Some((all, st)) = self.merge(&stored, &events, now, false)? else {
            // The events are already stored (a retry, or the rotation arrived first from someone else). A vault sent
            // with them is still the owner's new grant for the rotated key: store it, or confirm a retry ([HST-12]
            // case 3, [HST-20]), but never answer success without it.
            if let Some(v) = vault
                && stored.vault.as_ref() != Some(v)
            {
                self.require_home(&stored)?;
                if !rotated {
                    return Err(Error::Unauthorized.into());
                }
                return self
                    .replace_vault(&stored, v, &|c| matches!(c, VaultChange::Grant))
                    .map(|_| version_answer(&stored.state).into());
            }
            return Ok(version_answer(&stored.state).into());
        };
        let mut new = self.adopt(&stored, all, st);
        if let Some(v) = vault {
            self.require_home(&new)?;
            let old = stored.vault.as_ref().ok_or(Error::Unauthorized)?;
            if !rotated {
                return Err(Error::Unauthorized.into());
            }
            verify_vault(v, &new.state)?;
            if vault_change(old, v)? != VaultChange::Grant {
                return Err(Error::Unauthorized.into());
            }
            new.vault = Some(v.clone());
        }
        self.swap(&stored, &new)?;
        Ok(version_answer(&new.state).into())
    }

    /// `POST /id/{account}/instance` ([HST-5], [HST-6]).
    pub fn instance(&self, account: &str, body: &Value, now: i64) -> HostResult<Value> {
        let m = obj(body)?;
        members(m, &["instance", "vault"], &["events", "public"])?;
        let pending = field(m, "instance")?;
        let events = match m.get("events") {
            Some(_) => events_of(m, "events")?,
            None => Vec::new(),
        };
        let known = self.store.load(account)?;
        // The log the instance builds on: the stored log extended with the submitted events, or the submitted log.
        let base = match &known {
            Some(stored) => match self.merge(stored, &events, now, true)? {
                Some((all, st)) => Stored {
                    events: all,
                    state: st,
                    vault: None,
                    public: None,
                },
                None => stored.clone(),
            },
            None => {
                let st = verify_log(&events, &self.config.options(now))?;
                if st.account != account {
                    return Err(Error::AccountMismatch.into());
                }
                Stored {
                    events: events.clone(),
                    state: st,
                    vault: None,
                    public: None,
                }
            }
        };
        let s = seq_of(pending)?;
        let next = base.state.version.seq as usize + 1;
        if s < next {
            // A resubmission of an instance this host receipted is a retry ([HST-20]).
            if let Some(e) = base.events.get(s)
                && receipt_of(e).is_some()
                && without_receipt(e)? == without_receipt(pending)?
            {
                let st = verify_log(&base.events[..=s], &self.config.options(now))?;
                return Ok(version_answer(&st)
                    .with("receipt", receipt_of(e).unwrap_or(Value::Bool(false)))
                    .into());
            }
            return Err(behind(Error::Fork, &base, s));
        }
        if s > next {
            return Err(behind(Error::StaleVersion, &base, base.events.len()));
        }
        let (ev, st) = self.receipt(&base.state, pending, now)?;
        let vault = field(m, "vault")?;
        verify_vault(vault, &st)?;
        let public = match m.get("public") {
            Some(p) => {
                verify_public(p, &st)?;
                Some(p.clone())
            }
            None => None,
        };
        let mut all = base.events.clone();
        all.push(ev.clone());
        let new = Stored {
            events: all,
            state: st.clone(),
            vault: Some(vault.clone()),
            public,
        };
        match &known {
            Some(stored) => self.swap(stored, &new)?,
            None => {
                if self.store.insert(&new, false)? == Insert::Exists {
                    return self.instance(account, body, now);
                }
            }
        }
        Ok(version_answer(&st)
            .with("receipt", receipt_of(&ev).unwrap_or(Value::Bool(false)))
            .into())
    }

    /// `GET /id/lookup` ([HDL-3], [HDL-7]).
    pub fn lookup(&self, realm: Option<&str>, text: &str) -> HostResult<Value> {
        let realm = match realm {
            Some(r) => r.to_string(),
            None if self.config.realms.len() == 1 => self.config.realms[0].realm.clone(),
            None => return Err(HostError::with(Error::RealmNotAccepted, self.realms_extra())),
        };
        if self.config.realm(&realm).is_none() {
            return Err(HostError::with(Error::RealmNotAccepted, self.realms_extra()));
        }
        let h = parse_handle(text)?;
        let key = HandleKey {
            realm,
            username: h.username.to_ascii_lowercase(),
            tag: h.tag.clone(),
        };
        let all = self.store.by_handle(&key)?;
        let found: Vec<Stored> = all
            .iter()
            .filter_map(|a| self.store.load(a).ok().flatten())
            .filter(|s| h.matches(&s.state.username, &s.state.account))
            .collect();
        match found.as_slice() {
            [] => Err(Error::UnknownAccount.into()),
            [s] => {
                let mut m = version_answer(&s.state)
                    .with("account", s.state.account.as_str())
                    .with("handle", s.state.handle.as_str())
                    .with("retired", s.state.retired);
                if let Some(home) = home_value(&s.state) {
                    m.insert("home", home);
                }
                Ok(m.into())
            }
            many => {
                let ids: Vec<String> = all.clone();
                let tags = extended_tags(&ids);
                let candidates: Vec<Value> = many
                    .iter()
                    .map(|s| {
                        let t = ids
                            .iter()
                            .position(|i| *i == s.state.account)
                            .and_then(|p| tags.get(p))
                            .cloned()
                            .unwrap_or_default();
                        Map::new()
                            .with("account", s.state.account.as_str())
                            .with("handle", format!("{}#{t}", s.state.username))
                            .into()
                    })
                    .collect();
                Err(HostError::with(
                    Error::AmbiguousHandle,
                    Map::new().with("candidates", Value::Array(candidates)),
                ))
            }
        }
    }

    /// `GET /id/{account}/log?from=` (HOST_PROTOCOL.md §2).
    pub fn log(&self, account: &str, from: usize) -> HostResult<Value> {
        let s = self.load(account)?;
        let events = s.events.get(from.min(s.events.len())..).unwrap_or(&[]).to_vec();
        Ok(version_answer(&s.state).with("events", Value::Array(events)).into())
    }

    /// `GET /id/{account}/public`.
    pub fn public(&self, account: &str) -> HostResult<Value> {
        self.load(account)?.public.ok_or_else(|| Error::UnknownAccount.into())
    }

    /// `GET /id/{account}/locks`: the lock hints ([FET-2]).
    pub fn locks(&self, account: &str) -> HostResult<Value> {
        let s = self.load(account)?;
        self.require_home(&s)?;
        let vault = s.vault.as_ref().ok_or(Error::BadLocks)?;
        let info = verify_vault(vault, &s.state)?;
        let instance = s
            .state
            .instance
            .as_ref()
            .map(|i| base64url_encode(&i.hash))
            .unwrap_or_default();
        Ok(Map::new().with("instance", instance).with("locks", info.hints()).into())
    }

    /// `POST /id/{account}/challenge` ([CHL-1]). `nonce` is 32 random bytes.
    pub fn challenge(&self, account: &str, purpose: Purpose, now: i64, nonce: [u8; 32]) -> HostResult<Value> {
        let s = self.load(account)?;
        self.require_home(&s)?;
        let inst = s.state.instance.as_ref().ok_or(Error::NoInstance)?;
        let expires = now + rootcard::messages::CHALLENGE_LIFETIME;
        self.challenges.put(
            nonce,
            Issued {
                account: account.to_string(),
                purpose,
                expires,
            },
        )?;
        let ch = Challenge {
            nonce,
            host: inst.home.key,
            realm: s.state.realm.clone(),
            version: s.state.version,
            expires,
        };
        Ok(ch.to_value())
    }

    fn lock_key(&self, s: &Stored, lock: &str) -> HostResult<[u8; 32]> {
        if lock == "recovery" {
            return Ok(s.state.recovery);
        }
        let vault = s.vault.as_ref().ok_or(Error::BadLocks)?;
        let info = verify_vault(vault, &s.state)?;
        Ok(info.password_lock(lock).ok_or(Error::BadLocks)?.auth)
    }

    /// `POST /id/{account}/fetch` ([FET-1]).
    pub fn fetch(&self, account: &str, body: &Value, now: i64) -> HostResult<Value> {
        let m = obj(body)?;
        members(m, &["lock", "nonce", "url", "sig"], &[])?;
        let lock = string(m, "lock")?;
        let nonce = bytes::<32>(m, "nonce")?;
        let url = string(m, "url")?;
        let sig = bytes::<64>(m, "sig")?;
        let s = self.load(account)?;
        self.require_home(&s)?;
        self.check_url(url)?;
        self.take_challenge(&nonce, account, Purpose::Fetch, now)?;
        let key = self.lock_key(&s, lock)?;
        let home = s.state.instance.as_ref().ok_or(Error::NoInstance)?.home.key;
        ed25519_verify(&key, &fetch_message(account, &home, lock, &nonce, url), &sig)?;
        let vault = s.vault.ok_or(Error::BadLocks)?;
        Ok(Map::new().with("vault", vault).into())
    }

    /// `POST /id/{account}/login` ([LGN-1] step 6). `token` is 32 random bytes for the session ([HST-10]).
    pub fn login(&self, account: &str, body: &Value, now: i64, token: [u8; 32]) -> HostResult<Value> {
        let mut m = obj(body)?.clone();
        m.insert("account", account.into());
        let req = LoginRequest::from_value(&m.into())?;
        let result = self.login_result(&req, now)?;
        let hash = sha256(&token);
        self.sessions.put(
            hash,
            Session {
                account: result.account.clone(),
                instance: result.instance,
                last_used: now,
            },
        )?;
        Ok(Map::new()
            .with("token", base64url_encode(&token))
            .with("handle", result.handle.as_str())
            .with("instance", base64url_encode(&result.instance))
            .with("idle_timeout", SESSION_IDLE)
            .into())
    }

    /// The checks of [LGN-1] step 6, for an application that issues its own sessions.
    pub fn login_result(&self, req: &LoginRequest, now: i64) -> HostResult<LoginResult> {
        let s = self.load(&req.account)?;
        self.require_home(&s)?;
        self.check_url(&req.url)?;
        self.take_challenge(&req.nonce, &req.account, Purpose::Login, now)?;
        if req.version != s.state.version {
            return Err(behind(Error::StaleVersion, &s, req.version.seq as usize + 1));
        }
        let key = self.lock_key(&s, &req.lock)?;
        let inst = s.state.instance.as_ref().ok_or(Error::NoInstance)?;
        req.verify(&s.state.realm, &inst.home.key, &inst.account_key, &key)?;
        Ok(LoginResult {
            account: s.state.account.clone(),
            handle: handle(&s.state.username, &s.state.account),
            instance: inst.hash,
            version: s.state.version,
        })
    }

    /// Whether a session is still valid ([HST-11]): its instance is current, the log not retired, and it was used in
    /// the last 24 h. An application with its own sessions calls this on every use.
    pub fn session_valid(&self, session: &Session, now: i64) -> HostResult<bool> {
        let Some(s) = self.store.load(&session.account)? else {
            return Ok(false);
        };
        let current = s.state.instance.as_ref().map(|i| i.hash);
        Ok(!s.state.retired && current == Some(session.instance) && now - session.last_used <= SESSION_IDLE)
    }

    /// The session of a bearer token, checked ([HST-10], [HST-11]). → `unauthorized`
    pub fn session(&self, token: &str, now: i64) -> HostResult<(Session, Stored)> {
        let raw = base64url_decode(token).map_err(|_| Error::Unauthorized)?;
        if raw.len() != 32 {
            return Err(Error::Unauthorized.into());
        }
        let hash = sha256(&raw);
        let session = self.sessions.get(&hash)?.ok_or(Error::Unauthorized)?;
        if !self.session_valid(&session, now)? {
            self.sessions.remove(&hash)?;
            return Err(Error::Unauthorized.into());
        }
        self.sessions.touch(&hash, now)?;
        let s = self.load(&session.account)?;
        self.require_home(&s)
            .map_err(|_| HostError::from(Error::Unauthorized))?;
        Ok((session, s))
    }

    /// `POST /session/logout`.
    pub fn logout(&self, token: &str) -> HostResult<()> {
        let raw = base64url_decode(token).map_err(|_| Error::Unauthorized)?;
        self.sessions.remove(&sha256(&raw))?;
        Ok(())
    }

    /// `GET /session/vault`.
    pub fn session_vault(&self, token: &str, now: i64) -> HostResult<Value> {
        let (_, s) = self.session(token, now)?;
        Ok(Map::new().with("vault", s.vault.ok_or(Error::BadLocks)?).into())
    }

    fn replace_vault(&self, s: &Stored, vault: &Value, allow: &dyn Fn(&VaultChange) -> bool) -> HostResult<Value> {
        let info = verify_vault(vault, &s.state)?;
        let old = s.vault.as_ref().ok_or(Error::BadLocks)?;
        let change = vault_change(old, vault).map_err(|e| {
            let extra = Map::new().with("rev", s.vault_rev().unwrap_or(0)).with(
                "gen",
                old.as_object()
                    .and_then(|o| {
                        o.get("locks")?
                            .as_object()?
                            .get("grant")?
                            .as_object()?
                            .get("gen")
                            .cloned()
                    })
                    .unwrap_or(Value::Int(0)),
            );
            HostError::with(e, extra)
        })?;
        if !allow(&change) {
            return Err(Error::Unauthorized.into());
        }
        let mut new = s.clone();
        new.vault = Some(vault.clone());
        self.swap(s, &new)?;
        Ok(Map::new().with("rev", info.rev).into())
    }

    /// `PUT /session/vault`: a data update, or a new grant ([HST-12] cases 1 and 3).
    pub fn session_put_vault(&self, token: &str, body: &Value, now: i64) -> HostResult<Value> {
        let (_, s) = self.session(token, now)?;
        let m = obj(body)?;
        members(m, &["vault"], &[])?;
        self.replace_vault(&s, field(m, "vault")?, &|c| {
            matches!(c, VaultChange::Data | VaultChange::Grant)
        })
    }

    /// `PUT /id/{account}/vault`: a vault replacement authorized by a new grant ([HST-12] case 3).
    pub fn put_vault(&self, account: &str, body: &Value) -> HostResult<Value> {
        let s = self.load(account)?;
        self.require_home(&s)?;
        let m = obj(body)?;
        members(m, &["vault"], &[])?;
        self.replace_vault(&s, field(m, "vault")?, &|c| matches!(c, VaultChange::Grant))
    }

    /// `POST /session/password` ([CHG-2]).
    pub fn session_password(&self, token: &str, body: &Value, now: i64) -> HostResult<Value> {
        let (session, s) = self.session(token, now)?;
        let m = obj(body)?;
        members(m, &["lock", "nonce", "url", "proof", "vault"], &[])?;
        let lock = string(m, "lock")?;
        let nonce = bytes::<32>(m, "nonce")?;
        let url = string(m, "url")?;
        let proof = bytes::<64>(m, "proof")?;
        let vault = field(m, "vault")?;
        self.check_url(url)?;
        self.take_challenge(&nonce, &session.account, Purpose::Change, now)?;
        let old = s.vault.as_ref().ok_or(Error::BadLocks)?;
        let old_info = verify_vault(old, &s.state)?;
        let auth = old_info.password_lock(lock).ok_or(Error::BadLocks)?.auth;
        let new_lock = vault
            .as_object()
            .and_then(|v| v.get("locks")?.as_object()?.get("list")?.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .find(|l| l.as_object().and_then(|o| o.get("id")).and_then(Value::as_str) == Some(lock))
            .ok_or(Error::BadLocks)?;
        let new_hash = sha256(&canonical(&new_lock));
        let home = s.state.instance.as_ref().ok_or(Error::NoInstance)?.home.key;
        ed25519_verify(
            &auth,
            &change_message(&session.account, &home, lock, &new_hash, &nonce, url),
            &proof,
        )?;
        let slot = lock.to_string();
        self.replace_vault(
            &s,
            vault,
            &|c| matches!(c, VaultChange::Password { slot: sl, new_hash: h } if *sl == slot && *h == new_hash),
        )
        .map_err(|e| {
            if e.error == Error::Unauthorized {
                Error::StaleLocks.into()
            } else {
                e
            }
        })
    }

    /// `PUT /session/public` ([DAT-2], [DAT-3]).
    pub fn session_put_public(&self, token: &str, body: &Value, now: i64) -> HostResult<Value> {
        let (_, s) = self.session(token, now)?;
        let m = obj(body)?;
        members(m, &["public"], &[])?;
        self.adopt_public(&s, field(m, "public")?)
    }

    fn adopt_public(&self, s: &Stored, p: &Value) -> HostResult<Value> {
        let info = verify_public(p, &s.state)?;
        if s.public_rev().is_some_and(|r| info.rev <= r) {
            return Err(HostError::with(
                Error::StaleRev,
                Map::new().with("rev", s.public_rev().unwrap_or(0)),
            ));
        }
        let mut new = s.clone();
        new.public = Some(p.clone());
        self.swap(s, &new)?;
        Ok(Map::new().with("rev", info.rev).into())
    }

    /// `GET /session/export`: the account file ([FIL-2]).
    pub fn session_export(&self, token: &str, now: i64) -> HostResult<(String, Value)> {
        let (_, s) = self.session(token, now)?;
        let file = rootcard::file::export_account(&s.state, &s.events, s.public.as_ref(), s.vault.as_ref(), None);
        Ok((rootcard::file::account_file_name(&s.state), file))
    }

    /// `POST /peer/push` ([HST-15]): events and a profile, verified like data from anyone ([HST-14]).
    pub fn peer_push(&self, body: &Value, now: i64) -> HostResult<Value> {
        let m = obj(body)?;
        members(m, &["account"], &["events", "public"])?;
        let account = string(m, "account")?;
        if let Some(e) = m.get("events") {
            let b = Map::new().with("events", e.clone());
            match self.events(account, &b.into(), now) {
                Ok(_) => {}
                Err(e) if e.error == Error::StaleVersion && m.get("public").is_some() => {}
                Err(e) => return Err(e),
            }
        }
        let s = self.load(account)?;
        if let Some(p) = m.get("public") {
            match self.adopt_public(&s, p) {
                Ok(_) => {}
                Err(e) if e.error == Error::StaleRev => {}
                Err(e) => return Err(e),
            }
        }
        Ok(version_answer(&self.load(account)?.state).into())
    }

    /// `GET /peer/changes` ([HST-15]): accounts changed after `since`.
    pub fn peer_changes(&self, since: u64) -> HostResult<Value> {
        let (cursor, accounts) = self.store.changes(since, 500)?;
        let mut changes = Vec::new();
        for a in accounts {
            if let Some(s) = self.store.load(&a)? {
                let mut c = version_answer(&s.state).with("account", a.as_str());
                if let Some(r) = s.public_rev() {
                    c.insert("public_rev", r.into());
                }
                changes.push(c.into());
            }
        }
        Ok(Map::new()
            .with("cursor", cursor.to_string())
            .with("changes", Value::Array(changes))
            .into())
    }
}
