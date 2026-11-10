//! Helpers shared by the host's integration tests: two in-memory hosts, the router, a client that logs in with a
//! password, and registration.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use rootcard::account::{Registration, register};
use rootcard::crypto::ed25519_sign;
use rootcard::encoding::{base64url_decode, base64url_encode};
use rootcard::json::{Map, Value, canonical, parse_json};
use rootcard::keys::{KeyType, parse_key};
use rootcard::log::{Home, LogState, VerifyOptions, verify_log};
use rootcard::messages::{Challenge, LoginRequest, fetch_message};
use rootcard::testing::TestRandom;
use rootcard::vault::{Kdf, Secret, derive_lock_secrets, unlock_vault};
use rootcard_host::http::{API_VERSION, Request, route};
use rootcard_host::store::{MemoryChallengeStore, MemoryIdentityStore, MemorySessionStore};
use rootcard_host::{Host, HostConfig, RealmConfig, UsernamePolicy};
use std::cell::RefCell;
use zeroize::Zeroizing;

pub type TestHost = Host<MemoryIdentityStore, MemoryChallengeStore, MemorySessionStore>;

pub const T0: i64 = 1_800_000_000;
pub const PW: &str = "correct horse battery staple";
pub const PW2: &str = "a new and better passphrase";

pub fn config(seed: [u8; 32], url: &str) -> HostConfig {
    HostConfig {
        key_seed: Zeroizing::new(seed),
        retired_keys: Vec::new(),
        urls: vec![url.to_string()],
        realms: vec![RealmConfig {
            realm: "global".into(),
            policy: UsernamePolicy::DEFAULT,
        }],
        peers: Vec::new(),
    }
}

pub fn host(seed: [u8; 32], url: &str) -> TestHost {
    Host::new(
        config(seed, url),
        MemoryIdentityStore::new(),
        MemoryChallengeStore::new(),
        MemorySessionStore::new(),
    )
}

thread_local! {
    static RNG: RefCell<TestRandom> = RefCell::new(TestRandom::new(b"e2e"));
}

pub fn fill(b: &mut [u8]) {
    RNG.with(|r| r.borrow_mut().fill(b));
}

/// Call an endpoint; `path` is relative to the API root `<base URL>/v0` (HOST_PROTOCOL.md §1.3).
pub fn call(
    h: &TestHost,
    method: &str,
    path: &str,
    body: Option<Value>,
    bearer: Option<&str>,
    now: i64,
) -> (u16, Value) {
    call_raw(h, method, &format!("/{API_VERSION}{path}"), body, bearer, now)
}

/// Call a path relative to the base URL, without adding the API version.
pub fn call_raw(
    h: &TestHost,
    method: &str,
    path: &str,
    body: Option<Value>,
    bearer: Option<&str>,
    now: i64,
) -> (u16, Value) {
    let req = Request {
        method: method.into(),
        path: path.into(),
        bearer: bearer.map(str::to_string),
        peer: None,
        body: body.map(|b| canonical(&b)).unwrap_or_default(),
    };
    let r = route(h, &req, now, &mut fill);
    let v = r.body.map(|b| parse_json(&b).unwrap()).unwrap_or(Value::Bool(true));
    (r.status, v)
}

pub fn get<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.as_object()
        .unwrap()
        .get(k)
        .unwrap_or_else(|| panic!("no {k} in {v:?}"))
}

pub fn err(v: &Value) -> &str {
    get(v, "error").as_str().unwrap()
}

pub fn obj(pairs: &[(&str, Value)]) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(*k, v.clone());
    }
    m.into()
}

pub fn opts() -> VerifyOptions {
    VerifyOptions::new(["global"])
}

pub fn fetch_log(h: &TestHost, account: &str) -> (Vec<Value>, LogState) {
    let (s, v) = call(h, "GET", &format!("/id/{account}/log"), None, None, T0);
    assert_eq!(s, 200);
    let events = get(&v, "events").as_array().unwrap().clone();
    let st = verify_log(&events, &opts()).unwrap();
    (events, st)
}

/// A password login ([LGN-1]): lock hints, fetch with the lock's auth key, unlock, login. Returns the token.
pub fn login(h: &TestHost, account: &str, url: &str, password: &str, now: i64) -> Result<String, (u16, String)> {
    let (_, st) = fetch_log(h, account);
    let (s, hints) = call(h, "GET", &format!("/id/{account}/locks"), None, None, now);
    if s != 200 {
        return Err((s, err(&hints).to_string()));
    }
    let hint = &get(&hints, "locks").as_array().unwrap()[0];
    let lock = get(hint, "id").as_str().unwrap().to_string();
    let kdf = get(hint, "kdf");
    let salt: [u8; 16] = base64url_decode(get(kdf, "salt").as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let k = Kdf {
        m: get(kdf, "m").as_int().unwrap() as u32,
        t: get(kdf, "t").as_int().unwrap() as u32,
        p: 1,
    };
    let secrets = derive_lock_secrets(account, &lock, password, &k, &salt).unwrap();
    let (_, ch) = call(
        h,
        "POST",
        &format!("/id/{account}/challenge"),
        Some(obj(&[("purpose", "fetch".into())])),
        None,
        now,
    );
    let ch = Challenge::from_value(&ch).unwrap();
    let sig = ed25519_sign(
        &secrets.auth_seed,
        &fetch_message(account, &ch.host, &lock, &ch.nonce, url),
    );
    let body = obj(&[
        ("lock", lock.as_str().into()),
        ("nonce", base64url_encode(&ch.nonce).into()),
        ("url", url.into()),
        ("sig", base64url_encode(&sig).into()),
    ]);
    let (s, v) = call(h, "POST", &format!("/id/{account}/fetch"), Some(body), None, now);
    if s != 200 {
        return Err((s, err(&v).to_string()));
    }
    let vault = get(&v, "vault").clone();
    let u = unlock_vault(&vault, &st, &Secret::Password { lock: &lock, password })
        .map_err(|e| (0, e.code().to_string()))?;
    let (_, ch) = call(
        h,
        "POST",
        &format!("/id/{account}/challenge"),
        Some(obj(&[("purpose", "login".into())])),
        None,
        now,
    );
    let ch = Challenge::from_value(&ch).unwrap();
    let inst = st.instance.clone().unwrap();
    let req = LoginRequest::sign(
        account,
        "global",
        &inst.home.key,
        &st.version,
        &ch,
        url,
        &lock,
        &u.contents.account_seed,
        &u.lock_seed,
    )
    .unwrap();
    let mut body = req.to_value().as_object().unwrap().clone();
    body.remove("account");
    let (s, v) = call(h, "POST", &format!("/id/{account}/login"), Some(body.into()), None, now);
    if s != 200 {
        return Err((s, err(&v).to_string()));
    }
    Ok(get(&v, "token").as_str().unwrap().to_string())
}

/// The `home` of a host, from its descriptor.
pub fn home_of(h: &TestHost, url: &str) -> Home {
    let (_, desc) = call(h, "GET", "/host", None, None, T0);
    Home {
        key: parse_key(get(&desc, "key").as_str().unwrap(), KeyType::Ed25519).unwrap(),
        url: url.into(),
    }
}

/// Register `username` at `h` (reachable at `url`) with password [`PW`] and the recovery key drawn from `rng`. Returns
/// the registration and the recovery key.
pub fn register_at(h: &TestHost, url: &str, username: &str, rng: &mut TestRandom) -> (Registration, [u8; 32]) {
    let rk = rng.bytes::<32>();
    let mut random = |x: &mut [u8]| rng.fill(x);
    let reg = register(
        &rk,
        "global",
        username,
        PW,
        "Laptop",
        &home_of(h, url),
        T0,
        Kdf::MIN,
        &mut random,
    )
    .unwrap();
    let body = obj(&[
        ("log", Value::Array(reg.log.clone())),
        ("vault", reg.vault.clone()),
        ("public", reg.public.clone()),
    ]);
    let (s, v) = call(h, "POST", "/id/register", Some(body), None, T0);
    assert_eq!(s, 201, "{v:?}");
    (reg, rk)
}

/// A valid but non-canonical serialization of `v` ([CJ-7] tests): members in reverse order, insignificant whitespace,
/// and `A` and `/` written as escapes. It parses to the same value as `canonical(v)`.
pub fn loose(v: &Value) -> Vec<u8> {
    fn string(s: &str, out: &mut String) {
        out.push('"');
        for c in s.chars() {
            match c {
                'A' => out.push_str("\\u0041"),
                '/' => out.push_str("\\/"),
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    fn value(v: &Value, out: &mut String) {
        match v {
            Value::Object(m) => {
                out.push_str("{ ");
                let members: Vec<_> = m.iter().collect();
                for (i, (k, x)) in members.iter().rev().enumerate() {
                    if i > 0 {
                        out.push_str(",\n  ");
                    }
                    string(k, out);
                    out.push_str(" : ");
                    value(x, out);
                }
                out.push_str(" }");
            }
            Value::Array(a) => {
                out.push_str("[ ");
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push_str(" , ");
                    }
                    value(x, out);
                }
                out.push_str(" ]");
            }
            Value::String(s) => string(s, out),
            Value::Int(n) => out.push_str(&n.to_string()),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        }
    }
    let mut out = String::from("\n");
    value(v, &mut out);
    out.push('\n');
    out.into_bytes()
}
