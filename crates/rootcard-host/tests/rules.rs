//! Host rules about bytes and about what leaves the host, through the HTTP router: verification over canonical bytes
//! ([CJ-7]), canonical output ([CJ-10]), and vaults that never leave the primary host ([HST-13]).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;
use common::*;

use rootcard::crypto::{ed25519_public, sha256};
use rootcard::encoding::base64url_encode;
use rootcard::json::{Value, canonical, parse_json};
use rootcard::log::event_hash;
use rootcard::testing::TestRandom;
use rootcard_host::Host;
use rootcard_host::http::{API_VERSION, Request, Response, route};
use rootcard_host::peer::sign_peer_request;
use rootcard_host::store::{MemoryChallengeStore, MemoryIdentityStore, MemorySessionStore};

const A: &str = "https://a.example";

fn send(h: &TestHost, method: &str, path: &str, body: Vec<u8>) -> Response {
    let req = Request {
        method: method.into(),
        path: format!("/{API_VERSION}{path}"),
        body,
        ..Request::default()
    };
    route(h, &req, T0, &mut fill)
}

/// [CJ-10] the body is exactly the canonical bytes of what it holds.
fn assert_canonical(r: &Response) -> Value {
    let body = r.body.clone().unwrap();
    let v = parse_json(&body).unwrap();
    assert_eq!(canonical(&v), body, "a host answer is not canonical");
    v
}

#[test]
fn verification_is_over_canonical_bytes_and_answers_are_canonical() {
    let a = host([0xa1; 32], A);
    let mut rng = TestRandom::new(b"rules-cj");
    let rk = rng.bytes::<32>();
    let mut random = |x: &mut [u8]| rng.fill(x);
    let reg = rootcard::account::register(
        &rk,
        "global",
        "Astra",
        PW,
        "Laptop",
        &home_of(&a, A),
        T0,
        rootcard::vault::Kdf::MIN,
        &mut random,
    )
    .unwrap();
    let body = obj(&[
        ("log", Value::Array(reg.log.clone())),
        ("vault", reg.vault.clone()),
        ("public", reg.public.clone()),
    ]);

    // [CJ-7] a registration sent in another serialization of the same values is accepted: the host hashes and verifies
    // the parsed values, not the bytes it received.
    let text = loose(&body);
    assert_ne!(text, canonical(&body));
    assert_ne!(sha256(&text), sha256(&canonical(&body)));
    let r = send(&a, "POST", "/id/register", text);
    assert_eq!(r.status, 201);
    let answer = assert_canonical(&r);
    let account = get(&answer, "account").as_str().unwrap().to_string();
    assert_eq!(account, reg.account);
    // The version the host answers is the hash of the canonical instance event (with its receipt), not of any bytes
    // the client sent.
    let (events, state) = fetch_log(&a, &account);
    assert_eq!(event_hash(events[1].as_object().unwrap()), state.version.hash);
    assert_eq!(
        get(get(&answer, "version"), "hash").as_str().unwrap(),
        base64url_encode(&state.version.hash)
    );

    // [CJ-10] every answer that carries a structure is canonical, and so are the stored events it returns.
    for path in [
        "/host".to_string(),
        format!("/id/{account}/log"),
        format!("/id/{account}/public"),
        format!("/id/{account}/locks"),
        format!(
            "/id/lookup?realm=global&handle={}",
            get(&answer, "handle").as_str().unwrap().replace('#', "%23")
        ),
    ] {
        let r = send(&a, "GET", &path, Vec::new());
        assert_eq!(r.status, 200, "{path}");
        assert_canonical(&r);
    }
    // An error answer too.
    let r = send(&a, "POST", "/id/register", b"{\"log\":[]}".to_vec());
    assert_eq!(r.status, 400);
    assert_canonical(&r);
}

#[test]
fn vaults_never_leave_the_primary_host() {
    let (sa, sb) = ([0xa1u8; 32], [0xb2u8; 32]);
    let mut cfg = config(sa, A);
    cfg.peers = vec![ed25519_public(&sb)];
    let a = Host::new(
        cfg,
        MemoryIdentityStore::new(),
        MemoryChallengeStore::new(),
        MemorySessionStore::new(),
    );
    let mut rng = TestRandom::new(b"rules-hst13");
    let (reg, _) = register_at(&a, A, "Astra", &mut rng);
    let account = reg.account.clone();
    let ct = get(&reg.vault, "ct").as_str().unwrap().to_string();
    let pa = ed25519_public(&sa);
    let peer = |method: &str, path: &str, body: Vec<u8>| {
        let full = format!("/{API_VERSION}{path}");
        let req = Request {
            method: method.into(),
            path: full.clone(),
            peer: Some(sign_peer_request(&sb, method, &full, T0, &pa, &body)),
            body,
            ..Request::default()
        };
        route(&a, &req, T0, &mut fill)
    };

    // [HST-13] what a peer reads (the change list, then the log and the profile) holds no vault.
    let changes = peer("GET", "/peer/changes?since=0", Vec::new());
    assert_eq!(changes.status, 200);
    let mut shared = vec![changes];
    for path in [format!("/id/{account}/log"), format!("/id/{account}/public")] {
        shared.push(send(&a, "GET", &path, Vec::new()));
    }
    for r in &shared {
        assert_eq!(r.status, 200);
        let text = String::from_utf8(r.body.clone().unwrap()).unwrap();
        assert!(!text.contains(&ct), "a vault left the primary host");
        assert!(!text.contains("\"vault\""), "a vault left the primary host");
    }

    // [HST-13] a peer push carries the log and the profile only: a vault in it is refused, not stored.
    let (events, _) = fetch_log(&a, &account);
    let push = obj(&[
        ("account", account.clone().into()),
        ("events", Value::Array(events)),
        ("vault", reg.vault.clone()),
    ]);
    let r = peer("POST", "/peer/push", canonical(&push));
    assert_eq!(r.status, 400);
    assert_eq!(err(&parse_json(&r.body.unwrap()).unwrap()), "bad_field");
    // The same push without the vault is accepted.
    let without = obj(&[
        ("account", account.clone().into()),
        ("events", get(&push, "events").clone()),
    ]);
    assert_eq!(peer("POST", "/peer/push", canonical(&without)).status, 200);
}
