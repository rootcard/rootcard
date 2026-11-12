//! The shared test vectors (SPEC §21): a scenario built with the Rust core, and accept and reject vectors for the
//! rules. Every vector names an operation of [`crate::ops`]; the expected output is computed by running it.

use crate::ops::{Outcome, run};
use rootcard::account::{InstanceMode, new_instance, register, rotate_recovery};
use rootcard::crypto::{ed25519_public, ed25519_sign, sha256};
use rootcard::encoding::{base64url_encode, hex_encode};
use rootcard::file::{export_account, recovery_card};
use rootcard::json::{Map, Value};
use rootcard::keys::{KeyType, format_key};
use rootcard::log::{
    Home, LogState, VerifyOptions, add_receipt, event_message, receipt_message, retire_event, unsigned_event,
    verify_log,
};
use rootcard::messages::Challenge;
use rootcard::proof::{ProofBy, prove, statement_challenge};
use rootcard::recovery::{RecoveryKeys, derive_recovery_keys};
use rootcard::testing::TestRandom;
use rootcard::vault::{Kdf, Secret, unlock_vault};
use std::path::Path;

/// One vector before its output is computed.
pub struct V {
    name: String,
    rules: Vec<&'static str>,
    op: &'static str,
    input: Map,
}

fn v(name: &str, rules: &[&'static str], op: &'static str, input: Map) -> V {
    V {
        name: name.to_string(),
        rules: rules.to_vec(),
        op,
        input,
    }
}

fn h(b: &[u8]) -> Value {
    hex_encode(b).into()
}

fn m() -> Map {
    Map::new()
}

fn arr(v: &[Value]) -> Value {
    Value::Array(v.to_vec())
}

fn obj(v: &Value) -> Map {
    v.as_object().cloned().unwrap_or_default()
}

const T0: i64 = 1_800_000_000;
const HOST_A: [u8; 32] = [0xa1; 32];
const HOST_B: [u8; 32] = [0xb2; 32];
const PASSWORD: &str = "correct horse battery staple";
/// A recovery key whose signing seed for global/Astra is unusable ([CRY-9]): SHA-256("unusable recovery key 692").
const UNUSABLE_RK: &str = "a77a0382ec918aad9f4dda23aaeeb28875baab836c235d7a7d0719ad4e085866";
const NEW_PASSWORD: &str = "a new and better passphrase";

fn kdf_min() -> Value {
    m().with("m", Kdf::MIN.m).with("t", Kdf::MIN.t).into()
}

fn home(seed: &[u8; 32], url: &str) -> Home {
    Home {
        key: ed25519_public(seed),
        url: url.into(),
    }
}

fn home_input(seed: &[u8; 32], url: &str) -> Value {
    m().with("seed", h(seed)).with("url", url).into()
}

/// The scenario every vector file builds on.
pub struct Scenario {
    rk: [u8; 32],
    keys: RecoveryKeys,
    account_seed: [u8; 32],
    slot: String,
    reg_vault: Value,
    reg_public: Value,
    reg_card: Value,
    /// `[inception]`
    log0: Vec<Value>,
    /// registered at host A
    log1: Vec<Value>,
    /// restored at host B
    log2: Vec<Value>,
    vault2: Value,
    public2: Value,
    account_seed2: [u8; 32],
    /// after a recovery rotation
    log3: Vec<Value>,
    vault3: Value,
    card3: Value,
    new_rk: [u8; 32],
    /// retired
    log4: Vec<Value>,
}

fn opts() -> VerifyOptions {
    VerifyOptions::new(["global"])
}

pub fn scenario() -> Result<Scenario, String> {
    let e = |e: rootcard::Error| format!("scenario: {e}");
    let mut rng = TestRandom::new(b"scenario");
    let rk = rng.bytes::<32>();
    let keys = derive_recovery_keys(&rk, "global", "Astra");
    let mut reg_rng = TestRandom::new(b"register");
    let mut random = |b: &mut [u8]| reg_rng.fill(b);
    let reg = register(
        &rk,
        "global",
        "Astra",
        PASSWORD,
        "Laptop",
        &home(&HOST_A, "https://a.example"),
        T0,
        Kdf::MIN,
        &mut random,
    )
    .map_err(e)?;
    let mut pending = obj(&reg.log[1]);
    add_receipt(&mut pending, &HOST_A);
    let log0 = vec![reg.log[0].clone()];
    let log1 = vec![reg.log[0].clone(), pending.into()];
    let st1 = verify_log(&log1, &opts()).map_err(e)?;
    let u1 = unlock_vault(&reg.vault, &st1, &Secret::Recovery(&keys)).map_err(e)?;
    let account_seed = *u1.contents.account_seed;
    let slot = u1.info.slots[0].id.clone();

    let mut ni_rng = TestRandom::new(b"restore");
    let mut random = |b: &mut [u8]| ni_rng.fill(b);
    let ni = new_instance(
        &st1,
        &keys,
        Some(&u1),
        Some(&m()),
        InstanceMode::Restore,
        &home(&HOST_B, "https://b.example"),
        T0 + 100,
        &mut random,
    )
    .map_err(e)?;
    let mut ev = ni.event.clone();
    add_receipt(&mut ev, &HOST_B);
    let mut log2 = log1.clone();
    log2.push(ev.into());
    let st2 = verify_log(&log2, &opts()).map_err(e)?;
    let u2 = unlock_vault(&ni.vault, &st2, &Secret::Recovery(&keys)).map_err(e)?;

    let new_rk = rng.bytes::<32>();
    let mut rot_rng = TestRandom::new(b"rotate");
    let mut random = |b: &mut [u8]| rot_rng.fill(b);
    let rot = rotate_recovery(&st2, &log2, &keys, &new_rk, &ni.vault, &u2, T0 + 200, &mut random).map_err(e)?;
    let mut log3 = log2.clone();
    log3.push(rot.event.into());
    let st3 = verify_log(&log3, &opts()).map_err(e)?;
    let new_keys = derive_recovery_keys(&new_rk, "global", "Astra");
    let ret = retire_event(&st3, &new_keys.sign_seed, T0 + 300).map_err(e)?;
    let mut log4 = log3.clone();
    log4.push(ret.into());
    Ok(Scenario {
        rk,
        keys,
        account_seed,
        slot,
        reg_vault: reg.vault,
        reg_public: reg.public,
        reg_card: reg.card,
        log0,
        log1,
        log2,
        vault2: ni.vault,
        public2: ni.public,
        account_seed2: *u2.contents.account_seed,
        log3,
        vault3: rot.vault,
        card3: rot.card,
        new_rk,
        log4,
    })
}

/// Re-sign an event's owner signatures (and its receipt for `instance`) after a mutation.
fn resign(e: &mut Map, seeds: &[&[u8; 32]], receipt: Option<&[u8; 32]>) {
    let mut sigs = Vec::new();
    let msg = event_message(e);
    for s in seeds {
        sigs.push(
            m().with("key", format_key(KeyType::Ed25519, &ed25519_public(s)))
                .with("sig", base64url_encode(&ed25519_sign(s, &msg)))
                .into(),
        );
    }
    if let Some(hs) = receipt {
        sigs.push(
            m().with("key", format_key(KeyType::Ed25519, &ed25519_public(hs)))
                .with("sig", base64url_encode(&ed25519_sign(hs, &receipt_message(e))))
                .into(),
        );
    }
    e.insert("sigs", Value::Array(sigs));
}

fn with_body(e: &Map, k: &str, val: Value) -> Map {
    let mut e = e.clone();
    let mut b = e.get("body").and_then(Value::as_object).cloned().unwrap_or_default();
    b.insert(k, val);
    e.insert("body", b.into());
    e
}

fn set(mut e: Map, k: &str, val: impl Into<Value>) -> Map {
    e.insert(k, val.into());
    e
}

fn tamper_sig(v: &Value, index: usize) -> Value {
    let mut e = obj(v);
    let mut sigs = e.get("sigs").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut s = obj(&sigs[index]);
    let raw =
        rootcard::encoding::base64url_decode(s.get("sig").and_then(Value::as_str).unwrap_or("")).unwrap_or_default();
    let mut raw = raw;
    raw[0] ^= 1;
    s.insert("sig", base64url_encode(&raw).into());
    sigs[index] = s.into();
    e.insert("sigs", Value::Array(sigs));
    e.into()
}

fn log_input(events: &[Value]) -> Map {
    m().with("events", arr(events))
}

// ---------------------------------------------------------------------------------------------------------------------
// primitives.json

fn hexs(s: &str) -> Value {
    s.into()
}

fn primitives() -> Vec<V> {
    let mut out = Vec::new();
    let canon =
        |name: &str, rules: &[&'static str], text: &[u8]| v(name, rules, "canonical", m().with("text", h(text)));
    out.push(canon(
        "object members are sorted and whitespace removed",
        &["CJ-9"],
        br#" { "b" : 1, "a" : [ true , false , -5 ] } "#,
    ));
    out.push(canon(
        "members sorted by UTF-16 code units",
        &["CJ-9"],
        "{\"\u{e000}\":1,\"\u{1F600}\":2,\"a\":3}".as_bytes(),
    ));
    out.push(canon(
        "string escapes",
        &["CJ-9"],
        br#""\u0000\u0008\t\n\u000b\f\r\u001f\"\\\/\u007f\u2028\u00e9""#,
    ));
    out.push(canon("surrogate pair", &["CJ-3", "CJ-9"], br#""\ud83d\ude00""#));
    out.push(canon(
        "safe integer bounds",
        &["CJ-2"],
        b"[9007199254740991,-9007199254740991,0]",
    ));
    out.push(canon(
        "depth 32",
        &["CJ-5"],
        format!("{}{}", "[".repeat(32), "]".repeat(32)).as_bytes(),
    ));
    for (name, rules, text) in [
        ("null is not a value", vec!["CJ-1"], b"null".to_vec()),
        ("fraction", vec!["CJ-1", "CJ-6"], b"1.0".to_vec()),
        ("exponent", vec!["CJ-6"], b"1e2".to_vec()),
        ("negative zero", vec!["CJ-6"], b"-0".to_vec()),
        ("leading zero", vec!["CJ-6"], b"01".to_vec()),
        ("unsafe integer", vec!["CJ-2"], b"9007199254740992".to_vec()),
        ("duplicate member", vec!["CJ-4"], br#"{"a":1,"a":2}"#.to_vec()),
        (
            "duplicate member after unescaping",
            vec!["CJ-4"],
            br#"{"a":1,"a":2}"#.to_vec(),
        ),
        ("lone high surrogate", vec!["CJ-3", "CJ-6"], br#""\ud800""#.to_vec()),
        ("lone low surrogate", vec!["CJ-3", "CJ-6"], br#""\udc00""#.to_vec()),
        (
            "depth 33",
            vec!["CJ-5"],
            format!("{}{}", "[".repeat(33), "]".repeat(33)).into_bytes(),
        ),
        ("byte order mark", vec!["CJ-6"], b"\xef\xbb\xbf{}".to_vec()),
        ("invalid UTF-8", vec!["CJ-6"], b"\"\xc3\x28\"".to_vec()),
        ("trailing data", vec!["CJ-6"], b"{} {}".to_vec()),
        ("raw control character", vec!["CJ-6"], b"\"\x01\"".to_vec()),
        ("trailing comma", vec!["CJ-6"], b"[1,]".to_vec()),
    ] {
        out.push(v(name, &rules, "canonical", m().with("text", h(&text))));
    }
    for (raw, name) in [
        ("", "empty"),
        ("66", "one byte"),
        ("666f", "two bytes"),
        ("666f6f", "three bytes"),
        ("fbff", "url alphabet"),
    ] {
        out.push(v(
            &format!("base64url encode {name}"),
            &["B64-1"],
            "base64url_encode",
            m().with("hex", hexs(raw)),
        ));
    }
    for (text, name) in [
        ("Zm9v", "valid"),
        ("Zg", "valid two"),
        ("Zh", "non-zero unused bits"),
        ("Zm9=", "padding"),
        ("Z", "length 1 mod 4"),
        ("Zm+v", "plus"),
        ("Zm/v", "slash"),
    ] {
        out.push(v(
            &format!("base64url decode {name}"),
            &["B64-2"],
            "base64url_decode",
            m().with("text", text),
        ));
    }
    let k32 = sha256(b"base32");
    out.push(v(
        "base32 encode 32 bytes",
        &["B32-2"],
        "base32_encode",
        m().with("hex", h(&k32)),
    ));
    out.push(v(
        "base32 encode 1 byte",
        &["B32-2"],
        "base32_encode",
        m().with("hex", hexs("ff")),
    ));
    let enc = rootcard::encoding::base32_encode(&k32);
    for (text, len, lenient, name, rules) in [
        (enc.clone(), 32, false, "strict", vec!["B32-3"]),
        (
            enc.to_lowercase(),
            32,
            false,
            "strict rejects lower case",
            vec!["B32-3"],
        ),
        (
            enc.to_lowercase(),
            32,
            true,
            "lenient accepts lower case",
            vec!["B32-4"],
        ),
        ("ZZ".into(), 1, false, "strict rejects padding bits", vec!["B32-3"]),
        ("ZW".into(), 1, false, "strict one byte", vec!["B32-3"]),
        ("zw".into(), 1, true, "lenient one byte", vec!["B32-4"]),
        (
            "o-il o".into(),
            2,
            true,
            "lenient maps O I L and drops separators",
            vec!["B32-4"],
        ),
        ("U0".into(), 1, true, "lenient never accepts U", vec!["B32-4"]),
        (enc[..51].to_string(), 32, false, "wrong length", vec!["B32-3"]),
    ] {
        out.push(v(
            &format!("base32 decode {name}"),
            &rules,
            "base32_decode",
            m().with("text", text).with("len", len as i64).with("lenient", lenient),
        ));
    }
    let rk = sha256(b"recovery key");
    out.push(v(
        "recovery key written form",
        &["RK-1"],
        "format_recovery_key",
        m().with("key", h(&rk)),
    ));
    let w = rootcard::recovery::format_recovery_key(&rk);
    let mut bad_check = w.clone();
    let last = if w.ends_with('0') { "1" } else { "0" };
    bad_check.replace_range(72..73, last);
    let mut with_u = w.clone();
    with_u.replace_range(5..6, "U");
    for (text, name) in [
        (w.clone(), "written form"),
        (w.to_lowercase().replace('-', " "), "lower case with spaces"),
        (w[4..].to_string(), "without prefix"),
        (w.replace('0', "o").replace('1', "l"), "lenient letters"),
        (bad_check, "wrong checksum"),
        (with_u, "U is not accepted"),
        (w[..40].to_string(), "too short"),
    ] {
        out.push(v(
            &format!("parse recovery key: {name}"),
            &["RK-2", "B32-4"],
            "parse_recovery_key",
            m().with("text", text),
        ));
    }
    out.push(v(
        "recovery key derivation",
        &["RK-4"],
        "derive_recovery_keys",
        m().with("key", h(&rk))
            .with("realm", "global")
            .with("username", "Astra"),
    ));
    out.push(v(
        "recovery key derivation is bound to the username",
        &["RK-4"],
        "derive_recovery_keys",
        m().with("key", h(&rk))
            .with("realm", "global")
            .with("username", "astra"),
    ));
    // New recovery keys ([RK-3], [CRY-9]): the first draw of "new recovery key 686" gives an unusable signing seed.
    for (name, random) in [
        ("a new recovery key", "new recovery key 0"),
        (
            "a new recovery key is drawn again while its signing seed is unusable",
            "new recovery key 686",
        ),
    ] {
        out.push(v(
            name,
            &["RK-3", "CRY-9"],
            "new_recovery_key",
            m().with("realm", "global")
                .with("username", "Astra")
                .with("random", random),
        ));
    }
    out.push(v(
        "test random stream",
        &["VEC-2"],
        "random",
        m().with("random", "seed").with("len", 80i64),
    ));

    // Ed25519: RFC 8032 §7.1 tests 1 to 3.
    for (name, seed, msg) in [
        (
            "RFC 8032 test 1",
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "",
        ),
        (
            "RFC 8032 test 2",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "72",
        ),
        (
            "RFC 8032 test 3",
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "af82",
        ),
        // A seed with a zero last byte: an implementation that handles keys as big integers can drop it.
        (
            "seed with a zero last byte",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a600",
            "72",
        ),
    ] {
        out.push(v(
            name,
            &["CRY-1", "CRY-8"],
            "ed25519_sign",
            m().with("seed", seed).with("msg", msg),
        ));
    }
    // A seed with a zero first byte ([CRY-9]): WebKit's WebCrypto cannot import it, and signs with it only together
    // with its public key on record ([IMP-6]). A key on record that is not the seed's is refused.
    let mut zero_led = TestRandom::new(b"zero-led seed").bytes::<32>();
    zero_led[0] = 0;
    let other = ed25519_public(&[9; 32]);
    out.push(v(
        "seed with a zero first byte, signed with its key on record",
        &["CRY-8", "CRY-9", "IMP-6"],
        "ed25519_sign",
        m().with("seed", h(&zero_led))
            .with("known", h(&ed25519_public(&zero_led)))
            .with("msg", "72"),
    ));
    out.push(v(
        "a key on record that is not the seed's is refused",
        &["IMP-6"],
        "ed25519_sign",
        m().with("seed", h(&zero_led))
            .with("known", h(&other))
            .with("msg", "72"),
    ));
    for (name, public) in [
        ("the public key of a seed", ed25519_public(&zero_led)),
        ("another public key is not the seed's", other),
    ] {
        out.push(v(
            name,
            &["CRY-2", "IMP-6"],
            "ed25519_public_is",
            m().with("seed", h(&zero_led)).with("public", h(&public)),
        ));
    }
    out.extend(ed25519_rejects());
    // X25519: RFC 7748 §5.2 and §6.1.
    out.push(v(
        "RFC 7748 5.2 test 1",
        &["CRY-1", "CRY-2"],
        "x25519",
        m().with(
            "secret",
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        )
        .with(
            "peer",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        ),
    ));
    out.push(v(
        "RFC 7748 6.1 Alice and Bob",
        &["CRY-1"],
        "x25519",
        m().with(
            "secret",
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        )
        .with(
            "peer",
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        ),
    ));
    // Secrets with a zero byte at either end (WebKit's WebCrypto on Linux rejected the first kind); clamping makes
    // them the same scalars as secrets whose low bits of the first byte or whose last byte are set.
    for (name, secret) in [
        (
            "X25519 secret with a zero first byte",
            "0046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        ),
        (
            "X25519 secret with a zero last byte",
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a00",
        ),
        (
            "X25519 secret with zero first and last bytes",
            "0046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a00",
        ),
    ] {
        out.push(v(
            name,
            &["CRY-1", "CRY-2"],
            "x25519",
            m().with("secret", secret).with(
                "peer",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            ),
        ));
    }
    out.push(v(
        "X25519 with a small-order peer fails",
        &["CRY-4"],
        "x25519",
        m().with(
            "secret",
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        )
        .with(
            "peer",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
    ));
    out.push(v(
        "X25519 with the order-8 peer fails",
        &["CRY-4"],
        "x25519",
        m().with(
            "secret",
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        )
        .with(
            "peer",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        ),
    ));
    // HKDF: RFC 5869 A.1 and A.3 (first 32 bytes of the OKM).
    out.push(v(
        "RFC 5869 A.1",
        &["CRY-5"],
        "hkdf",
        m().with("ikm", h(&[0x0b; 22]))
            .with("salt", "000102030405060708090a0b0c")
            .with("info", "f0f1f2f3f4f5f6f7f8f9"),
    ));
    out.push(v(
        "RFC 5869 A.3 empty salt and info",
        &["CRY-5"],
        "hkdf",
        m().with("ikm", h(&[0x0b; 22])).with("salt", "").with("info", ""),
    ));
    // Argon2id without secret or associated data (the RFC 9106 vector with them is in the unit tests).
    out.push(v(
        "Argon2id small",
        &["CRY-6"],
        "argon2id",
        m().with("password", h(b"password"))
            .with("salt", h(b"somesaltsomesalt"))
            .with("m", 64i64)
            .with("t", 3i64)
            .with("p", 1i64),
    ));
    out.push(v(
        "Argon2id two lanes",
        &["CRY-6"],
        "argon2id",
        m().with("password", h(&[1; 32]))
            .with("salt", h(&[2; 16]))
            .with("m", 32i64)
            .with("t", 3i64)
            .with("p", 4i64),
    ));
    out.push(v(
        "Argon2id at the minimum lock parameters",
        &["CRY-6", "LCK-6"],
        "argon2id",
        m().with("password", h(PASSWORD.as_bytes()))
            .with("salt", h(&[7; 16]))
            .with("m", 47104i64)
            .with("t", 2i64)
            .with("p", 1i64),
    ));
    // AES-256-GCM.
    let key = sha256(b"aes key");
    let nonce = &sha256(b"nonce")[..12];
    out.push(v(
        "AES-256-GCM encrypt",
        &["CRY-7"],
        "aes_gcm_encrypt",
        m().with("key", h(&key))
            .with("nonce", h(nonce))
            .with("plaintext", h(b"rootcard"))
            .with("aad", h(b"aad")),
    ));
    let ct = rootcard::crypto::aes_gcm_encrypt(&key, nonce.try_into().unwrap_or(&[0; 12]), b"rootcard", b"aad")
        .unwrap_or_default();
    out.push(v(
        "AES-256-GCM decrypt",
        &["CRY-7"],
        "aes_gcm_decrypt",
        m().with("key", h(&key))
            .with("nonce", h(nonce))
            .with("ciphertext", h(&ct))
            .with("aad", h(b"aad")),
    ));
    out.push(v(
        "AES-256-GCM wrong aad fails",
        &["CRY-7"],
        "aes_gcm_decrypt",
        m().with("key", h(&key))
            .with("nonce", h(nonce))
            .with("ciphertext", h(&ct))
            .with("aad", h(b"aae")),
    ));
    // Keys.
    let pk = ed25519_public(&[9; 32]);
    let ok = format_key(KeyType::Ed25519, &pk);
    for (text, ty, name) in [
        (ok.clone(), "ed25519", "valid"),
        (ok.replace("ed25519", "x25519"), "ed25519", "wrong type"),
        (ok.clone(), "x25519", "required type differs"),
        (format!("{ok}A"), "ed25519", "wrong length"),
        (format!("{ok}="), "ed25519", "padding"),
        ("ed25519".to_string(), "ed25519", "no payload"),
        (format_key(KeyType::Ed25519, &[0; 32]), "ed25519", "small order"),
        (
            format!("ed25519:{}", base64url_encode(&[0xff; 32])),
            "ed25519",
            "non-canonical",
        ),
        (
            format_key(KeyType::X25519, &[0; 32]),
            "x25519",
            "x25519 has no point check",
        ),
    ] {
        out.push(v(
            &format!("key {name}"),
            &["KEY-1", "KEY-2", "KEY-3"],
            "parse_key",
            m().with("text", text).with("type", ty),
        ));
    }
    // [KEY-5] one key has one string: every other spelling of the valid key's bytes is rejected.
    let unused_bits = format!("{}h", &ok[..ok.len() - 1]);
    for (text, name) in [
        (ok.replace("ed25519:", "Ed25519:"), "type in upper case"),
        (ok.replace('_', "/").replace('-', "+"), "standard base64 alphabet"),
        (unused_bits, "non-zero unused bits"),
        (format!(" {ok}"), "leading space"),
        (ok.replace(':', ": "), "space after the colon"),
    ] {
        out.push(v(
            &format!("key spelled differently: {name}"),
            &["KEY-5"],
            "parse_key",
            m().with("text", text).with("type", "ed25519"),
        ));
    }
    out.push(v(
        "statement challenge",
        &["PRF-5"],
        "statement_challenge",
        m().with(
            "statement",
            m().with("for", "example.org").with("until", 1_900_000_000i64),
        ),
    ));
    out
}

fn ed25519_rejects() -> Vec<V> {
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    let seed = sha256(b"ed25519 seed");
    let pk = ed25519_public(&seed);
    let msg = b"rootcard".to_vec();
    let sig = ed25519_sign(&seed, &msg);
    let mut out = Vec::new();
    let mut verify = |name: &str, public: &[u8], msg: &[u8], sig: &[u8]| {
        out.push(v(
            name,
            &["CRY-3"],
            "ed25519_verify",
            m().with("public", h(public)).with("msg", h(msg)).with("sig", h(sig)),
        ));
    };
    verify("valid signature", &pk, &msg, &sig);
    verify("other message", &pk, b"rootcarc", &sig);
    verify("short signature", &pk, &msg, &sig[..63]);
    // S + L (still < 2^256).
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut s_plus_l = sig;
    let mut carry = 0u16;
    for i in 0..32 {
        let t = u16::from(s_plus_l[32 + i]) + u16::from(l[i]) + carry;
        s_plus_l[32 + i] = t as u8;
        carry = t >> 8;
    }
    verify("S is not reduced (S + L)", &pk, &msg, &s_plus_l);
    // Non-canonical encodings of A and R.
    let mut y_ge_p = [0xffu8; 32];
    y_ge_p[0] = 0xee; // p + 1
    y_ge_p[31] = 0x7f;
    verify("non-canonical A (y = p + 1)", &y_ge_p, &msg, &sig);
    let mut neg_zero = [0u8; 32];
    neg_zero[0] = 1;
    neg_zero[31] = 0x80;
    verify("non-canonical A (x = 0 with the sign bit)", &neg_zero, &msg, &sig);
    let mut bad_r = sig;
    bad_r[..32].copy_from_slice(&y_ge_p);
    verify("non-canonical R", &pk, &msg, &bad_r);
    // Small-order A and R.
    for (i, t) in EIGHT_TORSION.iter().enumerate() {
        let enc = t.compress().to_bytes();
        verify(&format!("small-order A ({i})"), &enc, &msg, &sig);
        let mut r = sig;
        r[..32].copy_from_slice(&enc);
        verify(&format!("small-order R ({i})"), &pk, &msg, &r);
    }
    // A mixed-order key: a cofactored verifier accepts, the cofactorless check of [CRY-3] step 5 rejects.
    let a = {
        let hsh = Sha512::digest(seed);
        let mut s = [0u8; 32];
        s.copy_from_slice(&hsh[..32]);
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
        Scalar::from_bytes_mod_order(s)
    };
    let a_mixed = (ED25519_BASEPOINT_POINT * a + EIGHT_TORSION[1]).compress().to_bytes();
    let r = Scalar::from_bytes_mod_order(sha256(b"nonce r"));
    let rp = (ED25519_BASEPOINT_POINT * r).compress().to_bytes();
    for n in 0u8..=255 {
        let mmsg = [b'm', n];
        let mut hasher = Sha512::new();
        hasher.update(rp);
        hasher.update(a_mixed);
        hasher.update(mmsg);
        let k = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());
        if k.to_bytes()[0].is_multiple_of(8) {
            continue;
        }
        let s = r + k * a;
        let mut sg = [0u8; 64];
        sg[..32].copy_from_slice(&rp);
        sg[32..].copy_from_slice(&s.to_bytes());
        // Sanity: the cofactored equation holds.
        let ap = CompressedEdwardsY(a_mixed).decompress();
        let rpp = CompressedEdwardsY(rp).decompress();
        if let (Some(ap), Some(rpp)) = (ap, rpp) {
            let lhs = ED25519_BASEPOINT_POINT * s - ap * k - rpp;
            assert!(lhs.mul_by_cofactor() == curve25519_dalek::edwards::EdwardsPoint::default());
        }
        verify(
            "mixed-order A that only a cofactored verifier accepts",
            &a_mixed,
            &mmsg,
            &sg,
        );
        break;
    }
    out
}

// ---------------------------------------------------------------------------------------------------------------------
// log.json

fn log_vectors(s: &Scenario) -> Vec<V> {
    let mut out = Vec::new();
    let rs = &s.keys.sign_seed;
    out.push(v(
        "inception of the scenario",
        &["ID-1", "ID-2", "ID-3", "HDL-1"],
        "inception",
        m().with("key", h(&s.rk))
            .with("realm", "global")
            .with("username", "Astra"),
    ));
    out.push(v(
        "inception of another realm",
        &["ID-1", "RK-4"],
        "inception",
        m().with("key", h(&s.rk))
            .with("realm", "xigna")
            .with("username", "Astra"),
    ));
    out.push(v(
        "inception with a bad username",
        &["USR-1"],
        "inception",
        m().with("key", h(&s.rk)).with("realm", "global").with("username", "-x"),
    ));
    for (t, ok) in [
        ("global", true),
        ("a.b_c-9", true),
        ("Global", false),
        ("-a", false),
        ("a-", false),
        ("", false),
    ] {
        out.push(v(
            &format!("realm {t:?}"),
            &["RLM-1"],
            "check_realm",
            m().with("text", t),
        ));
        let _ = ok;
    }
    out.push(v(
        "realm of 65 characters",
        &["RLM-1"],
        "check_realm",
        m().with("text", "a".repeat(65)),
    ));
    for t in ["Astra", "a", "9lives", "a-b_c", "_a", "-a", "a b", "å", ""] {
        out.push(v(
            &format!("username {t:?}"),
            &["USR-1"],
            "check_username",
            m().with("text", t),
        ));
    }
    out.push(v(
        "username of 33 characters",
        &["USR-1"],
        "check_username",
        m().with("text", "a".repeat(33)),
    ));
    for t in ["Astra", "ab", "9lives", "Abcdefghijklmnopqrst", "Abcdefghijklmnopqrstu"] {
        out.push(v(
            &format!("default policy {t:?}"),
            &["USR-3"],
            "default_username_policy",
            m().with("text", t),
        ));
    }
    for t in [
        "Astra#3F9C",
        "Astra#3f9c",
        "Astra#oilk-k2",
        "Astra#3F9C-",
        "Astra#3F9",
        "Astra",
        "a#b#3F9C",
        "Astra#3F9U",
        &format!("Astra#3F9C-{}", "A".repeat(49)),
    ] {
        out.push(v(
            &format!("handle {t:?}"),
            &["HDL-3"],
            "parse_handle",
            m().with("text", t),
        ));
    }
    let ids = |l: &[&str]| arr(&l.iter().map(|s| Value::from(*s)).collect::<Vec<_>>());
    out.push(v(
        "extended tags of two ids",
        &["HDL-6"],
        "extended_tags",
        m().with("ids", ids(&["3F9CK2AAAA", "3F9CK7AAAA"])),
    ));
    out.push(v(
        "extended tags need two characters",
        &["HDL-6"],
        "extended_tags",
        m().with("ids", ids(&["3F9CKAA", "3F9CKBA", "3F9CXAA"])),
    ));
    out.push(v(
        "one identity keeps the plain tag",
        &["HDL-6"],
        "extended_tags",
        m().with("ids", ids(&["3F9CKAA"])),
    ));
    // Regressions found by the differential test: ids shorter than a tag, and characters of more than one byte, made
    // the Rust core slice inside a string and panic. Extended tags count characters, not bytes or UTF-16 units.
    out.push(v(
        "extended tags of an id shorter than a tag",
        &["HDL-1", "HDL-6"],
        "extended_tags",
        m().with("ids", ids(&["3F9CKAA", "3F", "3F9CXAA"])),
    ));
    out.push(v(
        "extended tags count characters",
        &["HDL-1", "HDL-6"],
        "extended_tags",
        m().with("ids", ids(&["3F9C\u{e9}A", "3F9C\u{e9}B", "\u{1f600}F9CXY"])),
    ));

    // Valid logs.
    out.push(v(
        "log of the inception only",
        &["LOG-12"],
        "verify_log",
        log_input(&s.log0),
    ));
    out.push(v(
        "registered log",
        &["LOG-12", "LOG-3", "LOG-8", "LOG-10"],
        "verify_log",
        log_input(&s.log1),
    ));
    out.push(v(
        "restored at another host",
        &["LOG-12", "LOG-11"],
        "verify_log",
        log_input(&s.log2),
    ));
    out.push(v(
        "after a recovery rotation",
        &["LOG-12", "LOG-7"],
        "verify_log",
        log_input(&s.log3),
    ));
    out.push(v("retired", &["LOG-12", "LOG-14"], "verify_log", log_input(&s.log4)));
    out.push(v(
        "time within the window",
        &["LOG-12"],
        "verify_log",
        log_input(&s.log1).with("now", T0 - 600),
    ));

    let inc = obj(&s.log1[0]);
    let ev1 = obj(&s.log1[1]);
    let other_seed = sha256(b"other");
    let mut rej = |name: &str, rules: &[&'static str], events: Vec<Value>| {
        out.push(v(name, rules, "verify_log", log_input(&events)))
    };
    rej("empty log", &["LOG-12"], vec![]);
    rej("1001 events", &["LOG-1"], vec![Value::Bool(true); 1001]);
    rej("first event is not an inception", &["LOG-12"], vec![ev1.clone().into()]);
    rej(
        "inception after event 0",
        &["LOG-12"],
        vec![inc.clone().into(), inc.clone().into()],
    );
    rej(
        "unknown kind",
        &["LOG-12", "EXT-4"],
        vec![inc.clone().into(), set(ev1.clone(), "kind", "merge").into()],
    );
    rej(
        "unsupported version",
        &["CJ-12"],
        vec![set(inc.clone(), "v", 2i64).into()],
    );
    rej("missing version", &["CJ-12"], vec![inc.without("v").into()]);
    rej(
        "unknown member",
        &["CJ-11"],
        vec![set(inc.clone(), "time", 0i64).into()],
    );
    rej(
        "event too large",
        &["LOG-2"],
        vec![set(inc.clone(), "pad", "x".repeat(5000)).into()],
    );
    rej(
        "inception seq is not 0",
        &["LOG-12"],
        vec![set(inc.clone(), "seq", 1i64).into()],
    );
    rej(
        "bad realm",
        &["RLM-1"],
        vec![with_body(&inc, "realm", "Global".into()).into()],
    );
    rej(
        "bad username",
        &["USR-1"],
        vec![with_body(&inc, "username", "_x".into()).into()],
    );
    rej(
        "forged inception",
        &["LOG-12", "CRY-3"],
        vec![with_body(&inc, "username", "Astrb".into()).into()],
    );
    let mut wrong = inc.clone();
    resign(&mut wrong, &[&other_seed], None);
    rej("inception signed by another key", &["LOG-12"], vec![wrong.into()]);
    rej(
        "bad key in the inception",
        &["KEY-3"],
        vec![with_body(&inc, "recovery", format_key(KeyType::Ed25519, &[0; 32]).into()).into()],
    );
    rej(
        "account mismatch",
        &["LOG-12"],
        vec![inc.clone().into(), set(ev1.clone(), "account", "0".repeat(52)).into()],
    );
    rej(
        "wrong seq",
        &["LOG-12"],
        vec![inc.clone().into(), set(ev1.clone(), "seq", 2i64).into()],
    );
    rej(
        "wrong prev",
        &["LOG-12"],
        vec![
            inc.clone().into(),
            set(ev1.clone(), "prev", base64url_encode(&[0; 32])).into(),
        ],
    );
    // [LOG-3] the schema of every event after the inception; each is rejected before its signatures are checked.
    for (name, event) in [
        ("event without sigs", ev1.without("sigs")),
        ("event without a body", ev1.without("body")),
        ("event body is not an object", set(ev1.clone(), "body", "instance")),
        (
            "event sigs is not an array",
            set(ev1.clone(), "sigs", Value::Object(m())),
        ),
        ("prev of 31 bytes", set(ev1.clone(), "prev", base64url_encode(&[0; 31]))),
        ("prev is not base64url", set(ev1.clone(), "prev", "not base64url!")),
        ("negative time", set(ev1.clone(), "time", -1i64)),
        ("time is a string", set(ev1.clone(), "time", "1800000000")),
        ("account is not an account id", set(ev1.clone(), "account", "Astra")),
    ] {
        rej(name, &["LOG-3"], vec![inc.clone().into(), event.into()]);
    }
    let mut swapped = ev1.clone();
    let mut sigs = swapped
        .get("sigs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    sigs.swap(0, 1);
    swapped.insert("sigs", Value::Array(sigs.clone()));
    rej(
        "signers in the wrong order",
        &["LOG-12"],
        vec![inc.clone().into(), swapped.into()],
    );
    let mut short = ev1.clone();
    short.insert("sigs", Value::Array(sigs[..2].to_vec()));
    rej(
        "instance without a receipt",
        &["LOG-8", "LOG-12"],
        vec![inc.clone().into(), short.into()],
    );
    rej(
        "bad owner signature",
        &["LOG-12", "CRY-3"],
        vec![inc.clone().into(), tamper_sig(&s.log1[1], 1)],
    );
    rej(
        "bad receipt",
        &["LOG-8"],
        vec![inc.clone().into(), tamper_sig(&s.log1[1], 2)],
    );
    let mut reuse = with_body(
        &ev1,
        "account_key",
        format_key(KeyType::Ed25519, &ed25519_public(rs)).into(),
    );
    resign(&mut reuse, &[rs, rs], Some(&HOST_A));
    rej(
        "account key equals the recovery key",
        &["LOG-12"],
        vec![inc.clone().into(), reuse.into()],
    );
    let mut same = with_body(&ev1, "home", home(&s.account_seed, "https://a.example").to_value());
    resign(&mut same, &[rs, &s.account_seed], Some(&s.account_seed));
    rej(
        "home key equals the account key",
        &["LOG-12"],
        vec![inc.clone().into(), same.into()],
    );
    let mut first_restore = with_body(&ev1, "reason", "restore".into());
    resign(&mut first_restore, &[rs, &s.account_seed], Some(&HOST_A));
    rej(
        "first instance with reason restore",
        &["LOG-11"],
        vec![inc.clone().into(), first_restore.into()],
    );
    rej(
        "unknown reason",
        &["LOG-4"],
        vec![inc.clone().into(), with_body(&ev1, "reason", "move".into()).into()],
    );
    rej(
        "url with a space",
        &["LOG-4"],
        vec![
            inc.clone().into(),
            with_body(
                &ev1,
                "home",
                m().with("key", format_key(KeyType::Ed25519, &ed25519_public(&HOST_A)))
                    .with("url", "https://a example")
                    .into(),
            )
            .into(),
        ],
    );
    // Time.
    let ev2 = obj(&s.log2[2]);
    let mut back = set(ev2.clone(), "time", T0 - 1);
    let seed2 = s.account_seed2;
    resign(&mut back, &[rs, &seed2], Some(&HOST_B));
    rej(
        "time goes backwards",
        &["LOG-12"],
        vec![inc.clone().into(), ev1.clone().into(), back.into()],
    );
    out.push(v(
        "time too far in the future",
        &["LOG-12"],
        "verify_log",
        log_input(&s.log1).with("now", T0 - 601),
    ));
    out.push(v(
        "realm not accepted",
        &["RLM-3"],
        "verify_log",
        log_input(&s.log1).with("realms", arr(&["xigna".into()])),
    ));
    // Reuse of an earlier account key in a later instance.
    let mut again = with_body(
        &ev2,
        "account_key",
        format_key(KeyType::Ed25519, &ed25519_public(&s.account_seed)).into(),
    );
    resign(&mut again, &[rs, &s.account_seed], Some(&HOST_B));
    out.push(v(
        "earlier account key reused",
        &["LOG-12"],
        "verify_log",
        log_input(&[inc.clone().into(), ev1.clone().into(), again.into()]),
    ));
    // After retire.
    let st4 = verify_log(&s.log4, &opts());
    if let Ok(st4) = st4 {
        let new_keys = derive_recovery_keys(&s.new_rk, "global", "Astra");
        let mut after = unsigned_event(&st4, "retire", m(), T0 + 400);
        resign(&mut after, &[&new_keys.sign_seed], None);
        let mut l = s.log4.clone();
        l.push(after.into());
        out.push(v("event after retire", &["LOG-14"], "verify_log", log_input(&l)));
    }
    // The rotated-out key cannot sign.
    let st3 = verify_log(&s.log3, &opts());
    if let Ok(st3) = st3 {
        let mut old = unsigned_event(&st3, "retire", m(), T0 + 400);
        resign(&mut old, &[rs], None);
        let mut l = s.log3.clone();
        l.push(old.into());
        out.push(v(
            "retire signed by the rotated-out key",
            &["LOG-13", "LOG-12"],
            "verify_log",
            log_input(&l),
        ));
    }

    // Incremental verification.
    out.push(v(
        "extend the registered log",
        &["LOG-15"],
        "extend_log",
        log_input(&s.log1).with("new", arr(&s.log2[2..])),
    ));
    out.push(v(
        "extend by two events",
        &["LOG-15"],
        "extend_log",
        log_input(&s.log1).with("new", arr(&s.log3[2..])),
    ));
    out.push(v(
        "extend with a gap",
        &["LOG-15"],
        "extend_log",
        log_input(&s.log1).with("new", arr(&s.log3[3..])),
    ));
    out.push(v(
        "extend by nothing",
        &["LOG-15"],
        "extend_log",
        log_input(&s.log1).with("new", arr(&[])),
    ));
    // Pending instances.
    let mut pending = ev2.clone();
    let ps = pending
        .get("sigs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    pending.insert("sigs", Value::Array(ps[..2].to_vec()));
    out.push(v(
        "pending instance",
        &["LOG-9"],
        "verify_pending",
        log_input(&s.log1)
            .with("pending", pending.clone())
            .with("now", T0 + 100),
    ));
    out.push(v(
        "pending instance with a receipt",
        &["LOG-9"],
        "verify_pending",
        log_input(&s.log1).with("pending", ev2.clone()).with("now", T0 + 100),
    ));
    out.push(v(
        "pending instance from the future",
        &["LOG-9"],
        "verify_pending",
        log_input(&s.log1)
            .with("pending", pending.clone())
            .with("now", T0 - 600),
    ));
    out.push(v(
        "pending event that is not an instance",
        &["LOG-9"],
        "verify_pending",
        log_input(&s.log2)
            .with("pending", s.log3[3].clone())
            .with("now", T0 + 300),
    ));
    // Comparison.
    let other_inc = run_inception(&sha256(b"another key"));
    out.push(v(
        "same log",
        &["VER-2"],
        "compare_logs",
        m().with("a", arr(&s.log2)).with("b", arr(&s.log2)),
    ));
    out.push(v(
        "newer log",
        &["VER-2"],
        "compare_logs",
        m().with("a", arr(&s.log1)).with("b", arr(&s.log3)),
    ));
    out.push(v(
        "older log",
        &["VER-2"],
        "compare_logs",
        m().with("a", arr(&s.log3)).with("b", arr(&s.log1)),
    ));
    let mut fork = s.log1.clone();
    let mut fev = set(ev2.clone(), "time", T0 + 101);
    resign(&mut fev, &[rs, &seed2], Some(&HOST_B));
    fork.push(fev.into());
    out.push(v(
        "fork",
        &["VER-2", "VER-3"],
        "compare_logs",
        m().with("a", arr(&s.log3)).with("b", arr(&fork)),
    ));
    out.push(v(
        "fork of equal length",
        &["VER-2", "VER-3"],
        "compare_logs",
        m().with("a", arr(&s.log2)).with("b", arr(&fork)),
    ));
    out.push(v(
        "other account",
        &["VER-2"],
        "compare_logs",
        m().with("a", arr(&s.log1)).with("b", arr(&[other_inc])),
    ));
    out
}

fn run_inception(rk: &[u8; 32]) -> Value {
    let keys = derive_recovery_keys(rk, "global", "Other");
    rootcard::id::inception(&keys, "global", "Other")
        .map(Value::Object)
        .unwrap_or(Value::Bool(false))
}

// ---------------------------------------------------------------------------------------------------------------------
// vault.json

fn vault_vectors(s: &Scenario) -> Vec<V> {
    let mut out = Vec::new();
    out.push(v(
        "registration",
        &["CLT-1", "HST-3", "VLT-6", "LCK-7", "LCK-9", "RK-4"],
        "register",
        m().with("key", h(&s.rk))
            .with("realm", "global")
            .with("username", "Astra")
            .with("password", PASSWORD)
            .with("label", "Laptop")
            .with("home", home_input(&HOST_A, "https://a.example"))
            .with("time", T0)
            .with("kdf", kdf_min())
            .with("random", "register"),
    ));
    out.push(v(
        "registration with a weak password",
        &["LCK-8"],
        "register",
        m().with("key", h(&s.rk))
            .with("realm", "global")
            .with("username", "Astra")
            .with("password", "too short")
            .with("label", "Laptop")
            .with("home", home_input(&HOST_A, "https://a.example"))
            .with("time", T0)
            .with("kdf", kdf_min())
            .with("random", "register"),
    ));
    // [CRY-9]: an unusable recovery key is refused; an unusable account seed or password salt is drawn again. The
    // random streams were chosen so that the first draw is unusable.
    for (name, key, random) in [
        (
            "registration with an unusable recovery key",
            UNUSABLE_RK.to_string(),
            "register",
        ),
        (
            "registration draws the account seed again",
            hex_encode(&s.rk),
            "account seed 329",
        ),
        (
            "registration draws the password salt again",
            hex_encode(&s.rk),
            "password salt 132",
        ),
    ] {
        out.push(v(
            name,
            &["CRY-9", "CLT-1", "LCK-7"],
            "register",
            m().with("key", key.as_str())
                .with("realm", "global")
                .with("username", "Astra")
                .with("password", PASSWORD)
                .with("label", "Laptop")
                .with("home", home_input(&HOST_A, "https://a.example"))
                .with("time", T0)
                .with("kdf", kdf_min())
                .with("random", random),
        ));
    }
    let vi = |vault: &Value, events: &[Value]| log_input(events).with("vault", vault.clone());
    out.push(v(
        "registered vault verifies",
        &["VLT-3", "FET-2"],
        "verify_vault",
        vi(&s.reg_vault, &s.log1),
    ));
    out.push(v(
        "restored vault verifies",
        &["VLT-3"],
        "verify_vault",
        vi(&s.vault2, &s.log2),
    ));
    out.push(v(
        "vault of an old instance",
        &["VLT-3", "VER-6"],
        "verify_vault",
        vi(&s.reg_vault, &s.log2),
    ));
    out.push(v(
        "vault without an instance",
        &["VLT-3"],
        "verify_vault",
        vi(&s.reg_vault, &s.log0),
    ));
    out.push(v(
        "vault of a retired identity",
        &["VLT-3"],
        "verify_vault",
        vi(&s.vault3, &s.log4),
    ));
    out.push(v(
        "grant signed by the rotated-out key",
        &["LCK-3", "LCK-4"],
        "verify_vault",
        vi(&s.vault2, &s.log3),
    ));
    out.push(v(
        "vault after the rotation",
        &["KT-5", "LCK-3"],
        "verify_vault",
        vi(&s.vault3, &s.log3),
    ));
    let rv = obj(&s.reg_vault);
    let mut mutate = |name: &str, rules: &[&'static str], f: &dyn Fn(&mut Map)| {
        let mut x = rv.clone();
        f(&mut x);
        out.push(v(name, rules, "verify_vault", vi(&x.into(), &s.log1)));
    };
    mutate("vault version 2", &["CJ-12"], &|x| {
        x.insert("v", 2i64.into());
    });
    mutate("vault rev 0", &["VLT-4"], &|x| {
        x.insert("rev", 0i64.into());
    });
    mutate("vault of another account", &["VLT-3"], &|x| {
        x.insert("account", "0".repeat(52).into());
    });
    mutate("vault with a tampered ciphertext", &["VLT-2"], &|x| {
        x.insert("ct", base64url_encode(&[0; 32]).into());
    });
    mutate("vault with an unknown member", &["CJ-11"], &|x| {
        x.insert("revoked", Value::Array(vec![]));
    });
    let edit_locks = |x: &mut Map, f: &dyn Fn(&mut Map, &mut Vec<Value>)| {
        let mut locks = x.get("locks").and_then(Value::as_object).cloned().unwrap_or_default();
        let mut grant = locks
            .get("grant")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut list = locks.get("list").and_then(Value::as_array).cloned().unwrap_or_default();
        f(&mut grant, &mut list);
        locks.insert("grant", grant.into());
        locks.insert("list", Value::Array(list));
        x.insert("locks", locks.into());
    };
    mutate("no recovery lock", &["LCK-1"], &|x| {
        edit_locks(x, &|_, l| {
            l.remove(0);
        })
    });
    mutate("a lock without a slot", &["LCK-1"], &|x| {
        edit_locks(x, &|g, _| {
            g.insert("slots", Value::Array(vec![]));
        })
    });
    mutate("label with a control character", &["LCK-2"], &|x| {
        edit_locks(x, &|g, _| {
            let mut slots = g.get("slots").and_then(Value::as_array).cloned().unwrap_or_default();
            let mut s0 = obj(&slots[0]);
            s0.insert("label", "Lap\ntop".into());
            slots[0] = s0.into();
            g.insert("slots", Value::Array(slots));
        })
    });
    mutate("Argon2id memory below the bound", &["LCK-6"], &|x| {
        edit_locks(x, &|_, l| {
            let mut p = obj(&l[1]);
            let mut k = p.get("kdf").and_then(Value::as_object).cloned().unwrap_or_default();
            k.insert("m", 47103i64.into());
            p.insert("kdf", k.into());
            l[1] = p.into();
        })
    });
    mutate("unknown lock kind", &["LCK-1", "CJ-11"], &|x| {
        edit_locks(x, &|_, l| {
            let mut p = obj(&l[1]);
            p.insert("kind", "passkey".into());
            l[1] = p.into();
        })
    });
    mutate("grant without a valid signature", &["LCK-3"], &|x| {
        edit_locks(x, &|g, _| {
            g.insert("gen", 2i64.into());
        })
    });

    // Unlock.
    let ui = |vault: &Value, events: &[Value]| log_input(events).with("vault", vault.clone());
    out.push(v(
        "unlock with the password",
        &["VLT-8", "LCK-7", "LCK-9"],
        "unlock_vault",
        ui(&s.reg_vault, &s.log1)
            .with("lock", s.slot.as_str())
            .with("password", PASSWORD),
    ));
    out.push(v(
        "unlock with a wrong password",
        &["VLT-8", "LCK-9"],
        "unlock_vault",
        ui(&s.reg_vault, &s.log1)
            .with("lock", s.slot.as_str())
            .with("password", "wrong password!!"),
    ));
    out.push(v(
        "unlock an unknown slot",
        &["VLT-8"],
        "unlock_vault",
        ui(&s.reg_vault, &s.log1)
            .with("lock", "AAAAAAAAAAA")
            .with("password", PASSWORD),
    ));
    out.push(v(
        "unlock with the recovery key",
        &["VLT-8", "RK-4"],
        "unlock_vault",
        ui(&s.reg_vault, &s.log1).with("recovery_key", h(&s.rk)),
    ));
    out.push(v(
        "unlock with another recovery key",
        &["VLT-8"],
        "unlock_vault",
        ui(&s.reg_vault, &s.log1).with("recovery_key", h(&s.new_rk)),
    ));
    // A vault whose contents hold another account key, signed by the right one ([VLT-8] last step).
    if let Ok(st1) = verify_log(&s.log1, &opts()) {
        out.push(v(
            "contents with another account key",
            &["VLT-8"],
            "unlock_vault",
            ui(&wrong_seed_vault(s, &st1), &s.log1).with("recovery_key", h(&s.rk)),
        ));
    }

    // Changes.
    let ci = |vault: &Value, events: &[Value]| {
        log_input(events)
            .with("vault", vault.clone())
            .with("recovery_key", h(&s.rk))
    };
    out.push(v(
        "password change",
        &["CHG-1", "LCK-10"],
        "change_password",
        ci(&s.reg_vault, &s.log1)
            .with("lock", s.slot.as_str())
            .with("password", NEW_PASSWORD)
            .with("kdf", kdf_min())
            .with("random", "change"),
    ));
    out.push(v(
        "password change of an unknown slot",
        &["CHG-1"],
        "change_password",
        ci(&s.reg_vault, &s.log1)
            .with("lock", "AAAAAAAAAAA")
            .with("password", NEW_PASSWORD)
            .with("kdf", kdf_min())
            .with("random", "change"),
    ));
    out.push(v(
        "add a password slot",
        &["KT-4", "LCK-3"],
        "add_slot",
        ci(&s.reg_vault, &s.log1)
            .with("label", "Phone")
            .with("password", "phone passphrase 1")
            .with("kdf", kdf_min())
            .with("random", "add"),
    ));
    out.push(v(
        "data update",
        &["HST-12", "VLT-4", "DAT-6"],
        "update_contents",
        ci(&s.reg_vault, &s.log1)
            .with("data", m().with("user.motto", "hello").with("app.xigna.level", 3i64))
            .with("random", "data"),
    ));
    out.push(v(
        "data update with a bad key",
        &["DAT-4"],
        "update_contents",
        ci(&s.reg_vault, &s.log1)
            .with("data", m().with("motto", "hello"))
            .with("random", "data"),
    ));
    out.push(v(
        "restore at another host",
        &["KT-3", "LOG-9"],
        "new_instance",
        ci(&s.reg_vault, &s.log1)
            .with("public", s.reg_public.clone())
            .with("mode", "restore")
            .with("home", home_input(&HOST_B, "https://b.example"))
            .with("time", T0 + 100)
            .with("random", "restore"),
    ));
    out.push(v(
        "revoke the only password",
        &["KT-4", "LCK-5"],
        "new_instance",
        ci(&s.reg_vault, &s.log1)
            .with("mode", "revoke")
            .with("drop", arr(&[s.slot.as_str().into()]))
            .with("home", home_input(&HOST_A, "https://a.example"))
            .with("time", T0 + 100)
            .with("random", "revoke"),
    ));
    out.push(v(
        "reset a forgotten password",
        &["KT-8"],
        "new_instance",
        ci(&s.reg_vault, &s.log1)
            .with("mode", "reset")
            .with(
                "slot",
                m().with("label", "New")
                    .with("password", NEW_PASSWORD)
                    .with("kdf", kdf_min()),
            )
            .with("home", home_input(&HOST_A, "https://a.example"))
            .with("time", T0 + 100)
            .with("random", "reset"),
    ));
    out.push(v(
        "fresh instance",
        &["KT-3"],
        "new_instance",
        ci(&s.reg_vault, &s.log1)
            .with("mode", "fresh")
            .with(
                "slot",
                m().with("label", "Fresh")
                    .with("password", NEW_PASSWORD)
                    .with("kdf", kdf_min()),
            )
            .with("home", home_input(&HOST_A, "https://a.example"))
            .with("time", T0 + 100)
            .with("random", "fresh"),
    ));
    // [LCK-8] in every function that creates a password lock, not only in `register`.
    out.push(v(
        "password change to a weak password",
        &["LCK-8", "CHG-1"],
        "change_password",
        ci(&s.reg_vault, &s.log1)
            .with("lock", s.slot.as_str())
            .with("password", "too short")
            .with("kdf", kdf_min())
            .with("random", "change"),
    ));
    out.push(v(
        "add a slot with a weak password",
        &["LCK-8", "KT-4"],
        "add_slot",
        ci(&s.reg_vault, &s.log1)
            .with("label", "Phone")
            .with("password", "phone")
            .with("kdf", kdf_min())
            .with("random", "add"),
    ));
    out.push(v(
        "reset to a weak password",
        &["LCK-8", "KT-8"],
        "new_instance",
        ci(&s.reg_vault, &s.log1)
            .with("mode", "reset")
            .with(
                "slot",
                m().with("label", "New")
                    .with("password", "short")
                    .with("kdf", kdf_min()),
            )
            .with("home", home_input(&HOST_A, "https://a.example"))
            .with("time", T0 + 100)
            .with("random", "reset"),
    ));
    out.push(v(
        "rotate the recovery key",
        &["KT-5", "CRD-2"],
        "rotate_recovery",
        ci(&s.vault2, &s.log2)
            .with("new_key", h(&s.new_rk))
            .with("time", T0 + 200)
            .with("random", "rotate"),
    ));
    out.push(v(
        "rotation to an unusable recovery key is refused",
        &["KT-5", "CRY-9"],
        "rotate_recovery",
        ci(&s.vault2, &s.log2)
            .with("new_key", UNUSABLE_RK)
            .with("time", T0 + 200)
            .with("random", "rotate"),
    ));
    out.push(v(
        "the rotated-out key cannot open the new recovery lock",
        &["LCK-4", "KT-5"],
        "rotate_recovery",
        log_input(&s.log3)
            .with("vault", s.vault3.clone())
            .with("recovery_key", h(&s.rk))
            .with("new_key", h(&s.new_rk))
            .with("time", T0 + 300)
            .with("random", "rotate"),
    ));

    // Replacement rules.
    let changed = run_value(
        "change_password",
        &ci(&s.reg_vault, &s.log1)
            .with("lock", s.slot.as_str())
            .with("password", NEW_PASSWORD)
            .with("kdf", kdf_min())
            .with("random", "change"),
    );
    let changed_vault = changed
        .as_ref()
        .and_then(|c| c.as_object())
        .and_then(|c| c.get("vault"))
        .cloned();
    let data = run_value(
        "update_contents",
        &ci(&s.reg_vault, &s.log1)
            .with("data", m().with("user.motto", "hello"))
            .with("random", "data"),
    );
    let added = run_value(
        "add_slot",
        &ci(&s.reg_vault, &s.log1)
            .with("label", "Phone")
            .with("password", "phone passphrase 1")
            .with("kdf", kdf_min())
            .with("random", "add"),
    );
    if let (Some(cv), Some(d), Some(a)) = (changed_vault, data, added) {
        out.push(v(
            "replacement changing one password lock",
            &["VLT-4", "LCK-10"],
            "vault_change",
            m().with("old", s.reg_vault.clone()).with("new", cv.clone()),
        ));
        out.push(v(
            "replacement changing only the contents",
            &["VLT-4", "HST-12"],
            "vault_change",
            m().with("old", s.reg_vault.clone()).with("new", d.clone()),
        ));
        out.push(v(
            "replacement with a new grant",
            &["VLT-4", "HST-12"],
            "vault_change",
            m().with("old", s.reg_vault.clone()).with("new", a.clone()),
        ));
        out.push(v(
            "replacement going back",
            &["VLT-4"],
            "vault_change",
            m().with("old", d.clone()).with("new", s.reg_vault.clone()),
        ));
        out.push(v(
            "replacement going back in the grant",
            &["VLT-4"],
            "vault_change",
            m().with("old", a.clone()).with("new", set(obj(&cv), "rev", 9i64)),
        ));
        let mut am = obj(&a);
        let mut locks = am.get("locks").and_then(Value::as_object).cloned().unwrap_or_default();
        let grant = set(
            locks
                .get("grant")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default(),
            "gen",
            1i64,
        );
        locks.insert("grant", grant.into());
        am.insert("locks", locks.into());
        am.insert("rev", 5i64.into());
        out.push(v(
            "replacement changing the grant without a new gen",
            &["VLT-4"],
            "vault_change",
            m().with("old", s.reg_vault.clone()).with("new", am),
        ));
    }
    for (pw, user, name) in [
        (PASSWORD, "Astra", "long enough"),
        ("short pass", "Astra", "too short"),
        ("astraastraastra", "AstraAstraAstra", "equals the username"),
        (
            "e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}",
            "Astra",
            "short after NFC",
        ),
    ] {
        out.push(v(
            &format!("password {name}"),
            &["LCK-8"],
            "check_password",
            m().with("password", pw).with("username", user),
        ));
    }
    out
}

fn run_value(op: &'static str, input: &Map) -> Option<Value> {
    match run(op, input) {
        Ok(Outcome::Ok(v)) => Some(v),
        _ => None,
    }
}

fn wrong_seed_vault(s: &Scenario, st1: &LogState) -> Value {
    use rootcard::vault::{Contents, contents_aad, vault_message};
    let Ok(u) = unlock_vault(&s.reg_vault, st1, &Secret::Recovery(&s.keys)) else {
        return Value::Bool(false);
    };
    let mut x = obj(&s.reg_vault);
    let contents = Contents {
        account_seed: zeroize::Zeroizing::new(sha256(b"another account seed")),
        data: m(),
        known: None,
    };
    let nonce = [5u8; 12];
    x.insert("nonce", base64url_encode(&nonce).into());
    let ct = rootcard::crypto::aes_gcm_encrypt(
        &u.vault_key,
        &nonce,
        &rootcard::json::canonical(&contents.to_value()),
        &contents_aad(&x),
    )
    .unwrap_or_default();
    x.insert("ct", base64url_encode(&ct).into());
    let sig = ed25519_sign(&s.account_seed, &vault_message(&x));
    x.insert("sig", base64url_encode(&sig).into());
    x.into()
}

// ---------------------------------------------------------------------------------------------------------------------
// profile.json

fn profile_vectors(s: &Scenario) -> Vec<V> {
    let mut out = Vec::new();
    for k in [
        "user.name",
        "app.xigna.level",
        "app.a-1.x_y",
        "user.",
        "app.x.",
        "app.-x.y",
        "name",
        "User.x",
        "sys.x",
        "app.x",
        &format!("user.{}", "a".repeat(60)),
    ] {
        out.push(v(
            &format!("data key {k:?}"),
            &["DAT-4"],
            "check_data_key",
            m().with("key", k),
        ));
    }
    let d = m().with("user.name", "Astra");
    out.push(v(
        "set an own key",
        &["DAT-7"],
        "set_data",
        m().with("data", d.clone())
            .with("app", "xigna")
            .with("key", "app.xigna.level")
            .with("value", 3i64),
    ));
    out.push(v(
        "set a user key",
        &["DAT-7"],
        "set_data",
        m().with("data", d.clone())
            .with("app", "xigna")
            .with("key", "user.motto")
            .with("value", m().with("text", "hi")),
    ));
    out.push(v(
        "set another application's key",
        &["DAT-7"],
        "set_data",
        m().with("data", d.clone())
            .with("app", "xigna")
            .with("key", "app.other.level")
            .with("value", 3i64),
    ));
    let pi = |events: &[Value]| log_input(events);
    out.push(v(
        "sign a profile",
        &["DAT-1", "DAT-2"],
        "sign_public",
        pi(&s.log1)
            .with("account_seed", h(&s.account_seed))
            .with("rev", 2i64)
            .with("data", d.clone()),
    ));
    out.push(v(
        "sign a profile with a bad key",
        &["DAT-4"],
        "sign_public",
        pi(&s.log1)
            .with("account_seed", h(&s.account_seed))
            .with("rev", 2i64)
            .with("data", m().with("name", "x")),
    ));
    out.push(v(
        "registered profile verifies",
        &["DAT-2"],
        "verify_public",
        pi(&s.log1).with("profile", s.reg_public.clone()),
    ));
    out.push(v(
        "profile of an old instance",
        &["DAT-2", "DAT-3"],
        "verify_public",
        pi(&s.log2).with("profile", s.reg_public.clone()),
    ));
    out.push(v(
        "restored profile verifies",
        &["DAT-2"],
        "verify_public",
        pi(&s.log2).with("profile", s.public2.clone()),
    ));
    out.push(v(
        "profile of a retired identity",
        &["DAT-2"],
        "verify_public",
        pi(&s.log4).with("profile", s.public2.clone()),
    ));
    let mut t = obj(&s.reg_public);
    t.insert("data", m().with("user.name", "Mallory").into());
    out.push(v(
        "tampered profile",
        &["DAT-2"],
        "verify_public",
        pi(&s.log1).with("profile", t),
    ));
    let mut r0 = obj(&s.reg_public);
    r0.insert("rev", 0i64.into());
    out.push(v(
        "profile rev 0",
        &["DAT-2"],
        "verify_public",
        pi(&s.log1).with("profile", r0),
    ));
    out.push(v(
        "profile too large",
        &["DAT-1"],
        "verify_public",
        pi(&s.log1).with(
            "profile",
            set(obj(&s.reg_public), "data", m().with("user.big", "x".repeat(17000))),
        ),
    ));
    out
}

// ---------------------------------------------------------------------------------------------------------------------
// proof.json

fn proof_vectors(s: &Scenario) -> Vec<V> {
    let mut out = Vec::new();
    for url in [
        "https://id.example.com",
        "https://example.com/rootcard",
        "https://api.example.com:8443/auth/rootcard",
        "https://example.com/v0x",
        "http://127.0.0.1:8787",
        "http://localhost:8787/rootcard",
        "http://[::1]:8787",
        "id.example.com",
        "http://example.com",
        "http://localhost.example.com",
        "https://example.com/",
        "https://example.com//rootcard",
        "https://example.com/v0",
        "https://example.com/rootcard/V12",
        "https://example.com/rootcard?x=1",
        "https://user@example.com",
        "https://example.com/v0/..",
        "https://example.com/rootcard/.",
        "https://example.com/../rootcard",
        "https://example.com/%76%30",
        "https://example.com/root%2Fcard",
        "https://example.com/my_root-card.v2~x",
        "https://example.com/root;v=0",
    ] {
        out.push(v(
            &format!("base URL {url:?}"),
            &["HST-22"],
            "check_base_url",
            m().with("url", url),
        ));
    }
    // Host pointers ([HST-23]): accepted, and every reject in the order of the checks.
    let pointer = |base: &str, api: &[&str]| {
        Value::from(
            m().with("v", 1i64)
                .with("base", base)
                .with("api", Value::Array(api.iter().map(|a| Value::from(*a)).collect())),
        )
    };
    let mut many = m().with("v", 1i64).with("base", "https://example.com/rootcard");
    many.insert(
        "api",
        Value::Array((0..17).map(|i| Value::from(format!("v{i}"))).collect()),
    );
    for (name, origin, document) in [
        (
            "on a path",
            "https://example.com",
            pointer("https://example.com/rootcard", &["v0"]),
        ),
        (
            "to itself",
            "https://example.com",
            pointer("https://example.com", &["v0"]),
        ),
        (
            "host case",
            "https://Example.COM",
            pointer("https://example.com/auth/rootcard", &["v1", "v0"]),
        ),
        (
            "with a port",
            "http://127.0.0.1:8787",
            pointer("http://127.0.0.1:8787/rootcard", &["v0"]),
        ),
        (
            "origin with a path",
            "https://example.com/rootcard",
            pointer("https://example.com/rootcard", &["v0"]),
        ),
        (
            "origin not a base URL",
            "example.com",
            pointer("https://example.com/rootcard", &["v0"]),
        ),
        (
            "not an object",
            "https://example.com",
            Value::from("https://example.com/rootcard"),
        ),
        (
            "v 2",
            "https://example.com",
            Value::from(m().with("v", 2i64).with("base", "x")),
        ),
        (
            "missing api",
            "https://example.com",
            Value::from(m().with("v", 1i64).with("base", "https://example.com/r")),
        ),
        (
            "unknown member",
            "https://example.com",
            Value::from(obj(&pointer("https://example.com/rootcard", &["v0"])).with("realms", arr(&[]))),
        ),
        (
            "base with a version",
            "https://example.com",
            pointer("https://example.com/v0", &["v0"]),
        ),
        (
            "base with a dot segment",
            "https://example.com",
            pointer("https://example.com/v0/..", &["v0"]),
        ),
        (
            "no versions",
            "https://example.com",
            pointer("https://example.com/rootcard", &[]),
        ),
        ("17 versions", "https://example.com", Value::from(many.clone())),
        (
            "duplicate version",
            "https://example.com",
            pointer("https://example.com/rootcard", &["v0", "v0"]),
        ),
        (
            "not a version",
            "https://example.com",
            pointer("https://example.com/rootcard", &["0"]),
        ),
        (
            "another host",
            "https://example.com",
            pointer("https://id.example.net/rootcard", &["v0"]),
        ),
        (
            "a longer host",
            "https://example.com",
            pointer("https://example.com.evil.example/rootcard", &["v0"]),
        ),
        (
            "another port",
            "https://example.com",
            pointer("https://example.com:8443/rootcard", &["v0"]),
        ),
        (
            "another scheme",
            "http://localhost:8787",
            pointer("https://localhost:8787/rootcard", &["v0"]),
        ),
        (
            "without v0",
            "https://example.com",
            pointer("https://example.com/rootcard", &["v1"]),
        ),
    ] {
        out.push(v(
            &format!("host pointer: {name}"),
            &["HST-23"],
            "well_known_base",
            m().with("origin", origin).with("document", document),
        ));
    }
    let st1 = verify_log(&s.log1, &opts());
    let Ok(st1) = st1 else { return out };
    let host = format_key(KeyType::Ed25519, &ed25519_public(&HOST_A));
    let nonce = sha256(b"challenge nonce");
    out.push(v(
        "login message",
        &["LGN-1", "DS-1"],
        "login_message",
        m().with("account", st1.account.as_str())
            .with("host", host.as_str())
            .with("lock", s.slot.as_str())
            .with("nonce", h(&nonce))
            .with("realm", "global")
            .with("url", "https://a.example")
            .with("version", st1.version.to_value()),
    ));
    out.push(v(
        "fetch message",
        &["FET-1"],
        "fetch_message",
        m().with("account", st1.account.as_str())
            .with("host", host.as_str())
            .with("lock", "recovery")
            .with("nonce", h(&nonce))
            .with("url", "https://a.example"),
    ));
    out.push(v(
        "change message",
        &["CHG-1"],
        "change_message",
        m().with("account", st1.account.as_str())
            .with("host", host.as_str())
            .with("lock", s.slot.as_str())
            .with("new", h(&sha256(b"new lock")))
            .with("nonce", h(&nonce))
            .with("url", "https://a.example"),
    ));
    let ch = Challenge {
        nonce,
        host: ed25519_public(&HOST_A),
        realm: "global".into(),
        version: st1.version,
        expires: T0 + 60,
    };
    let lock_seed = s.keys.sign_seed.as_ref();
    let li = log_input(&s.log1)
        .with("url", "https://a.example")
        .with("lock", "recovery")
        .with("account_seed", h(&s.account_seed))
        .with("lock_seed", h(lock_seed));
    out.push(v(
        "login request",
        &["LGN-1"],
        "login_sign",
        li.clone().with("challenge", ch.to_value()),
    ));
    let mut wrong_host = ch.clone();
    wrong_host.host = ed25519_public(&HOST_B);
    out.push(v(
        "login challenge from another host",
        &["LGN-1", "CLT-3"],
        "login_sign",
        li.clone().with("challenge", wrong_host.to_value()),
    ));
    let mut stale = ch.clone();
    stale.version.seq = 0;
    out.push(v(
        "login challenge for another version",
        &["LGN-1"],
        "login_sign",
        li.clone().with("challenge", stale.to_value()),
    ));
    if let Some(Value::Object(req)) = run_value("login_sign", &li.clone().with("challenge", ch.to_value())) {
        let rk = format_key(KeyType::Ed25519, &st1.recovery);
        out.push(v(
            "login request verifies",
            &["LGN-1", "LGN-5"],
            "login_verify",
            log_input(&s.log1)
                .with("request", req.clone())
                .with("lock_key", rk.as_str()),
        ));
        out.push(v(
            "login request with the wrong lock key",
            &["LGN-5"],
            "login_verify",
            log_input(&s.log1)
                .with("request", req.clone())
                .with("lock_key", host.as_str()),
        ));
        out.push(v(
            "login request for another address",
            &["LGN-4"],
            "login_verify",
            log_input(&s.log1)
                .with("request", set(req.clone(), "url", "https://evil.example"))
                .with("lock_key", rk.as_str()),
        ));
        // Regression found by the differential test: the JS core counted UTF-16 units, so 9 characters of 2 bytes
        // passed there and failed in Rust.
        out.push(v(
            "login request with a lock id of more than 16 bytes",
            &["LGN-1"],
            "login_verify",
            log_input(&s.log1)
                .with(
                    "request",
                    set(
                        req.clone(),
                        "lock",
                        "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
                    ),
                )
                .with("lock_key", rk.as_str()),
        ));
    }
    // Proofs.
    let st2 = verify_log(&s.log2, &opts());
    let Ok(st2) = st2 else { return out };
    let challenge = statement_challenge(&Value::from("sign in to example.org")).unwrap_or([0; 32]);
    let pv = |by: &str, seed: &[u8; 32], log: &[Value]| {
        log_input(log)
            .with("by", by)
            .with("seed", h(seed))
            .with("challenge", h(&challenge))
            .with("recipient", "example.org")
    };
    out.push(v(
        "account proof",
        &["PRF-1", "PRF-3"],
        "prove",
        pv("account", &s.account_seed2, &s.log2),
    ));
    out.push(v(
        "root proof",
        &["PRF-2"],
        "prove",
        pv("recovery", &s.keys.sign_seed, &s.log2),
    ));
    out.push(v(
        "account proof with an old account key",
        &["PRF-1"],
        "prove",
        pv("account", &s.account_seed, &s.log2),
    ));
    let account_proof = prove(&st2, ProofBy::Account, &s.account_seed2, &challenge, "example.org");
    let root_proof = prove(&st2, ProofBy::Recovery, &s.keys.sign_seed, &challenge, "example.org");
    let old_proof = prove(&st1, ProofBy::Account, &s.account_seed, &challenge, "example.org");
    if let (Ok(ap), Ok(rp), Ok(op)) = (account_proof, root_proof, old_proof) {
        let vp = |p: &Value, log: &[Value]| {
            m().with("proof", p.clone())
                .with("log", arr(log))
                .with("challenge", h(&challenge))
                .with("recipient", "example.org")
        };
        out.push(v(
            "account proof verifies",
            &["PRF-4"],
            "verify_proof",
            vp(&ap, &s.log2),
        ));
        out.push(v(
            "account proof survives a rotation",
            &["PRF-1"],
            "verify_proof",
            vp(&ap, &s.log3),
        ));
        out.push(v(
            "account proof of an old instance",
            &["PRF-1", "PRF-4"],
            "verify_proof",
            vp(&op, &s.log2),
        ));
        out.push(v(
            "account proof after retire",
            &["PRF-4"],
            "verify_proof",
            vp(&ap, &s.log4),
        ));
        out.push(v(
            "root proof verifies",
            &["PRF-2", "PRF-4"],
            "verify_proof",
            vp(&rp, &s.log2),
        ));
        out.push(v(
            "root proof after a rotation",
            &["PRF-2"],
            "verify_proof",
            vp(&rp, &s.log3),
        ));
        out.push(v(
            "proof for another recipient",
            &["PRF-3", "PRF-4"],
            "verify_proof",
            vp(&ap, &s.log2).with("recipient", "evil.org"),
        ));
        out.push(v(
            "proof for another challenge",
            &["PRF-4"],
            "verify_proof",
            vp(&ap, &s.log2).with("challenge", h(&[0; 32])),
        ));
        out.push(v(
            "proof with a forged log",
            &["PRF-4"],
            "verify_proof",
            vp(&ap, &[s.log2[0].clone(), tamper_sig(&s.log2[1], 1)]),
        ));
        out.push(v(
            "proof against another identity",
            &["PRF-4"],
            "verify_proof",
            vp(&ap, &[run_inception(&sha256(b"another key"))]),
        ));
        let mut t = obj(&ap);
        t.insert("recipient", "example.org ".into());
        let t: Value = t.into();
        out.push(v(
            "tampered proof",
            &["PRF-4"],
            "verify_proof",
            vp(&t, &s.log2).with("recipient", "example.org "),
        ));
    }
    out
}

// ---------------------------------------------------------------------------------------------------------------------
// file.json

fn file_vectors(s: &Scenario) -> Vec<V> {
    let mut out = Vec::new();
    out.push(v(
        "export",
        &["FIL-2"],
        "export_account",
        log_input(&s.log2)
            .with("public", s.public2.clone())
            .with("vault", s.vault2.clone()),
    ));
    let Ok(st2) = verify_log(&s.log2, &opts()) else {
        return out;
    };
    let file = export_account(&st2, &s.log2, Some(&s.public2), Some(&s.vault2), None);
    out.push(v(
        "import",
        &["FIL-3"],
        "import_account",
        m().with("file", file.clone()),
    ));
    let fm = obj(&file);
    out.push(v(
        "import with host data",
        &["FIL-2", "FIL-3"],
        "import_account",
        m().with("file", set(fm.clone(), "host_data", m().with("note", "x"))),
    ));
    out.push(v(
        "import of another format",
        &["FIL-3"],
        "import_account",
        m().with("file", set(fm.clone(), "format", "rootcard-card")),
    ));
    out.push(v(
        "import with a wrong handle",
        &["FIL-3"],
        "import_account",
        m().with("file", set(fm.clone(), "handle", "Astra#0000")),
    ));
    out.push(v(
        "import with a stale version",
        &["FIL-3"],
        "import_account",
        m().with(
            "file",
            set(fm.clone(), "version", st2.version.to_value()).with("log", arr(&s.log3)),
        ),
    ));
    out.push(v(
        "import with the vault of another instance",
        &["FIL-3", "FIL-4"],
        "import_account",
        m().with("file", set(fm.clone(), "vault", s.reg_vault.clone())),
    ));
    out.push(v(
        "import with too much host data",
        &["FIL-2"],
        "import_account",
        m().with(
            "file",
            set(fm.clone(), "host_data", m().with("note", "x".repeat(17000))),
        ),
    ));
    // Cards.
    out.push(v(
        "registration card",
        &["CRD-1", "CRD-3"],
        "read_card",
        m().with("card", s.reg_card.clone()),
    ));
    out.push(v(
        "card after a rotation",
        &["CRD-2", "CRD-3"],
        "read_card",
        m().with("card", s.card3.clone()),
    ));
    let rc = obj(&s.reg_card);
    out.push(v(
        "card of another account",
        &["CRD-3"],
        "read_card",
        m().with("card", set(rc.clone(), "account", "0".repeat(52))),
    ));
    out.push(v(
        "card with a wrong username",
        &["CRD-3"],
        "read_card",
        m().with("card", set(rc.clone(), "username", "Astrb")),
    ));
    let key = rc.get("key").and_then(Value::as_str).unwrap_or("").to_string();
    let mut bad = key.clone();
    let last = if key.ends_with('0') { "1" } else { "0" };
    bad.replace_range(key.len() - 1.., last);
    out.push(v(
        "card with a bad checksum",
        &["CRD-3", "RK-2"],
        "read_card",
        m().with("card", set(rc.clone(), "key", bad)),
    ));
    let mut rotated_no_log = obj(&s.card3);
    rotated_no_log.remove("log");
    out.push(v(
        "rotated card without its log",
        &["CRD-2", "CRD-3"],
        "read_card",
        m().with("card", rotated_no_log),
    ));
    out.push(v(
        "old card with the rotated log",
        &["CRD-3", "RK-5"],
        "read_card",
        m().with("card", set(rc.clone(), "log", arr(&s.log3))),
    ));
    out.push(v(
        "card text",
        &["CRD-4"],
        "card_text",
        m().with("card", s.reg_card.clone()),
    ));
    out.push(v(
        "build a card",
        &["CRD-1"],
        "read_card",
        m().with("card", recovery_card("global", "Astra", &st2.account, &s.rk, None)),
    ));
    out
}

// ---------------------------------------------------------------------------------------------------------------------

// link.json

/// A JSON literal from the generator's own source.
fn j(text: &str) -> Value {
    rootcard::parse_json(text.as_bytes()).unwrap_or_else(|_| Value::from(format!("bad literal {text}")))
}

/// The bundled descriptor of `service`, as JSON.
fn descriptor_json(service: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../spec/links/{service}.json"));
    let text = std::fs::read(path).unwrap_or_default();
    rootcard::parse_json(&text).unwrap_or_else(|_| Value::from("missing descriptor"))
}

/// `d` with the JSON pointer-like `path` (member names) set to `val`, or removed for `None`.
fn edit(d: &Value, path: &[&str], val: Option<Value>) -> Value {
    let mut m = obj(d);
    match path {
        [] => {}
        [k] => {
            match val {
                Some(v) => m.insert(*k, v),
                None => m.remove(k),
            };
        }
        [k, rest @ ..] => {
            let inner = m.get(k).cloned().unwrap_or_else(m_val);
            m.insert(*k, edit(&inner, rest, val));
        }
    }
    m.into()
}

fn m_val() -> Value {
    Map::new().into()
}

fn link_vectors(s: &Scenario) -> Result<Vec<V>, String> {
    let account = verify_log(&s.log1, &opts()).map_err(|e| e.to_string())?.account;
    let other = rootcard::encoding::base32_encode(&[0x42; 32]);
    let token = format!("rootcard:{account}");
    let mut out = Vec::new();

    // Answers from outside rootcard ([LNK-9]).
    for (name, text) in [
        (
            "an answer with null, fractions and large numbers",
            r#"{"login":"alice","id":583231,"bio":null,"score":1.5,"big":12345678901234567890,"e":1e3,"list":[null,1,-0,"x"]}"#,
        ),
        ("an answer that is null", "null"),
        ("an answer with escapes", r#"{"bio":"A😀\/\n"}"#),
        ("a duplicate member", r#"{"a":1,"a":2}"#),
        (
            "a duplicate member whose first value is dropped",
            r#"{"a":null,"a":"x"}"#,
        ),
        ("a lone surrogate escape", r#"{"a":"\ud800"}"#),
        ("a number without digits after the point", "[1.]"),
        ("an exponent without digits", "[1e+]"),
        ("a leading zero", "[01]"),
        ("trailing text", "{} x"),
        ("a byte order mark", "\u{feff}{}"),
    ] {
        out.push(v(
            name,
            &["LNK-9"],
            "parse_response_json",
            m().with("text", h(text.as_bytes())),
        ));
    }
    let limit = "[".repeat(16) + "\t" + &"[".repeat(16) + &"]".repeat(32);
    out.push(v(
        "an answer nested 32 levels",
        &["LNK-9", "CJ-5"],
        "parse_response_json",
        m().with("text", h(limit.as_bytes())),
    ));
    let deep = "[".repeat(33) + &"]".repeat(33);
    out.push(v(
        "an answer nested 33 levels",
        &["LNK-9"],
        "parse_response_json",
        m().with("text", h(deep.as_bytes())),
    ));
    out.push(v(
        "an answer that is not UTF-8",
        &["LNK-9"],
        "parse_response_json",
        m().with("text", "22ff22"),
    ));

    // Tokens ([LNK-5], [LNK-6]).
    out.push(v(
        "the link token",
        &["LNK-5"],
        "link_token",
        m().with("account", account.as_str()),
    ));
    out.push(v(
        "the link token of a lower-case id",
        &["LNK-5", "ID-3"],
        "link_token",
        m().with("account", account.to_lowercase()),
    ));
    let tl = token.len() as i64;
    let lim = rootcard::links::TOKEN_SEARCH_LIMIT as i64;
    for (name, text, pad) in [
        ("token alone", token.clone(), 0),
        ("token in a sentence", format!("My rootcard: {token}."), 0),
        ("token in a URL", format!("https://example.org/?{token}&x"), 0),
        ("token followed by an underscore", format!("{token}_"), 0),
        ("token after a letter", format!("x{token}"), 0),
        ("token followed by a digit", format!("{token}0"), 0),
        ("token in lower case", token.to_lowercase(), 0),
        ("token after a bad occurrence", format!("a{token} {token}"), 0),
        ("tokens of two identities", format!("rootcard:{other} {token}"), 0),
        ("the token of another identity", format!("rootcard:{other}"), 0),
        ("token ending at the search limit", token.clone(), lim - tl),
        ("token past the search limit", token.clone(), lim - tl + 1),
    ] {
        out.push(v(
            name,
            &["LNK-6"],
            "find_link_token",
            m().with("account", account.as_str())
                .with("text", text)
                .with("pad", pad),
        ));
    }
    out.push(v(
        "token between bytes that are not UTF-8",
        &["LNK-6"],
        "find_link_token",
        m().with("account", account.as_str())
            .with("hex", format!("ff{}fe", hex_encode(token.as_bytes()))),
    ));
    out.push(v(
        "token search with an invalid id",
        &["LNK-6", "ID-3"],
        "find_link_token",
        m().with("account", "3F9C").with("text", ""),
    ));

    // Descriptors ([LNK-22], [LNK-7], [LNK-8], [LNK-13], [LNK-18]).
    let gh = descriptor_json("github");
    let web = descriptor_json("web");
    let dns = descriptor_json("dns");
    for (service, d) in [("github", &gh), ("dns", &dns), ("web", &web)] {
        out.push(v(
            &format!("registry descriptor {service}"),
            &["LNK-22", "LNK-19"],
            "parse_descriptor",
            m().with("descriptor", d.clone()),
        ));
    }
    let gh_bio_step = |step: Value| edit(&gh, &["checks"], Some(m().with("bio", arr(&[step])).into()));
    let bio_url = |url: &str| {
        gh_bio_step(j(&format!(
            r#"{{"kind":"http-json","url":"{url}","equal":{{"/id":"{{uid}}","/login":"{{name}}"}},"token_in":["/bio"]}}"#
        )))
    };
    let cases: Vec<(&str, &[&'static str], Value)> = vec![
        ("descriptor v 2", &["LNK-13"], edit(&gh, &["v"], Some(2i64.into()))),
        ("descriptor without v", &["LNK-22"], edit(&gh, &["v"], None)),
        (
            "descriptor with an unknown member",
            &["LNK-22"],
            edit(&gh, &["url"], Some("x".into())),
        ),
        (
            "descriptor with a bad service name",
            &["LNK-22"],
            edit(&gh, &["service"], Some("GitHub".into())),
        ),
        ("descriptor rev 0", &["LNK-22"], edit(&gh, &["rev"], Some(0i64.into()))),
        (
            "descriptor with an unknown status",
            &["LNK-22"],
            edit(&gh, &["status"], Some("paused".into())),
        ),
        (
            "retired descriptor",
            &["LNK-17"],
            edit(&gh, &["status"], Some("retired".into())),
        ),
        (
            "descriptor with an unknown field type",
            &["LNK-13"],
            edit(&gh, &["fields", "name", "type"], Some("handle".into())),
        ),
        (
            "descriptor with an unknown step kind",
            &["LNK-13"],
            gh_bio_step(j(r#"{"kind":"http-html","url":"https://github.com/{name}"}"#)),
        ),
        (
            "renamable names without a uid",
            &["LNK-18"],
            edit(
                &edit(&gh, &["fields", "uid"], None),
                &["checks"],
                Some(j(
                    r#"{"bio":[{"kind":"http-json","url":"https://api.github.com/users/{name}","equal":{"/login":"{name}"},"token_in":["/bio"]}]}"#,
                )),
            ),
        ),
        (
            "uid that no step compares",
            &["LNK-18"],
            gh_bio_step(j(
                r#"{"kind":"http-json","url":"https://api.github.com/user/{uid}","equal":{"/login":"{name}"},"token_in":["/bio"]}"#,
            )),
        ),
        (
            "name that no step compares",
            &["LNK-18"],
            gh_bio_step(j(
                r#"{"kind":"http-json","url":"https://api.github.com/user/{uid}","equal":{"/id":"{uid}"},"token_in":["/bio"]}"#,
            )),
        ),
        (
            "check that never looks for the token",
            &["LNK-22"],
            gh_bio_step(j(
                r#"{"kind":"http-json","url":"https://api.github.com/user/{uid}","equal":{"/id":"{uid}","/login":"{name}"}}"#,
            )),
        ),
        ("plain http", &["LNK-9"], bio_url("http://api.github.com/user/{uid}")),
        (
            "upper-case literal host",
            &["LNK-8"],
            bio_url("https://API.github.com/user/{uid}"),
        ),
        (
            "literal IP address host",
            &["LNK-8", "LNK-21"],
            bio_url("https://140.82.112.6/user/{uid}"),
        ),
        ("host without a path", &["LNK-8"], bio_url("https://api.github.com")),
        (
            "token field in the host",
            &["LNK-8"],
            bio_url("https://{name}.github.io/x/{uid}"),
        ),
        (
            "placeholder after a host prefix",
            &["LNK-8"],
            bio_url("https://api.github.com{uid}"),
        ),
        (
            "query in a template",
            &["LNK-8"],
            bio_url("https://api.github.com/user?id={uid}"),
        ),
        (
            "placeholder inside a path segment",
            &["LNK-8"],
            bio_url("https://api.github.com/user/u{uid}"),
        ),
        (
            "two placeholders in one segment",
            &["LNK-8"],
            bio_url("https://api.github.com/user/{uid}{name}"),
        ),
        (
            "unknown placeholder",
            &["LNK-22"],
            bio_url("https://api.github.com/user/{id}"),
        ),
        (
            "unclosed placeholder",
            &["LNK-22"],
            bio_url("https://api.github.com/user/{uid"),
        ),
        (
            "ref placeholder in a check without a ref value",
            &["LNK-22"],
            bio_url("https://api.github.com/gists/{ref}"),
        ),
        (
            "ref placeholder in the display URL",
            &["LNK-22"],
            edit(&gh, &["display"], Some("https://gist.github.com/{ref}".into())),
        ),
        (
            "wildcard in an equal pointer",
            &["LNK-22"],
            gh_bio_step(j(
                r#"{"kind":"http-json","url":"https://api.github.com/user/{uid}","equal":{"/*":"{uid}","/login":"{name}"},"token_in":["/bio"]}"#,
            )),
        ),
        (
            "bad pointer escape",
            &["LNK-22"],
            gh_bio_step(j(
                r#"{"kind":"http-json","url":"https://api.github.com/user/{uid}","equal":{"/id":"{uid}","/login":"{name}"},"token_in":["/b~2io"]}"#,
            )),
        ),
        (
            "pointer without a leading slash",
            &["LNK-22"],
            gh_bio_step(j(
                r#"{"kind":"http-json","url":"https://api.github.com/user/{uid}","equal":{"/id":"{uid}","/login":"{name}"},"token_in":["bio"]}"#,
            )),
        ),
        (
            "form without a check",
            &["LNK-22"],
            edit(&gh, &["checks", "gist"], None),
        ),
        (
            "check for an unknown form",
            &["LNK-22"],
            edit(
                &gh,
                &["checks", "repo"],
                Some(
                    edit(&gh, &[], None)
                        .as_object()
                        .and_then(|m| m.get("checks"))
                        .and_then(|c| c.as_object())
                        .and_then(|c| c.get("bio"))
                        .cloned()
                        .unwrap_or_else(m_val),
                ),
            ),
        ),
        ("five steps", &["LNK-22"], {
            let st = j(
                r#"{"kind":"http-json","url":"https://api.github.com/user/{uid}","equal":{"/id":"{uid}","/login":"{name}"},"token_in":["/bio"]}"#,
            );
            edit(
                &gh,
                &["checks"],
                Some(
                    m().with("bio", arr(&[st.clone(), st.clone(), st.clone(), st.clone(), st]))
                        .into(),
                ),
            )
        }),
        (
            "reversed character range",
            &["LNK-22"],
            edit(&gh, &["fields", "name", "chars"], Some("z-a".into())),
        ),
        (
            "min greater than max",
            &["LNK-22"],
            edit(&gh, &["fields", "name", "min"], Some(40i64.into())),
        ),
        (
            "uid with characters a link cannot hold",
            &["LNK-22", "LNK-1"],
            edit(&gh, &["fields", "uid", "chars"], Some("0-9/".into())),
        ),
        (
            "DNS name after the domain",
            &["LNK-22"],
            edit(
                &dns,
                &["checks"],
                Some(j(r#"{"*":[{"kind":"dns-txt","name":"{name}._rootcard"}]}"#)),
            ),
        ),
        (
            "DNS name for a token field",
            &["LNK-22"],
            edit(
                &gh,
                &["checks", "bio"],
                Some(j(
                    r#"[{"kind":"http-json","url":"https://api.github.com/user/{uid}","equal":{"/id":"{uid}","/login":"{name}"}},{"kind":"dns-txt","name":"_rootcard.{name}"}]"#,
                )),
            ),
        ),
    ];
    for (name, rules, d) in cases {
        out.push(v(name, rules, "parse_descriptor", m().with("descriptor", d)));
    }

    // user.links ([LNK-1], [LNK-2], [LNK-13]).
    let alice = j(r#"{"service":"github","name":"alice","uid":"583231","ref":"gist:5b1c0ffee"}"#);
    let links = |l: Vec<Value>| {
        m().with(
            "data",
            m().with("user.links", m().with("v", 1i64).with("links", arr(&l)))
                .with("user.name", "Astra"),
        )
    };
    out.push(v(
        "no links",
        &["LNK-2"],
        "parse_links",
        m().with("data", m().with("user.name", "Astra")),
    ));
    out.push(v(
        "links of three services",
        &["LNK-1", "LNK-2"],
        "parse_links",
        links(vec![
            alice.clone(),
            j(r#"{"service":"github","name":"Alice-2","uid":"9","ref":"bio"}"#),
            j(r#"{"service":"dns","name":"example.org"}"#),
            j(r#"{"service":"web","name":"xn--bcher-kva.example"}"#),
        ]),
    ));
    let whole: Vec<(&str, Value)> = vec![
        ("links v 2", m().with("v", 2i64).with("links", arr(&[])).into()),
        ("links without v", m().with("links", arr(&[])).into()),
        (
            "links with an extra member",
            m().with("v", 1i64).with("links", arr(&[])).with("x", true).into(),
        ),
        (
            "links that are not a list",
            m().with("v", 1i64).with("links", m()).into(),
        ),
        ("links that are a string", "github:alice".into()),
        (
            "17 links",
            m().with("v", 1i64)
                .with(
                    "links",
                    arr(&(0..17)
                        .map(|k| j(&format!(r#"{{"service":"dns","name":"d{k}.example"}}"#)))
                        .collect::<Vec<_>>()),
                )
                .into(),
        ),
    ];
    for (name, val) in whole {
        out.push(v(
            name,
            &["LNK-1", "LNK-2", "LNK-13"],
            "parse_links",
            m().with("data", m().with("user.links", val)),
        ));
    }
    let entries: Vec<(&str, &[&'static str], Vec<Value>)> = vec![
        (
            "16 links",
            &["LNK-1"],
            (0..16)
                .map(|k| j(&format!(r#"{{"service":"dns","name":"d{k}.example"}}"#)))
                .collect(),
        ),
        (
            "a link with an unknown member",
            &["LNK-1"],
            vec![
                j(r#"{"service":"dns","name":"example.org","url":"https://evil.example/"}"#),
                j(r#"{"service":"web","name":"example.org"}"#),
            ],
        ),
        (
            "a link that is not an object",
            &["LNK-1"],
            vec!["dns:example.org".into()],
        ),
        (
            "a link with a number name",
            &["LNK-1"],
            vec![j(r#"{"service":"dns","name":5}"#)],
        ),
        (
            "a link with an empty name",
            &["LNK-1"],
            vec![j(r#"{"service":"dns","name":""}"#)],
        ),
        (
            "a link with a bad service name",
            &["LNK-1"],
            vec![j(r#"{"service":"Dns","name":"example.org"}"#)],
        ),
        (
            "a link to an unknown service",
            &["LNK-13"],
            vec![j(r#"{"service":"gitlab","name":"alice","uid":"1","ref":"bio"}"#)],
        ),
        (
            "a GitHub name with a dot",
            &["LNK-2"],
            vec![j(r#"{"service":"github","name":"al.ice","uid":"1","ref":"bio"}"#)],
        ),
        (
            "a GitHub name of 40 characters",
            &["LNK-2"],
            vec![
                Map::new()
                    .with("service", "github")
                    .with("name", "a".repeat(40))
                    .with("uid", "1")
                    .with("ref", "bio")
                    .into(),
            ],
        ),
        (
            "a GitHub link without uid",
            &["LNK-18"],
            vec![j(r#"{"service":"github","name":"alice","ref":"bio"}"#)],
        ),
        (
            "a GitHub uid with letters",
            &["LNK-2"],
            vec![j(r#"{"service":"github","name":"alice","uid":"58x","ref":"bio"}"#)],
        ),
        (
            "a GitHub link without ref",
            &["LNK-2"],
            vec![j(r#"{"service":"github","name":"alice","uid":"1"}"#)],
        ),
        (
            "a GitHub ref of an unknown form",
            &["LNK-13"],
            vec![j(
                r#"{"service":"github","name":"alice","uid":"1","ref":"repo:alice/x"}"#,
            )],
        ),
        (
            "a GitHub ref with a value for bio",
            &["LNK-2"],
            vec![j(r#"{"service":"github","name":"alice","uid":"1","ref":"bio:x"}"#)],
        ),
        (
            "a GitHub gist ref without a value",
            &["LNK-2"],
            vec![j(r#"{"service":"github","name":"alice","uid":"1","ref":"gist"}"#)],
        ),
        (
            "a GitHub gist ref with an empty value",
            &["LNK-2"],
            vec![j(r#"{"service":"github","name":"alice","uid":"1","ref":"gist:"}"#)],
        ),
        (
            "a GitHub gist ref in upper case",
            &["LNK-2"],
            vec![j(r#"{"service":"github","name":"alice","uid":"1","ref":"gist:5B1C"}"#)],
        ),
        (
            "a ref form with a bad character",
            &["LNK-2"],
            vec![j(r#"{"service":"github","name":"alice","uid":"1","ref":"Gist:5b1c"}"#)],
        ),
        (
            "a dot-segment gist value",
            &["LNK-8"],
            vec![j(r#"{"service":"github","name":"alice","uid":"1","ref":"gist:.."}"#)],
        ),
        (
            "a domain link with a uid",
            &["LNK-2"],
            vec![j(r#"{"service":"dns","name":"example.org","uid":"1"}"#)],
        ),
        (
            "a domain link with a ref",
            &["LNK-13"],
            vec![j(r#"{"service":"dns","name":"example.org","ref":"txt"}"#)],
        ),
        (
            "a domain in upper case",
            &["LNK-21"],
            vec![j(r#"{"service":"web","name":"Example.org"}"#)],
        ),
        (
            "an IP address as a domain",
            &["LNK-21"],
            vec![j(r#"{"service":"web","name":"192.168.0.1"}"#)],
        ),
        (
            "a single-label domain",
            &["LNK-21"],
            vec![j(r#"{"service":"web","name":"localhost"}"#)],
        ),
        (
            "a domain with a trailing dot",
            &["LNK-21"],
            vec![j(r#"{"service":"dns","name":"example.org."}"#)],
        ),
        (
            "a Unicode domain",
            &["LNK-21", "LNK-12"],
            vec![j(r#"{"service":"web","name":"bücher.example"}"#)],
        ),
        (
            "the same GitHub account twice",
            &["LNK-2"],
            vec![
                alice.clone(),
                j(r#"{"service":"github","name":"ALICE","uid":"583231","ref":"bio"}"#),
            ],
        ),
        (
            "the same domain for two services",
            &["LNK-2"],
            vec![
                j(r#"{"service":"dns","name":"example.org"}"#),
                j(r#"{"service":"web","name":"example.org"}"#),
            ],
        ),
        (
            "a duplicate after an invalid link",
            &["LNK-2"],
            vec![
                j(r#"{"service":"dns","name":"Example.org"}"#),
                j(r#"{"service":"dns","name":"example.org"}"#),
                j(r#"{"service":"dns","name":"example.org"}"#),
            ],
        ),
    ];
    for (name, rules, l) in entries {
        out.push(v(name, rules, "parse_links", links(l)));
    }
    let retired = edit(&gh, &["status"], Some("retired".into()));
    out.push(v(
        "a link to a retired service",
        &["LNK-17"],
        "parse_links",
        links(vec![alice.clone()]).with("descriptors", arr(&[retired.clone(), dns.clone()])),
    ));

    out.push(v(
        "links value",
        &["LNK-1", "LNK-4"],
        "links_value",
        m().with(
            "links",
            arr(&[alice.clone(), j(r#"{"service":"dns","name":"example.org"}"#)]),
        ),
    ));
    out.push(v(
        "links value with a duplicate",
        &["LNK-2", "LNK-4"],
        "links_value",
        m().with("links", arr(&[alice.clone(), alice.clone()])),
    ));
    out.push(v(
        "links value with an unknown service",
        &["LNK-13", "LNK-4"],
        "links_value",
        m().with("links", arr(&[j(r#"{"service":"gitlab","name":"alice"}"#)])),
    ));
    out.push(v(
        "links value with an invalid link",
        &["LNK-2", "LNK-4"],
        "links_value",
        m().with("links", arr(&[j(r#"{"service":"dns","name":"example"}"#)])),
    ));
    out.push(v(
        "links value with 17 links",
        &["LNK-1", "LNK-4"],
        "links_value",
        m().with(
            "links",
            arr(&(0..17)
                .map(|k| j(&format!(r#"{{"service":"dns","name":"d{k}.example"}}"#)))
                .collect::<Vec<_>>()),
        ),
    ));

    // Requests and display ([LNK-8], [LNK-10], [LNK-12]).
    let bio = j(r#"{"service":"github","name":"Alice","uid":"583231","ref":"bio"}"#);
    let dns_link = j(r#"{"service":"dns","name":"example.org"}"#);
    let web_link = j(r#"{"service":"web","name":"astra.dev"}"#);
    for (name, link) in [
        ("GitHub bio", &bio),
        ("GitHub gist", &alice),
        ("DNS", &dns_link),
        ("web", &web_link),
    ] {
        out.push(v(
            &format!("requests for a {name} link"),
            &["LNK-8", "LNK-10"],
            "link_requests",
            m().with("link", link.clone()),
        ));
        out.push(v(
            &format!("display URL of a {name} link"),
            &["LNK-12"],
            "link_display",
            m().with("link", link.clone()),
        ));
    }
    out.push(v(
        "requests for an invalid link",
        &["LNK-2", "LNK-10"],
        "link_requests",
        m().with("link", j(r#"{"service":"github","name":"alice","uid":"1"}"#)),
    ));
    out.push(v(
        "requests for an unknown service",
        &["LNK-13"],
        "link_requests",
        m().with("link", j(r#"{"service":"gitlab","name":"alice"}"#)),
    ));
    out.push(v(
        "requests with another service's descriptor",
        &["LNK-10"],
        "link_requests",
        m().with("link", dns_link.clone()).with("service", "web"),
    ));
    let test = j(r#"{"v":1,"service":"test","rev":1,"status":"active",
        "fields":{"name":{"type":"token","chars":"!-~","min":1,"max":64},"uid":{"type":"token","chars":"0-9A-Za-z.:_-","min":1,"max":64}},
        "display":"https://example.org/u/{name}",
        "checks":{"*":[{"kind":"http-json","url":"https://example.org/u/{name}/{uid}","equal":{"/id":"{uid}","/name":"{name}","/tag":"id-{uid}"},"token_in":["/about","/links/*/text"]}]}}"#);
    out.push(v(
        "test descriptor",
        &["LNK-22"],
        "parse_descriptor",
        m().with("descriptor", test.clone()),
    ));
    let tl_link = j(r#"{"service":"test","name":"a/b?#%&+","uid":"x.y:z"}"#);
    out.push(v(
        "values are percent-encoded",
        &["LNK-8"],
        "link_requests",
        m().with("link", tl_link.clone())
            .with("descriptors", arr(std::slice::from_ref(&test))),
    ));
    out.push(v(
        "display values are percent-encoded",
        &["LNK-8", "LNK-12"],
        "link_display",
        m().with("link", tl_link.clone())
            .with("descriptors", arr(std::slice::from_ref(&test))),
    ));
    for dot in [".", ".."] {
        out.push(v(
            &format!("the name {dot:?} is never a value"),
            &["LNK-8"],
            "link_requests",
            m().with("link", m().with("service", "test").with("name", dot).with("uid", "1"))
                .with("descriptors", arr(std::slice::from_ref(&test))),
        ));
    }
    out.push(v(
        "the name ... is a value",
        &["LNK-8"],
        "link_requests",
        m().with("link", m().with("service", "test").with("name", "...").with("uid", "1"))
            .with("descriptors", arr(std::slice::from_ref(&test))),
    ));

    // Checking ([LNK-6], [LNK-7], [LNK-9], [LNK-10], [LNK-18], [LNK-20]).
    let user = |id: &str, login: &str, bio: &str| {
        format!(
            r#"{{"login":"{login}","id":{id},"node_id":"MDQ6VXNlcjU4MzIzMQ==","type":"User","site_admin":false,"name":null,"company":null,"bio":{bio},"public_repos":8,"created_at":"2011-03-01T12:00:00Z"}}"#
        )
    };
    let gist = |owner: &str, content: &str| {
        format!(
            r#"{{"id":"5b1c0ffee","public":true,"files":{{"rootcard.txt":{{"filename":"rootcard.txt","size":61,"content":"{content}"}},"other.md":{{"filename":"other.md","content":"hello"}}}},"owner":{owner},"comments":1,"history":[]}}"#
        )
    };
    let body = |t: String| m().with("text", t);
    let ok_bio = format!("\"Astronomer. {token}\"");
    let check = |name: &str, rules: &[&'static str], link: &Value, responses: Vec<Value>| {
        v(
            name,
            rules,
            "check_link",
            m().with("link", link.clone())
                .with("account", account.as_str())
                .with("responses", arr(&responses)),
        )
    };
    out.push(check(
        "GitHub bio verifies",
        &["LNK-10", "LNK-6"],
        &bio,
        vec![body(user("583231", "alice", &ok_bio)).into()],
    ));
    out.push(check(
        "GitHub bio of a renamed account",
        &["LNK-18", "LNK-10"],
        &bio,
        vec![body(user("583231", "alice2", &ok_bio)).into()],
    ));
    out.push(check(
        "GitHub bio of another account",
        &["LNK-18", "LNK-10"],
        &bio,
        vec![body(user("583232", "alice", &ok_bio)).into()],
    ));
    out.push(check(
        "GitHub id as a string",
        &["LNK-18"],
        &bio,
        vec![body(user("\"583231\"", "alice", &ok_bio)).into()],
    ));
    out.push(check(
        "GitHub id as a fraction",
        &["LNK-18"],
        &bio,
        vec![body(user("583231.0", "alice", &ok_bio)).into()],
    ));
    out.push(check(
        "GitHub bio without the token",
        &["LNK-10"],
        &bio,
        vec![body(user("583231", "alice", "\"Astronomer.\"")).into()],
    ));
    out.push(check(
        "GitHub bio null",
        &["LNK-10", "LNK-9"],
        &bio,
        vec![body(user("583231", "alice", "null")).into()],
    ));
    out.push(check(
        "GitHub bio with another identity's token",
        &["LNK-6", "LNK-10"],
        &bio,
        vec![body(user("583231", "alice", &format!("\"rootcard:{other}\""))).into()],
    ));
    out.push(check(
        "GitHub token outside the bio",
        &["LNK-7"],
        &bio,
        vec![
            body(user("583231", "alice", "\"x\"").replace("\"type\":\"User\"", &format!("\"type\":\"{token}\"")))
                .into(),
        ],
    ));
    out.push(check(
        "GitHub request failed",
        &["LNK-9", "LNK-10"],
        &bio,
        vec![m().with("failed", true).into()],
    ));
    out.push(check(
        "GitHub answer that is not JSON",
        &["LNK-9"],
        &bio,
        vec![body("<html>rate limited</html>".into()).into()],
    ));
    out.push(check(
        "GitHub answer over 64 KiB",
        &["LNK-9"],
        &bio,
        vec![
            body(user("583231", "alice", &ok_bio))
                .with(
                    "pad",
                    rootcard::links::RESPONSE_LIMIT as i64 - user("583231", "alice", &ok_bio).len() as i64 + 1,
                )
                .into(),
        ],
    ));
    out.push(check(
        "GitHub answer of exactly 64 KiB",
        &["LNK-9"],
        &bio,
        vec![
            body(user("583231", "alice", &ok_bio))
                .with(
                    "pad",
                    rootcard::links::RESPONSE_LIMIT as i64 - user("583231", "alice", &ok_bio).len() as i64,
                )
                .into(),
        ],
    ));
    out.push(check(
        "GitHub answer with a duplicate member",
        &["LNK-9"],
        &bio,
        vec![body(user("583231", "alice", &ok_bio).replace("\"type\"", "\"id\":1,\"type\"")).into()],
    ));
    let owner_ok = r#"{"login":"alice","id":583231}"#;
    out.push(check(
        "GitHub gist verifies",
        &["LNK-10", "LNK-7"],
        &alice,
        vec![
            body(user("583231", "alice", "null")).into(),
            body(gist(owner_ok, &token)).into(),
        ],
    ));
    out.push(check(
        "GitHub gist of another owner",
        &["LNK-18", "LNK-10"],
        &alice,
        vec![
            body(user("583231", "alice", "null")).into(),
            body(gist(r#"{"login":"mallory","id":7}"#, &token)).into(),
        ],
    ));
    out.push(check(
        "GitHub gist without an owner",
        &["LNK-18"],
        &alice,
        vec![
            body(user("583231", "alice", "null")).into(),
            body(gist("null", &token)).into(),
        ],
    ));
    out.push(check(
        "GitHub gist without the token",
        &["LNK-10"],
        &alice,
        vec![
            body(user("583231", "alice", "null")).into(),
            body(gist(owner_ok, "hi")).into(),
        ],
    ));
    out.push(check(
        "GitHub gist token only in a comment field",
        &["LNK-7"],
        &alice,
        vec![
            body(user("583231", "alice", "null")).into(),
            body(gist(owner_ok, "hi").replace("\"comments\":1", &format!("\"comments\":\"{token}\""))).into(),
        ],
    ));
    out.push(check(
        "GitHub gist of a renamed account",
        &["LNK-18"],
        &alice,
        vec![
            body(user("583231", "bob", "null")).into(),
            body(gist(owner_ok, &token)).into(),
        ],
    ));
    out.push(check(
        "GitHub gist with one answer",
        &["LNK-10"],
        &alice,
        vec![body(user("583231", "alice", "null")).into()],
    ));
    out.push(check(
        "GitHub gist, second request failed",
        &["LNK-9"],
        &alice,
        vec![
            body(user("583231", "alice", "null")).into(),
            m().with("failed", true).into(),
        ],
    ));
    out.push(check(
        "GitHub gist, first step fails before the second",
        &["LNK-10"],
        &alice,
        vec![body(user("1", "alice", "null")).into(), m().with("failed", true).into()],
    ));
    out.push(check(
        "DNS verifies",
        &["LNK-10"],
        &dns_link,
        vec![
            m().with(
                "txt",
                arr(&[
                    arr(&["v=spf1 -all".into()]),
                    arr(&["rootcard:".into(), account.as_str().into()]),
                ]),
            )
            .into(),
        ],
    ));
    out.push(check(
        "DNS token split across two records",
        &["LNK-10"],
        &dns_link,
        vec![
            m().with(
                "txt",
                arr(&[arr(&["rootcard:".into()]), arr(&[account.as_str().into()])]),
            )
            .into(),
        ],
    ));
    out.push(check(
        "DNS without records",
        &["LNK-10"],
        &dns_link,
        vec![m().with("txt", arr(&[])).into()],
    ));
    out.push(check(
        "DNS lookup failed",
        &["LNK-9"],
        &dns_link,
        vec![m().with("failed", true).into()],
    ));
    out.push(check(
        "DNS answered with a body",
        &["LNK-10"],
        &dns_link,
        vec![body(token.clone()).into()],
    ));
    out.push(check(
        "web file verifies",
        &["LNK-10"],
        &web_link,
        vec![body(format!("{token}\n")).into()],
    ));
    out.push(check(
        "web file with HTML around the token",
        &["LNK-6"],
        &web_link,
        vec![body(format!("<p>{token}</p>")).into()],
    ));
    out.push(check(
        "web file without the token",
        &["LNK-10"],
        &web_link,
        vec![body("hello".into()).into()],
    ));
    out.push(check(
        "web file answered with TXT records",
        &["LNK-10"],
        &web_link,
        vec![m().with("txt", arr(&[arr(&[token.as_str().into()])])).into()],
    ));
    out.push(v(
        "check with an invalid account id",
        &["LNK-10", "ID-3"],
        "check_link",
        m().with("link", web_link.clone())
            .with("account", "3F9C")
            .with("responses", arr(&[body(token.clone()).into()])),
    ));
    out.push(v(
        "check of an invalid link",
        &["LNK-2"],
        "check_link",
        m().with("link", j(r#"{"service":"web","name":"localhost"}"#))
            .with("account", account.as_str())
            .with("responses", arr(&[body(token.clone()).into()])),
    ));
    let test_body = |id: &str, nm: &str, tag: &str| {
        format!(r#"{{"id":"{id}","name":"{nm}","tag":"{tag}","links":[{{"text":"x"}},{{"text":"{token}"}}]}}"#)
    };
    let t1 = j(r#"{"service":"test","name":"Alice","uid":"77"}"#);
    let with_test = |name: &str, rules: &[&'static str], b: String| {
        v(
            name,
            rules,
            "check_link",
            m().with("link", t1.clone())
                .with("account", account.as_str())
                .with("descriptors", arr(std::slice::from_ref(&test)))
                .with("responses", arr(&[body(b).into()])),
        )
    };
    out.push(with_test(
        "token in an array element",
        &["LNK-10"],
        test_body("77", "Alice", "id-77"),
    ));
    out.push(with_test(
        "exact names differ in case",
        &["LNK-2", "LNK-18"],
        test_body("77", "alice", "id-77"),
    ));
    out.push(with_test(
        "a filled template differs",
        &["LNK-18"],
        test_body("77", "Alice", "id-78"),
    ));
    Ok(out)
}

/// Run every vector and produce the JSON of one file.
fn file(description: &str, vectors: Vec<V>) -> Result<Value, String> {
    let mut list = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for vec in vectors {
        if names.contains(&vec.name) {
            return Err(format!("duplicate vector name {:?}", vec.name));
        }
        names.push(vec.name.clone());
        let mut e = m()
            .with("name", vec.name.as_str())
            .with(
                "rules",
                Value::Array(vec.rules.iter().map(|r| Value::from(*r)).collect()),
            )
            .with("op", vec.op)
            .with("input", vec.input.clone());
        match run(vec.op, &vec.input).map_err(|e| format!("{}: {e}", vec.name))? {
            Outcome::Ok(o) => e.insert("output", o),
            Outcome::Err(err) => e.insert("error", err.code().into()),
        };
        list.push(e.into());
    }
    Ok(m()
        .with("description", description)
        .with("vectors", Value::Array(list))
        .into())
}

/// Every generated vector file: name and JSON.
pub fn files() -> Result<Vec<(&'static str, Value)>, String> {
    let s = scenario()?;
    Ok(vec![
        (
            "primitives.json",
            file(
                "Canonical JSON, encodings, recovery keys and the cryptographic primitives (SPEC §2–§6)",
                primitives(),
            )?,
        ),
        (
            "log.json",
            file(
                "Identities, handles, logs, incremental verification and comparison (SPEC §7–§10)",
                log_vectors(&s),
            )?,
        ),
        (
            "vault.json",
            file(
                "Vaults: creation, verification, unlocking and changes (SPEC §11, §13.4, §18)",
                vault_vectors(&s),
            )?,
        ),
        (
            "profile.json",
            file("Data keys and public profiles (SPEC §12)", profile_vectors(&s))?,
        ),
        (
            "proof.json",
            file(
                "Login, fetch and change messages, and proofs (SPEC §13, §14)",
                proof_vectors(&s),
            )?,
        ),
        (
            "file.json",
            file("Account files and recovery cards (SPEC §15)", file_vectors(&s))?,
        ),
        (
            "link.json",
            file(
                "Linked accounts: answers, tokens, descriptors, links, requests and checks (SPEC §12.3)",
                link_vectors(&s)?,
            )?,
        ),
    ])
}

/// Pretty JSON with two-space indentation, members in canonical order, a final newline.
pub fn pretty(v: &Value) -> String {
    let mut out = String::new();
    write_pretty(v, 0, &mut out);
    out.push('\n');
    out
}

fn write_pretty(v: &Value, indent: usize, out: &mut String) {
    let pad = |n: usize| "  ".repeat(n);
    let scalar = |v: &Value| String::from_utf8(rootcard::json::canonical(v)).unwrap_or_default();
    match v {
        Value::Object(m) if !m.is_empty() => {
            out.push_str("{\n");
            let n = m.len();
            for (i, (k, x)) in m.iter().enumerate() {
                out.push_str(&pad(indent + 1));
                out.push_str(&scalar(&Value::from(k)));
                out.push_str(": ");
                write_pretty(x, indent + 1, out);
                if i + 1 < n {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad(indent));
            out.push('}');
        }
        Value::Array(a) if !a.is_empty() => {
            if a.iter().all(|x| !matches!(x, Value::Object(_) | Value::Array(_))) && scalar(v).len() < 100 {
                out.push_str(&scalar(v));
                return;
            }
            out.push_str("[\n");
            for (i, x) in a.iter().enumerate() {
                out.push_str(&pad(indent + 1));
                write_pretty(x, indent + 1, out);
                if i + 1 < a.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad(indent));
            out.push(']');
        }
        _ => out.push_str(&scalar(v)),
    }
}
