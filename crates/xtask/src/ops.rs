//! The operations named by test vectors: each takes a JSON input and returns a JSON output or a rootcard error.
//! `packages/rootcard/test/ops.mjs` implements the same operations in JavaScript (SPEC §21).
//!
//! Conventions: byte strings in inputs and outputs are lower-case hex; JSON structures are embedded as JSON; `random`
//! names the seed of a [`TestRandom`] stream (UTF-8).

use rootcard::account::{InstanceMode, new_instance, register, rotate_recovery};
use rootcard::crypto::{self, ed25519_public};
use rootcard::encoding::{self, hex_decode, hex_encode};
use rootcard::file::{card_text, export_account, import_account, read_card};
use rootcard::id;
use rootcard::json::{Map, Value, canonical, parse_json};
use rootcard::keys::{KeyType, format_key, parse_key};
use rootcard::links::{self, Descriptor, Link, LinkResponse};
use rootcard::log::{
    Home, LogState, VerifyOptions, Version, add_receipt, compare_logs, extend_log, verify_log, verify_pending,
};
use rootcard::messages::{Challenge, LoginRequest, change_message, fetch_message, login_message};
use rootcard::profile::{check_data_key, set_data, sign_public, verify_public};
use rootcard::proof::{ProofBy, prove, statement_challenge, verify_proof};
use rootcard::recovery::{derive_recovery_keys, format_recovery_key, new_recovery_key, parse_recovery_key};
use rootcard::testing::TestRandom;
use rootcard::vault::{
    Kdf, NewSlot, Secret, VaultChange, add_slot, change_password, check_password, unlock_vault, update_contents,
    vault_change, verify_vault,
};
use rootcard::{Error, encoding::base64url_encode};

/// The result of an operation: `Err` is a rootcard error (an expected outcome); a malformed vector input is a bug in
/// the generator and is reported as `Bad`.
pub enum Outcome {
    Ok(Value),
    Err(Error),
}

type R<T> = Result<T, String>;

pub struct Input<'a>(pub &'a Map);

impl Input<'_> {
    fn get(&self, k: &str) -> R<&Value> {
        self.0.get(k).ok_or_else(|| format!("vector input: missing {k}"))
    }
    fn opt(&self, k: &str) -> Option<&Value> {
        self.0.get(k)
    }
    fn str(&self, k: &str) -> R<&str> {
        self.get(k)?
            .as_str()
            .ok_or_else(|| format!("vector input: {k} is not a string"))
    }
    fn int(&self, k: &str) -> R<i64> {
        self.get(k)?
            .as_int()
            .ok_or_else(|| format!("vector input: {k} is not an integer"))
    }
    fn hex(&self, k: &str) -> R<Vec<u8>> {
        hex_decode(self.str(k)?).map_err(|_| format!("vector input: {k} is not hex"))
    }
    fn hex32(&self, k: &str) -> R<[u8; 32]> {
        self.hex(k)?
            .try_into()
            .map_err(|_| format!("vector input: {k} is not 32 bytes"))
    }
    fn arr(&self, k: &str) -> R<&Vec<Value>> {
        self.get(k)?
            .as_array()
            .ok_or_else(|| format!("vector input: {k} is not an array"))
    }
    fn obj(&self, k: &str) -> R<&Map> {
        self.get(k)?
            .as_object()
            .ok_or_else(|| format!("vector input: {k} is not an object"))
    }
    fn realms(&self) -> R<VerifyOptions> {
        let realms = match self.opt("realms") {
            Some(v) => v
                .as_array()
                .ok_or("vector input: realms")?
                .iter()
                .map(|r| r.as_str().map(str::to_string).ok_or("vector input: realm"))
                .collect::<Result<Vec<_>, _>>()?,
            None => vec!["global".to_string()],
        };
        let mut o = VerifyOptions::new(realms);
        if let Some(n) = self.opt("now") {
            o.now = Some(n.as_int().ok_or("vector input: now")?);
        }
        Ok(o)
    }
    fn random(&self) -> R<TestRandom> {
        Ok(TestRandom::new(self.str("random")?.as_bytes()))
    }
    fn kdf(&self, k: &str) -> R<Kdf> {
        let m = Input(self.obj(k)?);
        Ok(Kdf {
            m: m.int("m")? as u32,
            t: m.int("t")? as u32,
            p: 1,
        })
    }
    fn text(&self) -> R<Vec<u8>> {
        text_of(self)
    }
    /// The descriptors of `descriptors`, or the bundled registry.
    fn registry(&self) -> R<Result<Vec<Descriptor>, Error>> {
        match self.opt("descriptors") {
            None => Ok(Ok(links::registry())),
            Some(v) => Ok(v
                .as_array()
                .ok_or("vector input: descriptors")?
                .iter()
                .map(links::parse_descriptor)
                .collect()),
        }
    }
    fn home(&self) -> R<Home> {
        let h = Input(self.obj("home")?);
        Ok(Home {
            key: ed25519_public(&h.hex32("seed")?),
            url: h.str("url")?.to_string(),
        })
    }
}

/// A text input: `text` (UTF-8) or `hex`, after `pad` spaces.
fn text_of(m: &Input<'_>) -> R<Vec<u8>> {
    let pad = match m.opt("pad") {
        None => 0,
        Some(p) => p
            .as_int()
            .filter(|p| (0..=1 << 20).contains(p))
            .ok_or("vector input: pad")?,
    };
    let mut b = vec![b' '; pad as usize];
    if m.opt("hex").is_some() {
        b.extend(m.hex("hex")?);
    } else {
        b.extend(m.str("text")?.as_bytes());
    }
    Ok(b)
}

/// A recorded answer: `{ failed: true }`, `{ text | hex, pad? }` (a body) or `{ txt: [[string, ...], ...] }`.
fn response(v: &Value) -> R<LinkResponse> {
    let m = Input(v.as_object().ok_or("vector input: response")?);
    if m.opt("failed").is_some() {
        return Ok(LinkResponse::Failed);
    }
    if let Some(t) = m.opt("txt") {
        let records = t
            .as_array()
            .ok_or("vector input: txt")?
            .iter()
            .map(|r| {
                r.as_array()
                    .ok_or("vector input: txt record")?
                    .iter()
                    .map(|s| {
                        s.as_str()
                            .map(|s| s.as_bytes().to_vec())
                            .ok_or("vector input: txt string")
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(LinkResponse::Txt(records));
    }
    Ok(LinkResponse::Body(text_of(&m)?))
}

fn hex(b: &[u8]) -> Value {
    hex_encode(b).into()
}

/// Verify the `events` input with the default options (realm `global`, no time check).
fn state_of(i: &Input<'_>) -> R<Result<LogState, Error>> {
    Ok(verify_log(i.arr("events")?, &VerifyOptions::new(["global"])))
}

macro_rules! tryr {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Ok(Outcome::Err(e)),
        }
    };
}

fn slot_list(info: &rootcard::vault::VaultInfo) -> Value {
    Value::Array(
        info.slots
            .iter()
            .map(|s| {
                Map::new()
                    .with("id", s.id.as_str())
                    .with("label", s.label.as_str())
                    .into()
            })
            .collect(),
    )
}

/// Run the operation `op` on `input`.
pub fn run(op: &str, input: &Map) -> R<Outcome> {
    let i = Input(input);
    let out: Value = match op {
        "canonical" => {
            let v = tryr!(parse_json(&i.hex("text")?));
            String::from_utf8(canonical(&v)).map_err(|e| e.to_string())?.into()
        }
        "base64url_encode" => encoding::base64url_encode(&i.hex("hex")?).into(),
        "base64url_decode" => hex(&tryr!(encoding::base64url_decode(i.str("text")?))),
        "base32_encode" => encoding::base32_encode(&i.hex("hex")?).into(),
        "base32_decode" => {
            let len = i.int("len")? as usize;
            let lenient = i.opt("lenient").and_then(Value::as_bool).unwrap_or(false);
            let r = if lenient {
                encoding::base32_decode_lenient(i.str("text")?, len)
            } else {
                encoding::base32_decode(i.str("text")?, len)
            };
            hex(&tryr!(r))
        }
        "random" => {
            let mut r = i.random()?;
            let mut b = vec![0u8; i.int("len")? as usize];
            r.fill(&mut b);
            hex(&b)
        }
        "parse_key" => {
            let t = match i.str("type")? {
                "ed25519" => KeyType::Ed25519,
                _ => KeyType::X25519,
            };
            hex(&tryr!(parse_key(i.str("text")?, t)))
        }
        "format_recovery_key" => format_recovery_key(&i.hex32("key")?).into(),
        "parse_recovery_key" => hex(tryr!(parse_recovery_key(i.str("text")?)).as_ref()),
        "derive_recovery_keys" => {
            let k = derive_recovery_keys(&i.hex32("key")?, i.str("realm")?, i.str("username")?);
            Map::new()
                .with("sign_seed", hex(k.sign_seed.as_ref()))
                .with("sign_public", hex(&k.sign_public()))
                .with("box_secret", hex(k.box_secret.as_ref()))
                .with("box_public", hex(&k.box_public()))
                .into()
        }
        "ed25519_sign" => {
            let seed = i.hex32("seed")?;
            // A public key on record that the seed is checked against first ([IMP-6]).
            if i.opt("known").is_some() && !crypto::ed25519_public_is(&seed, &i.hex32("known")?) {
                return Ok(Outcome::Err(Error::BadKey));
            }
            Map::new()
                .with("public", hex(&ed25519_public(&seed)))
                .with("sig", hex(&crypto::ed25519_sign(&seed, &i.hex("msg")?)))
                .into()
        }
        "ed25519_public_is" => crypto::ed25519_public_is(&i.hex32("seed")?, &i.hex32("public")?).into(),
        "new_recovery_key" => {
            let mut rng = i.random()?;
            let mut random = |b: &mut [u8]| rng.fill(b);
            hex(tryr!(new_recovery_key(i.str("realm")?, i.str("username")?, &mut random)).as_ref())
        }
        "ed25519_verify" => {
            tryr!(crypto::ed25519_verify(
                &i.hex("public")?,
                &i.hex("msg")?,
                &i.hex("sig")?
            ));
            true.into()
        }
        "x25519" => {
            let s = i.hex32("secret")?;
            let shared = tryr!(crypto::x25519(&s, &i.hex32("peer")?));
            Map::new()
                .with("public", hex(&crypto::x25519_public(&s)))
                .with("shared", hex(shared.as_ref()))
                .into()
        }
        "hkdf" => hex(crypto::hkdf(&i.hex("ikm")?, &i.hex("salt")?, &i.hex("info")?).as_ref()),
        "argon2id" => {
            let tag = tryr!(crypto::argon2id(
                &i.hex("password")?,
                &i.hex("salt")?,
                i.int("m")? as u32,
                i.int("t")? as u32,
                i.int("p")? as u32
            ));
            hex(tag.as_ref())
        }
        "aes_gcm_encrypt" => {
            let nonce: [u8; 12] = i.hex("nonce")?.try_into().map_err(|_| "nonce")?;
            hex(&tryr!(crypto::aes_gcm_encrypt(
                &i.hex32("key")?,
                &nonce,
                &i.hex("plaintext")?,
                &i.hex("aad")?,
            )))
        }
        "aes_gcm_decrypt" => {
            let nonce: [u8; 12] = i.hex("nonce")?.try_into().map_err(|_| "nonce")?;
            let pt = tryr!(crypto::aes_gcm_decrypt(
                &i.hex32("key")?,
                &nonce,
                &i.hex("ciphertext")?,
                &i.hex("aad")?
            ));
            hex(&pt)
        }
        "statement_challenge" => hex(&tryr!(statement_challenge(i.get("statement")?))),
        "check_realm" => {
            tryr!(id::check_realm(i.str("text")?));
            true.into()
        }
        "check_username" => {
            tryr!(id::check_username(i.str("text")?));
            true.into()
        }
        "default_username_policy" => id::default_username_policy(i.str("text")?).into(),
        "inception" => {
            let keys = derive_recovery_keys(&i.hex32("key")?, i.str("realm")?, i.str("username")?);
            let inc = tryr!(id::inception(&keys, i.str("realm")?, i.str("username")?));
            let account = id::account_id(&inc);
            Map::new()
                .with("handle", id::handle(i.str("username")?, &account))
                .with("account", account)
                .with("inception", inc)
                .into()
        }
        "parse_handle" => {
            let h = tryr!(id::parse_handle(i.str("text")?));
            let mut m = Map::new().with("username", h.username).with("tag", h.tag);
            if let Some(e) = h.extension {
                m.insert("extension", e.into());
            }
            m.into()
        }
        "extended_tags" => {
            let ids: Vec<String> = i
                .arr("ids")?
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            Value::Array(id::extended_tags(&ids).into_iter().map(Value::from).collect())
        }
        "verify_log" => tryr!(verify_log(i.arr("events")?, &i.realms()?)).to_value(),
        "extend_log" => {
            let base = tryr!(verify_log(i.arr("events")?, &VerifyOptions::new(["global"])));
            tryr!(extend_log(&base, i.arr("new")?, &i.realms()?)).to_value()
        }
        "verify_pending" => {
            let base = tryr!(state_of(&i)?);
            tryr!(verify_pending(&base, i.get("pending")?, i.int("now")?));
            true.into()
        }
        "compare_logs" => tryr!(compare_logs(i.arr("a")?, i.arr("b")?)).as_str().into(),
        "add_receipt" => {
            let mut e = i.obj("event")?.clone();
            add_receipt(&mut e, &i.hex32("host_seed")?);
            e.into()
        }
        "register" => {
            let mut rng = i.random()?;
            let mut random = |b: &mut [u8]| rng.fill(b);
            let reg = tryr!(register(
                &i.hex32("key")?,
                i.str("realm")?,
                i.str("username")?,
                i.str("password")?,
                i.str("label")?,
                &i.home()?,
                i.int("time")?,
                i.kdf("kdf")?,
                &mut random,
            ));
            Map::new()
                .with("account", reg.account)
                .with("log", Value::Array(reg.log))
                .with("vault", reg.vault)
                .with("public", reg.public)
                .with("card", reg.card)
                .into()
        }
        "verify_vault" => {
            let st = tryr!(state_of(&i)?);
            let info = tryr!(verify_vault(i.get("vault")?, &st));
            Map::new()
                .with("rev", info.rev)
                .with("gen", info.gen_)
                .with("slots", slot_list(&info))
                .with("hints", info.hints())
                .into()
        }
        "unlock_vault" => {
            let st = tryr!(state_of(&i)?);
            let u = match i.opt("recovery_key") {
                Some(_) => {
                    let keys = derive_recovery_keys(&i.hex32("recovery_key")?, &st.realm, &st.username);
                    tryr!(unlock_vault(i.get("vault")?, &st, &Secret::Recovery(&keys)))
                }
                None => tryr!(unlock_vault(
                    i.get("vault")?,
                    &st,
                    &Secret::Password {
                        lock: i.str("lock")?,
                        password: i.str("password")?
                    }
                )),
            };
            Map::new()
                .with("lock", u.lock.as_str())
                .with("account_key", format_key(KeyType::Ed25519, &u.account_key()))
                .with("lock_key", format_key(KeyType::Ed25519, &ed25519_public(&u.lock_seed)))
                .with("contents", u.contents.to_value())
                .into()
        }
        "change_password" | "add_slot" | "update_contents" | "rotate_recovery" | "new_instance" => {
            return vault_op(op, &i);
        }
        "vault_change" => match tryr!(vault_change(i.get("old")?, i.get("new")?)) {
            VaultChange::Data => Map::new().with("change", "data").into(),
            VaultChange::Grant => Map::new().with("change", "grant").into(),
            VaultChange::Password { slot, new_hash } => Map::new()
                .with("change", "password")
                .with("slot", slot)
                .with("new", base64url_encode(&new_hash))
                .into(),
        },
        "check_password" => {
            tryr!(check_password(i.str("password")?, i.str("username")?));
            true.into()
        }
        "check_base_url" => {
            tryr!(rootcard::check_base_url(i.str("url")?));
            true.into()
        }
        "well_known_base" => tryr!(rootcard::well_known_base(i.str("origin")?, i.get("document")?)).into(),
        "check_data_key" => {
            tryr!(check_data_key(i.str("key")?));
            true.into()
        }
        "set_data" => {
            let mut d = i.obj("data")?.clone();
            tryr!(set_data(&mut d, i.str("app")?, i.str("key")?, i.get("value")?.clone()));
            d.into()
        }
        "sign_public" => {
            let st = tryr!(state_of(&i)?);
            let inst = st.instance.as_ref().ok_or("vector input: no instance")?;
            tryr!(sign_public(
                &st.account,
                &base64url_encode(&inst.hash),
                i.int("rev")?,
                i.obj("data")?,
                &i.hex32("account_seed")?
            ))
        }
        "verify_public" => {
            let st = tryr!(state_of(&i)?);
            let p = tryr!(verify_public(i.get("profile")?, &st));
            Map::new().with("rev", p.rev).with("data", p.data).into()
        }
        "login_message" | "fetch_message" | "change_message" => {
            let host = tryr!(parse_key(i.str("host")?, KeyType::Ed25519));
            let nonce = i.hex32("nonce")?;
            let m = match op {
                "login_message" => {
                    let version = tryr!(Version::from_value(i.get("version")?));
                    login_message(
                        i.str("account")?,
                        &host,
                        i.str("lock")?,
                        &nonce,
                        i.str("realm")?,
                        i.str("url")?,
                        &version,
                    )
                }
                "fetch_message" => fetch_message(i.str("account")?, &host, i.str("lock")?, &nonce, i.str("url")?),
                _ => change_message(
                    i.str("account")?,
                    &host,
                    i.str("lock")?,
                    &i.hex32("new")?,
                    &nonce,
                    i.str("url")?,
                ),
            };
            hex(&m)
        }
        "login_sign" => {
            let st = tryr!(state_of(&i)?);
            let inst = st.instance.as_ref().ok_or("vector input: no instance")?;
            let ch = tryr!(Challenge::from_value(i.get("challenge")?));
            tryr!(LoginRequest::sign(
                &st.account,
                &st.realm,
                &inst.home.key,
                &st.version,
                &ch,
                i.str("url")?,
                i.str("lock")?,
                &i.hex32("account_seed")?,
                &i.hex32("lock_seed")?,
            ))
            .to_value()
        }
        "login_verify" => {
            let st = tryr!(state_of(&i)?);
            let inst = st.instance.as_ref().ok_or("vector input: no instance")?;
            let req = tryr!(LoginRequest::from_value(i.get("request")?));
            let lock_key = tryr!(parse_key(i.str("lock_key")?, KeyType::Ed25519));
            tryr!(req.verify(&st.realm, &inst.home.key, &inst.account_key, &lock_key));
            true.into()
        }
        "prove" => {
            let st = tryr!(state_of(&i)?);
            let by = if i.str("by")? == "account" {
                ProofBy::Account
            } else {
                ProofBy::Recovery
            };
            tryr!(prove(
                &st,
                by,
                &i.hex32("seed")?,
                &i.hex32("challenge")?,
                i.str("recipient")?
            ))
        }
        "verify_proof" => {
            let st = tryr!(verify_proof(
                i.get("proof")?,
                i.arr("log")?,
                &i.hex32("challenge")?,
                i.str("recipient")?,
                &i.realms()?
            ));
            st.version.to_value()
        }
        "export_account" => {
            let st = tryr!(state_of(&i)?);
            export_account(&st, i.arr("events")?, i.opt("public"), i.opt("vault"), None)
        }
        "import_account" => {
            let a = tryr!(import_account(i.get("file")?, &i.realms()?));
            let mut m = Map::new().with("state", a.state.to_value());
            if let Some((_, p)) = a.public {
                m.insert("public_rev", p.rev.into());
            }
            if let Some((_, v)) = a.vault {
                m.insert("vault_rev", v.rev.into());
            }
            m.into()
        }
        "read_card" => {
            let c = tryr!(read_card(i.get("card")?));
            Map::new()
                .with("account", c.account.as_str())
                .with("realm", c.realm.as_str())
                .with("username", c.username.as_str())
                .with("state", c.state.to_value())
                .into()
        }
        "card_text" => tryr!(card_text(i.get("card")?)).into(),
        "parse_response_json" => match tryr!(rootcard::json::parse_response_json(&i.hex("text")?)) {
            Some(v) => Map::new().with("value", v).into(),
            None => Map::new().into(),
        },
        "link_token" => tryr!(links::link_token(i.str("account")?)).into(),
        "find_link_token" => tryr!(links::find_link_token(&i.text()?, i.str("account")?)).into(),
        "parse_descriptor" => {
            let d = tryr!(links::parse_descriptor(i.get("descriptor")?));
            Map::new()
                .with("service", d.service.as_str())
                .with("rev", d.rev)
                .with("retired", d.retired)
                .into()
        }
        "parse_links" => {
            let reg = tryr!(i.registry()?);
            let entries = tryr!(links::parse_links(i.obj("data")?, &reg));
            Value::Array(
                entries
                    .iter()
                    .map(|e| {
                        let mut m = Map::new().with("status", e.status.map_or_else(|e| e.code(), |()| "ok"));
                        if let Some(l) = &e.link {
                            m.insert("link", l.to_value());
                        }
                        m.into()
                    })
                    .collect(),
            )
        }
        "links_value" => {
            let reg = tryr!(i.registry()?);
            let list = i
                .arr("links")?
                .iter()
                .map(Link::from_value)
                .collect::<Result<Vec<_>, _>>();
            tryr!(links::links_value(&tryr!(list), &reg))
        }
        "link_requests" | "link_display" | "check_link" => {
            let reg = tryr!(i.registry()?);
            let link = tryr!(Link::from_value(i.get("link")?));
            let service = i
                .opt("service")
                .and_then(Value::as_str)
                .unwrap_or(&link.service)
                .to_string();
            let Some(d) = links::find_descriptor(&reg, &service) else {
                return Ok(Outcome::Err(Error::Unsupported));
            };
            match op {
                "link_requests" => Value::Array(
                    tryr!(links::link_requests(&link, d))
                        .iter()
                        .map(links::LinkRequest::to_value)
                        .collect(),
                ),
                "link_display" => tryr!(links::link_display(&link, d)).into(),
                _ => {
                    let responses = i.arr("responses")?.iter().map(response).collect::<R<Vec<_>>>()?;
                    tryr!(links::check_link(&link, i.str("account")?, d, &responses));
                    true.into()
                }
            }
        }
        _ => return Err(format!("unknown operation {op}")),
    };
    Ok(Outcome::Ok(out))
}

fn vault_op(op: &str, i: &Input<'_>) -> R<Outcome> {
    let st = tryr!(state_of(i)?);
    let vault = i.get("vault")?;
    let keys = derive_recovery_keys(&i.hex32("recovery_key")?, &st.realm, &st.username);
    let u = tryr!(unlock_vault(vault, &st, &Secret::Recovery(&keys)));
    let mut rng = i.random()?;
    let mut random = |b: &mut [u8]| rng.fill(b);
    let out: Value = match op {
        "change_password" => {
            let (v, h) = tryr!(change_password(
                &u,
                vault,
                i.str("lock")?,
                i.str("password")?,
                &st.username,
                &i.kdf("kdf")?,
                &mut random
            ));
            Map::new().with("vault", v).with("new", base64url_encode(&h)).into()
        }
        "add_slot" => {
            let slot = NewSlot {
                label: i.str("label")?,
                password: i.str("password")?,
                username: &st.username,
                kdf: i.kdf("kdf")?,
            };
            tryr!(add_slot(&u, vault, &keys, &slot, &mut random))
        }
        "update_contents" => {
            let mut c = u.contents.clone();
            c.data = i.obj("data")?.clone();
            tryr!(update_contents(&u, vault, &c, &mut random))
        }
        "rotate_recovery" => {
            let r = tryr!(rotate_recovery(
                &st,
                i.arr("events")?,
                &keys,
                &i.hex32("new_key")?,
                vault,
                &u,
                i.int("time")?,
                &mut random
            ));
            Map::new()
                .with("event", r.event)
                .with("vault", r.vault)
                .with("card", r.card)
                .into()
        }
        _ => {
            let drop: Vec<String> = match i.opt("drop") {
                Some(d) => d
                    .as_array()
                    .ok_or("drop")?
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
                None => Vec::new(),
            };
            let drop_refs: Vec<&str> = drop.iter().map(String::as_str).collect();
            let slot = match i.opt("slot") {
                Some(s) => {
                    let s = Input(s.as_object().ok_or("slot")?);
                    Some((
                        s.str("label")?.to_string(),
                        s.str("password")?.to_string(),
                        s.kdf("kdf")?,
                    ))
                }
                None => None,
            };
            fn new_slot<'a>(s: &'a Option<(String, String, Kdf)>, username: &'a str) -> R<NewSlot<'a>> {
                let (l, p, k) = s.as_ref().ok_or("slot")?;
                Ok(NewSlot {
                    label: l,
                    password: p,
                    username,
                    kdf: *k,
                })
            }
            let mode = match i.str("mode")? {
                "restore" => InstanceMode::Restore,
                "revoke" => InstanceMode::Revoke(&drop_refs),
                "reset" => InstanceMode::Reset(new_slot(&slot, &st.username)?),
                _ => InstanceMode::Fresh(new_slot(&slot, &st.username)?),
            };
            let public = match i.opt("public") {
                Some(p) => Some(tryr!(verify_public(p, &st)).data),
                None => None,
            };
            let ni = tryr!(new_instance(
                &st,
                &keys,
                Some(&u),
                public.as_ref(),
                mode,
                &i.home()?,
                i.int("time")?,
                &mut random
            ));
            Map::new()
                .with("event", ni.event)
                .with("vault", ni.vault)
                .with("public", ni.public)
                .into()
        }
    };
    Ok(Outcome::Ok(out))
}
