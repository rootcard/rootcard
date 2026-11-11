//! End-to-end flows through the core: registration, login, password change, new instances, rotation, retirement,
//! proofs and files. Rule identifiers name what each step exercises.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rootcard::account::{InstanceMode, new_instance, register, rotate_recovery};
use rootcard::crypto::{ed25519_public, sha256};
use rootcard::encoding::{base64url_encode, hex_encode};
use rootcard::error::Error;
use rootcard::file::{export_account, import_account, read_card};
use rootcard::json::{Map, Value, canonical, parse_json};
use rootcard::log::{
    Home, LogOrder, LogState, VerifyOptions, add_receipt, compare_logs, event_hash, extend_log, retire_event,
    verify_log, verify_pending,
};
use rootcard::messages::{Challenge, LoginRequest, change_message};
use rootcard::profile::verify_public;
use rootcard::proof::{ProofBy, prove, statement_challenge, verify_proof};
use rootcard::recovery::{RecoveryKeys, derive_recovery_keys, format_recovery_key};
use rootcard::testing::TestRandom;
use rootcard::vault::{
    Contents, Kdf, NewSlot, Secret, VaultChange, add_slot, change_password, unlock_vault, update_contents,
    vault_change, verify_vault,
};

const HOST_A: [u8; 32] = [0xa1; 32];
const HOST_B: [u8; 32] = [0xb2; 32];
const T0: i64 = 1_800_000_000;
const PASSWORD: &str = "correct horse battery staple";

fn home(seed: &[u8; 32], url: &str) -> Home {
    Home {
        key: ed25519_public(seed),
        url: url.to_string(),
    }
}

fn opts() -> VerifyOptions {
    VerifyOptions::new(["global"]).at(T0 + 10_000)
}

fn receipt(mut e: Map, host: &[u8; 32]) -> Value {
    add_receipt(&mut e, host);
    Value::Object(e)
}

struct World {
    rk: [u8; 32],
    log: Vec<Value>,
    state: LogState,
    vault: Value,
    public: Value,
    card: Value,
}

fn registered(rng: &mut TestRandom) -> World {
    let rk = rng.bytes::<32>();
    let mut random = |b: &mut [u8]| rng.fill(b);
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
    .unwrap();
    let inc_state = verify_log(&reg.log[..1], &opts()).unwrap();
    verify_pending(&inc_state, &reg.log[1], T0).unwrap();
    let pending = reg.log[1].as_object().unwrap().clone();
    let log = vec![reg.log[0].clone(), receipt(pending, &HOST_A)];
    let state = verify_log(&log, &opts()).unwrap();
    assert_eq!(state.account, reg.account);
    World {
        rk,
        log,
        state,
        vault: reg.vault,
        public: reg.public,
        card: reg.card,
    }
}

/// [VLT-9] the contents hold none of the recovery keys' secrets, in any of the encodings the format uses.
fn no_recovery_key(contents: &Contents, keys: &[(&[u8; 32], &RecoveryKeys)]) {
    let text = String::from_utf8(canonical(&contents.to_value())).unwrap();
    for (rk, derived) in keys {
        for secret in [**rk, *derived.sign_seed, *derived.box_secret] {
            assert!(
                !text.contains(&base64url_encode(&secret)),
                "a recovery secret is in the contents"
            );
            assert!(
                !text.contains(&hex_encode(&secret)),
                "a recovery secret is in the contents"
            );
        }
        assert!(
            !text.contains(&format_recovery_key(rk)),
            "the recovery key is in the contents"
        );
    }
}

fn slot(w: &World) -> String {
    let info = verify_vault(&w.vault, &w.state).unwrap();
    info.slots[0].id.clone()
}

#[test]
fn register_login_change_password() {
    let mut rng = TestRandom::new(b"flow-1");
    let w = registered(&mut rng);
    // [ID-2] the inception is deterministic.
    let keys = derive_recovery_keys(&w.rk, "global", "Astra");
    assert_eq!(
        rootcard::id::inception(&keys, "global", "Astra").unwrap(),
        *w.log[0].as_object().unwrap()
    );
    assert_eq!(w.state.handle, format!("Astra#{}", &w.state.account[..4]));
    // [DAT-2] the profile verifies; [VLT-3] the vault verifies; hints carry no key material ([FET-2]).
    verify_public(&w.public, &w.state).unwrap();
    let info = verify_vault(&w.vault, &w.state).unwrap();
    let hints = canonical(&info.hints());
    assert!(!String::from_utf8(hints).unwrap().contains("auth"));
    let id = slot(&w);

    // [VLT-8] unlock with the password and with the recovery key; a wrong password fails.
    let u = unlock_vault(
        &w.vault,
        &w.state,
        &Secret::Password {
            lock: &id,
            password: PASSWORD,
        },
    )
    .unwrap();
    assert_eq!(u.account_key(), w.state.instance.as_ref().unwrap().account_key);
    let wrong = unlock_vault(
        &w.vault,
        &w.state,
        &Secret::Password {
            lock: &id,
            password: "wrong password!!",
        },
    );
    assert_eq!(wrong.err(), Some(Error::UnlockFailed));
    assert_eq!(
        unlock_vault(
            &w.vault,
            &w.state,
            &Secret::Password {
                lock: "AAAAAAAAAAA",
                password: PASSWORD
            }
        )
        .err(),
        Some(Error::BadLocks)
    );
    let ur = unlock_vault(&w.vault, &w.state, &Secret::Recovery(&keys)).unwrap();
    assert_eq!(*ur.vault_key, *u.vault_key);
    // [VLT-9] registration does not put the recovery key into the contents, and contents with a member for it are
    // refused ([VLT-7]).
    no_recovery_key(&u.contents, &[(&w.rk, &keys)]);
    let mut with_key = u.contents.to_value().as_object().unwrap().clone();
    with_key.insert("recovery_key", Value::from(base64url_encode(&w.rk)));
    assert_eq!(Contents::from_value(&with_key.into()).err(), Some(Error::BadField));

    // [LGN-1] a login with the account key and the lock's auth key.
    let inst = w.state.instance.clone().unwrap();
    let ch = Challenge {
        nonce: rng.bytes(),
        host: inst.home.key,
        realm: "global".into(),
        version: w.state.version,
        expires: T0 + 60,
    };
    let req = LoginRequest::sign(
        &w.state.account,
        "global",
        &inst.home.key,
        &w.state.version,
        &ch,
        "https://a.example",
        &id,
        &u.contents.account_seed,
        &u.lock_seed,
    )
    .unwrap();
    let req = LoginRequest::from_value(&parse_json(&canonical(&req.to_value())).unwrap()).unwrap();
    let auth = info.password_lock(&id).unwrap().auth;
    req.verify("global", &inst.home.key, &inst.account_key, &auth).unwrap();
    assert_eq!(
        req.verify("global", &inst.home.key, &inst.account_key, &w.state.recovery),
        Err(Error::BadSignature)
    );

    // [CHG-1] a password change: a new lock for the slot, proven with the old auth key.
    let mut random = |b: &mut [u8]| rng.fill(b);
    // [LCK-8] holds in every function that creates a password lock, not only at registration.
    let name = w.state.username.as_str();
    for weak in ["too short", "ASTRA", ""] {
        let weak = if weak == "ASTRA" {
            name.to_ascii_uppercase()
        } else {
            weak.to_string()
        };
        assert_eq!(
            change_password(&u, &w.vault, &id, &weak, name, &Kdf::MIN, &mut random).err(),
            Some(Error::WeakPassword)
        );
    }
    let (v2, new_hash) = change_password(
        &u,
        &w.vault,
        &id,
        "a new and better passphrase",
        name,
        &Kdf::MIN,
        &mut random,
    )
    .unwrap();
    verify_vault(&v2, &w.state).unwrap();
    assert_eq!(
        vault_change(&w.vault, &v2),
        Ok(VaultChange::Password {
            slot: id.clone(),
            new_hash
        })
    );
    let _msg = change_message(
        &w.state.account,
        &inst.home.key,
        &id,
        &new_hash,
        &ch.nonce,
        "https://a.example",
    );
    let u2 = unlock_vault(
        &v2,
        &w.state,
        &Secret::Password {
            lock: &id,
            password: "a new and better passphrase",
        },
    )
    .unwrap();
    assert_eq!(
        unlock_vault(
            &v2,
            &w.state,
            &Secret::Password {
                lock: &id,
                password: PASSWORD
            }
        )
        .err(),
        Some(Error::UnlockFailed)
    );
    // [LGN-5] the old lock key no longer matches the stored lock.
    let auth2 = verify_vault(&v2, &w.state).unwrap().password_lock(&id).unwrap().auth;
    assert_ne!(auth, auth2);

    // [VLT-4] a data update keeps the locks; replaying the old vault is stale.
    let mut c = u2.contents.clone();
    c.data.insert("user.motto", "hello".into());
    let v3 = update_contents(&u2, &v2, &c, &mut random).unwrap();
    assert_eq!(vault_change(&v2, &v3), Ok(VaultChange::Data));
    assert_eq!(vault_change(&v3, &v2), Err(Error::StaleRev));

    // [KT-4] add a password slot with the recovery key.
    assert_eq!(update_contents(&u2, &v3, &c, &mut random).err(), Some(Error::StaleRev));
    let u3 = unlock_vault(&v3, &w.state, &Secret::Recovery(&keys)).unwrap();
    let weak = NewSlot {
        label: "Phone",
        password: "short",
        username: &w.state.username,
        kdf: Kdf::MIN,
    };
    assert_eq!(
        add_slot(&u3, &v3, &keys, &weak, &mut random).err(),
        Some(Error::WeakPassword)
    );
    let v4 = add_slot(
        &u3,
        &v3,
        &keys,
        &NewSlot {
            label: "Phone",
            password: "phone passphrase 123",
            username: &w.state.username,
            kdf: Kdf::MIN,
        },
        &mut random,
    )
    .unwrap();
    assert_eq!(vault_change(&v3, &v4), Ok(VaultChange::Grant));
    assert_eq!(verify_vault(&v4, &w.state).unwrap().slots.len(), 2);
}

#[test]
fn instances_rotation_retire_proofs_files() {
    let mut rng = TestRandom::new(b"flow-2");
    let w = registered(&mut rng);
    let keys = derive_recovery_keys(&w.rk, "global", "Astra");
    let id = slot(&w);
    let u = unlock_vault(&w.vault, &w.state, &Secret::Recovery(&keys)).unwrap();
    let profile = verify_public(&w.public, &w.state).unwrap();

    // [KT-3] restore on host B: the password carries over.
    let mut random = |b: &mut [u8]| rng.fill(b);
    let ni = new_instance(
        &w.state,
        &keys,
        Some(&u),
        Some(&profile.data),
        InstanceMode::Restore,
        &home(&HOST_B, "https://b.example"),
        T0 + 100,
        &mut random,
    )
    .unwrap();
    verify_pending(&w.state, &Value::Object(ni.event.clone()), T0 + 100).unwrap();
    let ev = receipt(ni.event.clone(), &HOST_B);
    let st2 = extend_log(&w.state, std::slice::from_ref(&ev), &opts()).unwrap();
    let mut log2 = w.log.clone();
    log2.push(ev);
    assert_eq!(verify_log(&log2, &opts()).unwrap(), st2, "[LOG-15]");
    assert_eq!(compare_logs(&w.log, &log2), Ok(LogOrder::Newer));
    assert_eq!(compare_logs(&log2, &w.log), Ok(LogOrder::Older));
    // [VER-6] the old vault is invalid for the new instance; the new one unlocks with the old password.
    assert_eq!(verify_vault(&w.vault, &st2).err(), Some(Error::WrongInstance));
    unlock_vault(
        &ni.vault,
        &st2,
        &Secret::Password {
            lock: &id,
            password: PASSWORD,
        },
    )
    .unwrap();
    verify_public(&ni.public, &st2).unwrap();

    // A fork: another instance on top of the first log.
    let mut random = |b: &mut [u8]| rng.fill(b);
    let other = new_instance(
        &w.state,
        &keys,
        Some(&u),
        None,
        InstanceMode::Revoke(&[]),
        &home(&HOST_A, "https://a.example"),
        T0 + 50,
        &mut random,
    )
    .unwrap();
    let mut fork = w.log.clone();
    fork.push(receipt(other.event, &HOST_A));
    assert_eq!(compare_logs(&log2, &fork), Ok(LogOrder::Fork));

    // [KT-5] rotate the recovery key; the new card carries the log ([CRD-2]).
    let u2 = unlock_vault(&ni.vault, &st2, &Secret::Recovery(&keys)).unwrap();
    let new_rk = rng.bytes::<32>();
    let mut random = |b: &mut [u8]| rng.fill(b);
    let rot = rotate_recovery(&st2, &log2, &keys, &new_rk, &ni.vault, &u2, T0 + 200, &mut random).unwrap();
    let mut log3 = log2.clone();
    log3.push(Value::Object(rot.event.clone()));
    let st3 = verify_log(&log3, &opts()).unwrap();
    // [LCK-3] the old grant no longer verifies; the new one does.
    assert_eq!(verify_vault(&ni.vault, &st3).err(), Some(Error::BadSignature));
    verify_vault(&rot.vault, &st3).unwrap();
    let card = read_card(&rot.card).unwrap();
    assert_eq!(card.state, st3);
    assert_eq!(read_card(&w.card).unwrap().state.account, w.state.account);
    let new_keys = derive_recovery_keys(&new_rk, "global", "Astra");
    let u3 = unlock_vault(&rot.vault, &st3, &Secret::Recovery(&new_keys)).unwrap();
    // [VLT-9] neither the old nor the new recovery key is in the contents of any vault the flows built.
    for contents in [&u.contents, &u2.contents, &u3.contents] {
        no_recovery_key(contents, &[(&w.rk, &keys), (&new_rk, &new_keys)]);
    }
    // [RK-5] the old recovery key can no longer sign.
    assert_eq!(
        retire_event(&st3, &keys.sign_seed, T0 + 300).err(),
        Some(Error::WrongRecoveryKey)
    );

    // [PRF-1], [PRF-2] proofs.
    let ch = statement_challenge(&Value::from("sign in to example.org until 2030")).unwrap();
    let p = prove(&st3, ProofBy::Account, &u2.contents.account_seed, &ch, "example.org").unwrap();
    assert_eq!(
        verify_proof(&p, &log3, &ch, "example.org", &opts()).map(|s| s.version),
        Ok(st3.version)
    );
    assert_eq!(
        verify_proof(&p, &log3, &ch, "evil.org", &opts()).err(),
        Some(Error::WrongRecipient)
    );
    assert_eq!(
        verify_proof(&p, &log3, &[0; 32], "example.org", &opts()).err(),
        Some(Error::WrongChallenge)
    );
    let rp = prove(&st3, ProofBy::Recovery, &new_keys.sign_seed, &ch, "example.org").unwrap();
    verify_proof(&rp, &log3, &ch, "example.org", &opts()).unwrap();

    // [FIL-3] account file round trip.
    let file = export_account(&st3, &log3, Some(&ni.public), Some(&rot.vault), None);
    let bytes = canonical(&file);
    let imported = import_account(&parse_json(&bytes).unwrap(), &opts()).unwrap();
    assert_eq!(imported.state, st3);

    // [KT-6] retire: nothing valid afterwards ([LOG-14]).
    let ret = retire_event(&st3, &new_keys.sign_seed, T0 + 300).unwrap();
    let mut log4 = log3.clone();
    log4.push(Value::Object(ret));
    let st4 = verify_log(&log4, &opts()).unwrap();
    assert!(st4.retired && st4.instance.is_none());
    assert_eq!(verify_vault(&rot.vault, &st4).err(), Some(Error::AccountRetired));
    assert_eq!(
        verify_proof(&p, &log4, &ch, "example.org", &opts()).err(),
        Some(Error::AccountRetired)
    );
    let _ = (sha256(b""), base64url_encode(&[]), event_hash(&Map::new()));
}
