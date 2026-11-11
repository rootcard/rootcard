//! Regression tests for the key tool's order of operations: a new recovery card is saved before anything that makes it
//! the only copy of a key is sent to a host ([KT-5], [CLT-1]).
//!
//! The tests run offline: the identity's primary host is an address nobody listens on, so every request fails, and the
//! tool works from the card and the account file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use rootcard::account::register;
use rootcard::crypto::ed25519_public;
use rootcard::file::{account_file_name, export_account};
use rootcard::json::{Value, canonical};
use rootcard::log::{Home, VerifyOptions, add_receipt, verify_log};
use rootcard::vault::Kdf;
use std::path::{Path, PathBuf};
use std::process::Command;

const PASSWORD: &str = "correct horse battery staple";
/// Nothing listens on port 1, so requests to the primary host fail at once.
const HOST: &str = "http://127.0.0.1:1";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rootcard-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A registered identity whose primary host is unreachable: its card and account file in `dir`.
fn identity(dir: &Path) -> (PathBuf, PathBuf) {
    let host_seed = [7u8; 32];
    let home = Home {
        key: ed25519_public(&host_seed),
        url: HOST.to_string(),
    };
    let mut counter = 0u8;
    let mut random = |b: &mut [u8]| {
        for x in b.iter_mut() {
            counter = counter.wrapping_add(1);
            *x = counter;
        }
    };
    let reg = register(
        &[42u8; 32],
        "global",
        "Astra",
        PASSWORD,
        "Password",
        &home,
        now(),
        Kdf::MIN,
        &mut random,
    )
    .unwrap();
    let mut instance = reg.log[1].as_object().unwrap().clone();
    add_receipt(&mut instance, &host_seed);
    let log = vec![reg.log[0].clone(), Value::Object(instance)];
    let state = verify_log(&log, &VerifyOptions::new(["global"]).at(now())).unwrap();
    let file = export_account(&state, &log, Some(&reg.public), Some(&reg.vault), None);
    let card_path = dir.join("Astra.card.json");
    let file_path = dir.join(account_file_name(&state));
    std::fs::write(&card_path, canonical(&reg.card)).unwrap();
    std::fs::write(&file_path, canonical(&file)).unwrap();
    (card_path, file_path)
}

fn rootcard(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rootcard"))
        .args(args)
        .env("ROOTCARD_PASSWORD", PASSWORD)
        .output()
        .unwrap()
}

fn new_cards(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|d| {
            d.map(|e| e.unwrap().path())
                .filter(|p| p.file_name().unwrap().to_string_lossy().ends_with(".card.json"))
                .filter(|p| !p.ends_with("Astra.card.json"))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn rotate_recovery_saves_the_new_card_before_sending_the_rotation() {
    let dir = scratch("rotate");
    let (card, file) = identity(&dir);
    let out_dir = dir.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let out = rootcard(&[
        "rotate-recovery",
        "--card",
        card.to_str().unwrap(),
        "--account",
        file.to_str().unwrap(),
        "--dir",
        out_dir.to_str().unwrap(),
    ]);
    // The host cannot be reached, so the command fails, but only after the new card was written and shown.
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Keep both cards"), "{stderr}");
    assert_eq!(new_cards(&out_dir).len(), 1);
    assert!(String::from_utf8_lossy(&out.stdout).contains("rootcard recovery card"));
}

#[test]
fn rotate_recovery_sends_nothing_when_the_new_card_cannot_be_saved() {
    let dir = scratch("rotate-nodir");
    let (card, file) = identity(&dir);
    let missing = dir.join("missing");
    let out = rootcard(&[
        "rotate-recovery",
        "--card",
        card.to_str().unwrap(),
        "--account",
        file.to_str().unwrap(),
        "--dir",
        missing.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The write failed first: the tool never got as far as the host (whose failure would mention both cards).
    assert!(stderr.contains("missing"), "{stderr}");
    assert!(!stderr.contains("Keep both cards"), "{stderr}");
}

/// [CJ-10] the files the tool writes are the canonical bytes of what they hold (and one line feed, as `keytool.html`
/// writes them), so the CLI and the page write byte-identical files.
#[test]
fn files_are_written_canonical() {
    let dir = scratch("canonical");
    let out = rootcard(&[
        "new",
        "--realm",
        "global",
        "--username",
        "Astra",
        "--dir",
        dir.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let written: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with(".json"))
        .collect();
    assert_eq!(written.len(), 2, "a card and an account file: {written:?}");
    for path in written {
        let bytes = std::fs::read(&path).unwrap();
        let (body, end) = bytes.split_at(bytes.len() - 1);
        assert_eq!(end, b"\n");
        let value = rootcard::json::parse_json(body).unwrap();
        assert_eq!(canonical(&value), body, "{} is not canonical", path.display());
    }
}
