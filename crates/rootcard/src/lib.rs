//! # rootcard
//!
//! A portable, self-certifying identity for online logins. This crate is the core: formats, verification, the vault and
//! proofs. It is pure: it does no I/O, reads no clock and draws no randomness itself. Time and random bytes are passed in
//! ([IMP-1]).
//!
//! The normative format is `spec/SPEC.md` in the repository, and `spec/vectors/` holds the shared test vectors that this
//! crate and the npm package must both reproduce. Rule identifiers such as `[LOG-12]` refer to that specification.
//!
//! The `vault` feature (on by default) adds password and vault cryptography: X25519, AES-256-GCM, Argon2id and Unicode
//! normalization. Hosts and relying parties build without it (`default-features = false`).
//!
//! Status: `0.x`. Nothing here is stable before `1.0.0`.
//!
//! ## Where to start
//!
//! | You are | Start with |
//! |---|---|
//! | a host (a server that stores identities) | the crate `rootcard-host`, which builds on this one |
//! | a relying party (a server that checks proofs) | [`log::verify_log`] and [`proof::verify_proof`] |
//! | a client or the key tool | [`account`] (registration, instances, rotation) and [`vault`] (unlock, passwords) |
//!
//! `docs/GETTING_STARTED.md` in the repository walks through each role, and `docs/CONCEPTS.md` explains the log, the
//! vault, the recovery card and proofs.
//!
//! ## A tour
//!
//! An identity is registered, its first instance receipted by a host, and a proof made with the account key and
//! verified by someone who knows only the log. Real code passes the system clock and a secure generator (`getrandom`)
//! where this example uses fixed values and [`testing::TestRandom`].
//!
//! ```
//! # #[cfg(feature = "vault")] {
//! use rootcard::account::register;
//! use rootcard::crypto::ed25519_public;
//! use rootcard::log::{Home, VerifyOptions, add_receipt, verify_log};
//! use rootcard::proof::{ProofBy, prove, verify_proof};
//! use rootcard::recovery::new_recovery_key;
//! use rootcard::testing::TestRandom;
//! use rootcard::vault::{Kdf, Secret, unlock_vault, verify_vault};
//! use rootcard::Value;
//!
//! let now = 1_800_000_000;
//! let mut rng = TestRandom::new(b"tour");
//! let mut random = |b: &mut [u8]| rng.fill(b);
//! let host_seed = [0xa1; 32];
//! let home = Home { key: ed25519_public(&host_seed), url: "https://id.example.com".into() };
//!
//! // The client: a recovery key (for the recovery card), the inception, a pending instance and a vault ([CLT-1]).
//! let rk = new_recovery_key("global", "Astra", &mut random)?;
//! let password = "correct horse battery staple";
//! let reg = register(&rk, "global", "Astra", password, "Laptop", &home, now, Kdf::MIN, &mut random)?;
//!
//! // The host receipts the instance ([HST-3]); `rootcard-host` does this in `Host::register`.
//! let mut pending = reg.log[1].as_object().cloned().ok_or(rootcard::Error::BadField)?;
//! add_receipt(&mut pending, &host_seed);
//! let log = vec![reg.log[0].clone(), Value::Object(pending)];
//! let opts = VerifyOptions::new(["global"]).at(now);
//! let state = verify_log(&log, &opts)?;
//! assert_eq!(state.account, reg.account);
//!
//! // The client unlocks the vault with the password and proves control to a verifier ([VLT-8], [PRF-1]).
//! let lock = verify_vault(&reg.vault, &state)?.slots[0].id.clone();
//! let unlocked = unlock_vault(&reg.vault, &state, &Secret::Password { lock: &lock, password })?;
//! let challenge = [7u8; 32]; // fresh random bytes from the verifier
//! let proof = prove(&state, ProofBy::Account, &unlocked.contents.account_seed, &challenge, "example.org")?;
//!
//! // The verifier needs only the proof and the newest log ([PRF-4]).
//! let checked = verify_proof(&proof, &log, &challenge, "example.org", &opts)?;
//! assert_eq!(checked.handle, state.handle);
//! # }
//! # Ok::<(), rootcard::Error>(())
//! ```
//!
//! Every function that produces or checks bytes has shared vectors in `spec/vectors/`, and the npm package `rootcard`
//! implements the same functions under camelCase names.

#![forbid(unsafe_code)]

#[cfg(feature = "vault")]
pub mod account;
pub mod binding;
pub mod crypto;
pub mod encoding;
pub mod error;
pub mod file;
pub mod id;
pub mod json;
pub mod keys;
pub mod links;
pub mod log;
pub mod messages;
pub mod profile;
pub mod proof;
pub mod recovery;
pub mod testing;
pub mod vault;

pub use binding::{
    API_VERSION, MAX_WELL_KNOWN_APIS, WELL_KNOWN_LIMIT, WELL_KNOWN_PATH, check_base_url, is_origin, well_known_base,
};
pub use error::{Error, Result};
pub use json::{Map, Value, canonical, parse_json};

/// Version of the wire and storage format described by the specification.
pub const FORMAT_VERSION: u32 = 1;

/// Prefix of every domain-separation label (`rootcard/<purpose>/v<n>`).
pub const LABEL_PREFIX: &str = "rootcard/";

/// Build a domain-separation label for `purpose` at format version `version`, e.g. `rootcard/id/v1`.
pub fn label(purpose: &str, version: u32) -> String {
    format!("{LABEL_PREFIX}{purpose}/v{version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_prefixed_and_versioned() {
        assert_eq!(label("id", FORMAT_VERSION), "rootcard/id/v1");
        assert!(label("event", 2).starts_with(LABEL_PREFIX));
    }
}
