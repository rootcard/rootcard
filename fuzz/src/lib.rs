//! Helpers shared by the fuzz targets in `fuzz_targets/` and the seed writer in `src/bin/seeds.rs`: the shared vectors
//! as fixtures, the log re-signer of the `log_signed` target and the request framing of the `host` target. See
//! fuzz/README.md.

use rootcard::crypto::sha256;
use rootcard::json::{Map, Value, parse_json};
use rootcard::log::{LogOrder, LogState, VerifyOptions, compare_logs, extend_log, verify_log};
use rootcard_host::http::Request;
use rootcard_host::peer::PeerHeaders;
use rootcard_host::store::{MemoryChallengeStore, MemoryIdentityStore, MemorySessionStore};
use rootcard_host::{Host, HostConfig, RealmConfig, UsernamePolicy};
use std::sync::OnceLock;
use zeroize::Zeroizing;

/// The shared vector files, compiled in so a target needs no files at run time.
pub const VECTOR_FILES: [(&str, &str); 7] = [
    ("primitives", include_str!("../../spec/vectors/primitives.json")),
    ("log", include_str!("../../spec/vectors/log.json")),
    ("file", include_str!("../../spec/vectors/file.json")),
    ("profile", include_str!("../../spec/vectors/profile.json")),
    ("proof", include_str!("../../spec/vectors/proof.json")),
    ("vault", include_str!("../../spec/vectors/vault.json")),
    ("link", include_str!("../../spec/vectors/link.json")),
];

/// One shared vector: its operation, input and whether it expects an error.
pub struct Vector {
    /// The `op` of the vector.
    pub op: String,
    /// The `input` object.
    pub input: Map,
    /// The `output`, if any.
    pub output: Option<Value>,
    /// Whether the vector expects an `error`.
    pub rejects: bool,
}

/// Every shared vector, parsed once. Files that do not parse are skipped (the vector check would fail first).
pub fn vectors() -> &'static [Vector] {
    static ALL: OnceLock<Vec<Vector>> = OnceLock::new();
    ALL.get_or_init(|| {
        let mut all = Vec::new();
        for (_, text) in VECTOR_FILES {
            let Ok(file) = parse_json(text.as_bytes()) else {
                continue;
            };
            let list = file
                .as_object()
                .and_then(|m| m.get("vectors"))
                .and_then(Value::as_array);
            for v in list.into_iter().flatten() {
                let Some(m) = v.as_object() else { continue };
                let (Some(op), Some(input)) = (
                    m.get("op").and_then(Value::as_str),
                    m.get("input").and_then(Value::as_object),
                ) else {
                    continue;
                };
                all.push(Vector {
                    op: op.to_string(),
                    input: input.clone(),
                    output: m.get("output").cloned(),
                    rejects: m.get("error").is_some(),
                });
            }
        }
        all
    })
}

/// The first accepted vector of `op`.
pub fn accepted(op: &str) -> Option<&'static Vector> {
    vectors().iter().find(|v| v.op == op && !v.rejects)
}

/// The array `name` of a vector's input.
pub fn input_array<'a>(v: &'a Vector, name: &str) -> &'a [Value] {
    v.input.get(name).and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// The string `name` of a vector's input.
pub fn input_str<'a>(v: &'a Vector, name: &str) -> &'a str {
    v.input.get(name).and_then(Value::as_str).unwrap_or("")
}

// ---------------------------------------------------------------------------------------------------------------------
// The log re-signer (`log_signed`)
// ---------------------------------------------------------------------------------------------------------------------

// The re-signer lives in xtask, which also uses it for the differential test of the JS core against the Rust core
// (`cargo run -p xtask -- differential`); it needs nothing but the core.
#[path = "../../crates/xtask/src/resign.rs"]
mod resign;
pub use resign::{FIX_ACCOUNT, FIX_PREV, FIX_SIGS, resign};

// ---------------------------------------------------------------------------------------------------------------------
// Request framing (`host`)
// ---------------------------------------------------------------------------------------------------------------------

/// The separator between requests in a `host` input.
pub const REQUEST_SEPARATOR: &[u8] = b"\n\x00\n";

/// Parse one request: a first line `METHOD PATH` with optional ` bearer=<token>` and ` peer=<key>,<time>,<sig>`,
/// then the body. Returns `None` for a first line that is not UTF-8.
pub fn parse_request(chunk: &[u8]) -> Option<Request> {
    let (line, body) = match chunk.iter().position(|&b| b == b'\n') {
        Some(n) => (&chunk[..n], &chunk[n + 1..]),
        None => (chunk, &[][..]),
    };
    let line = std::str::from_utf8(line).ok()?;
    let mut words = line.split(' ');
    let method = words.next().unwrap_or("").to_string();
    let path = words.next().unwrap_or("").to_string();
    let mut req = Request {
        method,
        path,
        bearer: None,
        peer: None,
        body: body.to_vec(),
    };
    for w in words {
        if let Some(t) = w.strip_prefix("bearer=") {
            req.bearer = Some(t.to_string());
        } else if let Some(p) = w.strip_prefix("peer=") {
            let mut parts = p.splitn(3, ',');
            let key = parts.next().unwrap_or("").to_string();
            let time = parts.next().and_then(|t| t.parse().ok()).unwrap_or(0);
            let sig = parts.next().unwrap_or("").to_string();
            req.peer = Some(PeerHeaders { key, time, sig });
        }
    }
    Some(req)
}

/// Split a `host` input into requests.
pub fn requests(data: &[u8]) -> Vec<Request> {
    let mut out = Vec::new();
    let mut rest = data;
    loop {
        let at = rest
            .windows(REQUEST_SEPARATOR.len())
            .position(|w| w == REQUEST_SEPARATOR);
        let (chunk, next) = match at {
            Some(n) => (&rest[..n], Some(&rest[n + REQUEST_SEPARATOR.len()..])),
            None => (rest, None),
        };
        out.extend(parse_request(chunk));
        match next {
            Some(n) if out.len() < 16 => rest = n,
            _ => return out,
        }
    }
}

/// A deterministic byte stream for the host's nonces and tokens: the run must be reproducible from the input alone.
pub struct Counter(u64);

impl Counter {
    /// A stream starting at zero.
    pub fn new() -> Self {
        Counter(0)
    }

    /// Fill `buf`.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(32) {
            self.0 += 1;
            let block = sha256(&self.0.to_le_bytes());
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Invariants of an accepted log (`log`, `log_signed`)
// ---------------------------------------------------------------------------------------------------------------------

/// What must hold for a log `verify_log` accepted: every prefix is accepted too, extending a prefix gives the same
/// state ([LOG-15]), and the state survives its own serialization (the account file).
pub fn check_accepted(events: &[Value], state: &LogState, options: &VerifyOptions) {
    let mut splits = vec![1, events.len() / 2, events.len().saturating_sub(1)];
    splits.dedup();
    for k in splits.into_iter().filter(|&k| k >= 1 && k < events.len()) {
        let prefix = verify_log(&events[..k], options);
        assert!(prefix.is_ok(), "a prefix of an accepted log is rejected: {prefix:?}");
        if let Ok(prefix) = prefix {
            let extended = extend_log(&prefix, &events[k..], options);
            assert_eq!(extended.as_ref(), Ok(state), "extend_log differs from verify_log");
        }
    }
    let again = LogState::from_value(&state.to_value());
    assert_eq!(
        again.as_ref(),
        Ok(state),
        "the log state does not survive serialization"
    );
    assert_eq!(compare_logs(events, events), Ok(LogOrder::Same));
}

/// The time of the first request of a `host` input: just after the vectors' scenario, so their logs are not in the
/// future and their challenges are not expired.
pub const HOST_NOW: i64 = 1_800_000_100;

/// The host of the `host` target: the vectors' host key (`0xa1` × 32) and address, so the registrations and receipts
/// of the vectors are its own, and one peer.
pub fn fuzz_host() -> Host<MemoryIdentityStore, MemoryChallengeStore, MemorySessionStore> {
    let config = HostConfig {
        key_seed: Zeroizing::new([0xa1; 32]),
        retired_keys: Vec::new(),
        urls: vec!["https://a.example".into(), "https://example.com/rootcard".into()],
        realms: vec![RealmConfig {
            realm: "global".into(),
            policy: UsernamePolicy::DEFAULT,
        }],
        peers: vec![[9u8; 32]],
    };
    Host::new(
        config,
        MemoryIdentityStore::new(),
        MemoryChallengeStore::new(),
        MemorySessionStore::new(),
    )
}
