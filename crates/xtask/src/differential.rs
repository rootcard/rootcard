//! Differential testing of the JavaScript core against the Rust core (PLAN.md phase 6): `cargo fuzz` reaches only Rust,
//! so this runs both cores on the same inputs and requires the same output or the same error code (AGENTS.md rule 2).
//!
//! The inputs are the shared vectors' inputs, mutated by a seeded generator: bytes for the JSON parser and the
//! signature check, text for the encodings and names, JSON for documents, and event lists for logs, which are re-signed
//! with [`crate::resign`] so the mutations reach the checks behind the signatures. Each case is run through the vector
//! operations of [`crate::ops`]; a case the operation's harness cannot read (a member it needs is gone) is dropped, and
//! a Rust panic is a finding. The cases go to `target/differential/cases.jsonl` with Rust's output or error code, and
//! `tests/differential/run.mjs` runs them through `packages/rootcard/test/ops.mjs` and writes every disagreement to
//! `target/differential/mismatches.jsonl`.
//!
//! The same seed gives the same cases, so a finding is reproduced with `--seed`.

use crate::ops::{Outcome, run};
use crate::resign::{FIX_ACCOUNT, FIX_PREV, FIX_SIGS, resign};
use rootcard::crypto::sha256;
use rootcard::encoding::{hex_decode, hex_encode};
use rootcard::json::{MAX_SAFE, Map, Value, canonical, parse_json};
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

/// How a mutated input member is read by the core.
#[derive(Clone, Copy)]
enum Kind {
    /// Lower-case hex of bytes the core parses (JSON text, keys, signatures, ciphertexts).
    Bytes,
    /// A string the core parses or checks.
    Text,
    /// An array of strings.
    TextList,
    /// Any JSON value: a document, a request, a card.
    Json,
    /// An array of events, re-signed after mutation. `after` names the member whose events come before these (the
    /// log an extension or a pending event continues), so `prev` and `account` can be recomputed across both.
    Log { after: Option<&'static str> },
    /// One event that continues the log in the member `after` (a pending instance), re-signed with it.
    Event { after: &'static str },
}

use Kind::{Bytes, Json, Text, TextList};

/// The input members of an operation that are mutated, with how the core reads them.
type Members = &'static [(&'static str, Kind)];

/// The operations under test and the input members that are mutated, the first one most often. Operations that run
/// Argon2id, draw random bytes or only build messages are left out.
const OPS: &[(&str, Members)] = &[
    ("canonical", &[("text", Bytes)]),
    ("base64url_decode", &[("text", Text)]),
    ("base32_decode", &[("text", Text)]),
    ("parse_key", &[("text", Text)]),
    ("parse_recovery_key", &[("text", Text)]),
    ("ed25519_verify", &[("sig", Bytes), ("public", Bytes), ("msg", Bytes)]),
    ("x25519", &[("peer", Bytes)]),
    ("aes_gcm_decrypt", &[("ciphertext", Bytes), ("aad", Bytes)]),
    ("statement_challenge", &[("statement", Json)]),
    ("check_realm", &[("text", Text)]),
    ("check_username", &[("text", Text)]),
    ("default_username_policy", &[("text", Text)]),
    ("parse_handle", &[("text", Text)]),
    ("inception", &[("username", Text), ("realm", Text)]),
    ("extended_tags", &[("ids", TextList)]),
    ("verify_log", &[("events", Kind::Log { after: None })]),
    (
        "extend_log",
        &[
            ("new", Kind::Log { after: Some("events") }),
            ("events", Kind::Log { after: None }),
        ],
    ),
    (
        "verify_pending",
        &[
            ("pending", Kind::Event { after: "events" }),
            ("events", Kind::Log { after: None }),
        ],
    ),
    (
        "compare_logs",
        &[("a", Kind::Log { after: None }), ("b", Kind::Log { after: None })],
    ),
    (
        "verify_vault",
        &[("vault", Json), ("events", Kind::Log { after: None })],
    ),
    ("vault_change", &[("old", Json), ("new", Json)]),
    ("check_password", &[("password", Text), ("username", Text)]),
    ("check_base_url", &[("url", Text)]),
    ("well_known_base", &[("document", Json), ("origin", Text)]),
    ("check_data_key", &[("key", Text)]),
    (
        "set_data",
        &[("value", Json), ("key", Text), ("app", Text), ("data", Json)],
    ),
    (
        "verify_public",
        &[("profile", Json), ("events", Kind::Log { after: None })],
    ),
    ("login_verify", &[("request", Json), ("lock_key", Text)]),
    (
        "verify_proof",
        &[("proof", Json), ("log", Kind::Log { after: None }), ("recipient", Text)],
    ),
    ("import_account", &[("file", Json)]),
    ("read_card", &[("card", Json)]),
    ("card_text", &[("card", Json)]),
    ("parse_response_json", &[("text", Bytes)]),
    ("link_token", &[("account", Text)]),
    ("find_link_token", &[("text", Text), ("account", Text)]),
    ("parse_descriptor", &[("descriptor", Json)]),
    ("parse_links", &[("data", Json), ("descriptors", Json)]),
    ("links_value", &[("links", Json)]),
    ("link_requests", &[("link", Json), ("descriptors", Json)]),
    ("link_display", &[("link", Json)]),
    (
        "check_link",
        &[
            ("responses", Json),
            ("link", Json),
            ("descriptors", Json),
            ("account", Text),
        ],
    ),
];

/// SplitMix64: small, seedable and the same on every platform.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number below `n` (0 when `n` is 0).
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }

    /// True with probability `1 / n`.
    fn one_in(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }

    fn pick<'a, T>(&mut self, list: &'a [T]) -> Option<&'a T> {
        list.get(self.below(list.len()))
    }
}

/// Values taken from every vector, spliced into mutated inputs: real keys, hashes, events and documents reach places
/// they were not made for.
#[derive(Default)]
struct Dict {
    strings: Vec<String>,
    names: Vec<String>,
    values: Vec<Value>,
    events: Vec<Value>,
}

impl Dict {
    fn collect(&mut self, v: &Value, seen: &mut HashSet<Vec<u8>>) {
        let bytes = canonical(v);
        if bytes.len() <= 2048 && seen.insert(bytes) {
            self.values.push(v.clone());
            if let Value::String(s) = v {
                self.strings.push(s.clone());
            }
        }
        match v {
            Value::Array(a) => a.iter().for_each(|x| self.collect(x, seen)),
            Value::Object(m) => {
                if m.get("kind").is_some() && m.get("seq").is_some() {
                    self.events.push(v.clone());
                }
                for (name, x) in m.iter() {
                    if !self.names.iter().any(|n| n == name) {
                        self.names.push(name.to_string());
                    }
                    self.collect(x, seen);
                }
            }
            _ => {}
        }
    }
}

/// Characters that tend to sit on a boundary of some rule: controls, whitespace, non-ASCII letters, combining marks,
/// invisible characters, look-alikes of base32 and the separators of handles, keys and URLs.
const CHARS: &[char] = &[
    '\0',
    '\t',
    '\n',
    ' ',
    '\u{7f}',
    '\u{80}',
    '\u{a0}',
    'é',
    '\u{301}',
    'ß',
    'İ',
    'ı',
    'K',
    '\u{212a}',
    '\u{feff}',
    '\u{200b}',
    '\u{200d}',
    '\u{fffd}',
    '\u{ffff}',
    '\u{1f600}',
    '\u{10ffff}',
    'A',
    'Z',
    'a',
    'z',
    '0',
    '1',
    '9',
    'I',
    'L',
    'O',
    'U',
    '-',
    '_',
    '.',
    '/',
    ':',
    '#',
    '%',
    '@',
    '=',
    '+',
    '?',
    '&',
    '[',
    ']',
    '\\',
    '"',
    '~',
];

/// Byte sequences that are boundaries of the JSON parser or the encodings.
const TOKENS: &[&[u8]] = &[
    b"\\u0000",
    b"\\ud800",
    b"\\udc00\\ud800",
    b"\\ud83d\\ude00",
    b"\\/",
    b"\\u00e9",
    b"1e5",
    b"-0",
    b"0.5",
    b"01",
    b"9007199254740991",
    b"9007199254740992",
    b"-9007199254740992",
    b"true",
    b"null",
    b"\"\"",
    b"{}",
    b"[]",
    b"\xef\xbb\xbf",
    b"\xc0\x80",
    b"\xed\xa0\x80",
    b"\xf4\x90\x80\x80",
    b"\xe2\x80\xa8",
];

const INTS: &[i64] = &[
    0,
    1,
    -1,
    2,
    255,
    256,
    1000,
    1001,
    4096,
    65_536,
    i32::MAX as i64,
    1_800_000_000,
    MAX_SAFE,
    -MAX_SAFE,
];

fn mutate_text(s: &mut String, rng: &mut Rng, dict: &Dict) {
    let mut chars: Vec<char> = s.chars().collect();
    let at = rng.below(chars.len() + 1);
    match rng.below(10) {
        0 => chars.insert(at, *rng.pick(CHARS).unwrap_or(&'a')),
        1 if at < chars.len() => {
            chars.remove(at);
        }
        2 if at < chars.len() => chars[at] = *rng.pick(CHARS).unwrap_or(&'a'),
        3 if at < chars.len() => {
            let c = chars[at];
            chars[at] = if c.is_lowercase() {
                c.to_uppercase().next().unwrap_or(c)
            } else {
                c.to_lowercase().next().unwrap_or(c)
            };
        }
        4 => chars.truncate(at),
        5 if at < chars.len() => {
            let end = (at + 1 + rng.below(8)).min(chars.len());
            let part: Vec<char> = chars[at..end].to_vec();
            chars.splice(at..at, part);
        }
        6 if at < chars.len() => {
            // A neighbouring character: `z` + 1, `9` + 1, `/` - 1 are boundaries of character classes.
            let c = chars[at] as u32;
            let n = if rng.one_in(2) {
                c.wrapping_add(1)
            } else {
                c.wrapping_sub(1)
            };
            chars[at] = char::from_u32(n).unwrap_or('a');
        }
        7 => {
            if let Some(d) = rng.pick(&dict.strings) {
                chars.splice(at..at, d.chars());
            }
        }
        8 => {
            if let Some(d) = rng.pick(&dict.strings) {
                chars = d.chars().collect();
            }
        }
        _ => {
            for _ in 0..rng.below(4) + 1 {
                let at = rng.below(chars.len() + 1);
                chars.insert(at, *rng.pick(CHARS).unwrap_or(&'a'));
            }
        }
    }
    *s = chars.into_iter().collect();
}

fn mutate_bytes(b: &mut Vec<u8>, rng: &mut Rng) {
    let at = rng.below(b.len() + 1);
    match rng.below(9) {
        0 if at < b.len() => b[at] ^= 1 << rng.below(8),
        1 if at < b.len() => b[at] = *rng.pick(b"\0\x01\x7f\x80\xff\"\\{}[],: 0-e.\n\t").unwrap_or(&0),
        2 => b.insert(at, rng.next() as u8),
        3 if at < b.len() => {
            b.remove(at);
        }
        4 => {
            if let Some(t) = rng.pick(TOKENS) {
                b.splice(at..at, t.iter().copied());
            }
        }
        5 => b.truncate(at),
        6 if at < b.len() => {
            let end = (at + 1 + rng.below(16)).min(b.len());
            let part = b[at..end].to_vec();
            b.splice(at..at, part);
        }
        7 if at + 1 < b.len() => b.swap(at, at + 1),
        _ => {
            for _ in 0..rng.below(4) + 1 {
                let at = rng.below(b.len());
                if let Some(x) = b.get_mut(at) {
                    *x = rng.next() as u8;
                }
            }
        }
    }
}

fn count(v: &Value) -> usize {
    1 + match v {
        Value::Array(a) => a.iter().map(count).sum(),
        Value::Object(m) => m.iter().map(|(_, x)| count(x)).sum(),
        _ => 0,
    }
}

/// Mutate node `k` of `v` in pre-order. Returns true once the node was found.
fn mutate_at(v: &mut Value, k: &mut usize, rng: &mut Rng, dict: &Dict) -> bool {
    if *k == 0 {
        mutate_node(v, rng, dict);
        return true;
    }
    *k -= 1;
    match v {
        Value::Array(a) => a.iter_mut().any(|x| mutate_at(x, k, rng, dict)),
        Value::Object(m) => {
            let mut members: Vec<(String, Value)> = m.iter().map(|(n, x)| (n.to_string(), x.clone())).collect();
            if members.iter_mut().any(|(_, x)| mutate_at(x, k, rng, dict)) {
                *m = members.into_iter().fold(Map::new(), |m, (n, x)| m.with(n, x));
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

fn mutate_json(v: &mut Value, rng: &mut Rng, dict: &Dict) {
    let mut k = rng.below(count(v));
    mutate_at(v, &mut k, rng, dict);
}

fn mutate_node(v: &mut Value, rng: &mut Rng, dict: &Dict) {
    match rng.below(12) {
        0 => {
            if let Some(d) = rng.pick(&dict.values) {
                *v = d.clone();
            }
        }
        1 => {
            *v = match rng.below(5) {
                0 => Value::Bool(rng.one_in(2)),
                1 => Value::Int(*rng.pick(INTS).unwrap_or(&0)),
                2 => Value::String(String::new()),
                3 => Value::Array(Vec::new()),
                _ => Value::Object(Map::new()),
            }
        }
        _ => match v {
            Value::String(s) => mutate_text(s, rng, dict),
            Value::Int(i) => {
                *i = match rng.below(3) {
                    0 => i.saturating_add(1),
                    1 => i.saturating_sub(1),
                    _ => *rng.pick(INTS).unwrap_or(&0),
                }
                .clamp(-MAX_SAFE, MAX_SAFE)
            }
            Value::Bool(b) => *b = !*b,
            Value::Array(a) => {
                let at = rng.below(a.len());
                match rng.below(5) {
                    0 if !a.is_empty() => {
                        a.remove(at);
                    }
                    1 if !a.is_empty() => {
                        let x = a[at].clone();
                        a.insert(at, x);
                    }
                    2 if a.len() > 1 => {
                        let j = rng.below(a.len());
                        a.swap(at, j);
                    }
                    3 => a.truncate(at),
                    _ => {
                        if let Some(d) = rng.pick(&dict.values) {
                            a.insert(at.min(a.len()), d.clone());
                        }
                    }
                }
            }
            Value::Object(m) => {
                let names: Vec<String> = m.keys().map(str::to_string).collect();
                let name = rng.pick(&names).cloned();
                match (rng.below(4), name) {
                    (0, Some(n)) => {
                        m.remove(&n);
                    }
                    (1, Some(n)) => {
                        // Rename a member: a near miss of a name the schema knows.
                        if let Some(x) = m.remove(&n) {
                            let mut renamed = n;
                            mutate_text(&mut renamed, rng, dict);
                            m.insert(renamed, x);
                        }
                    }
                    (2, Some(n)) => {
                        if let Some(d) = rng.pick(&dict.values) {
                            m.insert(n, d.clone());
                        }
                    }
                    _ => {
                        let n = rng.pick(&dict.names).cloned().unwrap_or_else(|| "x".to_string());
                        let x = rng.pick(&dict.values).cloned().unwrap_or(Value::Bool(true));
                        m.insert(n, x);
                    }
                }
            }
        },
    }
}

fn mutate_events(events: &mut Vec<Value>, rng: &mut Rng, dict: &Dict) {
    let at = rng.below(events.len());
    match rng.below(8) {
        0 if !events.is_empty() => {
            events.remove(at);
        }
        1 if !events.is_empty() => {
            let e = events[at].clone();
            events.insert(at, e);
        }
        2 if events.len() > 1 => {
            let j = rng.below(events.len());
            events.swap(at, j);
        }
        3 => events.truncate(at),
        4 => {
            if let Some(e) = rng.pick(&dict.events) {
                events.insert(at.min(events.len()), e.clone());
            }
        }
        _ => {
            if let Some(e) = events.get_mut(at) {
                mutate_json(e, rng, dict);
            }
        }
    }
}

/// Re-sign `events` as the continuation of `before` (the whole log is re-signed, the continuation is returned). Most
/// of the time everything is recomputed; sometimes only part of it, and sometimes nothing, so the checks of `account`,
/// `prev` and the signatures themselves are reached too.
fn resign_after(before: &[Value], events: &[Value], rng: &mut Rng) -> Vec<Value> {
    if rng.one_in(8) {
        return events.to_vec();
    }
    let control = if rng.one_in(4) {
        rng.below(8) as u8
    } else {
        FIX_ACCOUNT | FIX_PREV | FIX_SIGS
    };
    let all: Vec<Value> = before.iter().chain(events).cloned().collect();
    resign(&all, control).split_off(before.len())
}

fn array_of(input: &Map, name: &str) -> Vec<Value> {
    input.get(name).and_then(Value::as_array).cloned().unwrap_or_default()
}

/// Mutate the member `name` of `input` as `kind`.
fn mutate_member(input: &mut Map, name: &str, kind: Kind, rng: &mut Rng, dict: &Dict) {
    let Some(old) = input.get(name).cloned() else {
        return;
    };
    let new = match (kind, old) {
        (Bytes, Value::String(s)) => {
            let Ok(mut b) = hex_decode(&s) else { return };
            if rng.one_in(3)
                && let Ok(mut v) = parse_json(&b)
            {
                // Structured: a mutated value written canonically, so deep members are reached as well.
                mutate_json(&mut v, rng, dict);
                b = canonical(&v);
            } else {
                // Mostly one mutation, so inputs near the vectors are often still accepted; sometimes a few.
                let rounds = if rng.one_in(4) { rng.below(3) + 2 } else { 1 };
                for _ in 0..rounds {
                    mutate_bytes(&mut b, rng);
                }
            }
            Value::String(hex_encode(&b))
        }
        (Text, Value::String(mut s)) => {
            mutate_text(&mut s, rng, dict);
            Value::String(s)
        }
        (TextList, Value::Array(mut a)) => {
            let at = rng.below(a.len());
            match rng.below(4) {
                0 if !a.is_empty() => {
                    a.remove(at);
                }
                1 => {
                    let s = rng.pick(&dict.strings).cloned().unwrap_or_default();
                    a.insert(at.min(a.len()), Value::String(s));
                }
                _ => {
                    if let Some(Value::String(s)) = a.get_mut(at) {
                        mutate_text(s, rng, dict);
                    }
                }
            }
            Value::Array(a)
        }
        (Kind::Log { after }, Value::Array(mut events)) => {
            mutate_events(&mut events, rng, dict);
            let before = after.map(|a| array_of(input, a)).unwrap_or_default();
            Value::Array(resign_after(&before, &events, rng))
        }
        (Kind::Event { after }, mut event) => {
            mutate_json(&mut event, rng, dict);
            let before = array_of(input, after);
            resign_after(&before, &[event.clone()], rng).pop().unwrap_or(event)
        }
        (_, mut v) => {
            mutate_json(&mut v, rng, dict);
            v
        }
    };
    input.insert(name, new);
}

/// One case: the operation, its mutated input and what the Rust core answered.
fn case_line(op: &str, input: &Map, outcome: &Outcome) -> Vec<u8> {
    let mut m = Map::new().with("op", op).with("input", input.clone());
    match outcome {
        Outcome::Ok(v) => m.insert("output", v.clone()),
        Outcome::Err(e) => m.insert("error", e.code().into()),
    };
    let mut line = canonical(&Value::Object(m));
    line.push(b'\n');
    line
}

/// Write `cases` mutated cases from `seed` to `dir/cases.jsonl`. Returns the number of cases per operation, or the
/// findings on the Rust side (panics).
fn write_cases(dir: &Path, cases: usize, seed: u64) -> Result<BTreeMap<&'static str, usize>, String> {
    let mut by_op: BTreeMap<String, Vec<Map>> = BTreeMap::new();
    let mut dict = Dict::default();
    let mut seen = HashSet::new();
    for (_, file) in crate::generate::files()? {
        for v in file
            .as_object()
            .and_then(|f| f.get("vectors"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(v) = v.as_object() else { continue };
            let (Some(op), Some(input)) = (
                v.get("op").and_then(Value::as_str),
                v.get("input").and_then(Value::as_object),
            ) else {
                continue;
            };
            dict.collect(&Value::Object(input.clone()), &mut seen);
            by_op.entry(op.to_string()).or_default().push(input.clone());
        }
    }
    let mut ops: Vec<(&'static str, Members, Vec<Map>)> = Vec::new();
    for (op, members) in OPS {
        let inputs = by_op
            .remove(*op)
            .ok_or_else(|| format!("differential: no vectors for {op}"))?;
        ops.push((op, members, inputs));
    }

    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    // Results of an earlier run must not be mistaken for this one's.
    for stale in ["rust-panics.jsonl", "mismatches.jsonl"] {
        let _ = std::fs::remove_file(dir.join(stale));
    }
    let path = dir.join("cases.jsonl");
    let file = std::fs::File::create(&path).map_err(|e| format!("writing {}: {e}", path.display()))?;
    let mut out = std::io::BufWriter::new(file);
    let mut rng = Rng(seed);
    let mut written: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut unique = HashSet::new();
    let mut panics = Vec::new();
    let mut attempts = 0usize;
    while written.values().sum::<usize>() < cases && attempts < cases * 20 {
        attempts += 1;
        let (op, members, inputs) = &ops[attempts % ops.len()];
        let Some(base) = rng.pick(inputs) else { continue };
        let mut input = base.clone();
        // Mostly one mutation, so inputs near the vectors are often still accepted; sometimes a few.
        let rounds = if rng.one_in(4) { rng.below(3) + 2 } else { 1 };
        for _ in 0..rounds {
            // The first member most of the time: it is the one the operation is about.
            let (name, kind) = if rng.one_in(2) {
                members[0]
            } else {
                *rng.pick(members).unwrap_or(&members[0])
            };
            mutate_member(&mut input, name, kind, &mut rng, &dict);
        }
        if !unique.insert(sha256(&canonical(&Value::Object(input.clone())))) || input == *base {
            continue;
        }
        let outcome = match catch_unwind(AssertUnwindSafe(|| run(op, &input))) {
            Ok(Ok(outcome)) => outcome,
            // The harness of the operation cannot read the input (a member it needs is gone): not a case.
            Ok(Err(_)) => continue,
            Err(_) => {
                let case = Map::new().with("op", *op).with("input", input.clone());
                panics.push(format!(
                    "{}\n",
                    String::from_utf8_lossy(&canonical(&Value::Object(case)))
                ));
                continue;
            }
        };
        out.write_all(&case_line(op, &input, &outcome))
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
        *written.entry(op).or_default() += 1;
    }
    out.flush().map_err(|e| format!("writing {}: {e}", path.display()))?;
    if !panics.is_empty() {
        let list = dir.join("rust-panics.jsonl");
        std::fs::write(&list, panics.concat()).map_err(|e| format!("writing {}: {e}", list.display()))?;
        return Err(format!(
            "differential: the Rust core panicked on {} inputs (seed {seed}); they are in {}",
            panics.len(),
            list.display()
        ));
    }
    Ok(written)
}

/// `cargo run -p xtask -- differential [--cases N] [--seed S]`: write the cases and check the JS core against them.
pub fn differential(args: &[&str]) -> Result<(), String> {
    let mut cases = 20_000usize;
    let mut seed = 1u64;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let value = rest
            .next()
            .ok_or_else(|| format!("differential: {flag} needs a value"))?;
        match *flag {
            "--cases" => {
                cases = value
                    .parse()
                    .map_err(|_| format!("differential: bad --cases {value}"))?
            }
            "--seed" => seed = value.parse().map_err(|_| format!("differential: bad --seed {value}"))?,
            _ => return Err(format!("differential: unknown option {flag}")),
        }
    }
    let root = crate::repo_dir();
    let dir = root.join("target/differential");
    let written = write_cases(&dir, cases, seed)?;
    let total: usize = written.values().sum();
    println!("differential: {total} cases from seed {seed}");
    for (op, n) in &written {
        println!("  {op:<24} {n}");
    }
    let status = std::process::Command::new("node")
        .arg(root.join("tests/differential/run.mjs"))
        .arg(dir.join("cases.jsonl"))
        .arg(dir.join("mismatches.jsonl"))
        .status()
        .map_err(|e| format!("differential: running node: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "differential: the JS core disagrees with the Rust core (seed {seed}); the cases are in {}",
            dir.join("mismatches.jsonl").display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The re-signer keeps the accepted logs of the vectors accepted, so mutations near them can be accepted too.
    #[test]
    fn resigned_vector_logs_stay_accepted() {
        let files = crate::generate::files().unwrap();
        let mut n = 0;
        for (_, file) in &files {
            for v in file.as_object().unwrap().get("vectors").unwrap().as_array().unwrap() {
                let v = v.as_object().unwrap();
                if v.get("op").unwrap().as_str() != Some("verify_log") || v.get("error").is_some() {
                    continue;
                }
                let input = v.get("input").unwrap().as_object().unwrap();
                let events = input.get("events").unwrap().as_array().unwrap();
                let resigned = resign(events, FIX_ACCOUNT | FIX_PREV | FIX_SIGS);
                let mut changed = input.clone();
                changed.insert("events", Value::Array(resigned));
                match run("verify_log", &changed).unwrap() {
                    Outcome::Ok(_) => n += 1,
                    Outcome::Err(e) => panic!("{}: {e:?}", v.get("name").unwrap().as_str().unwrap()),
                }
            }
        }
        assert!(n > 5);
    }
}
