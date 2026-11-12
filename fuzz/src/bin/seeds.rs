//! Write the seed corpora of the fuzz targets from the shared vectors: `cargo run --bin seeds` in `fuzz/` writes
//! `corpus/<target>/`. The seeds are derived, not stored, so they follow the vectors (fuzz/README.md).

use rootcard::crypto::sha256;
use rootcard::encoding::{hex_decode, hex_encode};
use rootcard::id::{account_id, handle};
use rootcard::json::{Map, Value, canonical};
use rootcard::log::{VerifyOptions, verify_log};
use rootcard_fuzz::{FIX_ACCOUNT, FIX_PREV, FIX_SIGS, REQUEST_SEPARATOR, accepted, input_array, resign, vectors};
use rootcard_host::http::route;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

struct Corpus {
    dir: PathBuf,
    seeds: BTreeSet<Vec<u8>>,
}

impl Corpus {
    fn new(root: &Path, target: &str) -> Self {
        Corpus {
            dir: root.join(target),
            seeds: BTreeSet::new(),
        }
    }

    fn add(&mut self, seed: Vec<u8>) {
        if !seed.is_empty() {
            self.seeds.insert(seed);
        }
    }

    fn write(&self) -> std::io::Result<usize> {
        std::fs::create_dir_all(&self.dir)?;
        for s in &self.seeds {
            std::fs::write(self.dir.join(hex_encode(&sha256(s)[..16])), s)?;
        }
        Ok(self.seeds.len())
    }
}

fn strings(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) if s.len() <= 512 => {
            out.insert(s.clone());
        }
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(m) => m.iter().for_each(|(_, x)| strings(x, out)),
        _ => {}
    }
}

fn with_byte(b: u8, v: &Value) -> Vec<u8> {
    let mut out = vec![b];
    out.extend(canonical(v));
    out
}

fn requests(list: &[String]) -> Vec<u8> {
    list.iter()
        .map(|r| r.as_bytes().to_vec())
        .collect::<Vec<_>>()
        .join(REQUEST_SEPARATOR)
}

/// The account and handle of a log, from its inception.
fn names(log: &[Value]) -> Option<(String, String)> {
    let inc = log.first()?.as_object()?;
    let username = inc.get("body")?.as_object()?.get("username")?.as_str()?;
    let account = account_id(inc);
    Some((handle(username, &account).replace('#', "%23"), account))
}

fn host_seeds(corpus: &mut Corpus) {
    let reads = |account: &str, handle: &str| {
        vec![
            format!("GET /v0/id/lookup?realm=global&handle={handle}"),
            format!("GET /v0/id/{account}/log?from=1"),
            format!("GET /v0/id/{account}/public"),
            format!("GET /v0/id/{account}/locks"),
            format!("POST /v0/id/{account}/challenge\n{{\"purpose\":\"fetch\"}}"),
            format!("POST /v0/id/{account}/challenge\n{{\"purpose\":\"login\"}}"),
            format!(
                "POST /v0/id/{account}/fetch\n{{\"lock\":\"recovery\",\"nonce\":\"\",\"url\":\"https://a.example\",\"sig\":\"\"}}"
            ),
        ]
    };
    // A registration from the vectors (the fuzz host has the vectors' host key), then every read of it.
    for v in vectors().iter().filter(|v| v.op == "register") {
        let Some(out) = v.output.as_ref().and_then(Value::as_object) else {
            continue;
        };
        let body: Value = ["log", "vault", "public"]
            .iter()
            .filter_map(|k| out.get(k).map(|x| (*k, x.clone())))
            .fold(Map::new(), |m, (k, x)| m.with(k, x))
            .into();
        let log = out.get("log").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
        let Some((handle, account)) = names(log) else { continue };
        let mut list = vec![format!(
            "POST /v0/id/register\n{}",
            String::from_utf8_lossy(&canonical(&body))
        )];
        list.extend(reads(&account, &handle));
        corpus.add(requests(&list));
    }
    // Every accepted log of the vectors pushed with `POST /events`, then read.
    for v in vectors().iter().filter(|v| v.op == "verify_log" && !v.rejects) {
        let events = input_array(v, "events");
        let Some((handle, account)) = names(events) else {
            continue;
        };
        let body: Value = Map::new().with("events", Value::Array(events.to_vec())).into();
        let mut list = vec![format!(
            "POST /v0/id/{account}/events\n{}",
            String::from_utf8_lossy(&canonical(&body))
        )];
        list.extend(reads(&account, &handle));
        corpus.add(requests(&list));
    }
    let peer = "peer=ed25519:CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk,1800000100,AAAA";
    corpus.add(requests(&[
        "GET /v0/host".into(),
        "OPTIONS /v0/peer/push".into(),
        "GET /.well-known/rootcard".into(),
        "GET /v1/host".into(),
        format!("GET /v0/peer/changes?since=0 {peer}"),
        format!("POST /v0/peer/push {peer}\n{{\"events\":[]}}"),
        "GET /v0/session/vault bearer=AAAA".into(),
        "PUT /v0/session/public bearer=AAAA\n{}".into(),
        "POST /v0/session/password bearer=AAAA\n{}".into(),
        "GET /v0/session/export bearer=AAAA".into(),
        "POST /v0/session/logout bearer=AAAA".into(),
    ]));
}

/// The re-signer must keep an accepted log accepted, or `log_signed` explores nothing past the signatures.
fn check_resign(events: &Value) {
    let Some(events) = events.as_array() else { return };
    let options = VerifyOptions::new(["global", "example"]);
    if verify_log(events, &options).is_err() {
        return;
    }
    let again = verify_log(&resign(events, FIX_ACCOUNT | FIX_PREV | FIX_SIGS), &options);
    assert!(again.is_ok(), "the re-signer breaks an accepted log: {again:?}");
}

/// Run the host seeds and print the statuses, so a seed that no longer registers is noticed.
fn run_host_seeds(corpus: &Corpus) {
    for seed in &corpus.seeds {
        let h = rootcard_fuzz::fuzz_host();
        let mut random = rootcard_fuzz::Counter::new();
        let statuses: Vec<u16> = rootcard_fuzz::requests(seed)
            .iter()
            .enumerate()
            .map(|(i, r)| route(&h, r, rootcard_fuzz::HOST_NOW + 10 * i as i64, &mut |b| random.fill(b)).status)
            .collect();
        println!("  host seed: {statuses:?}");
    }
}

/// Seeds of the `links` target from the vectors of `link.json`.
fn link_seeds(corpus: &mut Corpus, v: &rootcard_fuzz::Vector) {
    let get = |name: &str| v.input.get(name);
    let raw = |name: &str| get(name).and_then(Value::as_str).and_then(|t| hex_decode(t).ok());
    match v.op.as_str() {
        "parse_response_json" => {
            if let Some(b) = raw("text") {
                corpus.add([vec![0], b].concat());
            }
        }
        "parse_descriptor" => {
            if let Some(d) = get("descriptor") {
                corpus.add(with_byte(1, d));
            }
        }
        "parse_links" => {
            if let Some(d) = get("data") {
                corpus.add(with_byte(2, &Value::Array(vec![d.clone()])));
            }
        }
        "check_link" => {
            if let (Some(link), Some(Value::Array(responses))) = (get("link"), get("responses")) {
                let data = Map::new().with(
                    "user.links",
                    Map::new()
                        .with("v", 1i64)
                        .with("links", Value::Array(vec![link.clone()])),
                );
                let mut doc = vec![Value::Object(data)];
                for r in responses {
                    let r = r.as_object();
                    if let Some(t) = r.and_then(|r| r.get("text")) {
                        doc.push(t.clone());
                    } else if let Some(Value::Array(recs)) = r.and_then(|r| r.get("txt")) {
                        doc.push(Value::Array(
                            recs.iter()
                                .flat_map(|x| x.as_array().cloned().unwrap_or_default())
                                .collect(),
                        ));
                    } else {
                        doc.push(false.into());
                    }
                }
                corpus.add(with_byte(2, &Value::Array(doc)));
            }
        }
        "find_link_token" => {
            if let Some(t) = get("text").and_then(Value::as_str) {
                corpus.add([vec![3], t.as_bytes().to_vec()].concat());
            }
        }
        _ => {}
    }
}

fn main() -> std::io::Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let names = ["json", "text", "log", "log_signed", "documents", "host", "links"];
    let mut c: Vec<Corpus> = names.iter().map(|n| Corpus::new(&root, n)).collect();
    let [json, text, log, log_signed, documents, host, links] = &mut c[..] else {
        unreachable!()
    };

    let mut all_strings = BTreeSet::new();
    for v in vectors() {
        let input: Value = v.input.clone().into();
        json.add(canonical(&input));
        strings(&input, &mut all_strings);
        if v.op == "canonical"
            && let Some(Ok(raw)) = v.input.get("text").and_then(Value::as_str).map(hex_decode)
        {
            json.add(raw);
        }
        for name in ["events", "a", "b", "log"] {
            if let Some(events @ Value::Array(_)) = v.input.get(name) {
                log.add(canonical(events));
                if !v.rejects {
                    check_resign(events);
                    for control in [FIX_ACCOUNT | FIX_PREV | FIX_SIGS, FIX_PREV | FIX_SIGS, FIX_SIGS] {
                        log_signed.add(with_byte(control, events));
                    }
                }
            }
        }
        let doc = |name: &str| v.input.get(name).cloned();
        let seed = match v.op.as_str() {
            "verify_public" => doc("profile").map(|d| (0, d)),
            "verify_vault" => doc("vault").map(|d| (1, d)),
            "vault_change" => match (doc("old"), doc("new")) {
                (Some(o), Some(n)) => Some((2, Value::Array(vec![o, n]))),
                _ => None,
            },
            "import_account" => doc("file").map(|d| (3, d)),
            "read_card" | "card_text" => doc("card").map(|d| (4, d)),
            "verify_proof" => doc("proof").map(|d| (5, d)),
            "well_known_base" => doc("document").map(|d| (6, d)),
            "statement_challenge" => doc("statement").map(|d| (7, d)),
            "login_verify" => doc("request").map(|d| (7, d)),
            _ => None,
        };
        if let Some((op, d)) = seed {
            documents.add(with_byte(op, &d));
        }
        link_seeds(links, v);
        if let Some(contents) = v
            .output
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|o| o.get("contents"))
        {
            documents.add(with_byte(7, contents));
        }
    }
    for s in all_strings {
        text.add(s.into_bytes());
    }
    if let Some(v) = accepted("verify_log") {
        log.add(canonical(&Value::Array(input_array(v, "events").to_vec())));
    }
    host_seeds(host);
    run_host_seeds(host);
    for (name, corpus) in names.iter().zip(&c) {
        println!("{name}: {} seeds", corpus.write()?);
    }
    Ok(())
}
