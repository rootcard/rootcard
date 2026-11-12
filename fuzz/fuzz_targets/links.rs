//! Linked accounts (SPEC §12.3): the first byte chooses what the rest is. None of them panics, and every URL a check
//! would fetch keeps [LNK-8]: `https://`, a valid host name, a path without a query, a fragment or a dot segment.
//!
//! 0 an answer for `parse_response_json` ([LNK-9]): an accepted value is rootcard JSON; 1 a descriptor for
//! `parse_descriptor` ([LNK-22]), then the requests and display URLs of sample links; 2 `[data, body, ...]`:
//! `parse_links` of the profile data with the bundled registry, then `link_requests`, `link_display` and
//! `check_link` of every checkable link with the bodies as answers; 3 a text for `find_link_token` ([LNK-6]) and as
//! the answer to links of every bundled service.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rootcard::json::{Value, canonical, parse_json, parse_response_json};
use rootcard::links::{
    Descriptor, Link, LinkResponse, RequestKind, find_descriptor, find_link_token, is_domain, link_display,
    link_requests, parse_descriptor, parse_links, registry,
};
use std::sync::OnceLock;

const ACCOUNT: &str = "52WWGVFV9RWKHKHN9T45S1C9RRVX8MRCRWY292PGG6F4HKQYE1B0";

fn bundled() -> &'static [Descriptor] {
    static R: OnceLock<Vec<Descriptor>> = OnceLock::new();
    R.get_or_init(registry)
}

/// [LNK-8]: what a verifier may fetch or display.
fn check_url(url: &str) {
    let rest = url
        .strip_prefix("https://")
        .unwrap_or_else(|| panic!("not https: {url}"));
    let (host, path) = rest.split_at(rest.find('/').unwrap_or_else(|| panic!("no path: {url}")));
    assert!(is_domain(host), "host {host:?} of {url}");
    assert!(!path.contains(['?', '#', '\\']), "query or fragment in {url}");
    for seg in path.split('/') {
        let s = seg.to_ascii_lowercase().replace("%2e", ".");
        assert!(s != "." && s != "..", "dot segment in {url}");
    }
}

fn check_requests(link: &Link, d: &Descriptor) {
    if let Ok(reqs) = link_requests(link, d) {
        for r in reqs {
            match r.kind {
                RequestKind::DnsTxt => assert!(r.target.len() <= 253 + 64 && !r.target.contains('/')),
                _ => check_url(&r.target),
            }
        }
        check_url(&link_display(link, d).unwrap_or_else(|e| panic!("requests but no display: {e}")));
    }
}

fn sample_links(service: &str) -> Vec<Link> {
    let mut out = Vec::new();
    for name in ["alice", "example.org", "a-b", "..", "%2e"] {
        for uid in [None, Some("583231")] {
            for reference in [None, Some("bio"), Some("gist:5b1c"), Some("gist:.."), Some("x")] {
                out.push(Link {
                    service: service.into(),
                    name: name.into(),
                    uid: uid.map(Into::into),
                    reference: reference.map(Into::into),
                });
            }
        }
    }
    out
}

fn answers(bodies: &[Value], n: usize) -> Vec<LinkResponse> {
    (0..n)
        .map(|i| match bodies.get(i) {
            Some(Value::String(s)) => LinkResponse::Body(s.as_bytes().to_vec()),
            Some(Value::Array(records)) => LinkResponse::Txt(
                records
                    .iter()
                    .map(|r| vec![r.as_str().unwrap_or_default().as_bytes().to_vec()])
                    .collect(),
            ),
            _ => LinkResponse::Failed,
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&op, rest)) = data.split_first() else { return };
    match op % 4 {
        0 => {
            if let Ok(Some(v)) = parse_response_json(rest) {
                assert_eq!(parse_json(&canonical(&v)).as_ref(), Ok(&v));
            }
        }
        1 => {
            let Ok(doc) = parse_json(rest) else { return };
            if let Ok(d) = parse_descriptor(&doc) {
                for link in sample_links(&d.service) {
                    check_requests(&link, &d);
                }
            }
        }
        2 => {
            let Ok(Value::Array(doc)) = parse_json(rest) else {
                return;
            };
            let Some(Value::Object(data)) = doc.first() else { return };
            let reg = bundled();
            let Ok(entries) = parse_links(data, reg) else { return };
            for e in entries {
                let (Some(link), Ok(())) = (e.link, e.status) else {
                    continue;
                };
                let d = find_descriptor(reg, &link.service).unwrap_or_else(|| panic!("ok without a descriptor"));
                let reqs = link_requests(&link, d).unwrap_or_else(|e| panic!("ok link without requests: {e}"));
                check_requests(&link, d);
                let _ = rootcard::links::check_link(&link, ACCOUNT, d, &answers(&doc[1..], reqs.len()));
            }
        }
        _ => {
            let _ = find_link_token(rest, ACCOUNT);
            let text = String::from_utf8_lossy(rest).into_owned();
            let reg = bundled();
            for d in reg {
                for link in sample_links(&d.service) {
                    if let Ok(reqs) = link_requests(&link, d) {
                        let mut bodies = vec![Value::from(text.as_str()); reqs.len()];
                        if let Some(RequestKind::DnsTxt) = reqs.first().map(|r| r.kind) {
                            bodies = vec![Value::Array(vec![text.as_str().into()])];
                        }
                        let _ = rootcard::links::check_link(&link, ACCOUNT, d, &answers(&bodies, reqs.len()));
                    }
                }
            }
        }
    }
});
