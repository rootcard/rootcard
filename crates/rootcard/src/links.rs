//! Linked accounts (SPEC §12.3): the `user.links` profile key, link tokens and the interpreter of service descriptors.
//!
//! A link says that the identity and an account at another service (a GitHub account, a domain) have the same owner.
//! The identity side is the signed public profile; the external side is the link token `rootcard:<account id>`,
//! placed where only the external account's owner can write. A verifier checks both sides itself ([LNK-11]).
//!
//! This module does no I/O ([IMP-1]): [`link_requests`] says what to fetch, the caller fetches it under the rules of
//! [LNK-9] (HTTPS, no redirects, no credentials, at most [`RESPONSE_LIMIT`] bytes, [`FETCH_TIMEOUT_SECS`]), and
//! [`check_link`] decides from the answers. Services are described by data, the descriptors of the registry in
//! `spec/links/` ([LNK-19]); [`registry`] returns the descriptors bundled with this crate.

use crate::error::{Error, Result};
use crate::id::check_account_id;
use crate::json::{Map, Value, parse_json, parse_response_json};

/// The profile data key that holds the links ([LNK-1]).
pub const LINKS_KEY: &str = "user.links";
/// At most this many links ([LNK-1]).
pub const MAX_LINKS: usize = 16;
/// The prefix of a link token ([LNK-5]).
pub const TOKEN_PREFIX: &str = "rootcard:";
/// Only this many bytes of a text are searched for a link token ([LNK-6]).
pub const TOKEN_SEARCH_LIMIT: usize = 64 * 1024;
/// A verifier reads at most this many bytes of an answer ([LNK-9]); a longer one is `fetch_failed`.
pub const RESPONSE_LIMIT: usize = 64 * 1024;
/// A verifier gives up on a request after this many seconds ([LNK-9]).
pub const FETCH_TIMEOUT_SECS: u32 = 10;

const MAX_STEPS: usize = 4;
const MAX_ENTRIES: usize = 8;
const MAX_FORMS: usize = 16;
const MAX_POINTER_SEGMENTS: usize = 8;
const MAX_TEMPLATE: usize = 256;
const MAX_CHARS: usize = 64;
const MAX_REV: i64 = 1 << 32;

// ---------------------------------------------------------------------------------------------------------------------
// Links

/// One link of `user.links` ([LNK-1]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The service name, the key of a descriptor.
    pub service: String,
    /// The account name at the service.
    pub name: String,
    /// The stable account id at the service, for services where names can change hands ([LNK-18]).
    pub uid: Option<String>,
    /// Where the token is: a form of the descriptor, alone (`bio`) or with a value (`gist:5b1c`).
    pub reference: Option<String>,
}

impl Link {
    /// A link from its JSON form, checked against the schema of [LNK-1]. → `bad_link`
    pub fn from_value(v: &Value) -> Result<Link> {
        link_schema(v)
    }

    /// The link as a JSON object (`ref` for [`Link::reference`]).
    pub fn to_value(&self) -> Value {
        let mut m = Map::new()
            .with("service", self.service.as_str())
            .with("name", self.name.as_str());
        if let Some(u) = &self.uid {
            m.insert("uid", u.as_str().into());
        }
        if let Some(r) = &self.reference {
            m.insert("ref", r.as_str().into());
        }
        m.into()
    }
}

/// One entry of [`parse_links`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkEntry {
    /// The link, if the entry has the schema of [LNK-1].
    pub link: Option<Link>,
    /// `Ok` if the link can be checked; otherwise `bad_link` or `unsupported` ([LNK-2], [LNK-13]).
    pub status: Result<()>,
}

/// A service name ([LNK-1]): 1 to 32 characters of `a–z 0–9 -`, beginning with `a–z`.
fn is_service_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// A `ref` form ([LNK-1]): the same characters as a service name.
fn is_form_name(s: &str) -> bool {
    is_service_name(s)
}

fn is_uid_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-')
}

/// A link with the schema of [LNK-1]. → `bad_link`
fn link_schema(v: &Value) -> Result<Link> {
    let m = v.as_object().ok_or(Error::BadLink)?;
    if m.keys().any(|k| !matches!(k, "service" | "name" | "uid" | "ref")) {
        return Err(Error::BadLink);
    }
    let s = |k: &str| -> Result<Option<String>> {
        match m.get(k) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(Error::BadLink),
        }
    };
    let service = s("service")?.ok_or(Error::BadLink)?;
    let name = s("name")?.ok_or(Error::BadLink)?;
    let uid = s("uid")?;
    let reference = s("ref")?;
    let ok = is_service_name(&service)
        && (1..=256).contains(&name.len())
        && uid
            .as_ref()
            .is_none_or(|u| (1..=64).contains(&u.len()) && u.bytes().all(is_uid_char))
        && reference.as_ref().is_none_or(|r| (1..=256).contains(&r.len()));
    if ok {
        Ok(Link {
            service,
            name,
            uid,
            reference,
        })
    } else {
        Err(Error::BadLink)
    }
}

/// The descriptor for `service` in `registry`: the first one with that name ([LNK-19]).
pub fn find_descriptor<'a>(registry: &'a [Descriptor], service: &str) -> Option<&'a Descriptor> {
    registry.iter().find(|d| d.service == service)
}

/// The links of a verified profile's `data` ([LNK-1], [LNK-2], [LNK-13]), one entry per link, in order. No
/// `user.links` key means no links. → `bad_link` or `unsupported` for the value as a whole
pub fn parse_links(data: &Map, registry: &[Descriptor]) -> Result<Vec<LinkEntry>> {
    let Some(value) = data.get(LINKS_KEY) else {
        return Ok(Vec::new());
    };
    let m = value.as_object().ok_or(Error::BadLink)?;
    match m.get("v") {
        Some(Value::Int(1)) => {}
        Some(Value::Int(_)) => return Err(Error::Unsupported),
        _ => return Err(Error::BadLink),
    }
    if m.len() != 2 {
        return Err(Error::BadLink);
    }
    let list = m.get("links").and_then(Value::as_array).ok_or(Error::BadLink)?;
    if list.len() > MAX_LINKS {
        return Err(Error::BadLink);
    }
    let mut out: Vec<LinkEntry> = Vec::new();
    for v in list {
        let entry = match link_schema(v) {
            Err(e) => LinkEntry {
                link: None,
                status: Err(e),
            },
            Ok(link) => {
                let status = match find_descriptor(registry, &link.service) {
                    None => Err(Error::Unsupported),
                    Some(d) => d.check_fields(&link).and_then(|()| {
                        let duplicate = out.iter().any(|e| {
                            e.status.is_ok()
                                && e.link
                                    .as_ref()
                                    .is_some_and(|o| o.service == link.service && d.same_name(o, &link))
                        });
                        if duplicate { Err(Error::BadLink) } else { Ok(()) }
                    }),
                };
                LinkEntry {
                    link: Some(link),
                    status,
                }
            }
        };
        out.push(entry);
    }
    Ok(out)
}

/// The `user.links` value for `links` ([LNK-1]), for a client that publishes them ([LNK-4]). Every link must be
/// checkable with `registry` and appear once. → `bad_link`, `unsupported`
pub fn links_value(links: &[Link], registry: &[Descriptor]) -> Result<Value> {
    if links.len() > MAX_LINKS {
        return Err(Error::BadLink);
    }
    for (i, link) in links.iter().enumerate() {
        link_schema(&link.to_value())?;
        let d = find_descriptor(registry, &link.service).ok_or(Error::Unsupported)?;
        d.check_fields(link)?;
        if links[..i]
            .iter()
            .any(|o| o.service == link.service && d.same_name(o, link))
        {
            return Err(Error::BadLink);
        }
    }
    Ok(Map::new()
        .with("v", 1i64)
        .with("links", Value::Array(links.iter().map(Link::to_value).collect()))
        .into())
}

// ---------------------------------------------------------------------------------------------------------------------
// Tokens

/// The link token of an identity ([LNK-5]): `rootcard:` and the account id, 61 characters. → `bad_field`
pub fn link_token(account: &str) -> Result<String> {
    check_account_id(account)?;
    Ok(format!("{TOKEN_PREFIX}{account}"))
}

/// Whether the link token of `account` occurs in the first [`TOKEN_SEARCH_LIMIT`] bytes of `text`, with no ASCII
/// letter or digit directly before or after it ([LNK-6]). → `bad_field`
pub fn find_link_token(text: &[u8], account: &str) -> Result<bool> {
    let token = link_token(account)?;
    let t = token.as_bytes();
    let text = &text[..text.len().min(TOKEN_SEARCH_LIMIT)];
    if text.len() < t.len() {
        return Ok(false);
    }
    Ok((0..=text.len() - t.len()).any(|i| {
        text[i..i + t.len()] == *t
            && (i == 0 || !text[i - 1].is_ascii_alphanumeric())
            && text.get(i + t.len()).is_none_or(|c| !c.is_ascii_alphanumeric())
    }))
}

// ---------------------------------------------------------------------------------------------------------------------
// Descriptors

/// How a field's values are compared ([LNK-2]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compare {
    Exact,
    AsciiCi,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FieldKind {
    /// A string of `min ..= max` characters from a set of ASCII characters.
    Token { chars: [bool; 128], min: usize, max: usize },
    /// A lower-case ASCII host name.
    Domain,
    /// A `ref` form without a value.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Field {
    kind: FieldKind,
    compare: Compare,
}

impl Field {
    fn check(&self, s: &str) -> bool {
        match &self.kind {
            // `.` and `..` are never values: in a URL path they are dot segments, even percent-encoded ([LNK-8]).
            FieldKind::Token { chars, min, max } => {
                (*min..=*max).contains(&s.len())
                    && s.bytes().all(|c| c < 128 && chars[c as usize])
                    && s != "."
                    && s != ".."
            }
            FieldKind::Domain => is_domain(s),
            FieldKind::None => false,
        }
    }

    fn equal(&self, a: &str, b: &str) -> bool {
        match self.compare {
            Compare::Exact => a == b,
            Compare::AsciiCi => a.eq_ignore_ascii_case(b),
        }
    }
}

/// A domain name ([LNK-21]): at most 253 characters, at least two labels of 1 to 63 characters `a–z 0–9 -` that do not
/// begin or end with `-`, and a last label that is not all digits (so that it is never an IPv4 address).
pub fn is_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    let label_ok = |l: &&str| {
        let b = l.as_bytes();
        (1..=63).contains(&b.len())
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
    };
    labels.len() >= 2
        && labels.iter().all(label_ok)
        && labels.last().is_some_and(|l| !l.bytes().all(|c| c.is_ascii_digit()))
}

/// The placeholders of a template ([LNK-22]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Name,
    Uid,
    Ref,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Lit(String),
    Slot(Slot),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Template(Vec<Part>);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Name(String),
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pointer(Vec<Segment>);

/// The kind of a request ([LNK-22]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// An HTTPS `GET` whose answer is JSON.
    HttpJson,
    /// An HTTPS `GET` whose answer is text.
    HttpText,
    /// A DNS query for TXT records.
    DnsTxt,
}

impl RequestKind {
    /// The name of the kind in descriptors and requests.
    pub fn as_str(self) -> &'static str {
        match self {
            RequestKind::HttpJson => "http-json",
            RequestKind::HttpText => "http-text",
            RequestKind::DnsTxt => "dns-txt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Step {
    kind: RequestKind,
    target: Template,
    equal: Vec<(Pointer, Template)>,
    token_in: Vec<Pointer>,
}

/// A service descriptor of the registry ([LNK-22]), checked by [`parse_descriptor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// The service name.
    pub service: String,
    /// The descriptor's revision in the registry.
    pub rev: i64,
    /// A retired service: its links are `unsupported` ([LNK-17]).
    pub retired: bool,
    name: Field,
    uid: Option<Field>,
    forms: Vec<(String, Field)>,
    display: Template,
    checks: Vec<(String, Vec<Step>)>,
}

fn field_of(v: &Value, allow: &[&str]) -> Result<Field> {
    let m = v.as_object().ok_or(Error::BadField)?;
    let kind = m.get("type").and_then(Value::as_str).ok_or(Error::BadField)?;
    match kind {
        "token" | "domain" | "none" => {}
        _ => return Err(Error::Unsupported),
    }
    if !allow.contains(&kind) {
        return Err(Error::BadField);
    }
    if kind != "token" {
        if m.len() != 1 {
            return Err(Error::BadField);
        }
        let kind = if kind == "domain" {
            FieldKind::Domain
        } else {
            FieldKind::None
        };
        return Ok(Field {
            kind,
            compare: Compare::Exact,
        });
    }
    if m.keys()
        .any(|k| !matches!(k, "type" | "chars" | "min" | "max" | "compare"))
    {
        return Err(Error::BadField);
    }
    let chars = char_set(m.get("chars").and_then(Value::as_str).ok_or(Error::BadField)?)?;
    let int = |k: &str| {
        m.get(k)
            .and_then(Value::as_int)
            .filter(|n| (1..=256).contains(n))
            .ok_or(Error::BadField)
    };
    let (min, max) = (int("min")? as usize, int("max")? as usize);
    if min > max {
        return Err(Error::BadField);
    }
    let compare = match m.get("compare") {
        None => Compare::Exact,
        Some(Value::String(s)) if s == "exact" => Compare::Exact,
        Some(Value::String(s)) if s == "ascii-ci" => Compare::AsciiCi,
        Some(_) => return Err(Error::BadField),
    };
    Ok(Field {
        kind: FieldKind::Token { chars, min, max },
        compare,
    })
}

/// A character set ([LNK-22]): printable ASCII, where `x-y` is the range from `x` to `y` and any other character,
/// including a `-` at the start or the end, stands for itself.
fn char_set(s: &str) -> Result<[bool; 128]> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > MAX_CHARS || !b.iter().all(|c| (0x21..=0x7e).contains(c)) {
        return Err(Error::BadField);
    }
    let mut set = [false; 128];
    let mut i = 0;
    while i < b.len() {
        if i + 2 < b.len() && b[i + 1] == b'-' {
            if b[i] > b[i + 2] {
                return Err(Error::BadField);
            }
            for c in b[i]..=b[i + 2] {
                set[c as usize] = true;
            }
            i += 3;
        } else {
            set[b[i] as usize] = true;
            i += 1;
        }
    }
    Ok(set)
}

fn template_of(s: &str) -> Result<Template> {
    if s.is_empty() || s.len() > MAX_TEMPLATE {
        return Err(Error::BadField);
    }
    let mut parts = Vec::new();
    let mut lit = String::new();
    let mut rest = s;
    while let Some(c) = rest.chars().next() {
        if c == '{' {
            let end = rest.find('}').ok_or(Error::BadField)?;
            let slot = match &rest[1..end] {
                "name" => Slot::Name,
                "uid" => Slot::Uid,
                "ref" => Slot::Ref,
                _ => return Err(Error::BadField),
            };
            if !lit.is_empty() {
                parts.push(Part::Lit(core::mem::take(&mut lit)));
            }
            parts.push(Part::Slot(slot));
            rest = &rest[end + 1..];
        } else if c == '}' {
            return Err(Error::BadField);
        } else {
            lit.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    if !lit.is_empty() {
        parts.push(Part::Lit(lit));
    }
    Ok(Template(parts))
}

fn is_path_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~' | b'/')
}

/// Which placeholders a template may use, and the type of the name field.
struct Slots {
    uid: bool,
    reference: bool,
    name_is_domain: bool,
}

impl Slots {
    fn allows(&self, s: Slot) -> bool {
        match s {
            Slot::Name => true,
            Slot::Uid => self.uid,
            Slot::Ref => self.reference,
        }
    }
}

/// A URL template ([LNK-8], [LNK-22]): `https://`, then a literal host name or `{name}` of type `domain`, then a path
/// of literal characters `A–Z a–z 0–9 - . _ ~ /` and placeholders that are whole path segments.
fn url_template(s: &str, slots: &Slots) -> Result<Template> {
    let t = template_of(s)?;
    let mut parts = t.0.iter();
    let Some(Part::Lit(first)) = parts.next() else {
        return Err(Error::BadField);
    };
    let after = first.strip_prefix("https://").ok_or(Error::BadField)?;
    let path_start: String;
    if after.is_empty() {
        if !slots.name_is_domain || parts.next() != Some(&Part::Slot(Slot::Name)) {
            return Err(Error::BadField);
        }
        match parts.next() {
            Some(Part::Lit(l)) if l.starts_with('/') => path_start = l.clone(),
            _ => return Err(Error::BadField),
        }
    } else {
        let slash = after.find('/').ok_or(Error::BadField)?;
        if !is_domain(&after[..slash]) {
            return Err(Error::BadField);
        }
        path_start = after[slash..].to_string();
    }
    if !path_start.bytes().all(is_path_char) {
        return Err(Error::BadField);
    }
    // Every placeholder in the path is a whole segment: after a `/`, before a `/` or the end ([LNK-8]).
    let mut prev_ends_slash = path_start.ends_with('/');
    let rest: Vec<&Part> = parts.collect();
    for (k, p) in rest.iter().enumerate() {
        match p {
            Part::Lit(l) if l.bytes().all(is_path_char) => prev_ends_slash = l.ends_with('/'),
            Part::Slot(s) if slots.allows(*s) => {
                let next_ok = match rest.get(k + 1) {
                    None => true,
                    Some(Part::Lit(l)) => l.starts_with('/'),
                    Some(Part::Slot(_)) => false,
                };
                if !prev_ends_slash || !next_ok {
                    return Err(Error::BadField);
                }
                prev_ends_slash = false;
            }
            _ => return Err(Error::BadField),
        }
    }
    Ok(t)
}

/// A DNS name template ([LNK-22]): literal labels of `a–z 0–9 - _`, each followed by a dot, then `{name}` of type
/// `domain`.
fn dns_template(s: &str, slots: &Slots) -> Result<Template> {
    let t = template_of(s)?;
    let ok = slots.name_is_domain
        && match t.0.as_slice() {
            [Part::Slot(Slot::Name)] => true,
            [Part::Lit(l), Part::Slot(Slot::Name)] => l.strip_suffix('.').is_some_and(|l| {
                l.split('.').all(|label| {
                    (1..=63).contains(&label.len())
                        && label
                            .bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_'))
                })
            }),
            _ => false,
        };
    if ok { Ok(t) } else { Err(Error::BadField) }
}

/// A template for a value an answer must hold ([LNK-22]): any text and placeholders.
fn value_template(s: &str, slots: &Slots) -> Result<Template> {
    let t = template_of(s)?;
    if t.0.iter().all(|p| match p {
        Part::Slot(s) => slots.allows(*s),
        Part::Lit(_) => true,
    }) {
        Ok(t)
    } else {
        Err(Error::BadField)
    }
}

/// A JSON pointer (RFC 6901) of at most 8 segments, where a segment `*` stands for every member or element.
fn pointer_of(s: &str, wildcard: bool) -> Result<Pointer> {
    if s.is_empty() {
        return Ok(Pointer(Vec::new()));
    }
    let rest = s.strip_prefix('/').ok_or(Error::BadField)?;
    let mut segs = Vec::new();
    for raw in rest.split('/') {
        if raw == "*" {
            if !wildcard {
                return Err(Error::BadField);
            }
            segs.push(Segment::Any);
            continue;
        }
        let mut out = String::new();
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c == '~' {
                match chars.next() {
                    Some('0') => out.push('~'),
                    Some('1') => out.push('/'),
                    _ => return Err(Error::BadField),
                }
            } else {
                out.push(c);
            }
        }
        segs.push(Segment::Name(out));
    }
    if segs.len() > MAX_POINTER_SEGMENTS {
        return Err(Error::BadField);
    }
    Ok(Pointer(segs))
}

fn step_of(v: &Value, slots: &Slots) -> Result<Step> {
    let m = v.as_object().ok_or(Error::BadField)?;
    let kind = match m.get("kind").and_then(Value::as_str).ok_or(Error::BadField)? {
        "http-json" => RequestKind::HttpJson,
        "http-text" => RequestKind::HttpText,
        "dns-txt" => RequestKind::DnsTxt,
        _ => return Err(Error::Unsupported),
    };
    let allowed: &[&str] = match kind {
        RequestKind::HttpJson => &["kind", "url", "equal", "token_in"],
        RequestKind::HttpText => &["kind", "url"],
        RequestKind::DnsTxt => &["kind", "name"],
    };
    if m.keys().any(|k| !allowed.contains(&k)) {
        return Err(Error::BadField);
    }
    let target = match kind {
        RequestKind::DnsTxt => dns_template(m.get("name").and_then(Value::as_str).ok_or(Error::BadField)?, slots)?,
        _ => url_template(m.get("url").and_then(Value::as_str).ok_or(Error::BadField)?, slots)?,
    };
    let mut equal = Vec::new();
    if let Some(e) = m.get("equal") {
        let e = e.as_object().ok_or(Error::BadField)?;
        if !(1..=MAX_ENTRIES).contains(&e.len()) {
            return Err(Error::BadField);
        }
        for (p, t) in e.iter() {
            equal.push((
                pointer_of(p, false)?,
                value_template(t.as_str().ok_or(Error::BadField)?, slots)?,
            ));
        }
    }
    let mut token_in = Vec::new();
    if let Some(t) = m.get("token_in") {
        let t = t.as_array().ok_or(Error::BadField)?;
        if !(1..=MAX_ENTRIES).contains(&t.len()) {
            return Err(Error::BadField);
        }
        for p in t {
            token_in.push(pointer_of(p.as_str().ok_or(Error::BadField)?, true)?);
        }
    }
    if kind == RequestKind::HttpJson && equal.is_empty() && token_in.is_empty() {
        return Err(Error::BadField);
    }
    Ok(Step {
        kind,
        target,
        equal,
        token_in,
    })
}

impl Step {
    /// Whether the step looks for the token.
    fn finds_token(&self) -> bool {
        self.kind != RequestKind::HttpJson || !self.token_in.is_empty()
    }

    /// Whether the step compares a value with exactly the placeholder `s`.
    fn compares(&self, s: Slot) -> bool {
        self.equal.iter().any(|(_, t)| t.0 == [Part::Slot(s)])
    }
}

/// Check a service descriptor against the format of [LNK-22] and the rules every descriptor must keep ([LNK-7],
/// [LNK-8], [LNK-18]). → `bad_field`; `unsupported` for a `v`, field type or step kind this interpreter does not know
/// ([LNK-13])
pub fn parse_descriptor(v: &Value) -> Result<Descriptor> {
    let m = v.as_object().ok_or(Error::BadField)?;
    match m.get("v") {
        Some(Value::Int(1)) => {}
        Some(Value::Int(_)) => return Err(Error::Unsupported),
        _ => return Err(Error::BadField),
    }
    if m.keys()
        .any(|k| !matches!(k, "v" | "service" | "rev" | "status" | "fields" | "display" | "checks"))
    {
        return Err(Error::BadField);
    }
    let service = m
        .get("service")
        .and_then(Value::as_str)
        .filter(|s| is_service_name(s))
        .ok_or(Error::BadField)?;
    let rev = m
        .get("rev")
        .and_then(Value::as_int)
        .filter(|r| (1..=MAX_REV).contains(r))
        .ok_or(Error::BadField)?;
    let retired = match m.get("status").and_then(Value::as_str) {
        Some("active") => false,
        Some("retired") => true,
        _ => return Err(Error::BadField),
    };
    let fields = m.get("fields").and_then(Value::as_object).ok_or(Error::BadField)?;
    if fields.keys().any(|k| !matches!(k, "name" | "uid" | "ref")) {
        return Err(Error::BadField);
    }
    let name = field_of(fields.get("name").ok_or(Error::BadField)?, &["token", "domain"])?;
    let uid = fields.get("uid").map(|u| field_of(u, &["token"])).transpose()?;
    if let Some(Field {
        kind: FieldKind::Token { chars, max, .. },
        ..
    }) = &uid
        && (*max > 64 || (0u8..128).any(|c| chars[c as usize] && !is_uid_char(c)))
    {
        return Err(Error::BadField);
    }
    // [LNK-18]: a service whose names can change hands needs the stable id.
    let name_is_domain = name.kind == FieldKind::Domain;
    if !name_is_domain && uid.is_none() {
        return Err(Error::BadField);
    }
    let mut forms = Vec::new();
    if let Some(r) = fields.get("ref") {
        let r = r.as_object().ok_or(Error::BadField)?;
        if !(1..=MAX_FORMS).contains(&r.len()) {
            return Err(Error::BadField);
        }
        for (form, f) in r.iter() {
            if !is_form_name(form) {
                return Err(Error::BadField);
            }
            forms.push((form.to_string(), field_of(f, &["token", "none"])?));
        }
    }
    let display = url_template(
        m.get("display").and_then(Value::as_str).ok_or(Error::BadField)?,
        &Slots {
            uid: uid.is_some(),
            reference: false,
            name_is_domain,
        },
    )?;
    let checks_m = m.get("checks").and_then(Value::as_object).ok_or(Error::BadField)?;
    if checks_m.is_empty() {
        return Err(Error::BadField);
    }
    let mut checks = Vec::new();
    for (key, steps) in checks_m.iter() {
        let form = forms.iter().find(|(f, _)| f == key);
        if key != "*" && form.is_none() {
            return Err(Error::BadField);
        }
        let slots = Slots {
            uid: uid.is_some(),
            reference: form.is_some_and(|(_, f)| f.kind != FieldKind::None),
            name_is_domain,
        };
        let steps = steps.as_array().ok_or(Error::BadField)?;
        if !(1..=MAX_STEPS).contains(&steps.len()) {
            return Err(Error::BadField);
        }
        let steps = steps.iter().map(|s| step_of(s, &slots)).collect::<Result<Vec<_>>>()?;
        if !steps.iter().any(Step::finds_token) {
            return Err(Error::BadField);
        }
        // [LNK-18]: the account the stable id names is checked to be the one the link names, under that name.
        if uid.is_some()
            && !(steps.iter().any(|s| s.compares(Slot::Uid)) && steps.iter().any(|s| s.compares(Slot::Name)))
        {
            return Err(Error::BadField);
        }
        checks.push((key.to_string(), steps));
    }
    if forms.iter().any(|(f, _)| !checks.iter().any(|(k, _)| k == f)) {
        return Err(Error::BadField);
    }
    Ok(Descriptor {
        service: service.to_string(),
        rev,
        retired,
        name,
        uid,
        forms,
        display,
        checks,
    })
}

/// The bundled registry as canonical JSON: an array of descriptors, generated from `spec/links/` by `xtask`.
mod bundled {
    include!("links_registry.rs");
}

/// The descriptors bundled with this crate, from the registry in `spec/links/` ([LNK-19]). A descriptor this
/// interpreter cannot read is left out, so that its service is `unsupported`.
pub fn registry() -> Vec<Descriptor> {
    match parse_json(bundled::REGISTRY.as_bytes()) {
        Ok(Value::Array(list)) => list.iter().filter_map(|d| parse_descriptor(d).ok()).collect(),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Checking

impl Descriptor {
    /// Split a reference into its form and the field of the form.
    fn form<'a>(&self, reference: &'a str) -> Result<(&str, &Field, Option<&'a str>)> {
        let (form, value) = match reference.split_once(':') {
            Some((f, v)) => (f, Some(v)),
            None => (reference, None),
        };
        if !is_form_name(form) {
            return Err(Error::BadLink);
        }
        let (name, field) = self.forms.iter().find(|(f, _)| f == form).ok_or(Error::Unsupported)?;
        Ok((name.as_str(), field, value))
    }

    /// The service's rules for the fields of a link ([LNK-2], [LNK-13]): name, then uid, then ref. → `bad_link`,
    /// `unsupported`
    fn check_fields(&self, link: &Link) -> Result<()> {
        link_schema(&link.to_value())?;
        if self.retired {
            return Err(Error::Unsupported);
        }
        if !self.name.check(&link.name) {
            return Err(Error::BadLink);
        }
        match (&self.uid, &link.uid) {
            (Some(f), Some(u)) if f.check(u) => {}
            (None, None) => {}
            _ => return Err(Error::BadLink),
        }
        match &link.reference {
            None if self.checks.iter().any(|(k, _)| k == "*") => Ok(()),
            None => Err(Error::BadLink),
            Some(r) => {
                let (_, field, value) = self.form(r)?;
                match (&field.kind, value) {
                    (FieldKind::None, None) => Ok(()),
                    (FieldKind::None, Some(_)) | (_, None) => Err(Error::BadLink),
                    (_, Some(v)) if field.check(v) => Ok(()),
                    _ => Err(Error::BadLink),
                }
            }
        }
    }

    /// Whether two links of this service name the same account ([LNK-2]).
    fn same_name(&self, a: &Link, b: &Link) -> bool {
        self.name.equal(&a.name, &b.name)
    }

    fn steps(&self, link: &Link) -> Result<&[Step]> {
        self.check_fields(link)?;
        let key = match &link.reference {
            Some(r) => self.form(r)?.0,
            None => "*",
        };
        self.checks
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, s)| s.as_slice())
            .ok_or(Error::BadLink)
    }

    fn slot_value<'a>(&self, link: &'a Link, s: Slot) -> &'a str {
        match s {
            Slot::Name => &link.name,
            Slot::Uid => link.uid.as_deref().unwrap_or(""),
            Slot::Ref => link
                .reference
                .as_deref()
                .and_then(|r| r.split_once(':'))
                .map_or("", |(_, v)| v),
        }
    }

    fn slot_field(&self, s: Slot) -> Option<&Field> {
        match s {
            Slot::Name => Some(&self.name),
            Slot::Uid => self.uid.as_ref(),
            Slot::Ref => None,
        }
    }

    /// Fill a template; `encode` percent-encodes the values ([LNK-8]).
    fn fill(&self, t: &Template, link: &Link, encode: bool) -> String {
        let mut out = String::new();
        for p in &t.0 {
            match p {
                Part::Lit(l) => out.push_str(l),
                Part::Slot(s) => {
                    let v = self.slot_value(link, *s);
                    if encode {
                        percent_encode(v, &mut out);
                    } else {
                        out.push_str(v);
                    }
                }
            }
        }
        out
    }
}

/// Percent-encode every byte outside the unreserved characters of RFC 3986, with upper-case hex.
fn percent_encode(s: &str, out: &mut String) {
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~') {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
}

/// One request of [`link_requests`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRequest {
    /// What to do.
    pub kind: RequestKind,
    /// The URL (`http-json`, `http-text`) or the DNS name (`dns-txt`).
    pub target: String,
}

impl LinkRequest {
    /// The request as JSON: `{ kind, url }` or `{ kind, name }`.
    pub fn to_value(&self) -> Value {
        let k = if self.kind == RequestKind::DnsTxt {
            "name"
        } else {
            "url"
        };
        Map::new()
            .with("kind", self.kind.as_str())
            .with(k, self.target.as_str())
            .into()
    }
}

/// The requests that check `link` with descriptor `d`, in order ([LNK-10]). Every URL is built from the descriptor
/// and the link's validated fields ([LNK-8]). → `bad_link`, `unsupported`
pub fn link_requests(link: &Link, d: &Descriptor) -> Result<Vec<LinkRequest>> {
    if link.service != d.service {
        return Err(Error::BadLink);
    }
    Ok(d.steps(link)?
        .iter()
        .map(|s| LinkRequest {
            kind: s.kind,
            target: d.fill(&s.target, link, s.kind != RequestKind::DnsTxt),
        })
        .collect())
}

/// The URL that shows the linked account, from the descriptor's `display` template ([LNK-12]). It is shown as text or
/// as a link to that URL, never fetched. → `bad_link`, `unsupported`
pub fn link_display(link: &Link, d: &Descriptor) -> Result<String> {
    if link.service != d.service {
        return Err(Error::BadLink);
    }
    d.check_fields(link)?;
    Ok(d.fill(&d.display, link, true))
}

/// The answer to one request of [`link_requests`], as the caller received it under [LNK-9].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkResponse {
    /// The request failed: network, TLS, a status other than 200, a redirect, the size or the time limit.
    Failed,
    /// The body of a `200` answer to an HTTPS request.
    Body(Vec<u8>),
    /// The TXT records of a DNS answer, each a list of character strings.
    Txt(Vec<Vec<Vec<u8>>>),
}

fn resolve<'a>(v: Option<&'a Value>, p: &[Segment], out: &mut Vec<&'a Value>) {
    let Some(v) = v else { return };
    let Some((first, rest)) = p.split_first() else {
        out.push(v);
        return;
    };
    match (first, v) {
        (Segment::Name(n), Value::Object(m)) => resolve(m.get(n), rest, out),
        (Segment::Any, Value::Object(m)) => {
            for (_, x) in m.iter() {
                resolve(Some(x), rest, out);
            }
        }
        (Segment::Any, Value::Array(a)) => {
            for x in a {
                resolve(Some(x), rest, out);
            }
        }
        _ => {}
    }
}

/// Check a link with the answers to its [`link_requests`] ([LNK-10]). The steps run in order and the first that fails
/// decides: `fetch_failed` for a failed request or an answer that is too large or does not parse ([LNK-9]),
/// `wrong_owner` if the answer names another account ([LNK-18]), `token_missing` if the token of `account` is not
/// where the step looks ([LNK-6], [LNK-7]). `Ok` means verified, by this check, now ([LNK-11]). → also `bad_link`,
/// `unsupported`, and `bad_field` for an invalid account id or answers that do not match the requests
pub fn check_link(link: &Link, account: &str, d: &Descriptor, responses: &[LinkResponse]) -> Result<()> {
    check_account_id(account)?;
    if link.service != d.service {
        return Err(Error::BadLink);
    }
    let steps = d.steps(link)?;
    if responses.len() != steps.len() {
        return Err(Error::BadField);
    }
    for (step, resp) in steps.iter().zip(responses) {
        match (step.kind, resp) {
            (_, LinkResponse::Failed) => return Err(Error::FetchFailed),
            (RequestKind::DnsTxt, LinkResponse::Txt(records)) => {
                if records.iter().flatten().map(Vec::len).sum::<usize>() > RESPONSE_LIMIT {
                    return Err(Error::FetchFailed);
                }
                let mut found = false;
                for r in records {
                    found |= find_link_token(&r.concat(), account)?;
                }
                if !found {
                    return Err(Error::TokenMissing);
                }
            }
            (RequestKind::HttpText, LinkResponse::Body(body)) => {
                if body.len() > RESPONSE_LIMIT {
                    return Err(Error::FetchFailed);
                }
                if !find_link_token(body, account)? {
                    return Err(Error::TokenMissing);
                }
            }
            (RequestKind::HttpJson, LinkResponse::Body(body)) => {
                if body.len() > RESPONSE_LIMIT {
                    return Err(Error::FetchFailed);
                }
                let root = parse_response_json(body).map_err(|_| Error::FetchFailed)?;
                for (p, t) in &step.equal {
                    let want = d.fill(t, link, false);
                    let field = match t.0.as_slice() {
                        [Part::Slot(s)] => d.slot_field(*s),
                        _ => None,
                    };
                    let mut got = Vec::new();
                    resolve(root.as_ref(), &p.0, &mut got);
                    let ok = match got.first() {
                        Some(Value::String(s)) => field.map_or(*s == want, |f| f.equal(s, &want)),
                        Some(Value::Int(n)) => n.to_string() == want,
                        _ => false,
                    };
                    if !ok {
                        return Err(Error::WrongOwner);
                    }
                }
                if !step.token_in.is_empty() {
                    let mut found = false;
                    for p in &step.token_in {
                        let mut got = Vec::new();
                        resolve(root.as_ref(), &p.0, &mut got);
                        for v in got {
                            if let Value::String(s) = v {
                                found |= find_link_token(s.as_bytes(), account)?;
                            }
                        }
                    }
                    if !found {
                        return Err(Error::TokenMissing);
                    }
                }
            }
            _ => return Err(Error::BadField),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        let id = crate::encoding::base32_encode(&[7; 32]);
        let id = id.as_str();
        let t = link_token(id).unwrap();
        assert_eq!(t.len(), 61);
        let f = |s: &str| find_link_token(s.as_bytes(), id).unwrap();
        assert!(f(&t));
        assert!(f(&format!("my id: {t}.")));
        assert!(!f(&format!("x{t}")));
        assert!(!f(&format!("{t}0")));
        assert!(f(&format!("x{t} and {t}")));
        assert!(!f(&t.to_lowercase()));
        let far = " ".repeat(TOKEN_SEARCH_LIMIT - t.len()) + &t;
        assert!(f(&far));
        assert!(!f(&(String::from(" ") + &far)));
        assert_eq!(link_token("abc"), Err(Error::BadField));
    }

    #[test]
    fn domains() {
        for ok in ["example.org", "a.b.c", "xn--bcher-kva.example", "1.example", "a-b.c0"] {
            assert!(is_domain(ok), "{ok}");
        }
        for bad in [
            "example",
            "Example.org",
            "-a.org",
            "a-.org",
            "a..org",
            "1.2.3.4",
            "a.org.",
            "",
            "a_b.org",
        ] {
            assert!(!is_domain(bad), "{bad}");
        }
    }

    #[test]
    fn char_sets() {
        let s = char_set("A-Za-z0-9-").unwrap();
        assert!(s[b'-' as usize] && s[b'q' as usize] && s[b'Q' as usize] && s[b'5' as usize]);
        assert!(!s[b'_' as usize]);
        assert_eq!(char_set("z-a"), Err(Error::BadField));
        assert_eq!(char_set(""), Err(Error::BadField));
        assert_eq!(char_set("a b"), Err(Error::BadField));
    }

    #[test]
    fn bundled_registry_parses() {
        let r = registry();
        let names: Vec<&str> = r.iter().map(|d| d.service.as_str()).collect();
        assert_eq!(names, ["dns", "github", "web"]);
    }
}
