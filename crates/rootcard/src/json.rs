//! Canonical JSON (SPEC §2): a strict parser and the RFC 8785 serialization of the rootcard subset of JSON.

use crate::error::{Error, Result};
use core::cmp::Ordering;

/// The largest safe integer, 2⁵³ − 1 ([CJ-2]).
pub const MAX_SAFE: i64 = (1 << 53) - 1;

/// The maximum nesting depth of arrays and objects ([CJ-5]).
pub const MAX_DEPTH: usize = 32;

/// A rootcard JSON value ([CJ-1]): no `null` and no non-integer numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An object, with unique member names.
    Object(Map),
    /// An array.
    Array(Vec<Value>),
    /// A string of Unicode scalar values.
    String(String),
    /// A safe integer.
    Int(i64),
    /// `true` or `false`.
    Bool(bool),
}

/// A JSON object. Members are kept sorted in canonical order (UTF-16 code units, [CJ-9]) and names are unique.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Map(Vec<(String, Value)>);

/// Compare two member names as sequences of UTF-16 code units (RFC 8785 §3.2.3).
pub fn cmp_names(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

impl Map {
    /// An empty object.
    pub fn new() -> Self {
        Map(Vec::new())
    }

    fn find(&self, name: &str) -> core::result::Result<usize, usize> {
        self.0.binary_search_by(|(k, _)| cmp_names(k, name))
    }

    /// Insert or replace a member. Returns the previous value.
    pub fn insert(&mut self, name: impl Into<String>, value: Value) -> Option<Value> {
        let name = name.into();
        match self.find(&name) {
            Ok(i) => Some(core::mem::replace(&mut self.0[i].1, value)),
            Err(i) => {
                self.0.insert(i, (name, value));
                None
            }
        }
    }

    /// Builder form of [`Map::insert`].
    pub fn with(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.insert(name, value.into());
        self
    }

    /// The member `name`.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.find(name).ok().map(|i| &self.0[i].1)
    }

    /// Remove the member `name`.
    pub fn remove(&mut self, name: &str) -> Option<Value> {
        self.find(name).ok().map(|i| self.0.remove(i).1)
    }

    /// The object without the member `name` (the `x without f` of SPEC §0.1).
    pub fn without(&self, name: &str) -> Map {
        let mut m = self.clone();
        m.remove(name);
        m
    }

    /// The members, in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// The member names, in canonical order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(k, _)| k.as_str())
    }

    /// The number of members.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the object has no members.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Map> for Value {
    fn from(m: Map) -> Self {
        Value::Object(m)
    }
}
impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Self {
        Value::Array(v)
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_string())
    }
}
impl From<&String> for Value {
    fn from(s: &String) -> Self {
        Value::String(s.clone())
    }
}
impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::Int(i)
    }
}
impl From<u64> for Value {
    fn from(i: u64) -> Self {
        Value::Int(i64::try_from(i).unwrap_or(i64::MAX))
    }
}
impl From<u32> for Value {
    fn from(i: u32) -> Self {
        Value::Int(i64::from(i))
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl Value {
    /// The object, if this is one.
    pub fn as_object(&self) -> Option<&Map> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }
    /// The array, if this is one.
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    /// The integer, if this is one.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    /// The boolean, if this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Whether the value satisfies [CJ-2] and [CJ-5] (strings are always valid in Rust).
    fn check(&self, depth: usize) -> bool {
        match self {
            Value::Object(m) => depth < MAX_DEPTH && m.0.iter().all(|(_, v)| v.check(depth + 1)),
            Value::Array(a) => depth < MAX_DEPTH && a.iter().all(|v| v.check(depth + 1)),
            Value::Int(i) => (-MAX_SAFE..=MAX_SAFE).contains(i),
            Value::String(_) | Value::Bool(_) => true,
        }
    }

    /// Check that a value built in code is a rootcard JSON value ([CJ-1]–[CJ-5]). → `bad_json`
    pub fn validate(&self) -> Result<()> {
        if self.check(0) { Ok(()) } else { Err(Error::BadJson) }
    }
}

/// `canonical(x)`: the RFC 8785 serialization ([CJ-9]).
pub fn canonical(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(value, &mut out);
    out
}

/// `canonical(x)` of an object.
pub fn canonical_map(map: &Map) -> Vec<u8> {
    let mut out = Vec::new();
    write_map(map, &mut out);
    out
}

fn write_map(m: &Map, out: &mut Vec<u8>) {
    out.push(b'{');
    for (i, (k, v)) in m.0.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        write_string(k, out);
        out.push(b':');
        write_value(v, out);
    }
    out.push(b'}');
}

fn write_value(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Object(m) => write_map(m, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(x, out);
            }
            out.push(b']');
        }
        Value::String(s) => write_string(s, out),
        Value::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
    }
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                let b = c as u32 as usize;
                out.extend_from_slice(b"\\u00");
                out.push(HEX[b >> 4]);
                out.push(HEX[b & 15]);
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Parse a JSON text strictly ([CJ-6]). → `bad_json`
pub fn parse_json(bytes: &[u8]) -> Result<Value> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(Error::BadJson);
    }
    parse_with(bytes, false)?.ok_or(Error::BadJson)
}

/// Parse a JSON text from outside rootcard, such as a linked service's answer (SPEC [LNK-9]): any RFC 8259 text that
/// is well-formed UTF-8 without a byte order mark, with unique member names, no lone surrogate escapes and at most 32
/// levels of nesting. `null` and numbers that are not safe integers in the form `0|-?[1-9][0-9]*` are dropped: an
/// object member with such a value is left out, as is an array element. The result is `None` if the whole text is such
/// a value. → `bad_json`
pub fn parse_response_json(bytes: &[u8]) -> Result<Option<Value>> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(Error::BadJson);
    }
    parse_with(bytes, true)
}

fn parse_with(bytes: &[u8], lenient: bool) -> Result<Option<Value>> {
    let text = core::str::from_utf8(bytes).map_err(|_| Error::BadJson)?;
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
        lenient,
    };
    p.ws();
    let v = p.value(1)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(Error::BadJson);
    }
    Ok(v)
}

/// Parse a structure with a size limit ([CJ-8]): the received bytes against ⌊1.25 × limit⌋ before parsing, the
/// canonical bytes against `limit` after. → `too_large`, `bad_json`
pub fn parse_limited(bytes: &[u8], limit: usize) -> Result<Value> {
    if bytes.len() > limit + limit / 4 {
        return Err(Error::TooLarge);
    }
    let v = parse_json(bytes)?;
    if canonical(&v).len() > limit {
        return Err(Error::TooLarge);
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    /// [`parse_response_json`]: `null` and other numbers are accepted and dropped (`None`).
    lenient: bool,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &[u8]) -> Result<()> {
        if self.s.get(self.i..).is_some_and(|r| r.starts_with(lit)) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(Error::BadJson)
        }
    }

    /// A value; `None` only in lenient mode, for a dropped value.
    fn value(&mut self, depth: usize) -> Result<Option<Value>> {
        match self.peek().ok_or(Error::BadJson)? {
            b'{' => {
                if depth > MAX_DEPTH {
                    return Err(Error::BadJson);
                }
                self.i += 1;
                let mut m = Map::new();
                let mut dropped: Vec<String> = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Some(Value::Object(m)));
                }
                loop {
                    self.ws();
                    if self.peek() != Some(b'"') {
                        return Err(Error::BadJson);
                    }
                    let k = self.string()?;
                    self.ws();
                    self.eat(b":")?;
                    self.ws();
                    let v = self.value(depth + 1)?;
                    if m.get(&k).is_some() || dropped.contains(&k) {
                        return Err(Error::BadJson);
                    }
                    match v {
                        Some(v) => {
                            m.insert(k, v);
                        }
                        None => dropped.push(k),
                    }
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Some(Value::Object(m)));
                        }
                        _ => return Err(Error::BadJson),
                    }
                }
            }
            b'[' => {
                if depth > MAX_DEPTH {
                    return Err(Error::BadJson);
                }
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Some(Value::Array(a)));
                }
                loop {
                    self.ws();
                    if let Some(v) = self.value(depth + 1)? {
                        a.push(v);
                    }
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Some(Value::Array(a)));
                        }
                        _ => return Err(Error::BadJson),
                    }
                }
            }
            b'"' => Ok(Some(Value::String(self.string()?))),
            b't' => self.eat(b"true").map(|_| Some(Value::Bool(true))),
            b'f' => self.eat(b"false").map(|_| Some(Value::Bool(false))),
            b'n' if self.lenient => self.eat(b"null").map(|_| None),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(Error::BadJson),
        }
    }

    fn number(&mut self) -> Result<Option<Value>> {
        let start = self.i;
        let neg = self.peek() == Some(b'-');
        if neg {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(Error::BadJson),
        }
        let int_end = self.i;
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            if !self.lenient {
                return Err(Error::BadJson);
            }
            // RFC 8259 fraction and exponent; the number is dropped.
            if self.peek() == Some(b'.') {
                self.i += 1;
                self.digits()?;
            }
            if matches!(self.peek(), Some(b'e' | b'E')) {
                self.i += 1;
                if matches!(self.peek(), Some(b'+' | b'-')) {
                    self.i += 1;
                }
                self.digits()?;
            }
            return Ok(None);
        }
        let text = core::str::from_utf8(&self.s[start..int_end]).map_err(|_| Error::BadJson)?;
        let n = if text == "-0" || text.len() > 17 {
            None
        } else {
            text.parse::<i64>().ok().filter(|n| (-MAX_SAFE..=MAX_SAFE).contains(n))
        };
        match n {
            Some(n) => Ok(Some(Value::Int(n))),
            None if self.lenient => Ok(None),
            None => Err(Error::BadJson),
        }
    }

    /// One or more decimal digits.
    fn digits(&mut self) -> Result<()> {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(Error::BadJson);
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32> {
        let h = self.s.get(self.i..self.i + 4).ok_or(Error::BadJson)?;
        let mut v = 0u32;
        for &c in h {
            let d = (c as char).to_digit(16).ok_or(Error::BadJson)?;
            v = v * 16 + d;
        }
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or(Error::BadJson)?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or(Error::BadJson)?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let u = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&u) {
                                self.eat(b"\\u")?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(Error::BadJson);
                                }
                                0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&u) {
                                return Err(Error::BadJson);
                            } else {
                                u
                            };
                            out.push(char::from_u32(cp).ok_or(Error::BadJson)?);
                        }
                        _ => return Err(Error::BadJson),
                    }
                }
                0x00..=0x1F => return Err(Error::BadJson),
                _ => {
                    // Copy one UTF-8 encoded character; the input is known to be valid UTF-8.
                    let len = match c {
                        0x00..=0x7F => 1,
                        0xC0..=0xDF => 2,
                        0xE0..=0xEF => 3,
                        _ => 4,
                    };
                    let ch = core::str::from_utf8(self.s.get(self.i..self.i + len).ok_or(Error::BadJson)?)
                        .map_err(|_| Error::BadJson)?;
                    out.push_str(ch);
                    self.i += len;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(s: &str) -> String {
        String::from_utf8(canonical(&parse_json(s.as_bytes()).unwrap())).unwrap()
    }

    #[test]
    fn canonical_form() {
        assert_eq!(
            rt(r#" { "b" : 1, "a" : [true, false, -5, "x"] } "#),
            r#"{"a":[true,false,-5,"x"],"b":1}"#
        );
        assert_eq!(rt(r#""\u0001\u001f\/\u2028é\u00e9""#), "\"\\u0001\\u001f/\u{2028}éé\"");
        assert_eq!(
            rt(r#"{"\ud83d\ude00":1,"\uffff":2}"#),
            "{\"\u{1F600}\":1,\"\u{FFFF}\":2}"
        );
    }

    #[test]
    fn rejects() {
        for bad in [
            "null",
            "1.0",
            "1e2",
            "-0",
            "01",
            "9007199254740992",
            "{\"a\":1,\"a\":2}",
            "\"\\ud800\"",
            "\"\\udc00\"",
            "[1,]",
            "{}x",
            "\u{feff}{}",
            "\"\t\"",
            "",
            "[1 2]",
            "\"\\x\"",
        ] {
            assert_eq!(parse_json(bad.as_bytes()), Err(Error::BadJson), "{bad:?}");
        }
        assert_eq!(parse_json(b"\"\xff\""), Err(Error::BadJson));
        let deep = "[".repeat(32) + &"]".repeat(32);
        assert!(parse_json(deep.as_bytes()).is_ok());
        let deeper = "[".repeat(33) + &"]".repeat(33);
        assert_eq!(parse_json(deeper.as_bytes()), Err(Error::BadJson));
    }

    #[test]
    fn response_json() {
        let r =
            |s: &str| parse_response_json(s.as_bytes()).map(|v| v.map(|v| String::from_utf8(canonical(&v)).unwrap()));
        assert_eq!(
            r(r#"{"a":null,"b":[1,null,2.5,-0,1e3,9007199254740992,3],"c":"x"}"#),
            Ok(Some(r#"{"b":[1,3],"c":"x"}"#.into()))
        );
        assert_eq!(r("null"), Ok(None));
        assert_eq!(r(" 1.5e-3 "), Ok(None));
        for bad in [
            "{\"a\":null,\"a\":1}",
            "{\"a\":1,\"a\":null}",
            "nul",
            "1.",
            "1e",
            "1e+",
            ".5",
            "01",
            "\"\\ud800\"",
            "\u{feff}{}",
            "[1,]",
        ] {
            assert_eq!(parse_response_json(bad.as_bytes()), Err(Error::BadJson), "{bad:?}");
        }
        assert_eq!(parse_json(b"null"), Err(Error::BadJson));
        let deeper = "[".repeat(33) + &"]".repeat(33);
        assert_eq!(parse_response_json(deeper.as_bytes()), Err(Error::BadJson));
    }
}
