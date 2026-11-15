//! Realm, username, inception, account id (SPEC §7), handles and tags (SPEC §8).

use crate::crypto::{ed25519_sign, frame_map, sha256};
use crate::encoding::{B32, base32_decode, base32_encode};
use crate::error::{Error, Result};
use crate::json::{Map, Value};
use crate::keys::{KeyType, format_key};
use crate::label;
use crate::recovery::RecoveryKeys;

/// A realm is 1 to 64 characters of `a–z 0–9 . _ -`, beginning and ending with `a–z 0–9` ([RLM-1]). → `bad_realm`
pub fn check_realm(realm: &str) -> Result<()> {
    let b = realm.as_bytes();
    let ok_inner = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-');
    let ok_edge = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let valid = (1..=64).contains(&b.len())
        && b.iter().all(ok_inner)
        && b.first().is_some_and(ok_edge)
        && b.last().is_some_and(ok_edge);
    if valid { Ok(()) } else { Err(Error::BadRealm) }
}

/// The username format rule: 1 to 32 characters of ASCII `A–Z a–z 0–9 _ -`, beginning with `A–Z a–z 0–9` ([USR-1]).
/// → `bad_username`
pub fn check_username(username: &str) -> Result<()> {
    let b = username.as_bytes();
    let valid = (1..=32).contains(&b.len())
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
        && b[0].is_ascii_alphanumeric();
    if valid { Ok(()) } else { Err(Error::BadUsername) }
}

/// A username policy ([USR-3]): a predicate at least as strict as [USR-1], applied by hosts at registration.
pub type UsernamePolicy = fn(&str) -> bool;

/// The default username policy: [USR-1], 2 to 20 characters, beginning with `A–Z a–z` ([USR-3]).
pub fn default_username_policy(username: &str) -> bool {
    check_username(username).is_ok()
        && (2..=20).contains(&username.len())
        && username.as_bytes()[0].is_ascii_alphabetic()
}

/// Two usernames are similar when they are equal after ASCII lower-casing ([USR-2]).
pub fn similar_usernames(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// An account id in strict form: 52 characters of Crockford base32 of 32 bytes ([ID-3]). → `bad_field`
pub fn check_account_id(id: &str) -> Result<()> {
    base32_decode(id, 32).map(|_| ()).map_err(|_| Error::BadField)
}

/// The account id of an inception ([ID-3]): `SHA-256(frame("rootcard/id/v1", inception without sigs))` in base32.
pub fn account_id(inception: &Map) -> String {
    base32_encode(&sha256(&frame_map(&label("id", 1), &inception.without("sigs"))))
}

/// The deterministic inception of an identity ([ID-1], [ID-2]). → `bad_realm`, `bad_username`
pub fn inception(keys: &RecoveryKeys, realm: &str, username: &str) -> Result<Map> {
    check_realm(realm)?;
    check_username(username)?;
    let recovery = format_key(KeyType::Ed25519, &keys.sign_public());
    let body = Map::new()
        .with("realm", realm)
        .with("username", username)
        .with("recovery", recovery.as_str());
    let unsigned = Map::new()
        .with("v", 1i64)
        .with("kind", "incept")
        .with("seq", 0i64)
        .with("body", body);
    let sig = ed25519_sign(&keys.sign_seed, &frame_map(&label("event", 1), &unsigned));
    let entry = Map::new()
        .with("key", recovery.as_str())
        .with("sig", crate::encoding::base64url_encode(&sig));
    Ok(unsigned.with("sigs", Value::Array(vec![entry.into()])))
}

/// The tag of an account id: its first 4 characters ([HDL-1]).
pub fn tag(account: &str) -> &str {
    match account.char_indices().nth(4) {
        Some((end, _)) => &account[..end],
        None => account,
    }
}

/// `username + "#" + tag` ([HDL-1]).
pub fn handle(username: &str, account: &str) -> String {
    format!("{username}#{}", tag(account))
}

/// A parsed handle ([HDL-3]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHandle {
    /// The username.
    pub username: String,
    /// The 4-character tag, strict upper case.
    pub tag: String,
    /// The further characters of an extended tag (characters 5 and on of the account id), if given.
    pub extension: Option<String>,
}

fn lenient_chars(s: &str) -> Option<String> {
    s.chars()
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        })
        .map(|c| {
            if c.is_ascii() && B32.contains(&(c as u8)) {
                Some(c)
            } else {
                None
            }
        })
        .collect()
}

/// Parse a typed handle `username#TAG` or `username#TAG-EXT` ([HDL-3]). → `bad_handle`
pub fn parse_handle(text: &str) -> Result<ParsedHandle> {
    let (username, t) = text.rsplit_once('#').ok_or(Error::BadHandle)?;
    check_username(username).map_err(|_| Error::BadHandle)?;
    let (t4, ext) = match t.split_once('-') {
        Some((a, b)) => (a, Some(b)),
        None => (t, None),
    };
    let t4 = lenient_chars(t4).filter(|s| s.len() == 4).ok_or(Error::BadHandle)?;
    let extension = match ext {
        None => None,
        Some(e) => Some(
            lenient_chars(e)
                .filter(|s| (1..=48).contains(&s.len()))
                .ok_or(Error::BadHandle)?,
        ),
    };
    Ok(ParsedHandle {
        username: username.to_string(),
        tag: t4,
        extension,
    })
}

impl ParsedHandle {
    /// Whether an identity with this username and account id matches the handle (similar username, [USR-2]).
    pub fn matches(&self, username: &str, account: &str) -> bool {
        let prefix = match &self.extension {
            Some(e) => format!("{}{e}", self.tag),
            None => self.tag.clone(),
        };
        similar_usernames(&self.username, username) && account.starts_with(&prefix)
    }
}

/// The extended tags of a set of colliding account ids ([HDL-6]), in the order given. A set of fewer than two distinct
/// ids keeps plain tags.
pub fn extended_tags(ids: &[String]) -> Vec<String> {
    let mut distinct: Vec<&String> = Vec::new();
    for id in ids {
        if !distinct.contains(&id) {
            distinct.push(id);
        }
    }
    if distinct.len() < 2 {
        return ids.iter().map(|id| tag(id).to_string()).collect();
    }
    // Characters, not bytes ([HDL-6]): account ids are ASCII, but the function takes any strings and must not panic.
    let chars: Vec<Vec<char>> = distinct.iter().map(|s| s.chars().collect()).collect();
    let max = chars.iter().map(Vec::len).min().unwrap_or(4);
    let mut n = 5;
    while n < max {
        let prefixes: Vec<&[char]> = chars.iter().map(|c| &c[..n]).collect();
        if prefixes.iter().enumerate().all(|(i, p)| !prefixes[i + 1..].contains(p)) {
            break;
        }
        n += 1;
    }
    let n = n.min(max);
    ids.iter()
        .map(|id| {
            let head: String = id.chars().take(4).collect();
            let rest: String = id.chars().skip(4).take(n.saturating_sub(4)).collect();
            format!("{head}-{rest}")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realms_and_usernames() {
        for ok in ["global", "a", "xigna.eu-1", "a_b"] {
            assert_eq!(check_realm(ok), Ok(()), "{ok}");
        }
        for bad in ["", "Global", ".a", "a.", "a b", &"a".repeat(65)] {
            assert_eq!(check_realm(bad), Err(Error::BadRealm), "{bad}");
        }
        for ok in ["A", "Astra", "a-b_c", "9lives"] {
            assert_eq!(check_username(ok), Ok(()));
        }
        for bad in ["", "_a", "-a", "a b", "å", &"a".repeat(33)] {
            assert_eq!(check_username(bad), Err(Error::BadUsername), "{bad}");
        }
        assert!(default_username_policy("Astra"));
        assert!(!default_username_policy("9lives"));
        assert!(default_username_policy("ab"));
        assert!(!default_username_policy("a"));
    }

    #[test]
    fn handles() {
        let h = parse_handle("Astra#3f9c").unwrap();
        assert_eq!(
            (h.username.as_str(), h.tag.as_str(), h.extension),
            ("Astra", "3F9C", None)
        );
        let h = parse_handle("Astra#oilk-k2").unwrap();
        assert_eq!((h.username.as_str(), h.tag.as_str()), ("Astra", "011K"));
        assert_eq!(h.extension.as_deref(), Some("K2"));
        for bad in ["a#b#0000", "Astra", "Astra#3F9", "Astra#3F9CU", "Astra#3F9C-", "#3F9C"] {
            assert_eq!(parse_handle(bad), Err(Error::BadHandle), "{bad}");
        }
    }

    #[test]
    fn extended() {
        let ids = ["ABCDEF".to_string(), "ABCDEG".to_string()];
        assert_eq!(extended_tags(&ids), ["ABCD-EF", "ABCD-EG"]);
        let ids = ["ABCDXF".to_string(), "ABCDYG".to_string()];
        assert_eq!(extended_tags(&ids), ["ABCD-X", "ABCD-Y"]);
    }
}
