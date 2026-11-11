//! Error codes (SPEC §20).

use core::fmt;

macro_rules! codes {
    ($($variant:ident => $code:literal,)*) => {
        /// A rootcard error. Every variant is one of the stable error codes of SPEC §20.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum Error {
            $(
                #[doc = concat!("`", $code, "`")]
                $variant,
            )*
        }

        impl Error {
            /// The stable error code (SPEC §20).
            pub fn code(self) -> &'static str {
                match self {
                    $(Error::$variant => $code,)*
                }
            }

            /// The error for a stable error code, if there is one.
            pub fn from_code(code: &str) -> Option<Error> {
                match code {
                    $($code => Some(Error::$variant),)*
                    _ => None,
                }
            }

            /// Every error, in the order of SPEC §20.
            pub const ALL: &'static [Error] = &[$(Error::$variant,)*];
        }
    };
}

codes! {
    BadJson => "bad_json",
    BadField => "bad_field",
    UnsupportedVersion => "unsupported_version",
    TooLarge => "too_large",
    BadBase64 => "bad_base64",
    BadBase32 => "bad_base32",
    BadChecksum => "bad_checksum",
    BadKey => "bad_key",
    BadSignature => "bad_signature",
    BadRealm => "bad_realm",
    RealmNotAccepted => "realm_not_accepted",
    BadUsername => "bad_username",
    UsernamePolicy => "username_policy",
    BadHandle => "bad_handle",
    HandleTaken => "handle_taken",
    AmbiguousHandle => "ambiguous_handle",
    AccountMismatch => "account_mismatch",
    WrongRecoveryKey => "wrong_recovery_key",
    TooManyEvents => "too_many_events",
    BadKind => "bad_kind",
    BadSeq => "bad_seq",
    BadPrev => "bad_prev",
    TimeBackwards => "time_backwards",
    FutureTime => "future_time",
    BadTime => "bad_time",
    WrongSigner => "wrong_signer",
    KeyReuse => "key_reuse",
    BadReceipt => "bad_receipt",
    BadReason => "bad_reason",
    AccountRetired => "account_retired",
    NoInstance => "no_instance",
    StaleVersion => "stale_version",
    Fork => "fork",
    WrongInstance => "wrong_instance",
    StaleRev => "stale_rev",
    StaleLocks => "stale_locks",
    BadLocks => "bad_locks",
    KdfParams => "kdf_params",
    WeakPassword => "weak_password",
    UnlockFailed => "unlock_failed",
    WrongAccountKey => "wrong_account_key",
    BadDataKey => "bad_data_key",
    BadLink => "bad_link",
    Unsupported => "unsupported",
    WrongOwner => "wrong_owner",
    TokenMissing => "token_missing",
    FetchFailed => "fetch_failed",
    WrongChallenge => "wrong_challenge",
    WrongRecipient => "wrong_recipient",
    ChallengeUnknown => "challenge_unknown",
    ChallengeExpired => "challenge_expired",
    NotHome => "not_home",
    WrongHost => "wrong_host",
    UnknownAccount => "unknown_account",
    Unauthorized => "unauthorized",
    RateLimited => "rate_limited",
    UnsupportedBrowser => "unsupported_browser",
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Error {}

/// The result type of every rootcard operation.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_are_unique() {
        for (i, e) in Error::ALL.iter().enumerate() {
            assert_eq!(Error::from_code(e.code()), Some(*e));
            assert!(!Error::ALL[i + 1..].iter().any(|o| o.code() == e.code()));
        }
        assert_eq!(Error::ALL.len(), 57);
    }
}
