//! Line-numbered configuration diagnostics.
//!
//! The original accepted a malformed `network` line silently and carried on with
//! a nonsensical zone — which is how a missing `/64` turned it into an
//! authoritative server for all of IPv6 reverse DNS. Every problem here is fatal
//! and points at the offending line, and all of them are reported at once rather
//! than one per run.

use core::fmt;
use core::ops::Range;
use std::path::{Path, PathBuf};

/// A single configuration problem, anchored to the line that caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// 1-based line number.
    pub line: u32,
    /// The offending line, verbatim (whitespace preserved, so carets line up).
    pub snippet: String,
    /// Byte range within `snippet` to underline, if known.
    pub span: Option<Range<usize>>,
    pub kind: ConfigErrorKind,
}

/// What specifically was wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigErrorKind {
    NotUtf8,
    UnknownDirective {
        keyword: String,
    },
    /// A recognised keyword with nothing after it.
    MissingValue {
        keyword: &'static str,
    },
    /// A zone-scoped directive appeared before any `network` line.
    DirectiveBeforeNetwork {
        keyword: &'static str,
    },
    /// A global setting appeared after a `network`. Indentation carries no
    /// meaning in this format, so position is the only unambiguous scope rule.
    GlobalAfterNetwork {
        keyword: &'static str,
    },
    /// A numeric directive value did not parse, or was out of range.
    InvalidNumber {
        what: &'static str,
        allowed: &'static str,
    },
    /// A directive expecting a DNS name got something else.
    InvalidDnsName {
        what: &'static str,
    },
    /// An enumerated directive value was not one of the permitted words.
    InvalidChoice {
        what: &'static str,
        allowed: &'static str,
    },
    /// Two directives only make sense together (SOA needs both halves).
    MissingCompanionDirective {
        missing: &'static str,
        present: String,
    },
    DuplicateDirective {
        keyword: &'static str,
        first_line: u32,
    },
    MissingResolvesTo,
    NetworkMissingPrefixLen,
    NetworkInvalidAddress,
    NetworkPrefixLenNotANumber,
    NetworkPrefixLenOutOfRange {
        mask: u32,
    },
    /// One `ip6.arpa` label carries exactly one nibble, so a prefix that does
    /// not end on a nibble boundary cannot map onto a zone.
    NetworkPrefixNotNibbleAligned {
        mask: u8,
    },
    /// Bits below the prefix length were set, e.g. `2a00:15a0::192:/64`.
    NetworkHostBitsSet {
        suggestion: String,
    },
    /// `/0` would claim the entire IPv6 reverse namespace.
    NetworkPrefixTooShort {
        mask: u8,
    },
    /// `/128` leaves no digits for `%DIGITS%` to vary.
    NetworkIsSingleAddress,
    DuplicateNetwork {
        first_line: u32,
    },
    PlaceholderMissing,
    PlaceholderRepeated {
        count: usize,
    },
    /// `%DIGITS-DASHED%` groups hex digits in 4s; a `host_nibbles` that is not a
    /// multiple of 4 would leave the last group's width ambiguous to invert
    /// when matching a forward query.
    DashedDigitsNotNibbleMultipleOfFour {
        host_nibbles: u8,
    },
    /// The template cannot produce a valid DNS name even before digits are
    /// substituted (empty label, illegal byte, …).
    ResolvesToInvalidName {
        reason: String,
    },
    /// The widest possible synthesized name (all-`f` digits) would exceed a DNS
    /// limit. Checked once at startup so the request path cannot fail.
    ForwardNameTooLong {
        reason: String,
    },
    DuplicateForwardPattern {
        first_line: u32,
    },
    InvalidListenAddress,
    InvalidUpstreamAddress,
}

impl ConfigErrorKind {
    /// The headline message.
    fn message(&self) -> String {
        match self {
            Self::NotUtf8 => "line is not valid UTF-8".into(),
            Self::UnknownDirective { keyword } => {
                format!("unknown directive `{keyword}`")
            }
            Self::MissingValue { keyword } => {
                format!("`{keyword}` requires a value")
            }
            Self::DirectiveBeforeNetwork { keyword } => {
                format!("`{keyword}` appears before any `network` directive")
            }
            Self::GlobalAfterNetwork { keyword } => {
                format!(
                    "`{keyword}` is a global setting and must appear before the first `network`"
                )
            }
            Self::InvalidNumber { what, .. } => format!("`{what}` is not a valid number"),
            Self::InvalidDnsName { what } => format!("`{what}` is not a valid DNS name"),
            Self::InvalidChoice { what, .. } => format!("invalid value for `{what}`"),
            Self::MissingCompanionDirective { missing, present } => {
                format!("`{present}` is set but `{missing}` is missing; a SOA record needs both")
            }
            Self::DuplicateDirective {
                keyword,
                first_line,
            } => format!("duplicate `{keyword}` for this network (first set on line {first_line})"),
            Self::MissingResolvesTo => "this `network` has no `resolves to` directive".into(),
            Self::NetworkMissingPrefixLen => {
                "network is missing a prefix length, e.g. `/64`".into()
            }
            Self::NetworkInvalidAddress => "not a valid IPv6 address".into(),
            Self::NetworkPrefixLenNotANumber => "prefix length is not a number".into(),
            Self::NetworkPrefixLenOutOfRange { mask } => {
                format!("prefix length /{mask} is out of range (0-128)")
            }
            Self::NetworkPrefixNotNibbleAligned { mask } => {
                format!("prefix length /{mask} is not nibble-aligned (must be a multiple of 4)")
            }
            Self::NetworkHostBitsSet { .. } => {
                "network has bits set below its prefix length".into()
            }
            Self::NetworkPrefixTooShort { mask } => format!(
                "prefix length /{mask} would make this server authoritative for all of ip6.arpa"
            ),
            Self::NetworkIsSingleAddress => {
                "/128 is a single address, leaving no digits for %DIGITS%".into()
            }
            Self::DuplicateNetwork { first_line } => {
                format!("network is already configured on line {first_line}")
            }
            Self::PlaceholderMissing => {
                "`resolves to` must contain %DIGITS% or %DIGITS-DASHED%".into()
            }
            Self::PlaceholderRepeated { count } => format!(
                "`resolves to` contains %DIGITS%/%DIGITS-DASHED% {count} times, expected exactly \
                 once"
            ),
            Self::DashedDigitsNotNibbleMultipleOfFour { host_nibbles } => format!(
                "%DIGITS-DASHED% needs a host part that is a multiple of 4 hex digits wide, but \
                 this network's is {host_nibbles}"
            ),
            Self::ResolvesToInvalidName { reason } => {
                format!("`resolves to` is not a valid DNS name: {reason}")
            }
            Self::ForwardNameTooLong { reason } => {
                format!("the widest name this template can produce is invalid: {reason}")
            }
            Self::DuplicateForwardPattern { first_line } => {
                format!("this `resolves to` pattern is already used on line {first_line}")
            }
            Self::InvalidListenAddress => "not a valid IP address or address:port".into(),
            Self::InvalidUpstreamAddress => "not a valid IP address".into(),
        }
    }

    /// An optional actionable hint printed under the caret.
    fn hint(&self) -> Option<String> {
        match self {
            Self::NetworkMissingPrefixLen => Some(
                "a `network` without a prefix length is what made AllKnowingDNS claim \
                 the whole ip6.arpa namespace"
                    .into(),
            ),
            Self::NetworkPrefixNotNibbleAligned { .. } => {
                Some("expected /0, /4, /8, … /128".into())
            }
            Self::NetworkHostBitsSet { suggestion } => {
                Some(format!("did you mean `{suggestion}`?"))
            }
            Self::PlaceholderMissing => Some("e.g. `resolves to ipv6-%DIGITS%.example.net`".into()),
            Self::DashedDigitsNotNibbleMultipleOfFour { .. } => {
                Some("prefix length must leave a multiple of 4 hex digits, e.g. /48, /96".into())
            }
            Self::InvalidListenAddress => {
                Some("e.g. `listen 2001:db8::1`, `listen 0.0.0.0`, `listen [::]:5353`".into())
            }
            Self::InvalidNumber { allowed, .. } | Self::InvalidChoice { allowed, .. } => {
                Some(format!("expected {allowed}"))
            }
            Self::InvalidDnsName { .. } => {
                Some("e.g. `ns1.example.net.` (a trailing dot is optional)".into())
            }
            Self::GlobalAfterNetwork { .. } => Some(
                "indentation is decorative in this format, so globals are recognised by position"
                    .into(),
            ),
            _ => None,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind.message())
    }
}

impl std::error::Error for ConfigError {}

/// All problems found in one configuration file, rendered together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigErrors {
    pub path: Option<PathBuf>,
    pub errors: Vec<ConfigError>,
}

impl ConfigErrors {
    #[must_use]
    pub fn new(errors: Vec<ConfigError>) -> Self {
        Self { path: None, errors }
    }

    /// Attach the source path so diagnostics can point at it.
    #[must_use]
    pub fn with_path(mut self, path: impl AsRef<Path>) -> Self {
        self.path = Some(path.as_ref().to_path_buf());
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.errors.len()
    }
}

impl fmt::Display for ConfigErrors {
    /// rustc-style, because operators already know how to read it:
    ///
    /// ```text
    /// error: prefix length /63 is not nibble-aligned (must be a multiple of 4)
    ///   --> /etc/panoptidns/panoptidns.conf:12
    ///    |
    /// 12 |     network 2001:db8::/63
    ///    |                       ^^^ expected /0, /4, /8, … /128
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self
            .path
            .as_deref()
            .map_or_else(|| "<config>".to_string(), |p| p.display().to_string());

        for (i, err) in self.errors.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            let num = err.line.to_string();
            let gutter = " ".repeat(num.len());

            writeln!(f, "error: {}", err.kind.message())?;
            writeln!(f, "{gutter}--> {path}:{}", err.line)?;
            writeln!(f, "{gutter} |")?;
            writeln!(f, "{num} | {}", err.snippet)?;

            // Caret line. Tabs in the source would misalign a naive caret, so
            // they are mirrored into the pad.
            let (pad, carets) = match &err.span {
                Some(span) => {
                    let prefix: String = err
                        .snippet
                        .bytes()
                        .take(span.start)
                        .map(|b| if b == b'\t' { '\t' } else { ' ' })
                        .collect();
                    let width = span.len().max(1);
                    (prefix, "^".repeat(width))
                }
                None => (String::new(), "^".repeat(err.snippet.len().max(1))),
            };
            match err.kind.hint() {
                Some(hint) => writeln!(f, "{gutter} | {pad}{carets} {hint}")?,
                None => writeln!(f, "{gutter} | {pad}{carets}")?,
            }
        }

        let n = self.errors.len();
        let plural = if n == 1 { "error" } else { "errors" };
        write!(f, "\naborting due to {n} configuration {plural}")
    }
}

impl std::error::Error for ConfigErrors {}
