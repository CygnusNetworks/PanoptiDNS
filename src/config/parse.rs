//! Line-oriented parser for the AllKnowingDNS configuration format.
//!
//! Grammar (keywords case-insensitive, leading indentation decorative):
//!
//! ```text
//! # global settings — must precede the first `network`
//! listen <addr>[:port]
//! primary <name>            # SOA MNAME
//! hostmaster <name>         # SOA RNAME
//! ns <name>                 # repeatable
//! ttl <seconds>
//! out-of-zone refused|nxdomain
//! max-udp-payload <bytes>
//! upstream-timeout <milliseconds>
//! rrl off | rrl responses-per-second <n> | rrl burst <n> | rrl slip <n>
//!
//! network <ipv6>/<prefixlen>
//!     resolves to <template containing %DIGITS%>
//!     with upstream <addr>
//! ```
//!
//! `#` starts a comment, but only as the first non-whitespace character of a
//! line — the original had no inline comments, and `#` is legal inside a DNS
//! name, so introducing them would be a compatibility hazard.
//!
//! Global directives must appear before the first `network`. Since indentation
//! carries no meaning in this format, that positional rule is the only
//! unambiguous way to tell a global setting from a zone-scoped one.
//!
//! This stage only splits directives from values. All semantic validation happens
//! in [`super::compile`], so one pass can report every problem in the file.

use core::ops::Range;

use super::error::{ConfigError, ConfigErrorKind};

/// A directive value together with enough provenance to point a caret at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawValue {
    pub line: u32,
    pub raw_line: String,
    /// Byte range of the value within `raw_line`.
    pub span: Range<usize>,
    pub value: String,
}

impl RawValue {
    /// Build an error anchored at this value.
    pub(crate) fn error(&self, kind: ConfigErrorKind) -> ConfigError {
        ConfigError {
            line: self.line,
            snippet: self.raw_line.clone(),
            span: Some(self.span.clone()),
            kind,
        }
    }

    /// Build an error anchored at a sub-range of this value.
    pub(crate) fn error_at(&self, offset: usize, len: usize, kind: ConfigErrorKind) -> ConfigError {
        let start = self.span.start.saturating_add(offset).min(self.span.end);
        let end = start.saturating_add(len).min(self.span.end.max(start));
        ConfigError {
            line: self.line,
            snippet: self.raw_line.clone(),
            span: Some(start..end),
            kind,
        }
    }
}

/// One `network` block, before validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawZone {
    pub network: RawValue,
    pub resolves_to: Option<RawValue>,
    pub upstream: Option<RawValue>,
}

/// A global setting, before validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GlobalKey {
    Primary,
    Hostmaster,
    Ns,
    Ttl,
    OutOfZone,
    MaxUdpPayload,
    UpstreamTimeout,
    RrlOff,
    RrlRps,
    RrlBurst,
    RrlSlip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawGlobal {
    pub key: GlobalKey,
    pub value: RawValue,
}

/// The whole file, before validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RawConfig {
    pub listen: Vec<RawValue>,
    pub zones: Vec<RawZone>,
    pub globals: Vec<RawGlobal>,
}

/// Where a directive may appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Before the first `network`.
    Global,
    /// Attaches to the current `network`.
    Zone,
    /// Valid anywhere.
    Anywhere,
}

/// What to do with the parsed value.
#[derive(Debug, Clone, Copy)]
enum Target {
    Listen,
    Network,
    ResolvesTo,
    Upstream,
    Global(GlobalKey),
}

struct Directive {
    /// Keyword words, matched case-insensitively with flexible whitespace
    /// between them.
    words: &'static [&'static str],
    /// Display form for diagnostics.
    display: &'static str,
    scope: Scope,
    target: Target,
    /// Whether the value is ASCII-lowercased. `resolves to` is the one directive
    /// kept verbatim — the original deliberately preserved case there and its
    /// test suite pins it.
    lowercase: bool,
}

/// Longest keywords first, so `resolves to` is tried before any single word that
/// could prefix it.
const DIRECTIVES: &[Directive] = &[
    Directive {
        words: &["resolves", "to"],
        display: "resolves to",
        scope: Scope::Zone,
        target: Target::ResolvesTo,
        lowercase: false,
    },
    Directive {
        words: &["with", "upstream"],
        display: "with upstream",
        scope: Scope::Zone,
        target: Target::Upstream,
        lowercase: true,
    },
    Directive {
        words: &["rrl", "responses-per-second"],
        display: "rrl responses-per-second",
        scope: Scope::Global,
        target: Target::Global(GlobalKey::RrlRps),
        lowercase: true,
    },
    Directive {
        words: &["rrl", "burst"],
        display: "rrl burst",
        scope: Scope::Global,
        target: Target::Global(GlobalKey::RrlBurst),
        lowercase: true,
    },
    Directive {
        words: &["rrl", "slip"],
        display: "rrl slip",
        scope: Scope::Global,
        target: Target::Global(GlobalKey::RrlSlip),
        lowercase: true,
    },
    Directive {
        words: &["upstream-timeout"],
        display: "upstream-timeout",
        scope: Scope::Global,
        target: Target::Global(GlobalKey::UpstreamTimeout),
        lowercase: true,
    },
    Directive {
        words: &["max-udp-payload"],
        display: "max-udp-payload",
        scope: Scope::Global,
        target: Target::Global(GlobalKey::MaxUdpPayload),
        lowercase: true,
    },
    Directive {
        words: &["out-of-zone"],
        display: "out-of-zone",
        scope: Scope::Global,
        target: Target::Global(GlobalKey::OutOfZone),
        lowercase: true,
    },
    Directive {
        words: &["hostmaster"],
        display: "hostmaster",
        scope: Scope::Global,
        target: Target::Global(GlobalKey::Hostmaster),
        lowercase: true,
    },
    Directive {
        words: &["primary"],
        display: "primary",
        scope: Scope::Global,
        target: Target::Global(GlobalKey::Primary),
        lowercase: true,
    },
    Directive {
        words: &["network"],
        display: "network",
        scope: Scope::Anywhere,
        target: Target::Network,
        lowercase: true,
    },
    Directive {
        words: &["listen"],
        display: "listen",
        scope: Scope::Anywhere,
        target: Target::Listen,
        lowercase: true,
    },
    Directive {
        words: &["ttl"],
        display: "ttl",
        scope: Scope::Global,
        target: Target::Global(GlobalKey::Ttl),
        lowercase: true,
    },
    Directive {
        words: &["ns"],
        display: "ns",
        scope: Scope::Global,
        target: Target::Global(GlobalKey::Ns),
        lowercase: true,
    },
];

/// Keywords whose entire line is the directive, with no value.
const FLAGS: &[(&[&str], &str, GlobalKey)] = &[(&["rrl", "off"], "rrl off", GlobalKey::RrlOff)];

/// Case-insensitively match a multi-word keyword, returning the byte offset of
/// the value within `line` and the value (trailing whitespace removed).
fn strip_keyword(line: &[u8], words: &[&str]) -> Option<(usize, Vec<u8>)> {
    let (consumed, rest) = match_words(line, words)?;

    // The keyword must be followed by whitespace and then a non-empty value.
    let trimmed = rest.trim_ascii_start();
    if trimmed.len() == rest.len() {
        return None;
    }
    let consumed = consumed.saturating_add(rest.len() - trimmed.len());

    let value = trimmed.trim_ascii_end();
    if value.is_empty() {
        return None;
    }
    Some((consumed, value.to_vec()))
}

/// Match the keyword words, returning bytes consumed and the remainder.
fn match_words<'a>(line: &'a [u8], words: &[&str]) -> Option<(usize, &'a [u8])> {
    let mut rest = line;
    let mut consumed = 0usize;
    for (i, word) in words.iter().enumerate() {
        if i > 0 {
            let trimmed = rest.trim_ascii_start();
            if trimmed.len() == rest.len() {
                return None; // words must be whitespace-separated
            }
            consumed = consumed.saturating_add(rest.len() - trimmed.len());
            rest = trimmed;
        }
        let (head, tail) = rest.split_at_checked(word.len())?;
        if !head.eq_ignore_ascii_case(word.as_bytes()) {
            return None;
        }
        consumed = consumed.saturating_add(word.len());
        rest = tail;
    }
    Some((consumed, rest))
}

/// True if the whole line is exactly these keyword words.
fn matches_flag(line: &[u8], words: &[&str]) -> bool {
    match_words(line, words).is_some_and(|(_, rest)| rest.trim_ascii().is_empty())
}

/// True if the line's first word is `word`.
fn starts_with_word(line: &[u8], word: &str) -> bool {
    match line.split_at_checked(word.len()) {
        Some((head, tail)) => {
            head.eq_ignore_ascii_case(word.as_bytes())
                && tail.first().is_none_or(u8::is_ascii_whitespace)
        }
        None => false,
    }
}

/// Parse a configuration file body.
pub(crate) fn parse(input: &str) -> (RawConfig, Vec<ConfigError>) {
    let mut cfg = RawConfig::default();
    let mut errors = Vec::new();

    for (idx, raw) in input.lines().enumerate() {
        let line_no = u32::try_from(idx.saturating_add(1)).unwrap_or(u32::MAX);
        // `str::lines` removes `\n`; strip a `\r` so CRLF files work.
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let bytes = raw.as_bytes();

        let body = bytes.trim_ascii_start();
        let indent = bytes.len().saturating_sub(body.len());

        if body.is_empty() || body.first() == Some(&b'#') {
            continue;
        }

        // Value-less flags first, so `rrl off` is not read as `rrl` + value.
        if let Some((_, display, key)) = FLAGS
            .iter()
            .find(|(words, _, _)| matches_flag(body, words))
            .copied()
        {
            let value = RawValue {
                line: line_no,
                raw_line: raw.to_string(),
                span: indent..bytes.len(),
                value: String::new(),
            };
            if !cfg.zones.is_empty() {
                errors.push(value.error(ConfigErrorKind::GlobalAfterNetwork { keyword: display }));
            } else {
                cfg.globals.push(RawGlobal { key, value });
            }
            continue;
        }

        let matched = DIRECTIVES
            .iter()
            .find_map(|d| strip_keyword(body, d.words).map(|(off, value)| (d, off, value)));

        let Some((directive, offset, value_bytes)) = matched else {
            errors.push(unmatched_line_error(line_no, raw, indent, body));
            continue;
        };

        let start = indent.saturating_add(offset);
        let Ok(text) = String::from_utf8(value_bytes) else {
            errors.push(ConfigError {
                line: line_no,
                snippet: raw.to_string(),
                span: Some(start..bytes.len()),
                kind: ConfigErrorKind::NotUtf8,
            });
            continue;
        };
        let text = if directive.lowercase {
            text.to_ascii_lowercase()
        } else {
            text
        };
        let value = RawValue {
            line: line_no,
            raw_line: raw.to_string(),
            span: start..start.saturating_add(text.len()),
            value: text,
        };

        // Scope check.
        match directive.scope {
            Scope::Global if !cfg.zones.is_empty() => {
                errors.push(value.error(ConfigErrorKind::GlobalAfterNetwork {
                    keyword: directive.display,
                }));
                continue;
            }
            Scope::Zone if cfg.zones.is_empty() => {
                errors.push(value.error(ConfigErrorKind::DirectiveBeforeNetwork {
                    keyword: directive.display,
                }));
                continue;
            }
            _ => {}
        }

        match directive.target {
            Target::Listen => cfg.listen.push(value),
            Target::Network => cfg.zones.push(RawZone {
                network: value,
                resolves_to: None,
                upstream: None,
            }),
            Target::ResolvesTo | Target::Upstream => {
                // Scope::Zone was checked above, so a zone exists.
                if let Some(zone) = cfg.zones.last_mut() {
                    let slot = match directive.target {
                        Target::ResolvesTo => &mut zone.resolves_to,
                        _ => &mut zone.upstream,
                    };
                    match slot {
                        Some(first) => {
                            let first_line = first.line;
                            errors.push(value.error(ConfigErrorKind::DuplicateDirective {
                                keyword: directive.display,
                                first_line,
                            }));
                        }
                        None => *slot = Some(value),
                    }
                }
            }
            Target::Global(key) => {
                // `ns` is repeatable; everything else is single-valued.
                if key != GlobalKey::Ns {
                    if let Some(first) = cfg.globals.iter().find(|g| g.key == key) {
                        let first_line = first.value.line;
                        errors.push(value.error(ConfigErrorKind::DuplicateDirective {
                            keyword: directive.display,
                            first_line,
                        }));
                        continue;
                    }
                }
                cfg.globals.push(RawGlobal { key, value });
            }
        }
    }

    (cfg, errors)
}

/// Distinguish a known keyword missing its value from an unknown directive,
/// because the fixes differ. The original silently ignored both.
fn unmatched_line_error(line_no: u32, raw: &str, indent: usize, body: &[u8]) -> ConfigError {
    let known = DIRECTIVES
        .iter()
        .map(|d| (d.display, d.words))
        .chain(FLAGS.iter().map(|(words, display, _)| (*display, *words)))
        .find(|(_, words)| words.first().is_some_and(|w| starts_with_word(body, w)));

    let first_word = body
        .split(u8::is_ascii_whitespace)
        .next()
        .unwrap_or_default();
    let word_len = first_word.len().max(1);

    ConfigError {
        line: line_no,
        snippet: raw.to_string(),
        span: Some(indent..indent.saturating_add(word_len)),
        kind: match known {
            Some((display, _)) => ConfigErrorKind::MissingValue { keyword: display },
            None => ConfigErrorKind::UnknownDirective {
                keyword: String::from_utf8_lossy(first_word).into_owned(),
            },
        },
    }
}
