use serde::{Deserialize, Serialize};
use std::fmt;

/// The high-level secret contributors this lab tracks across Noise patterns.
///
/// This is symbolic only. The tool does not compute real Noise handshakes or
/// real Diffie-Hellman values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretContributor {
    Es,
    Ss,
    Ee,
    Se,
    Psk,
}

pub const ALL_CONTRIBUTORS: [SecretContributor; 5] = [
    SecretContributor::Es,
    SecretContributor::Ss,
    SecretContributor::Ee,
    SecretContributor::Se,
    SecretContributor::Psk,
];

impl fmt::Display for SecretContributor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            SecretContributor::Es => "es",
            SecretContributor::Ss => "ss",
            SecretContributor::Ee => "ee",
            SecretContributor::Se => "se",
            SecretContributor::Psk => "psk",
        };
        write!(f, "{label}")
    }
}

/// A mutation applied to a contributor lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretVariant {
    Correct,
    WrongSe,
    ZeroPsk,
    Omitted,
    NotInPattern,
}

impl fmt::Display for SecretVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            SecretVariant::Correct => "Correct",
            SecretVariant::WrongSe => "WrongSe",
            SecretVariant::ZeroPsk => "ZeroPsk",
            SecretVariant::Omitted => "Omitted",
            SecretVariant::NotInPattern => "NotInPattern",
        };
        write!(f, "{label}")
    }
}

/// Tri-state exposure result used by the secret table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackerKnowledge {
    Unknown,
    Known,
    NotApplicable,
}

impl fmt::Display for AttackerKnowledge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            AttackerKnowledge::Unknown => "No",
            AttackerKnowledge::Known => "Yes",
            AttackerKnowledge::NotApplicable => "N/A",
        };
        write!(f, "{label}")
    }
}

impl AttackerKnowledge {
    pub fn is_unknown(self) -> bool {
        self == Self::Unknown
    }

    pub fn is_known(self) -> bool {
        self == Self::Known
    }
}

/// Attacker capability presets used by the heuristic evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttackerScenario {
    None,
    InitStaticCompromised,
    RespStaticCompromised,
    InitEphemeralCompromised,
    RespEphemeralCompromised,
    BothStaticsCompromised,
    PskKnown,
    AllStaticsLaterCompromised,
}

impl fmt::Display for AttackerScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            AttackerScenario::None => "none",
            AttackerScenario::InitStaticCompromised => "init-static-compromised",
            AttackerScenario::RespStaticCompromised => "resp-static-compromised",
            AttackerScenario::InitEphemeralCompromised => "init-ephemeral-compromised",
            AttackerScenario::RespEphemeralCompromised => "resp-ephemeral-compromised",
            AttackerScenario::BothStaticsCompromised => "both-statics-compromised",
            AttackerScenario::PskKnown => "psk-known",
            AttackerScenario::AllStaticsLaterCompromised => "all-statics-later-compromised",
        };
        write!(f, "{label}")
    }
}

/// Qualitative status used for high-level properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PropertyStatus {
    Intact,
    Degraded,
    Broken,
    NotApplicable,
}

impl fmt::Display for PropertyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            PropertyStatus::Intact => "Intact",
            PropertyStatus::Degraded => "Degraded",
            PropertyStatus::Broken => "Broken",
            PropertyStatus::NotApplicable => "N/A",
        };
        write!(f, "{label}")
    }
}

/// Protocol mutation state for contributor slots.
///
/// `Default` keeps every contributor enabled, which is closest to the older
/// single-pattern baseline. For pattern-aware defaults, prefer `for_pattern`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConfig {
    pub es: SecretVariant,
    pub ss: SecretVariant,
    pub ee: SecretVariant,
    pub se: SecretVariant,
    pub psk: SecretVariant,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            es: SecretVariant::Correct,
            ss: SecretVariant::Correct,
            ee: SecretVariant::Correct,
            se: SecretVariant::Correct,
            psk: SecretVariant::Correct,
        }
    }
}

impl ProtocolConfig {
    pub fn for_pattern(pattern: &PatternDefinition) -> Self {
        let mut config = Self {
            es: SecretVariant::NotInPattern,
            ss: SecretVariant::NotInPattern,
            ee: SecretVariant::NotInPattern,
            se: SecretVariant::NotInPattern,
            psk: SecretVariant::NotInPattern,
        };

        for contributor in pattern.contributors_used() {
            config.set_variant(contributor, SecretVariant::Correct);
        }

        config
    }

    pub fn variant_for(&self, contributor: SecretContributor) -> SecretVariant {
        match contributor {
            SecretContributor::Es => self.es,
            SecretContributor::Ss => self.ss,
            SecretContributor::Ee => self.ee,
            SecretContributor::Se => self.se,
            SecretContributor::Psk => self.psk,
        }
    }

    pub fn set_variant(&mut self, contributor: SecretContributor, variant: SecretVariant) {
        match contributor {
            SecretContributor::Es => self.es = variant,
            SecretContributor::Ss => self.ss = variant,
            SecretContributor::Ee => self.ee = variant,
            SecretContributor::Se => self.se = variant,
            SecretContributor::Psk => self.psk = variant,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageDirection {
    ToResponder,
    ToInitiator,
}

#[derive(Debug, Clone)]
struct PatternMessage {
    direction: MessageDirection,
    tokens: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct PatternDefinition {
    pub name: &'static str,
    pub transcript: &'static str,
}

pub const DEFAULT_PATTERN_NAME: &str = "IKpsk2";

pub const IMPORTANT_PATTERNS: &[PatternDefinition] = &[
    PatternDefinition { name: "IK", transcript: "<- s ... -> e, es, s, ss <- e, ee, se" },
    PatternDefinition { name: "IN", transcript: "-> e, s <- e, ee, se" },
    PatternDefinition { name: "IX", transcript: "-> e, s <- e, ee, se, s, es" },
    PatternDefinition { name: "K", transcript: "<- s ... -> s, ss" },
    PatternDefinition { name: "KK", transcript: "-> s <- s ... -> e, es, ss <- e, ee, se" },
    PatternDefinition { name: "KN", transcript: "-> s ... -> e <- e, ee, se" },
    PatternDefinition { name: "KX", transcript: "-> s ... -> e <- e, ee, se, s, es" },
    PatternDefinition { name: "N", transcript: "<- s ... -> e, es" },
    PatternDefinition { name: "NK", transcript: "<- s ... -> e, es <- e, ee" },
    PatternDefinition { name: "NN", transcript: "-> e <- e, ee" },
    PatternDefinition { name: "NX", transcript: "-> e <- e, ee, s, es" },
    PatternDefinition { name: "XK", transcript: "<- s ... -> e, es <- e, ee -> s, se" },
    PatternDefinition { name: "XN", transcript: "-> e <- e, ee -> s, se" },
    PatternDefinition { name: "XX", transcript: "-> e <- e, ee, s, es -> s, se" },
    PatternDefinition { name: "NK1", transcript: "<- s ... -> e <- e, ee, es" },
    PatternDefinition { name: "NX1", transcript: "-> e <- e, ee, s" },
    PatternDefinition { name: "X", transcript: "<- s ... -> e, es, s, ss" },
    PatternDefinition { name: "X1K", transcript: "<- s ... -> e <- e, ee, se -> s, es" },
    PatternDefinition { name: "XK1", transcript: "<- s ... -> e, es <- e, ee -> s, se" },
    PatternDefinition { name: "X1K1", transcript: "<- s ... -> e <- e, ee, se, es -> s" },
    PatternDefinition { name: "X1N", transcript: "-> e <- e, ee, se -> s" },
    PatternDefinition { name: "X1X", transcript: "-> e <- e, ee, s, es -> s" },
    PatternDefinition { name: "XX1", transcript: "-> e <- e, ee, s -> s, se, es" },
    PatternDefinition { name: "X1X1", transcript: "-> e <- e, ee, s, se -> s, es" },
    PatternDefinition { name: "K1N", transcript: "-> s ... -> e <- e, ee" },
    PatternDefinition { name: "K1K", transcript: "-> s <- s ... -> e <- e, ee, es" },
    PatternDefinition { name: "KK1", transcript: "-> s <- s ... -> e, es <- e, ee, se" },
    PatternDefinition { name: "K1K1", transcript: "-> s <- s ... -> e <- e, ee, es, se" },
    PatternDefinition { name: "K1X", transcript: "-> s ... -> e <- e, ee, s, es" },
    PatternDefinition { name: "KX1", transcript: "-> s ... -> e, es <- e, ee, s" },
    PatternDefinition { name: "K1X1", transcript: "-> s ... -> e <- e, ee, s, es" },
    PatternDefinition { name: "I1N", transcript: "-> e, s <- e, ee" },
    PatternDefinition { name: "I1K", transcript: "<- s ... -> e, es, s <- e, ee" },
    PatternDefinition { name: "IK1", transcript: "<- s ... -> e, es, s, ss <- e, ee" },
    PatternDefinition { name: "I1K1", transcript: "<- s ... -> e, es, s <- e, ee, ss" },
    PatternDefinition { name: "I1X", transcript: "-> e, s <- e, ee, se, s" },
    PatternDefinition { name: "IX1", transcript: "-> e, s <- e, ee, se, s, es" },
    PatternDefinition { name: "I1X1", transcript: "-> e, s <- e, ee, se, s, es" },
    PatternDefinition { name: "Npsk0", transcript: "<- s ... -> psk, e, es" },
    PatternDefinition { name: "Kpsk0", transcript: "<- s ... -> psk, s, ss" },
    PatternDefinition { name: "Xpsk1", transcript: "<- s ... -> e, es, psk, s, ss" },
    PatternDefinition { name: "NNpsk0", transcript: "-> psk, e <- e, ee" },
    PatternDefinition { name: "NNpsk2", transcript: "-> e <- e, ee, psk" },
    PatternDefinition { name: "NKpsk0", transcript: "<- s ... -> psk, e, es <- e, ee" },
    PatternDefinition { name: "NKpsk2", transcript: "<- s ... -> e, es <- e, ee, psk" },
    PatternDefinition { name: "NXpsk2", transcript: "-> e <- e, ee, s, es, psk" },
    PatternDefinition { name: "XNpsk3", transcript: "-> e <- e, ee -> s, se, psk" },
    PatternDefinition { name: "XKpsk3", transcript: "<- s ... -> e, es <- e, ee -> s, se, psk" },
    PatternDefinition { name: "XXpsk3", transcript: "-> e <- e, ee, s, es -> s, se, psk" },
    PatternDefinition { name: "KNpsk0", transcript: "-> psk, s ... -> e <- e, ee, se" },
    PatternDefinition { name: "KNpsk2", transcript: "-> s ... -> e <- e, ee, se, psk" },
    PatternDefinition { name: "KKpsk0", transcript: "-> psk, s <- s ... -> e, es, ss <- e, ee, se" },
    PatternDefinition { name: "KKpsk2", transcript: "-> s <- s ... -> e, es, ss <- e, ee, se, psk" },
    PatternDefinition { name: "KXpsk2", transcript: "-> s ... -> e <- e, ee, se, s, es, psk" },
    PatternDefinition { name: "INpsk1", transcript: "-> e, s, psk <- e, ee, se" },
    PatternDefinition { name: "INpsk2", transcript: "-> e, s <- e, ee, se, psk" },
    PatternDefinition { name: "IKpsk1", transcript: "<- s ... -> e, es, s, ss, psk <- e, ee, se" },
    PatternDefinition { name: "IKpsk2", transcript: "<- s ... -> e, es, s, ss <- e, ee, se, psk" },
    PatternDefinition { name: "IXpsk2", transcript: "-> e, s <- e, ee, se, s, es, psk" },
];

impl PatternDefinition {
    pub fn default_config(&self) -> ProtocolConfig {
        ProtocolConfig::for_pattern(self)
    }

    pub fn contributors_used(&self) -> Vec<SecretContributor> {
        let mut contributors = Vec::new();

        for message in self.all_messages() {
            for token in message.tokens {
                if let Some(contributor) = contributor_from_token(&token) {
                    push_unique(&mut contributors, contributor);
                }
            }
        }

        contributors
    }

    pub fn supports_contributor(&self, contributor: SecretContributor) -> bool {
        self.contributors_used().contains(&contributor)
    }

    pub fn handshake_message_count(&self) -> usize {
        self.handshake_messages().len()
    }

    pub fn has_responder_handshake_message(&self) -> bool {
        self.handshake_messages()
            .iter()
            .any(|message| message.direction == MessageDirection::ToInitiator)
    }

    pub fn initiator_static_in_handshake(&self) -> bool {
        self.handshake_messages().iter().any(|message| {
            message.direction == MessageDirection::ToResponder
                && message.tokens.iter().any(|token| token == "s")
        })
    }

    pub fn initiator_static_anywhere(&self) -> bool {
        self.all_messages().iter().any(|message| {
            message.direction == MessageDirection::ToResponder
                && message.tokens.iter().any(|token| token == "s")
        })
    }

    pub fn responder_static_available(&self) -> bool {
        self.all_messages().iter().any(|message| {
            message.direction == MessageDirection::ToInitiator
                && message.tokens.iter().any(|token| token == "s")
        })
    }

    pub fn contributors_before_initiator_static(&self) -> Vec<SecretContributor> {
        let mut seen = Vec::new();

        for message in self.handshake_messages() {
            if message.direction == MessageDirection::ToResponder {
                for token in message.tokens {
                    if token == "s" {
                        return seen;
                    }

                    if let Some(contributor) = contributor_from_token(&token) {
                        push_unique(&mut seen, contributor);
                    }
                }
            } else {
                for token in message.tokens {
                    if let Some(contributor) = contributor_from_token(&token) {
                        push_unique(&mut seen, contributor);
                    }
                }
            }
        }

        seen
    }

    pub fn contributors_by_end_of_first_responder_message(&self) -> Vec<SecretContributor> {
        let mut seen = Vec::new();

        for message in self.handshake_messages() {
            for token in message.tokens {
                if let Some(contributor) = contributor_from_token(&token) {
                    push_unique(&mut seen, contributor);
                }
            }

            if message.direction == MessageDirection::ToInitiator {
                break;
            }
        }

        seen
    }

    fn all_messages(&self) -> Vec<PatternMessage> {
        let mut messages = self.pre_messages();
        messages.extend(self.handshake_messages());
        messages
    }

    fn pre_messages(&self) -> Vec<PatternMessage> {
        match self.transcript.split_once("...") {
            Some((prefix, _)) => parse_message_block(prefix.trim()),
            None => Vec::new(),
        }
    }

    fn handshake_messages(&self) -> Vec<PatternMessage> {
        let body = match self.transcript.split_once("...") {
            Some((_, suffix)) => suffix.trim(),
            None => self.transcript.trim(),
        };

        parse_message_block(body)
    }
}

pub fn default_pattern() -> &'static PatternDefinition {
    find_pattern(DEFAULT_PATTERN_NAME).expect("default pattern must exist")
}

pub fn find_pattern(name: &str) -> Option<&'static PatternDefinition> {
    let normalized = normalize_pattern_name(name);

    IMPORTANT_PATTERNS
        .iter()
        .find(|pattern| normalize_pattern_name(pattern.name) == normalized)
}

pub fn pattern_name_list() -> String {
    IMPORTANT_PATTERNS
        .iter()
        .map(|pattern| pattern.name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn normalize_pattern_name(input: &str) -> String {
    input
        .trim()
        .chars()
        .filter(|ch| !matches!(ch, '-' | '_' | ' '))
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn contributor_from_token(token: &str) -> Option<SecretContributor> {
    match token {
        "es" => Some(SecretContributor::Es),
        "ss" => Some(SecretContributor::Ss),
        "ee" => Some(SecretContributor::Ee),
        "se" => Some(SecretContributor::Se),
        "psk" => Some(SecretContributor::Psk),
        _ => None,
    }
}

fn parse_message_block(block: &str) -> Vec<PatternMessage> {
    let mut messages = Vec::new();
    let mut current_direction = None;
    let mut current_tokens: Vec<String> = Vec::new();

    for raw_piece in block.split_whitespace() {
        let piece = raw_piece.trim_end_matches(',');

        let new_direction = match piece {
            "->" => Some(MessageDirection::ToResponder),
            "<-" => Some(MessageDirection::ToInitiator),
            _ => None,
        };

        if let Some(direction) = new_direction {
            if let Some(previous_direction) = current_direction.take() {
                messages.push(PatternMessage {
                    direction: previous_direction,
                    tokens: std::mem::take(&mut current_tokens),
                });
            }

            current_direction = Some(direction);
        } else if !piece.is_empty() {
            current_tokens.push(piece.to_string());
        }
    }

    if let Some(direction) = current_direction {
        messages.push(PatternMessage {
            direction,
            tokens: current_tokens,
        });
    }

    messages
}

fn push_unique<T: PartialEq + Copy>(items: &mut Vec<T>, value: T) {
    if !items.contains(&value) {
        items.push(value);
    }
}
