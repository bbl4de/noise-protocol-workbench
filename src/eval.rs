use crate::model::{
    ALL_CONTRIBUTORS, AttackerKnowledge, AttackerScenario, PatternDefinition, PropertyStatus, ProtocolConfig,
    SecretContributor, SecretVariant,
};
use crate::scenarios::{scenario_description, scenario_name};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Row used by Table A and JSON output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretExposure {
    pub secret: SecretContributor,
    pub enabled: bool,
    pub variant: SecretVariant,
    pub attacker_knows: AttackerKnowledge,
    pub reason: String,
}

/// Row used by Table B and JSON output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyImpact {
    pub property: String,
    pub status: PropertyStatus,
    pub explanation: String,
}

/// Full evaluation output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationReport {
    pub pattern: String,
    pub pattern_transcript: String,
    pub pattern_message_count: usize,
    pub disclaimer: String,
    pub scenario: AttackerScenario,
    pub scenario_name: String,
    pub scenario_description: String,
    pub config: ProtocolConfig,
    pub secrets: Vec<SecretExposure>,
    pub properties: Vec<PropertyImpact>,
}

#[derive(Debug, Default)]
struct AttackerCapabilities {
    knows_init_static: bool,
    knows_resp_static: bool,
    knows_init_ephemeral: bool,
    knows_resp_ephemeral: bool,
    knows_psk: bool,
    statics_compromised_later: bool,
}

impl AttackerCapabilities {
    fn from_scenario(scenario: AttackerScenario) -> Self {
        match scenario {
            AttackerScenario::None => Self::default(),
            AttackerScenario::InitStaticCompromised => Self {
                knows_init_static: true,
                ..Self::default()
            },
            AttackerScenario::RespStaticCompromised => Self {
                knows_resp_static: true,
                ..Self::default()
            },
            AttackerScenario::InitEphemeralCompromised => Self {
                knows_init_ephemeral: true,
                ..Self::default()
            },
            AttackerScenario::RespEphemeralCompromised => Self {
                knows_resp_ephemeral: true,
                ..Self::default()
            },
            AttackerScenario::BothStaticsCompromised => Self {
                knows_init_static: true,
                knows_resp_static: true,
                ..Self::default()
            },
            AttackerScenario::PskKnown => Self {
                knows_psk: true,
                ..Self::default()
            },
            AttackerScenario::AllStaticsLaterCompromised => Self {
                knows_init_static: true,
                knows_resp_static: true,
                statics_compromised_later: true,
                ..Self::default()
            },
        }
    }
}

pub fn evaluate_protocol(
    pattern: &PatternDefinition,
    config: &ProtocolConfig,
    scenario: AttackerScenario,
) -> EvaluationReport {
    let caps = AttackerCapabilities::from_scenario(scenario);

    let secrets: Vec<SecretExposure> = ALL_CONTRIBUTORS
        .iter()
        .map(|&contributor| evaluate_secret(contributor, config.variant_for(contributor), &caps))
        .collect();

    let secret_map: HashMap<SecretContributor, &SecretExposure> =
        secrets.iter().map(|entry| (entry.secret, entry)).collect();

    let properties = evaluate_properties(pattern, &secret_map, &secrets, scenario);

    EvaluationReport {
        pattern: pattern.name.to_string(),
        pattern_transcript: pattern.transcript.to_string(),
        pattern_message_count: pattern.handshake_message_count(),
        disclaimer: "Heuristic protocol-property reasoning only. This tool does not perform formal verification or cryptographic proof."
            .to_string(),
        scenario,
        scenario_name: scenario_name(scenario).to_string(),
        scenario_description: scenario_description(scenario).to_string(),
        config: config.clone(),
        secrets,
        properties,
    }
}

fn evaluate_secret(
    secret: SecretContributor,
    variant: SecretVariant,
    caps: &AttackerCapabilities,
) -> SecretExposure {
    let enabled = !matches!(variant, SecretVariant::Omitted | SecretVariant::NotInPattern);

    match variant {
        SecretVariant::NotInPattern => SecretExposure {
            secret,
            enabled,
            variant,
            attacker_knows: AttackerKnowledge::NotApplicable,
            reason: "This selected Noise pattern does not use this contributor lane.".to_string(),
        },
        SecretVariant::Omitted => SecretExposure {
            secret,
            enabled,
            variant,
            attacker_knows: AttackerKnowledge::NotApplicable,
            reason: "Contributor was manually disabled, so it contributes no hidden material.".to_string(),
        },
        SecretVariant::Correct => {
            let (attacker_knows, reason) = evaluate_correct_secret(secret, caps);
            SecretExposure {
                secret,
                enabled,
                variant,
                attacker_knows,
                reason,
            }
        }
        SecretVariant::WrongSe => {
            let reason = if secret == SecretContributor::Se {
                "`se` is intentionally wrong or misbound; the model treats this lane as attacker-computable."
            } else {
                "Unexpected WrongSe mutation on a non-`se` lane; the model conservatively treats it as exposed."
            };

            SecretExposure {
                secret,
                enabled,
                variant,
                attacker_knows: AttackerKnowledge::Known,
                reason: reason.to_string(),
            }
        }
        SecretVariant::ZeroPsk => {
            let reason = if secret == SecretContributor::Psk {
                "PSK was set to a predictable zero-style value, so the attacker can treat it as known."
            } else {
                "Unexpected ZeroPsk mutation on a non-PSK lane; the model conservatively treats it as exposed."
            };

            SecretExposure {
                secret,
                enabled,
                variant,
                attacker_knows: AttackerKnowledge::Known,
                reason: reason.to_string(),
            }
        }
    }
}

fn evaluate_correct_secret(
    secret: SecretContributor,
    caps: &AttackerCapabilities,
) -> (AttackerKnowledge, String) {
    match secret {
        SecretContributor::Es => {
            if caps.knows_init_ephemeral {
                (
                    AttackerKnowledge::Known,
                    "Initiator ephemeral private key compromise makes `es` directly computable.".to_string(),
                )
            } else if caps.knows_resp_static {
                let reason = if caps.statics_compromised_later {
                    "Responder static key is compromised later; with a recorded transcript, `es` can be recomputed."
                } else {
                    "Responder static private key compromise makes `es = DH(e_i, s_r)` computable."
                };
                (AttackerKnowledge::Known, reason.to_string())
            } else {
                (
                    AttackerKnowledge::Unknown,
                    "No modeled compromise reveals the initiator ephemeral private key or responder static private key needed for `es`."
                        .to_string(),
                )
            }
        }
        SecretContributor::Ss => {
            if caps.knows_init_static && caps.knows_resp_static {
                let reason = if caps.statics_compromised_later {
                    "Both static keys are compromised later; `ss` can be recomputed from captured handshake context."
                } else {
                    "Both static private keys are compromised; `ss` is trivially computable."
                };
                (AttackerKnowledge::Known, reason.to_string())
            } else if caps.knows_init_static {
                (
                    AttackerKnowledge::Known,
                    "Initiator static private key compromise makes `ss = DH(s_i, s_r)` computable."
                        .to_string(),
                )
            } else if caps.knows_resp_static {
                (
                    AttackerKnowledge::Known,
                    "Responder static private key compromise makes `ss = DH(s_i, s_r)` computable."
                        .to_string(),
                )
            } else {
                (
                    AttackerKnowledge::Unknown,
                    "No modeled compromise reveals a static private key needed for `ss`.".to_string(),
                )
            }
        }
        SecretContributor::Ee => {
            if caps.knows_init_ephemeral {
                (
                    AttackerKnowledge::Known,
                    "Initiator ephemeral private key compromise makes `ee = DH(e_i, e_r)` computable."
                        .to_string(),
                )
            } else if caps.knows_resp_ephemeral {
                (
                    AttackerKnowledge::Known,
                    "Responder ephemeral private key compromise makes `ee = DH(e_i, e_r)` computable."
                        .to_string(),
                )
            } else {
                (
                    AttackerKnowledge::Unknown,
                    "No modeled compromise reveals either ephemeral private key required for `ee`.".to_string(),
                )
            }
        }
        SecretContributor::Se => {
            if caps.knows_init_static {
                let reason = if caps.statics_compromised_later {
                    "Initiator static key is compromised later; `se` can be recomputed from recorded data."
                } else {
                    "Initiator static private key compromise makes `se = DH(s_i, e_r)` computable."
                };
                (AttackerKnowledge::Known, reason.to_string())
            } else if caps.knows_resp_ephemeral {
                (
                    AttackerKnowledge::Known,
                    "Responder ephemeral private key compromise makes `se = DH(s_i, e_r)` computable."
                        .to_string(),
                )
            } else {
                (
                    AttackerKnowledge::Unknown,
                    "No modeled compromise reveals the initiator static private key or responder ephemeral private key needed for `se`."
                        .to_string(),
                )
            }
        }
        SecretContributor::Psk => {
            if caps.knows_psk {
                (
                    AttackerKnowledge::Known,
                    "Scenario marks the PSK as known to the attacker, so the PSK lane is exposed."
                        .to_string(),
                )
            } else {
                (
                    AttackerKnowledge::Unknown,
                    "PSK remains unknown in this scenario and still contributes an independent secret lane."
                        .to_string(),
                )
            }
        }
    }
}

fn evaluate_properties(
    pattern: &PatternDefinition,
    secret_map: &HashMap<SecretContributor, &SecretExposure>,
    secrets: &[SecretExposure],
    scenario: AttackerScenario,
) -> Vec<PropertyImpact> {
    vec![
        assess_initiator_identity_confidentiality(pattern, secret_map, scenario),
        assess_responder_authentication(pattern, secret_map),
        assess_forward_secrecy(pattern, secret_map, scenario),
        assess_kci_resistance(pattern, secret_map, scenario),
        assess_defense_in_depth(secrets),
        assess_psk_backup(pattern, secret_map),
        assess_overall_session_key_protection(secret_map, secrets),
    ]
}

fn assess_initiator_identity_confidentiality(
    pattern: &PatternDefinition,
    secret_map: &HashMap<SecretContributor, &SecretExposure>,
    scenario: AttackerScenario,
) -> PropertyImpact {
    if !pattern.initiator_static_in_handshake() {
        return PropertyImpact {
            property: "initiator identity confidentiality".to_string(),
            status: PropertyStatus::NotApplicable,
            explanation: "This pattern does not transmit the initiator static key during the handshake."
                .to_string(),
        };
    }

    let shielding_lanes = pattern.contributors_before_initiator_static();
    let unknown_lanes = unknown_lanes_from(secret_map, &shielding_lanes);

    // heuristic rule: this is a simplification, not a formal claim
    let mut status = if shielding_lanes.is_empty() || unknown_lanes.is_empty() {
        PropertyStatus::Broken
    } else if unknown_lanes.len() == 1 {
        PropertyStatus::Degraded
    } else {
        PropertyStatus::Intact
    };

    let mut explanation = if shielding_lanes.is_empty() {
        "The initiator static key appears before any modeled masking contributor is mixed in."
            .to_string()
    } else {
        format!(
            "Contributors available before the initiator static is sent: {}. Unknown ones in this scenario: {}.",
            format_lanes(&shielding_lanes),
            format_lanes(&unknown_lanes)
        )
    };

    if matches!(
        scenario,
        AttackerScenario::InitStaticCompromised
            | AttackerScenario::BothStaticsCompromised
            | AttackerScenario::AllStaticsLaterCompromised
    ) && status == PropertyStatus::Intact
    {
        status = PropertyStatus::Degraded;
        explanation.push_str(" Initiator static compromise pressure downgrades confidence in this simplified model.");
    }

    PropertyImpact {
        property: "initiator identity confidentiality".to_string(),
        status,
        explanation,
    }
}

fn assess_responder_authentication(
    pattern: &PatternDefinition,
    secret_map: &HashMap<SecretContributor, &SecretExposure>,
) -> PropertyImpact {
    if !pattern.has_responder_handshake_message() {
        return PropertyImpact {
            property: "responder authentication".to_string(),
            status: PropertyStatus::NotApplicable,
            explanation: "This pattern has no responder handshake message to evaluate.".to_string(),
        };
    }

    if !pattern.responder_static_available() {
        return PropertyImpact {
            property: "responder authentication".to_string(),
            status: PropertyStatus::Broken,
            explanation: "The pattern has a responder message but no responder static identity is pre-known or transmitted, so identity authentication is weak by design."
                .to_string(),
        };
    }

    let auth_window = pattern.contributors_by_end_of_first_responder_message();
    let unknown_lanes = unknown_lanes_from(secret_map, &auth_window);
    let mut status = match unknown_lanes.len() {
        0 => PropertyStatus::Broken,
        1 => PropertyStatus::Degraded,
        _ => PropertyStatus::Intact,
    };

    let mut explanation = format!(
        "Contributors mixed by the end of the first responder message: {}. Unknown ones in this scenario: {}.",
        format_lanes(&auth_window),
        format_lanes(&unknown_lanes)
    );

    if auth_window.contains(&SecretContributor::Se)
        && secret_map[&SecretContributor::Se].variant == SecretVariant::WrongSe
    {
        status = downgrade_status(status);
        explanation.push_str(" `se` is wrong or misbound, which weakens responder-side binding.");
    }

    PropertyImpact {
        property: "responder authentication".to_string(),
        status,
        explanation,
    }
}

fn assess_forward_secrecy(
    pattern: &PatternDefinition,
    secret_map: &HashMap<SecretContributor, &SecretExposure>,
    scenario: AttackerScenario,
) -> PropertyImpact {
    if !pattern.supports_contributor(SecretContributor::Ee) {
        return PropertyImpact {
            property: "forward secrecy".to_string(),
            status: PropertyStatus::Broken,
            explanation: "This selected pattern has no `ee` lane, so forward secrecy is weak or absent in this simplified model."
                .to_string(),
        };
    }

    let ee = secret_map[&SecretContributor::Ee];

    // heuristic rule: this is a simplification, not a formal claim
    let (status, explanation) = if ee.attacker_knows.is_known() {
        (
            PropertyStatus::Broken,
            "`ee` is attacker-computable, so ephemeral forward-secrecy protection is lost.".to_string(),
        )
    } else if scenario == AttackerScenario::AllStaticsLaterCompromised {
        (
            PropertyStatus::Intact,
            "Even with later static compromise, unknown `ee` still provides forward-secrecy support."
                .to_string(),
        )
    } else {
        (
            PropertyStatus::Intact,
            "`ee` remains meaningful and unknown, preserving forward-secrecy behavior in this model."
                .to_string(),
        )
    };

    PropertyImpact {
        property: "forward secrecy".to_string(),
        status,
        explanation,
    }
}

fn assess_kci_resistance(
    pattern: &PatternDefinition,
    secret_map: &HashMap<SecretContributor, &SecretExposure>,
    scenario: AttackerScenario,
) -> PropertyImpact {
    if !pattern.initiator_static_anywhere() || !pattern.responder_static_available() {
        return PropertyImpact {
            property: "KCI resistance under initiator static compromise".to_string(),
            status: PropertyStatus::NotApplicable,
            explanation: "This pattern does not strongly model both a usable initiator static identity and a responder identity surface for this KCI heuristic."
                .to_string(),
        };
    }

    let se = secret_map[&SecretContributor::Se];

    // heuristic rule: this is a simplification, not a formal claim
    let (status, explanation) = if se.variant == SecretVariant::WrongSe {
        (
            PropertyStatus::Degraded,
            "WrongSe weakens responder-binding logic, so KCI resistance is reduced.".to_string(),
        )
    } else if !pattern.supports_contributor(SecretContributor::Psk) {
        (
            PropertyStatus::Broken,
            "This simplified lab treats an unknown PSK lane as the main backup against initiator-static compromise, and this pattern has no PSK lane."
                .to_string(),
        )
    } else {
        let psk = secret_map[&SecretContributor::Psk];

        if !psk.enabled || psk.variant == SecretVariant::ZeroPsk || psk.attacker_knows.is_known() {
            (
                PropertyStatus::Broken,
                "PSK backup is unavailable or exposed, so KCI resistance is weak in this simplified model."
                    .to_string(),
            )
        } else if matches!(
            scenario,
            AttackerScenario::InitStaticCompromised
                | AttackerScenario::BothStaticsCompromised
                | AttackerScenario::AllStaticsLaterCompromised
        ) {
            (
                PropertyStatus::Intact,
                "The scenario includes initiator-static pressure, but the PSK lane remains unknown and still acts as a backup barrier."
                    .to_string(),
            )
        } else {
            (
                PropertyStatus::Intact,
                "Under a hypothetical initiator-static compromise, the unknown PSK lane still acts as a backup barrier."
                    .to_string(),
            )
        }
    };

    PropertyImpact {
        property: "KCI resistance under initiator static compromise".to_string(),
        status,
        explanation,
    }
}

fn assess_defense_in_depth(secrets: &[SecretExposure]) -> PropertyImpact {
    let unknown_lanes: Vec<SecretContributor> = secrets
        .iter()
        .filter(|entry| entry.enabled && entry.attacker_knows.is_unknown())
        .map(|entry| entry.secret)
        .collect();

    // heuristic rule: this is a simplification, not a formal claim
    let status = match unknown_lanes.len() {
        0 => PropertyStatus::Broken,
        1 | 2 => PropertyStatus::Degraded,
        _ => PropertyStatus::Intact,
    };

    let explanation = if unknown_lanes.is_empty() {
        "No enabled contributor remains unknown to the attacker, so there is no depth left.".to_string()
    } else {
        format!(
            "Unknown enabled contributors: {} (count = {}).",
            format_lanes(&unknown_lanes),
            unknown_lanes.len()
        )
    };

    PropertyImpact {
        property: "defense in depth".to_string(),
        status,
        explanation,
    }
}

fn assess_psk_backup(
    pattern: &PatternDefinition,
    secret_map: &HashMap<SecretContributor, &SecretExposure>,
) -> PropertyImpact {
    if !pattern.supports_contributor(SecretContributor::Psk) {
        return PropertyImpact {
            property: "PSK backup protection".to_string(),
            status: PropertyStatus::NotApplicable,
            explanation: "This selected pattern has no PSK lane.".to_string(),
        };
    }

    let psk = secret_map[&SecretContributor::Psk];

    // heuristic rule: this is a simplification, not a formal claim
    let (status, explanation) = if !psk.enabled {
        (
            PropertyStatus::Broken,
            "The PSK lane was manually disabled, so there is no PSK backup protection.".to_string(),
        )
    } else if psk.variant == SecretVariant::ZeroPsk {
        (
            PropertyStatus::Broken,
            "PSK is zeroed or predictable, so backup protection is effectively gone.".to_string(),
        )
    } else if psk.attacker_knows.is_known() {
        (
            PropertyStatus::Broken,
            "The attacker knows the PSK in this scenario, so backup protection is unavailable.".to_string(),
        )
    } else {
        (
            PropertyStatus::Intact,
            "PSK remains enabled and unknown, so backup protection remains available.".to_string(),
        )
    };

    PropertyImpact {
        property: "PSK backup protection".to_string(),
        status,
        explanation,
    }
}

fn assess_overall_session_key_protection(
    secret_map: &HashMap<SecretContributor, &SecretExposure>,
    secrets: &[SecretExposure],
) -> PropertyImpact {
    let unknown_lanes: Vec<SecretContributor> = secrets
        .iter()
        .filter(|entry| entry.enabled && entry.attacker_knows.is_unknown())
        .map(|entry| entry.secret)
        .collect();

    // heuristic rule: this is a simplification, not a formal claim
    let mut status = match unknown_lanes.len() {
        0 => PropertyStatus::Broken,
        1 | 2 => PropertyStatus::Degraded,
        _ => PropertyStatus::Intact,
    };

    let mut explanation = format!(
        "Unknown enabled contributors feeding the session key: {} (count = {}).",
        format_lanes(&unknown_lanes),
        unknown_lanes.len()
    );

    let se = secret_map[&SecretContributor::Se];
    let psk = secret_map[&SecretContributor::Psk];

    if status == PropertyStatus::Intact
        && (se.variant == SecretVariant::WrongSe
            || psk.variant == SecretVariant::ZeroPsk
            || psk.attacker_knows.is_known())
    {
        status = PropertyStatus::Degraded;
        explanation.push_str(
            " Redundancy is reduced because the `se` or PSK path is weakened, even though several lanes remain unknown.",
        );
    }

    PropertyImpact {
        property: "overall session key protection".to_string(),
        status,
        explanation,
    }
}

fn unknown_lanes_from(
    secret_map: &HashMap<SecretContributor, &SecretExposure>,
    lanes: &[SecretContributor],
) -> Vec<SecretContributor> {
    lanes.iter()
        .copied()
        .filter(|lane| {
            secret_map
                .get(lane)
                .map(|entry| entry.enabled && entry.attacker_knows.is_unknown())
                .unwrap_or(false)
        })
        .collect()
}

fn format_lanes(lanes: &[SecretContributor]) -> String {
    if lanes.is_empty() {
        "none".to_string()
    } else {
        lanes.iter()
            .map(|lane| lane.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn downgrade_status(status: PropertyStatus) -> PropertyStatus {
    match status {
        PropertyStatus::Intact => PropertyStatus::Degraded,
        PropertyStatus::Degraded => PropertyStatus::Broken,
        other => other,
    }
}

// TODO: Split each property into finer sub-properties (e.g. active MITM vs passive recovery).
// TODO: Attach a confidence score to each heuristic rule for teaching trade-offs.
// TODO: Add optional transcript-aware explanation detail without implementing real crypto.
