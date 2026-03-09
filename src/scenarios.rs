use crate::model::AttackerScenario;

/// Named presets that can be selected via `--scenario <name>`.
#[derive(Debug, Clone, Copy)]
pub struct ScenarioPreset {
    pub name: &'static str,
    pub scenario: AttackerScenario,
    pub description: &'static str,
}

pub const PRESET_SCENARIOS: [ScenarioPreset; 8] = [
    ScenarioPreset {
        name: "none",
        scenario: AttackerScenario::None,
        description: "No explicit long-term or ephemeral secret compromise is modeled.",
    },
    ScenarioPreset {
        name: "init-static-compromised",
        scenario: AttackerScenario::InitStaticCompromised,
        description: "Attacker learns initiator static private key.",
    },
    ScenarioPreset {
        name: "resp-static-compromised",
        scenario: AttackerScenario::RespStaticCompromised,
        description: "Attacker learns responder static private key.",
    },
    ScenarioPreset {
        name: "init-ephemeral-compromised",
        scenario: AttackerScenario::InitEphemeralCompromised,
        description: "Attacker learns initiator ephemeral private key.",
    },
    ScenarioPreset {
        name: "resp-ephemeral-compromised",
        scenario: AttackerScenario::RespEphemeralCompromised,
        description: "Attacker learns responder ephemeral private key.",
    },
    ScenarioPreset {
        name: "both-statics-compromised",
        scenario: AttackerScenario::BothStaticsCompromised,
        description: "Attacker learns both static private keys.",
    },
    ScenarioPreset {
        name: "psk-known",
        scenario: AttackerScenario::PskKnown,
        description: "Attacker knows the pre-shared key input.",
    },
    ScenarioPreset {
        name: "all-statics-later-compromised",
        scenario: AttackerScenario::AllStaticsLaterCompromised,
        description: "Both static private keys are compromised later (post-handshake model).",
    },
];

pub fn parse_scenario(input: &str) -> Option<AttackerScenario> {
    let normalized = input.trim().to_ascii_lowercase().replace('_', "-");
    PRESET_SCENARIOS
        .iter()
        .find(|preset| preset.name == normalized)
        .map(|preset| preset.scenario)
}

pub fn scenario_name(scenario: AttackerScenario) -> &'static str {
    PRESET_SCENARIOS
        .iter()
        .find(|preset| preset.scenario == scenario)
        .map(|preset| preset.name)
        .unwrap_or("unknown")
}

pub fn scenario_description(scenario: AttackerScenario) -> &'static str {
    PRESET_SCENARIOS
        .iter()
        .find(|preset| preset.scenario == scenario)
        .map(|preset| preset.description)
        .unwrap_or("No description available.")
}

pub fn scenario_name_list() -> String {
    PRESET_SCENARIOS
        .iter()
        .map(|preset| preset.name)
        .collect::<Vec<_>>()
        .join(", ")
}

// TODO: Add scenario categories (active MITM, replay constraints, transcript tampering).
// TODO: Add scenario metadata for expected pedagogical "difficulty" levels.
