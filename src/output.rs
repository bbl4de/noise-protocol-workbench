use crate::eval::EvaluationReport;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, ContentArrangement, Table};

pub fn print_human_readable(report: &EvaluationReport) {
    println!("Noise Pattern Heuristic Workbench");
    println!("Pattern: {}", report.pattern);
    println!("Pattern shape: {}", report.pattern_transcript);
    println!("Handshake messages: {}", report.pattern_message_count);
    println!("Scenario: {}", report.scenario_name);
    println!("Scenario details: {}", report.scenario_description);
    println!();
    println!("Important: {}", report.disclaimer);
    println!();

    println!("Table A: Secret exposure");
    println!();
    let mut secrets_table = Table::new();
    secrets_table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    secrets_table.set_content_arrangement(ContentArrangement::Dynamic);
    secrets_table.set_header(vec![
        "Secret",
        "Enabled",
        "Variant",
        "Attacker knows it?",
        "Reason",
    ]);

    for entry in &report.secrets {
        secrets_table.add_row(vec![
            entry.secret.to_string(),
            yes_no(entry.enabled).to_string(),
            entry.variant.to_string(),
            entry.attacker_knows.to_string(),
            entry.reason.clone(),
        ]);
    }

    println!("{secrets_table}");
    println!();

    println!("Table B: Security property impact");
    println!();
    let mut property_table = Table::new();
    property_table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    property_table.set_content_arrangement(ContentArrangement::Dynamic);
    property_table.set_header(vec!["Property", "Status", "Explanation"]);

    for property in &report.properties {
        property_table.add_row(vec![
            property.property.clone(),
            property.status.to_string(),
            property.explanation.clone(),
        ]);
    }

    println!("{property_table}");
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}
