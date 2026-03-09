mod eval;
mod model;
mod output;
mod scenarios;

use clap::Parser;
use eval::evaluate_protocol;
use model::{
    default_pattern, find_pattern, pattern_name_list, AttackerScenario, PatternDefinition, ProtocolConfig,
    SecretContributor, SecretVariant, IMPORTANT_PATTERNS,
};
use scenarios::{parse_scenario, scenario_name_list};

#[derive(Parser, Debug)]
#[command(
    name = "noise-protocol-workbench",
    version,
    about = "Educational heuristic protocol-analysis CLI for multiple Noise patterns",
    long_about = "Educational protocol-property workbench for important Noise handshake patterns.\n\
This tool models high-level secret dependencies and compromise scenarios.\n\
It does NOT perform formal cryptographic verification or quantitative security proofs."
)]
struct Cli {
    #[arg(long, help = "Pattern name, for example `IKpsk2`, `XX`, `NN`, or `XKpsk3`")]
    pattern: Option<String>,

    #[arg(long, help = "List the built-in Noise pattern catalog and exit")]
    list_patterns: bool,

    #[arg(long, help = "Preset attacker scenario name")]
    scenario: Option<String>,

    #[arg(long, help = "Mutate `se` to a wrong or misbound variant")]
    wrong_se: bool,

    #[arg(long, help = "Set PSK to a predictable zero-value variant")]
    zero_psk: bool,

    #[arg(long, help = "Omit the `es` contributor")]
    omit_es: bool,

    #[arg(long, help = "Omit the `ss` contributor")]
    omit_ss: bool,

    #[arg(long, help = "Omit the `ee` contributor")]
    omit_ee: bool,

    #[arg(long, help = "Omit the `se` contributor")]
    omit_se: bool,

    #[arg(long, help = "Emit JSON report instead of terminal tables")]
    json: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();

    if cli.list_patterns {
        print_pattern_catalog();
        return Ok(());
    }

    let pattern = parse_requested_pattern(cli.pattern.as_deref())?;
    let scenario = parse_requested_scenario(cli.scenario.as_deref())?;

    let mut config = pattern.default_config();
    apply_cli_mutations(pattern, &mut config, &cli)?;

    let report = evaluate_protocol(pattern, &config, scenario);

    if cli.json {
        let json = serde_json::to_string_pretty(&report)
            .map_err(|err| format!("failed to serialize JSON output: {err}"))?;
        println!("{json}");
    } else {
        output::print_human_readable(&report);
    }

    Ok(())
}

fn parse_requested_pattern(raw: Option<&str>) -> Result<&'static PatternDefinition, String> {
    match raw {
        None => Ok(default_pattern()),
        Some(name) => find_pattern(name).ok_or_else(|| {
            format!(
                "unknown pattern '{name}'. Use `--list-patterns` or choose one of: {}",
                pattern_name_list()
            )
        }),
    }
}

fn parse_requested_scenario(raw: Option<&str>) -> Result<AttackerScenario, String> {
    match raw {
        None => Ok(AttackerScenario::None),
        Some(name) => parse_scenario(name).ok_or_else(|| {
            format!(
                "unknown scenario '{name}'. Available scenarios: {}",
                scenario_name_list()
            )
        }),
    }
}

fn apply_cli_mutations(
    pattern: &PatternDefinition,
    config: &mut ProtocolConfig,
    cli: &Cli,
) -> Result<(), String> {
    if cli.wrong_se {
        ensure_pattern_support(pattern, SecretContributor::Se, "--wrong-se")?;
        config.set_variant(SecretContributor::Se, SecretVariant::WrongSe);
    }

    if cli.zero_psk {
        ensure_pattern_support(pattern, SecretContributor::Psk, "--zero-psk")?;
        config.set_variant(SecretContributor::Psk, SecretVariant::ZeroPsk);
    }

    if cli.omit_es {
        ensure_pattern_support(pattern, SecretContributor::Es, "--omit-es")?;
        config.set_variant(SecretContributor::Es, SecretVariant::Omitted);
    }
    if cli.omit_ss {
        ensure_pattern_support(pattern, SecretContributor::Ss, "--omit-ss")?;
        config.set_variant(SecretContributor::Ss, SecretVariant::Omitted);
    }
    if cli.omit_ee {
        ensure_pattern_support(pattern, SecretContributor::Ee, "--omit-ee")?;
        config.set_variant(SecretContributor::Ee, SecretVariant::Omitted);
    }
    if cli.omit_se {
        ensure_pattern_support(pattern, SecretContributor::Se, "--omit-se")?;
        config.set_variant(SecretContributor::Se, SecretVariant::Omitted);
    }

    Ok(())
}

fn ensure_pattern_support(
    pattern: &PatternDefinition,
    contributor: SecretContributor,
    flag_name: &str,
) -> Result<(), String> {
    if pattern.supports_contributor(contributor) {
        Ok(())
    } else {
        Err(format!(
            "cannot use `{flag_name}` with pattern `{}` because that pattern has no `{}` lane",
            pattern.name, contributor
        ))
    }
}

fn print_pattern_catalog() {
    println!("Built-in Noise pattern catalog");
    println!();

    for pattern in IMPORTANT_PATTERNS {
        println!("{:<8} {}", pattern.name, pattern.transcript);
    }
}
