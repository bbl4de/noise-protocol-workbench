# noise-ikpsk2-workbench

A small Rust CLI scaffold for **educational heuristic analysis** of the Noise **IKpsk2** handshake pattern.

This tool models high-level secret dependencies and lets you mutate individual contributors (`es`, `ss`, `ee`, `se`, `psk`) to see how qualitative security properties change.

## What this project is

- A qualitative protocol-property reasoning lab.
- A simple, readable starting point for non-expert developers.
- A CLI that reports:
  - which contributors are still unknown to an attacker
  - which contributors become attacker-computable
  - which high-level properties appear intact / degraded / broken under heuristic rules

## What this project is NOT

- Not real cryptanalysis.
- Not formal verification.
- Not a quantitative proof engine.
- Not a real Noise implementation (no actual DH or transcript processing yet).

Every output should be treated as a **structured heuristic explanation**, not a formal claim.

## IKpsk2 (high-level reminder)

In Noise IKpsk2, this scaffold tracks five key secret contributors:

- `es`
- `ss`
- `ee`
- `se`
- `psk`

The evaluator models how compromises or mutations in those lanes influence a set of protocol properties.

## Build and run

```bash
cargo build
```

Example commands:

```bash
cargo run -- --scenario init-static-compromised
cargo run -- --wrong-se --zero-psk --scenario init-static-compromised
cargo run -- --omit-ee
cargo run -- --json --scenario both-statics-compromised
```

## Supported CLI flags

- `--scenario <name>`
- `--wrong-se`
- `--zero-psk`
- `--omit-es`
- `--omit-ss`
- `--omit-ee`
- `--omit-se`
- `--json`

Available scenario names:

- `none`
- `init-static-compromised`
- `resp-static-compromised`
- `init-ephemeral-compromised`
- `resp-ephemeral-compromised`
- `both-statics-compromised`
- `psk-known`
- `all-statics-later-compromised`

## Project layout

- `src/main.rs` - CLI parsing and mutation wiring.
- `src/model.rs` - core enums/structs for contributors, variants, scenarios, and status.
- `src/scenarios.rs` - scenario presets and lookup helpers.
- `src/eval.rs` - heuristic rule engine and report generation.
- `src/output.rs` - terminal table rendering.
- `README.md` - project intent, limits, and usage.

## TODO:

- more attacker scenarios
- more mutation types
- richer explanation text
- future integration with actual Noise transcripts or symbolic tooling

