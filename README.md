# noise-protocol-workbench

`noise-protocol-workbench` is a small Rust CLI for **educational, heuristic analysis of important Noise handshake patterns**.

The repository name is historical. The tool no longer focuses only on `IKpsk2`.

It now supports a built-in catalog of important patterns from the Noise Explorer pattern list, including classic base patterns such as `N`, `K`, `X`, `NN`, `NK`, `XX`, extended `1` variants such as `XK1` and `I1X1`, and PSK variants such as `Npsk0`, `NNpsk2`, `IKpsk2`, and `XXpsk3`.

Pattern names and transcript shapes were taken from the Noise Explorer catalog:
https://noiseexplorer.com/patterns/


## How the model works

Each built-in pattern starts with a baseline set of contributor lanes inferred from its transcript shape.

Examples:

- `IKpsk2` uses `es`, `ss`, `ee`, `se`, and `psk`.
- `XX` uses `es`, `ee`, and `se`.
- `N` uses only `es`.
- Non-PSK patterns mark the `psk` lane as `NotInPattern`.

The evaluator distinguishes between:

- a lane that is part of the pattern and still unknown to the attacker
- a lane that becomes attacker-computable under a compromise scenario
- a lane that the selected pattern does not use at all
- a lane that you manually disabled with a CLI flag

Some properties may show `N/A` when the selected pattern does not even attempt that property in this simplified model.

## Install

Install the CLI from this checkout:

```bash
cargo install --locked --path .
```

Install both the CLI and the Claude Code skill:

```bash
./scripts/install-local.sh
```

Install from GitHub with `curl`:

```bash
curl -fsSL https://raw.githubusercontent.com/bbl4de/noise-ikpsk2-workbench/main/scripts/install-via-curl.sh | bash
```

The local installer script:

- installs the `noise-protocol-workbench` binary with Cargo
- creates a personal Claude Code skill symlink at `~/.claude/skills/noise-protocol-assumptions`

The curl installer:

- installs the `noise-protocol-workbench` binary from the GitHub repository with Cargo
- copies the Claude Code skill into `~/.claude/skills/noise-protocol-assumptions`

If you only use Claude Code inside this repository, the project-local skill under `.claude/skills/noise-protocol-assumptions/` is already available without the install script.

## Build

```bash
cargo build
```

## CLI usage

List the built-in pattern catalog:

```bash
cargo run -- --list-patterns
```

Run the default pattern (`IKpsk2`):

```bash
cargo run --
```

Pick a different pattern:

```bash
cargo run -- --pattern XX
cargo run -- --pattern NKpsk2 --scenario resp-static-compromised
cargo run -- --pattern XXpsk3 --zero-psk
cargo run -- --pattern N --json
```

Disable or mutate lanes that exist in the selected pattern:

```bash
cargo run -- --pattern IKpsk2 --wrong-se --zero-psk
cargo run -- --pattern XX --omit-ee
```

If you try to mutate a lane that the selected pattern does not have, the CLI returns an error instead of silently doing something misleading.

## CLI flags

- `--pattern <name>`
- `--list-patterns`
- `--scenario <name>`
- `--wrong-se`
- `--zero-psk`
- `--omit-es`
- `--omit-ss`
- `--omit-ee`
- `--omit-se`
- `--json`

## Claude Code skill

This repository now includes a Claude Code skill:

```text
.claude/skills/noise-protocol-assumptions/
```

The skill uses this wrapper script:

```bash
.claude/skills/noise-protocol-assumptions/scripts/run-noise-workbench.sh
```

It also includes a first-pass audit scan script:

```bash
.claude/skills/noise-protocol-assumptions/scripts/scan-noise-audit-clues.sh
```

The wrapper first tries the installed `noise-protocol-workbench` binary from `PATH`. If the binary is not installed, it falls back to `cargo run` from this repository.

### How Claude Code uses it

The skill is intended to be directly invocable as:

```text
/noise-protocol-assumptions
```

You can also pass a natural-language task after the slash command:

```text
/noise-protocol-assumptions audit this repo's Noise handshake implementation, verify the actual pattern and DH token wiring, then visualize the security impact of confirmed issues
```

The intended workflow is now:

1. inspect the target repository for the claimed Noise construction and handshake flow
2. verify pattern names, constants, ECDH call sites, and state handling against the Noise specification
3. identify confirmed implementation findings such as zeroed PSK, omitted DH lanes, or truly misbound tokens
4. map those confirmed findings into the CLI model
5. use the CLI as a final qualitative visualization layer

This is deliberately different from a pure scenario simulator. The skill should audit the codebase first and only then use the CLI.

Example prompt to Claude Code in another project:

```text
Audit this repo's Noise handshake implementation. Verify the claimed pattern, check the PSK and ECDH wiring against the Noise spec, then use the noise-protocol-assumptions skill to visualize the effect of any confirmed issues.
```

Example manual command:

```bash
~/.claude/skills/noise-protocol-assumptions/scripts/run-noise-workbench.sh --pattern IKpsk2 --scenario init-static-compromised --json
```

Example first-pass audit scan:

```bash
~/.claude/skills/noise-protocol-assumptions/scripts/scan-noise-audit-clues.sh .
```

If Claude says the skill is not listed in the current session, check `/context`. Claude Code can exclude some slash-invocable skills when the slash-command description budget is exhausted, so keeping the skill description short helps.

## Built-in attacker scenarios

- `none`
- `init-static-compromised`
- `resp-static-compromised`
- `init-ephemeral-compromised`
- `resp-ephemeral-compromised`
- `both-statics-compromised`
- `psk-known`
- `all-statics-later-compromised`

## Output overview

Table A shows contributor exposure:

- whether the lane is enabled
- whether it is `Correct`, mutated, omitted, or `NotInPattern`
- whether the attacker knows it in the selected scenario
- why the evaluator reached that conclusion

Table B shows heuristic property impact:

- initiator identity confidentiality
- responder authentication
- forward secrecy
- KCI resistance under initiator static compromise
- defense in depth
- PSK backup protection
- overall session key protection

## Notes for extension

- Add more mutation types in [src/model.rs](/Users/bbl4de/Documents/A_work/cv_projects/noise_ikpsk2_workbench/src/model.rs).
- Add richer compromise presets in [src/scenarios.rs](/Users/bbl4de/Documents/A_work/cv_projects/noise_ikpsk2_workbench/src/scenarios.rs).
- Improve the heuristic rules in [src/eval.rs](/Users/bbl4de/Documents/A_work/cv_projects/noise_ikpsk2_workbench/src/eval.rs).
- Improve table presentation or add other formats in [src/output.rs](/Users/bbl4de/Documents/A_work/cv_projects/noise_ikpsk2_workbench/src/output.rs).
- Later, you can attach real transcript parsing or symbolic tooling without rewriting the current CLI layout.
