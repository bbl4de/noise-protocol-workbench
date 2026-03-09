---
name: noise-protocol-assumptions
description: Use this skill when a user wants to inspect, test, or discuss Noise protocol handshake assumptions, pattern selection, weakened DH/PSK lanes, or qualitative security trade-offs. It uses the local `noise-protocol-workbench` CLI to run heuristic analyses across important Noise patterns and summarize the results without claiming formal verification.
---

# Noise Protocol Assumptions

Use this skill to analyze a codebase or protocol design that appears to use the Noise framework.

This skill is for:

- selecting a likely Noise pattern from code, docs, config, or transcripts
- testing what happens when `es`, `ss`, `ee`, `se`, or `psk` are weakened, omitted, or known
- explaining high-level trade-offs such as identity confidentiality, responder authentication, forward secrecy, KCI resistance, and PSK backup behavior

This skill is not for:

- formal proofs
- real cryptographic verification
- claiming a protocol is secure or insecure in a mathematical sense

## Workflow

1. Inspect the target repository for Noise clues before running the CLI.
2. Identify the most likely pattern name, for example `XX`, `IKpsk2`, or `NNpsk2`.
3. Identify candidate weaknesses or assumptions worth testing:
   `psk` zeroed or known, `se` misbound, missing `ee`, static compromise, ephemeral compromise.
4. Run the local wrapper script in this skill with `--json`.
5. Summarize the output as heuristic reasoning only.
6. If the pattern is uncertain, run 2-3 plausible candidates and compare.

## Where to look

- source files mentioning `Noise_`, `IK`, `XX`, `psk`, `handshake`, `initiator`, `responder`
- protocol docs or comments describing message order
- test vectors or transcript snippets
- library configuration that encodes a pattern string

Useful search terms:

```bash
rg "Noise_|IKpsk2|XXpsk3|handshake|initiator|responder|psk|pattern"
```

## Commands

List available patterns:

```bash
.claude/skills/noise-protocol-assumptions/scripts/run-noise-workbench.sh --list-patterns
```

Run a baseline analysis:

```bash
.claude/skills/noise-protocol-assumptions/scripts/run-noise-workbench.sh --pattern IKpsk2 --json
```

Run a compromised scenario:

```bash
.claude/skills/noise-protocol-assumptions/scripts/run-noise-workbench.sh --pattern XX --scenario init-static-compromised --json
```

Test a weakened configuration:

```bash
.claude/skills/noise-protocol-assumptions/scripts/run-noise-workbench.sh --pattern IKpsk2 --wrong-se --zero-psk --json
```

## Output handling

Focus on these report sections:

- `secrets`: which lanes remain unknown vs attacker-computable
- `properties`: which high-level protocol properties are intact, degraded, broken, or `N/A`

When reporting back:

- say which pattern you assumed
- say which scenario or mutations you tested
- state that the result is heuristic, not a proof
- separate observed repository facts from your inferences

## Notes

- The wrapper script prefers an installed `noise-protocol-workbench` binary from `PATH`.
- If the binary is not installed, it falls back to `cargo run` from this repository.
- If a requested mutation does not make sense for the selected pattern, the CLI returns an error instead of silently accepting it.
