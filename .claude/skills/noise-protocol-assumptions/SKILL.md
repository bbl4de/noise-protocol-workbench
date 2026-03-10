---
name: noise-protocol-assumptions
description: Audit a codebase that implements or configures a Noise handshake. Verify the claimed pattern, constants, DH token wiring, and handshake flow against the Noise specification, then use the local `noise-protocol-workbench` CLI to visualize how confirmed implementation findings affect heuristic security properties.
user-invocable: true
argument-hint: [repo focus, suspected pattern, suspected bug, scenario, or audit scope]
---

# Noise Protocol Assumptions

Use this skill to audit a repository that appears to implement or configure a Noise handshake.

Invoke it directly as:

```text
/noise-protocol-assumptions audit this repo's Noise handshake implementation and show how the real code affects the protocol assumptions
```

## Purpose

This skill is for:

- verifying that the implemented handshake matches the claimed Noise pattern string
- checking PSK constants, pattern names, and algorithm choices found in code or docs
- inspecting ECDH call sites and mapping them to Noise tokens such as `es`, `ss`, `ee`, and `se`
- auditing handshake state flow: which keys are stored, when they are mixed, and which functions send or accept each message
- turning confirmed implementation findings into a `noise-protocol-workbench` visualization

This skill is not for:

- formal verification
- mathematical security proofs
- treating the CLI model as if it proved the implementation correct

## Critical rule

Do not start with the CLI.

First audit the target codebase and produce concrete findings from code. Use the CLI only after you have enough evidence to map implementation issues into high-level protocol mutations or compromise assumptions.

Read `references/noise-implementation-audit.md` before judging DH token correctness or message flow.

## Workflow

1. Gather repository evidence.
2. Identify the claimed Noise construction string and break it into pattern, DH choice, cipher, and hash.
3. Build a concrete handshake flow from code:
   init function, response function, accept/read function, handshake state, and key storage.
4. Verify ECDH token wiring against the Noise specification.
5. Verify constants and defaults:
   PSK values, static key sources, ephemeral generation, prologue, and any fixed test values leaking into production.
6. Write findings from observed code facts first.
7. Only then run `noise-protocol-workbench` to visualize the security effect of the confirmed findings.
8. State clearly which parts come from code observation and which parts are heuristic CLI interpretation.

## Audit procedure

### 1. Evidence gathering

Start with the bundled scan script from the target repository root:

```bash
.claude/skills/noise-protocol-assumptions/scripts/scan-noise-audit-clues.sh .
```

Then inspect the relevant files directly. Prefer concrete evidence over guesses.

Look for:

- `Noise_...` construction strings
- handshake functions such as `send`, `respond`, `accept`, `read_message`, `write_message`
- ECDH helpers and their call sites
- handshake state structs storing local or remote static and ephemeral keys
- PSK defaults or fixed arrays such as `[0u8; 32]`
- chaining-key / transcript-hash mixing logic

### 2. Pattern and transcript verification

Confirm that the claimed Noise pattern string matches the actual message flow.

Check:

- which side knows the responder static key up front
- which side sends static keys during the handshake
- whether the implementation shape matches the expected number and direction of handshake messages
- whether the code says one pattern name while behaving like another

If the pattern name and the flow disagree, treat that as a primary finding.

### 3. DH token verification

Use the spec mapping from `references/noise-implementation-audit.md`.

For each DH call site, determine:

- which side is executing it
- which local private key is used
- which remote public key is used
- which Noise token that call is supposed to represent at that point in the transcript

Be careful:

- Do not flag a DH as wrong just because the operands appear reversed.
- Noise token names are initiator/responder-role based, not "current sender/current receiver" based.
- DH commutativity means `DH(local_a, remote_b)` and the peer's matching `DH(local_b, remote_a)` can be the same intended token.

Only flag a token mismatch if, after accounting for the local role and the spec, the implementation is using the wrong key lane for that token.

### 4. Flow and state audit

Verify that the code keeps the right keys available at the right time.

Common failure modes:

- remote static or remote ephemeral not stored when later tokens need them
- a token effectively omitted because no corresponding DH call occurs
- PSK configured in the construction string but not actually mixed in
- message ordering inconsistent with the claimed pattern
- production code reusing test constants

### 5. Map findings into the CLI model

Use the CLI only after the code audit.

Mapping guidance:

- zero, fixed, or public PSK -> `--zero-psk`
- `se` lane truly wrong or misbound -> `--wrong-se`
- missing `ee` / `es` / `ss` / `se` lane -> matching `--omit-*`
- confirmed compromise assumptions from the deployment model -> `--scenario ...`

If a real finding does not fit the current CLI flags, do not force it into a bad approximation. Report the finding directly, then use the nearest CLI visualization only if you explicitly label it as an approximation.

### 6. Output format

Present findings first, ordered by severity, with file and line references.

Then include:

- claimed construction
- observed implementation flow
- confirmed mismatches or risky constants
- CLI commands you ran
- the heuristic impact interpretation

Keep a hard separation between:

- observed code facts
- your spec-based inference
- CLI-based qualitative visualization

## Commands

Gather initial clues:

```bash
.claude/skills/noise-protocol-assumptions/scripts/scan-noise-audit-clues.sh .
```

List built-in patterns:

```bash
.claude/skills/noise-protocol-assumptions/scripts/run-noise-workbench.sh --list-patterns
```

Visualize a verified zero-PSK issue in `IKpsk2`:

```bash
.claude/skills/noise-protocol-assumptions/scripts/run-noise-workbench.sh --pattern IKpsk2 --zero-psk --json
```

Visualize a verified wrong-`se` issue:

```bash
.claude/skills/noise-protocol-assumptions/scripts/run-noise-workbench.sh --pattern IKpsk2 --wrong-se --json
```

Visualize a verified implementation issue under a compromise scenario:

```bash
.claude/skills/noise-protocol-assumptions/scripts/run-noise-workbench.sh --pattern IKpsk2 --wrong-se --zero-psk --scenario init-static-compromised --json
```

## Notes

- The wrapper script prefers an installed `noise-protocol-workbench` binary from `PATH`.
- If the binary is not installed, it falls back to `cargo run` from this repository.
- The CLI is a qualitative model. It does not verify the target implementation by itself.
- The audit value comes from the code inspection plus spec mapping, then the CLI visualization.
