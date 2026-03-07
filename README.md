# noise-ikpsk2-workbench

A small Rust CLI scaffold for **educational heuristic analysis** of the Noise **IKpsk2** handshake pattern.

This tool models high-level secret dependencies and lets you mutate individual contributors (`es`, `ss`, `ee`, `se`, `psk`) to see how qualitative security properties change.

**IT IS NOT A FORMAL QUANTITATIVE PROOF ENGINE NOR A FORMAL VERIFICATION TOOL, IT'S MEANT FOR EDUCATIONAL PURPOSES ONLY**

## IKpsk2 - quick recap

In Noise IKpsk2, this scaffold tracks five key secret contributors: `es`, `ss`, `ee`, `se` and `psk`.

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

## CLI flags

All the CLI flags:
- `--scenario <name>`
- `--wrong-se`
- `--zero-psk`
- `--omit-es`
- `--omit-ss`
- `--omit-ee`
- `--omit-se`
- `--json`

And the scenario names that are currently available ( will be expanding in the future ):
- `none`
- `init-static-compromised`
- `resp-static-compromised`
- `init-ephemeral-compromised`
- `resp-ephemeral-compromised`
- `both-statics-compromised`
- `psk-known`
- `all-statics-later-compromised`

## TODO:

- more attacker scenarios
- more mutation types
- richer explanation text
- future integration with actual Noise transcripts or symbolic tooling

# noise-ikpsk2-workbench
