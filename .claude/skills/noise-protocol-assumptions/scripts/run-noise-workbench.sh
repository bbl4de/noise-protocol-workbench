#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
SKILL_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd -P)"
REPO_ROOT="$(CDPATH= cd -- "${SKILL_DIR}/../../.." && pwd -P)"

if [ -n "${NOISE_WORKBENCH_BIN:-}" ]; then
  exec "${NOISE_WORKBENCH_BIN}" "$@"
fi

if command -v noise-protocol-workbench >/dev/null 2>&1; then
  exec noise-protocol-workbench "$@"
fi

if [ -n "${CARGO_HOME:-}" ] && [ -x "${CARGO_HOME}/bin/noise-protocol-workbench" ]; then
  exec "${CARGO_HOME}/bin/noise-protocol-workbench" "$@"
fi

if [ -x "${HOME}/.cargo/bin/noise-protocol-workbench" ]; then
  exec "${HOME}/.cargo/bin/noise-protocol-workbench" "$@"
fi

if [ -f "${REPO_ROOT}/Cargo.toml" ]; then
  exec cargo run --manifest-path "${REPO_ROOT}/Cargo.toml" -- "$@"
fi

echo "error: could not find the noise-protocol-workbench binary or repository checkout" >&2
echo "install the CLI with 'cargo install --locked --path /path/to/noise-protocol-workbench-source'" >&2
exit 1
