#!/usr/bin/env bash
set -euo pipefail

SKILL_NAME="noise-protocol-assumptions"
REPO_URL="${NOISE_WORKBENCH_REPO_URL:-https://github.com/bbl4de/noise-ikpsk2-workbench.git}"
ARCHIVE_URL="${NOISE_WORKBENCH_ARCHIVE_URL:-https://github.com/bbl4de/noise-ikpsk2-workbench/archive/refs/heads/main.tar.gz}"
TARGET_SKILL_DIR="${HOME}/.claude/skills/${SKILL_NAME}"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${TMP_DIR}"
}

trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command '$1' is not installed" >&2
    exit 1
  fi
}

need_cmd cargo
need_cmd curl
need_cmd tar

if [ -n "${NOISE_WORKBENCH_SOURCE_DIR:-}" ]; then
  SOURCE_DIR="${NOISE_WORKBENCH_SOURCE_DIR}"
  cargo install --locked --path "${SOURCE_DIR}"
  SOURCE_SKILL_DIR="${SOURCE_DIR}/.claude/skills/${SKILL_NAME}"
else
  cargo install --locked --git "${REPO_URL}"

  curl -fsSL "${ARCHIVE_URL}" | tar -xzf - -C "${TMP_DIR}"
  EXTRACTED_REPO_DIR="$(find "${TMP_DIR}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  SOURCE_SKILL_DIR="${EXTRACTED_REPO_DIR}/.claude/skills/${SKILL_NAME}"
fi

if [ ! -d "${SOURCE_SKILL_DIR}" ]; then
  echo "error: could not find skill directory at ${SOURCE_SKILL_DIR}" >&2
  exit 1
fi

mkdir -p "${HOME}/.claude/skills"

if [ -e "${TARGET_SKILL_DIR}" ] && [ ! -L "${TARGET_SKILL_DIR}" ]; then
  echo "error: ${TARGET_SKILL_DIR} already exists" >&2
  exit 1
fi

rm -f "${TARGET_SKILL_DIR}"
cp -R "${SOURCE_SKILL_DIR}" "${TARGET_SKILL_DIR}"

echo "Installed CLI and Claude Code skill."
echo "Binary: noise-protocol-workbench"
echo "Skill:  ${TARGET_SKILL_DIR}"
