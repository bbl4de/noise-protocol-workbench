#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd -P)"
SOURCE_SKILL_DIR="${REPO_ROOT}/.claude/skills/noise-protocol-assumptions"
TARGET_SKILL_DIR="${HOME}/.claude/skills/noise-protocol-assumptions"

cargo install --locked --path "${REPO_ROOT}"

mkdir -p "${HOME}/.claude/skills"

if [ -L "${TARGET_SKILL_DIR}" ]; then
  CURRENT_TARGET="$(CDPATH= cd -- "${TARGET_SKILL_DIR}" && pwd -P)"
  EXPECTED_TARGET="$(CDPATH= cd -- "${SOURCE_SKILL_DIR}" && pwd -P)"

  if [ "${CURRENT_TARGET}" != "${EXPECTED_TARGET}" ]; then
    echo "error: ${TARGET_SKILL_DIR} already points to a different location" >&2
    exit 1
  fi
elif [ -e "${TARGET_SKILL_DIR}" ]; then
  echo "error: ${TARGET_SKILL_DIR} already exists and is not a symlink" >&2
  exit 1
else
  ln -s "${SOURCE_SKILL_DIR}" "${TARGET_SKILL_DIR}"
fi

echo "Installed CLI and Claude Code skill."
echo "Binary: noise-protocol-workbench"
echo "Skill:  ${TARGET_SKILL_DIR}"
