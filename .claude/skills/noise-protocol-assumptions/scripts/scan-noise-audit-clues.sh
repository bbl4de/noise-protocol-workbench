#!/usr/bin/env bash
set -euo pipefail

TARGET_ROOT="${1:-.}"

if ! command -v rg >/dev/null 2>&1; then
  echo "error: this script requires ripgrep ('rg')" >&2
  exit 1
fi

print_section() {
  printf '\n== %s ==\n' "$1"
}

run_search() {
  local pattern="$1"
  rg -n --hidden \
    --glob '!target' \
    --glob '!.git' \
    --glob '!node_modules' \
    --glob '!dist' \
    --glob '!build' \
    "$pattern" "$TARGET_ROOT" || true
}

echo "Noise audit clue scan"
echo "Target: ${TARGET_ROOT}"
echo "This is a clue-gathering pass only. Confirm findings by reading the referenced files."

print_section "Construction strings"
run_search 'Noise_[A-Za-z0-9]+(?:psk[0-9])?_[A-Za-z0-9]+_[A-Za-z0-9]+_[A-Za-z0-9]+'

print_section "Pattern and handshake terminology"
run_search 'IKpsk2|XXpsk3|NNpsk2|handshake|initiator|responder|pattern|prologue|pre-message|premessage'

print_section "Potential PSK constants"
run_search '\[0u8;\s*32\]|psk|pre.?shared|zero.{0,20}psk|default.{0,20}psk|fixed.{0,20}psk|constant.{0,20}psk'

print_section "DH and ECDH call sites"
run_search '\b(ecdh|dh|diffie|x25519|curve25519|secp256k1)\s*\('

print_section "Handshake state and key storage"
run_search 'HandshakeState|struct .*Handshake|remote_static|remote_ephemeral|local_static|local_ephemeral|initiator_static|initiator_ephemeral|responder_static|responder_ephemeral|ephemeral_keypair|static_keypair'

print_section "Mixing and transcript logic"
run_search 'mix_key|mix_hash|encrypt_and_hash|decrypt_and_hash|MixKey|MixHash|EncryptAndHash|DecryptAndHash|chaining key|cipherstate|symmetricstate'

print_section "Handshake flow entry points"
run_search 'send_handshake|recv_handshake|accept_handshake|respond_handshake|write_message|read_message|initialize|init_handshake|finish_handshake'
