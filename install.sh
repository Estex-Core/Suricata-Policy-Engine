#!/usr/bin/env bash
set -e

echo "[+] Installing Suricata Policy Engine"

if ! command -v pipx >/dev/null 2>&1; then
  echo "[+] Installing pipx"
  sudo apt update
  sudo apt install -y pipx
fi

pipx install . --force

BIN_DIR="/root/.local/bin"
TARGETS=(
  suricata-policy-engine
  suricata-policy-engine-tui
  suricata-policy-engine-cli
  suricata-policy-engine-audit
  suricata-policy-engine-explore
)

for bin in "${TARGETS[@]}"; do
  if [ -f "$BIN_DIR/$bin" ]; then
    sudo ln -sf "$BIN_DIR/$bin" "/usr/local/bin/$bin"
  fi
done

echo "[+] Installation complete"
echo "Run: suricata-policy-engine --help"
