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
MAIN_BIN="suricata-policy-engine"

# Remove any legacy suffixed entry points from older installations.
rm -f "$BIN_DIR"/suricata-policy-engine-* 2>/dev/null || true
for bin in /usr/local/bin/suricata-policy-engine-*; do
  [ -e "$bin" ] || [ -L "$bin" ] || continue
  sudo rm -f "$bin"
done

if [ -f "$BIN_DIR/$MAIN_BIN" ]; then
  sudo ln -sf "$BIN_DIR/$MAIN_BIN" "/usr/local/bin/$MAIN_BIN"
fi

echo "[+] Installation complete"
echo "Run: suricata-policy-engine"
