#!/usr/bin/env bash
set -euo pipefail

PREFIX=/opt/suricata-policy-engine
BIN=/usr/local/bin/spe

sudo mkdir -p "$PREFIX"
sudo python3 -m venv "$PREFIX/venv"
sudo "$PREFIX/venv/bin/pip" install --upgrade pip
sudo "$PREFIX/venv/bin/pip" install .

sudo ln -sf "$PREFIX/venv/bin/spe" "$BIN"

echo "Installed: $BIN"
