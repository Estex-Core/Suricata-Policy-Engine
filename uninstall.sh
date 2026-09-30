#!/usr/bin/env bash
set -e

pipx uninstall suricata-policy-engine || true

for bin in suricata-policy-engine suricata-policy-engine-tui suricata-policy-engine-cli suricata-policy-engine-audit suricata-policy-engine-explore
do
  sudo rm -f "/usr/local/bin/$bin"
done

echo "[+] Removed"
