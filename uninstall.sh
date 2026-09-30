#!/usr/bin/env bash
set -euo pipefail

sudo rm -f /usr/local/bin/spe
sudo rm -rf /opt/suricata-policy-engine

echo "Removed Suricata Policy Engine"
