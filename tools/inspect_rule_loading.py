#!/usr/bin/env python3
"""Read-only diagnose duplicate Suricata rule-files and SID collisions.

Examples:
  python3 tools/inspect_rule_loading.py --config /etc/suricata/suricata.yaml
  sudo python3 tools/inspect_rule_loading.py --config /etc/suricata/suricata.yaml
"""
from __future__ import annotations

import argparse
import glob
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import generate_suricata_policy as core


def scan(config: Path) -> tuple[int, str]:
    doc = yaml.safe_load(config.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("rule-files"), list):
        raise ValueError("Expected a top-level rule-files list")
    base = Path(doc.get("default-rule-path") or config.parent)
    paths = []
    missing = []
    for entry in doc["rule-files"]:
        if not isinstance(entry, str):
            raise ValueError("Unsupported rule-files entry")
        p = Path(entry)
        if not p.is_absolute():
            p = base / p
        candidates = [Path(x) for x in sorted(glob.glob(str(p)))] if glob.has_magic(str(p)) else [p]
        if not candidates:
            missing.append(str(p))
        paths.extend(candidates)
    aliases = defaultdict(list)
    by_sid = defaultdict(list)
    errors = []
    for p in paths:
        if not p.is_file():
            missing.append(str(p))
            continue
        aliases[str(p.resolve())].append(str(p))
        try:
            rules = core.load_rules(p)
        except Exception as exc:
            errors.append(f"{p}: {exc}")
            continue
        for sid in rules:
            by_sid[sid].append(str(p))
    repeated_paths = {k: v for k, v in aliases.items() if len(v) > 1}
    conflicting_sids = {sid: v for sid, v in by_sid.items() if len(v) > 1}
    lines = [f"Configured entries: {len(doc['rule-files'])}", f"Resolved file loads: {len(paths)}",
             f"Repeated paths: {len(repeated_paths)}", f"Overlapping SIDs across files: {len(conflicting_sids)}"]
    for path, values in list(repeated_paths.items())[:30]:
        lines.append(f"DUPLICATE PATH: {path} referenced {len(values)} times")
    for sid, files in list(sorted(conflicting_sids.items()))[:30]:
        lines.append(f"DUPLICATE SID {sid}: {', '.join(files)}")
    for path in missing:
        lines.append(f"MISSING: {path}")
    for err in errors:
        lines.append(f"PARSE ERROR: {err}")
    rc = 1 if repeated_paths or conflicting_sids or errors or missing else 0
    return rc, "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/etc/suricata/suricata.yaml"))
    args = parser.parse_args()
    try:
        rc, result = scan(args.config)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(result)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
