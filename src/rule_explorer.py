#!/usr/bin/env python3
"""Search/filter engine for the TUI Rule Explorer."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import generate_suricata_policy as core
from runtime_paths import default_policy_path


def _tokens(query: str) -> list[str]:
    # Small shell-like parser without introducing another dependency.
    return re.findall(r'[^\s"]+:"[^"]*"|"[^"]*"|\S+', query or "")


def _match_token(rule, token: str) -> bool:
    if ":" not in token:
        needle = token.strip('"').lower()
        return needle in (rule.msg or "").lower() or needle in rule.raw.lower()
    key, value = token.split(":", 1)
    key, value = key.lower(), value.strip('"')
    low = value.lower()
    if key == "sid":
        return str(rule.sid) == value
    if key == "rev":
        return str(rule.rev) == value
    if key in {"cat", "category"}:
        return low in (rule.category or "").lower()
    if key == "state":
        states = {
            "active": bool(rule.final_enabled),
            "inactive": not bool(rule.final_enabled),
            "feed-active": bool(rule.source_enabled),
            "feed-inactive": not bool(rule.source_enabled),
            "review": bool(getattr(rule, "asset_review_candidate", False)),
        }
        return states.get(low, False)
    if key == "asset":
        return low in (getattr(rule, "asset_match_asset", "") or "").lower()
    if key == "flowbit":
        return any(low in x.lower() for x in (rule.flow_set | rule.flow_get))
    if key == "xbit":
        return any(low in x.lower() for x in (rule.xbit_set | rule.xbit_get))
    if key in {"msg", "text"}:
        return low in (rule.msg or "").lower()
    if key == "reason":
        return low in (rule.reason or "").lower()
    if key == "cve":
        return low in rule.raw.lower()
    if key == "meta":
        return any(low in (k + " " + " ".join(v)).lower() for k, v in rule.metadata.items())
    return low in rule.raw.lower()


def search_rules(rules: dict, query: str, limit: int = 200) -> list:
    tokens = _tokens(query)
    out = []
    for rule in rules.values():
        if all(_match_token(rule, t) for t in tokens):
            out.append(rule)
            if len(out) >= limit:
                break
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Search a Suricata ruleset")
    ap.add_argument("query")
    ap.add_argument("--rules", type=Path, default=Path("/var/lib/suricata/rules/suricata.rules"))
    ap.add_argument("--policy", type=Path, default=default_policy_path(Path(__file__).resolve().parent))
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    policy = core.load_policy(args.policy)
    rules = core.load_rules(args.rules)
    import tune_rules as tuner
    tuner.apply_policy(rules, policy)
    rows = search_rules(rules, args.query, args.limit)
    if args.json:
        print(json.dumps([{"sid": r.sid, "rev": r.rev, "category": r.category, "msg": r.msg,
                           "feed_enabled": r.source_enabled, "final_enabled": r.final_enabled,
                           "reason": r.reason} for r in rows], indent=2))
    else:
        for r in rows:
            print(f"{r.sid:<8} rev={r.rev:<3} {'ON' if r.final_enabled else 'OFF':<3} {r.category or 'UNMAPPED':<24} {r.msg}")
        print(f"\n{len(rows)} result(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
