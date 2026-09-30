#!/usr/bin/env python3
"""Read-only EVE telemetry analysis for Suricata Policy Engine.

Telemetry never suppresses or disables signatures automatically. It summarizes observed
alert volume and produces review recommendations that an operator can translate into
explicit policy (for example alert_tuning.sid_overrides) after investigation.
"""
from __future__ import annotations

import gzip
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional


def _open_text(path: Path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _parse_timestamp(value: object) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _safe_ip(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def analyze_eve(paths: Iterable[Path], rules: dict, policy: dict) -> dict:
    cfg = policy.get("telemetry", {}) or {}
    rec_cfg = cfg.get("recommendations", {}) or {}
    min_alerts = max(1, int(rec_cfg.get("min_alerts", 100)))
    noisy_rate = max(0.0, float(rec_cfg.get("noisy_rate_per_hour", 20.0)))
    top_n = max(1, min(200, int(rec_cfg.get("top_n", 25))))
    concentration_max_sources = max(1, int(rec_cfg.get("concentrated_max_unique_sources", 3)))

    per_sid = defaultdict(lambda: {
        "alerts": 0, "src": set(), "dst": set(), "first": None, "last": None,
        "actions": Counter(),
    })
    total_lines = invalid_json = alert_events = known_sid_alerts = 0
    files = []
    global_first = global_last = None

    for raw_path in paths:
        path = Path(raw_path)
        files.append(str(path))
        with _open_text(path) as fh:
            for line in fh:
                total_lines += 1
                try:
                    event = json.loads(line)
                except (json.JSONDecodeError, TypeError):
                    invalid_json += 1
                    continue
                if event.get("event_type") != "alert" or not isinstance(event.get("alert"), dict):
                    continue
                alert_events += 1
                alert = event["alert"]
                try:
                    sid = int(alert.get("signature_id"))
                except (TypeError, ValueError):
                    continue
                row = per_sid[sid]
                row["alerts"] += 1
                src = _safe_ip(event.get("src_ip"))
                dst = _safe_ip(event.get("dest_ip"))
                if src:
                    row["src"].add(src)
                if dst:
                    row["dst"].add(dst)
                action = alert.get("action")
                if action:
                    row["actions"][str(action)] += 1
                ts = _parse_timestamp(event.get("timestamp"))
                if ts is not None:
                    if row["first"] is None or ts < row["first"]:
                        row["first"] = ts
                    if row["last"] is None or ts > row["last"]:
                        row["last"] = ts
                    if global_first is None or ts < global_first:
                        global_first = ts
                    if global_last is None or ts > global_last:
                        global_last = ts
                if sid in rules:
                    known_sid_alerts += 1

    if global_first and global_last:
        observation_hours = max((global_last - global_first).total_seconds() / 3600.0, 1.0 / 3600.0)
    else:
        observation_hours = None

    sid_rows = []
    for sid, data in per_sid.items():
        rule = rules.get(sid)
        rate = (data["alerts"] / observation_hours) if observation_hours else None
        sid_rows.append({
            "sid": sid,
            "alerts": data["alerts"],
            "alerts_per_hour": round(rate, 3) if rate is not None else None,
            "unique_sources": len(data["src"]),
            "unique_destinations": len(data["dst"]),
            "first_seen": data["first"].isoformat() if data["first"] else None,
            "last_seen": data["last"].isoformat() if data["last"] else None,
            "actions": dict(data["actions"]),
            "known_rule": rule is not None,
            "enabled_after_tuning": bool(rule.final_enabled) if rule else None,
            "category": (rule.category or "UNMAPPED") if rule else None,
            "msg": rule.msg if rule else None,
        })
    sid_rows.sort(key=lambda x: (-x["alerts"], x["sid"]))

    recommendations = []
    for row in sid_rows:
        if not row["known_rule"] or not row["enabled_after_tuning"]:
            continue
        rate = row["alerts_per_hour"] or 0.0
        if row["alerts"] < min_alerts and rate < noisy_rate:
            continue
        concentrated = row["unique_sources"] <= concentration_max_sources
        rationale = (
            f"Observed {row['alerts']} alerts"
            + (f" (~{rate:.1f}/hour)" if row["alerts_per_hour"] is not None else "")
            + f" from {row['unique_sources']} unique source(s)."
        )
        if concentrated:
            rationale += " Activity is source-concentrated; investigate the source/asset before thresholding."
        else:
            rationale += " Activity is broadly distributed; review rule fidelity and environment-wide prevalence."
        recommendations.append({
            "sid": row["sid"],
            "category": row["category"],
            "msg": row["msg"],
            "alerts": row["alerts"],
            "alerts_per_hour": row["alerts_per_hour"],
            "unique_sources": row["unique_sources"],
            "unique_destinations": row["unique_destinations"],
            "classification": "high-volume-concentrated" if concentrated else "high-volume-distributed",
            "recommendation": "review-alert-tuning",
            "why": rationale,
            "safety_note": "Telemetry volume is not evidence of a false positive; do not suppress without investigation.",
        })
        if len(recommendations) >= top_n:
            break

    category_counts = Counter()
    for row in sid_rows:
        if row["category"]:
            category_counts[row["category"]] += row["alerts"]

    return {
        "mode": "recommendation-only",
        "files": files,
        "total_lines": total_lines,
        "invalid_json_lines": invalid_json,
        "alert_events": alert_events,
        "known_sid_alerts": known_sid_alerts,
        "observation_start": global_first.isoformat() if global_first else None,
        "observation_end": global_last.isoformat() if global_last else None,
        "observation_hours": round(observation_hours, 3) if observation_hours is not None else None,
        "top_sids": sid_rows[:top_n],
        "alerts_by_category": dict(category_counts.most_common()),
        "recommendations": recommendations,
    }
