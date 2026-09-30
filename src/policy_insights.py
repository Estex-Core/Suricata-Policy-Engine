#!/usr/bin/env python3
"""Deterministic policy insights for Suricata Policy Engine.

This module does not make packet-level decisions. It explains and audits the
exact results produced by the tuner core so TUI/CLI/reporting stay consistent.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_DEDUCTION = {"critical": 20, "high": 10, "medium": 4, "low": 1, "info": 0}


def _get(data: Any, *path: str, default=None):
    cur = data
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def _rec(code: str, severity: str, title: str, why: str, action: str, evidence: Optional[dict] = None) -> dict:
    return {
        "code": code,
        "severity": severity,
        "title": title,
        "why": why,
        "action": action,
        "evidence": evidence or {},
    }


def _sorted_recommendations(items: Iterable[dict]) -> list[dict]:
    return sorted(items, key=lambda x: (SEVERITY_ORDER.get(x.get("severity", "info"), 99), x.get("code", "")))


def generate_recommendations(rules, policy: dict, result: dict, tracked_audit: dict, diff: Optional[dict] = None) -> list[dict]:
    """Return actionable, evidence-based recommendations from the current tuner state."""
    recs: list[dict] = []

    # Dependency integrity is the highest-priority correctness issue.
    missing_flow = sorted(result.get("missing_flow", []) or [])
    missing_xbit = sorted(result.get("missing_xbit", []) or [])
    if missing_flow:
        recs.append(_rec(
            "missing-flowbit-setters", "critical", "Required flowbit setters are missing",
            f"{len(missing_flow)} flowbit name(s) are required by enabled rules but no setter exists in the loaded ruleset.",
            "Review the affected rules/feed before deployment; do not treat the ruleset as dependency-complete.",
            {"names": missing_flow[:50], "count": len(missing_flow)},
        ))
    if missing_xbit:
        recs.append(_rec(
            "missing-xbit-setters", "critical", "Required xbit setters are missing",
            f"{len(missing_xbit)} xbit name(s) are required by enabled rules but no setter exists in the loaded ruleset.",
            "Review the affected rules/feed before deployment; do not treat the ruleset as dependency-complete.",
            {"names": missing_xbit[:50], "count": len(missing_xbit)},
        ))

    ambiguous_flow = sorted(result.get("ambiguous_flow", []) or [])
    ambiguous_xbit = sorted(result.get("ambiguous_xbit", []) or [])
    if ambiguous_flow or ambiguous_xbit:
        recs.append(_rec(
            "toggle-only-dependencies", "medium", "Toggle-only bit dependencies need review",
            "At least one enabled consumer has no deterministic set producer, but a toggle operation exists. Toggle flips state and is therefore not safe to auto-restore as a guaranteed producer.",
            "Review the producer/consumer chain. Prefer an explicit set producer when the rule logic requires a positive isset prerequisite.",
            {"flowbits": ambiguous_flow[:50], "xbits": ambiguous_xbit[:50]},
        ))

    defaults = policy.get("defaults", {}) or {}
    dep_cfg = defaults.get("dependency_restore", {}) or {}
    if not defaults.get("preserve_dependencies", True) or not dep_cfg.get("enabled", True):
        recs.append(_rec(
            "dependency-restore-disabled", "high", "Dynamic dependency restoration is disabled",
            "flowbits/xbits setter rules can be removed even when an enabled rule depends on them.",
            "Enable defaults.preserve_dependencies and defaults.dependency_restore.enabled unless you have an external dependency resolver.",
        ))

    # Tracked-SID drift.
    if tracked_audit.get("baseline_missing"):
        recs.append(_rec(
            "tracked-baseline-missing", "high", "Tracked SID baseline is missing",
            "Tracked SID drift cannot be compared reliably without a reviewed baseline.",
            "Review the current tracked SIDs with the read-only Feed Audit / Explain SID workflow, then update the baseline only after review.",
        ))
    for key, severity, title, action in (
        ("unbaselined", "high", "Tracked SIDs have no baseline fingerprint", "Review these tracked SIDs and accept/update the baseline only after confirming them."),
        ("missing", "high", "Tracked SIDs disappeared from the feed", "Use Explain SID and semantic replacement search before accepting a new baseline."),
        ("logic_changed", "high", "Tracked SID detection logic changed", "Review the changed rule logic before accepting the new baseline."),
        ("category_changed", "high", "Tracked SIDs changed logical category", "Review category mapping and the affected rule before accepting the new baseline."),
        ("rev_changed", "medium", "Tracked SID revisions changed", "Review the revised SIDs; REV drift can be benign but should be acknowledged."),
        ("message_changed", "medium", "Tracked SID messages changed", "Review whether semantic selectors still describe the intended detection."),
        ("feed_disabled", "medium", "Tracked SIDs are now disabled by the feed", "Review vendor/feed intent before considering any force-enable exception."),
    ):
        vals = sorted(set(tracked_audit.get(key, []) or []))
        if vals:
            recs.append(_rec(
                f"tracked-{key.replace('_', '-')}", severity, title,
                f"{len(vals)} tracked SID(s) have this state in the current feed.", action,
                {"sids": vals[:100], "count": len(vals)},
            ))

    # Organization-policy contradictions.
    org = policy.get("organization_policy", {}) or {}
    for key in ("tor", "file_sharing", "p2p", "chat", "dynamic_dns", "games", "inappropriate_content"):
        cfg = org.get(key, {}) or {}
        if isinstance(cfg, dict) and cfg.get("prohibited") is True and not cfg.get("detection_enabled", False):
            recs.append(_rec(
                f"org-{key}-prohibited-undetected", "high", f"{key.replace('_', ' ').title()} is prohibited but detection is OFF",
                "The organization policy says this activity is forbidden while the IDS policy would not detect it.",
                f"Enable organization_policy.{key}.detection_enabled or change the prohibition decision if this is intentional.",
            ))
    remote = org.get("remote_access", {}) or {}
    if isinstance(remote, dict):
        apps = remote.get("applications", {}) or {}
        any_prohibited = remote.get("default_policy") == "prohibited" or any(str(v).lower() == "prohibited" for v in apps.values())
        if any_prohibited and not remote.get("detection_enabled", False):
            recs.append(_rec(
                "org-remote-access-prohibited-undetected", "high", "Remote access is prohibited but detection is OFF",
                "At least one remote-access policy is prohibited while ET_REMOTE_ACCESS detection is disabled.",
                "Enable organization_policy.remote_access.detection_enabled or revise the organization policy.",
            ))

    # Conservative asset matching intentionally sends ambiguous matches to review.
    asset_review = [r for r in rules.values() if getattr(r, "asset_review_candidate", False)]
    if asset_review:
        recs.append(_rec(
            "ambiguous-asset-matches", "medium", "Some asset matches need administrator review",
            f"{len(asset_review)} rule(s) have partial asset evidence below the automatic match threshold.",
            "Review these candidates; add precise metadata/alias/regex evidence instead of lowering thresholds globally.",
            {"sids": [r.sid for r in asset_review[:100]], "count": len(asset_review)},
        ))

    # Validate matcher threshold ordering for enabled web applications.
    apps = _get(policy, "assets", "web_specific_apps", default={}) or {}
    for name, cfg in apps.items():
        if not isinstance(cfg, dict) or not cfg.get("enabled", False):
            continue
        match_t = int(cfg.get("match_threshold", 80))
        review_t = int(cfg.get("review_threshold", 50))
        if match_t <= review_t:
            recs.append(_rec(
                f"asset-threshold-{name}", "high", f"Invalid asset thresholds for {name}",
                f"match_threshold={match_t} must be greater than review_threshold={review_t} to keep a real review band.",
                "Increase match_threshold or lower review_threshold.",
            ))

    unknown_enabled = int(result.get("unknown_enabled", 0) or 0)
    if unknown_enabled:
        recs.append(_rec(
            "unknown-enabled-categories", "high", "Feed-enabled rules are not mapped to policy categories",
            f"{unknown_enabled} feed-enabled rule(s) do not map to a known logical category and are being preserved conservatively.",
            "Inspect the new rule/category names and add explicit policy mapping before the next deployment.",
            {"count": unknown_enabled},
        ))

    unresolved = result.get("unresolved_selective", {}) or {}
    if unresolved:
        count = sum(int(v) for v in unresolved.values())
        recs.append(_rec(
            "unresolved-selective-policy", "medium", "Selective policy still has unresolved rules",
            f"{count} rule decision(s) fall back to preserving feed state pending review.",
            "Review the listed categories and replace generic selective fallback with an explicit strategy if needed.",
            {"categories": dict(unresolved), "count": count},
        ))

    # Suppression hygiene.
    suppressions = _get(policy, "alert_tuning", "suppressions", default=[]) or []
    missing_suppression_sids = []
    for item in suppressions:
        if not isinstance(item, dict) or "sid" not in item:
            continue
        try:
            sid = int(item["sid"])
        except (TypeError, ValueError):
            continue
        if sid not in rules:
            missing_suppression_sids.append(sid)
    if missing_suppression_sids:
        recs.append(_rec(
            "stale-suppressions", "medium", "Suppression entries reference missing SIDs",
            f"{len(missing_suppression_sids)} suppression SID(s) are not present in the current feed.",
            "Remove stale suppressions or confirm whether the corresponding signature was replaced.",
            {"sids": sorted(set(missing_suppression_sids)), "count": len(set(missing_suppression_sids))},
        ))

    # Update-change review recommendation. This is about change magnitude, not attack likelihood.
    if diff and not diff.get("baseline", True):
        changed_state = len(diff.get("newly_enabled", []) or []) + len(diff.get("newly_disabled", []) or [])
        final_enabled = max(sum(1 for r in rules.values() if getattr(r, "final_enabled", False)), 1)
        threshold = max(100, int(final_enabled * 0.01))
        if changed_state >= threshold:
            recs.append(_rec(
                "large-active-state-change", "medium", "This update changes many active rule states",
                f"{changed_state} existing SID(s) change enabled/disabled state, crossing the review threshold of {threshold}.",
                "Inspect Update Impact Preview by category before deployment.",
                {"changed_state": changed_state, "review_threshold": threshold},
            ))

    if not recs:
        recs.append(_rec(
            "no-actionable-findings", "info", "No actionable policy-integrity findings",
            "The deterministic checks did not find a current policy consistency or dependency issue.",
            "Continue normal feed review and Suricata validation; this is not a guarantee of detection coverage.",
        ))
    return _sorted_recommendations(recs)


def policy_health_report(policy: dict, rules, result: dict, tracked_audit: dict, recommendations: list[dict]) -> dict:
    """Configuration-health score. This is explicitly not a security/detection score."""
    actionable = [r for r in recommendations if r.get("severity") != "info"]
    deductions = [SEVERITY_DEDUCTION.get(r.get("severity", "info"), 0) for r in actionable]
    score = max(0, 100 - sum(deductions))
    if score >= 95:
        status = "CLEAN"
    elif score >= 85:
        status = "GOOD"
    elif score >= 70:
        status = "REVIEW"
    else:
        status = "ATTENTION"

    by_severity = Counter(r.get("severity", "info") for r in recommendations)
    checks = {
        "dependency_integrity": not bool(result.get("missing_flow") or result.get("missing_xbit")),
        "tracked_sid_integrity": not bool(
            tracked_audit.get("unbaselined") or tracked_audit.get("missing") or tracked_audit.get("logic_changed") or tracked_audit.get("category_changed")
        ),
        "known_enabled_categories": int(result.get("unknown_enabled", 0) or 0) == 0,
        "no_ambiguous_asset_matches": not any(getattr(r, "asset_review_candidate", False) for r in rules.values()),
        "dependency_restore_enabled": bool(_get(policy, "defaults", "preserve_dependencies", default=True))
            and bool(_get(policy, "defaults", "dependency_restore", "enabled", default=True)),
    }
    return {
        "score": score,
        "status": status,
        "note": "Configuration/policy health only; not a security coverage or threat-detection score.",
        "actionable_findings": len(actionable),
        "by_severity": dict(by_severity),
        "checks": checks,
    }


def build_update_impact(diff: dict, rules, previous_state: Optional[dict] = None, tracked_audit: Optional[dict] = None) -> dict:
    """Describe what a new feed/policy would change before deployment."""
    if not diff or diff.get("baseline", True):
        return {
            "baseline": True,
            "summary": "No previous tuner state exists; this run establishes the comparison baseline.",
            "new_sids": 0,
            "removed_sids": 0,
            "rev_changed": 0,
            "newly_enabled": 0,
            "newly_disabled": 0,
            "review_sids": [],
            "categories": {},
        }

    by_sid = rules
    new_sids = set(diff.get("new_sids", []) or [])
    removed_sids = set(diff.get("removed_sids", []) or [])
    revised = set(diff.get("rev_changed", []) or [])
    newly_enabled = set(diff.get("newly_enabled", []) or [])
    newly_disabled = set(diff.get("newly_disabled", []) or [])

    category_counts: dict[str, Counter] = {}
    old_rules = ((previous_state or {}).get("rules", {}) or {}) if isinstance(previous_state, dict) else {}
    for label, sids in (("new", new_sids), ("revised", revised), ("newly_enabled", newly_enabled), ("newly_disabled", newly_disabled), ("removed", removed_sids)):
        c = Counter()
        for sid in sids:
            r = by_sid.get(sid)
            if r is not None:
                cat = getattr(r, "category", None) or "UNMAPPED"
            else:
                cat = (old_rules.get(str(sid), {}) or {}).get("category", "UNMAPPED")
            c[cat] += 1
        for cat, value in c.items():
            category_counts.setdefault(cat, Counter())[label] += value

    removed_were_enabled = sum(1 for sid in removed_sids if (old_rules.get(str(sid), {}) or {}).get("enabled", False))
    new_feed_enabled = sum(1 for sid in new_sids if sid in by_sid and bool(by_sid[sid].source_enabled))
    new_final_enabled = sum(1 for sid in new_sids if sid in by_sid and bool(by_sid[sid].final_enabled))
    revised_final_enabled = sum(1 for sid in revised if sid in by_sid and bool(by_sid[sid].final_enabled))

    review_sids = {r.sid for r in rules.values() if getattr(r, "asset_review_candidate", False)}
    if tracked_audit:
        for key in ("unbaselined", "missing", "logic_changed", "category_changed", "rev_changed", "feed_disabled"):
            review_sids.update(tracked_audit.get(key, []) or [])
    changed_universe = new_sids | revised | newly_enabled | newly_disabled | removed_sids
    review_sids = sorted(review_sids & changed_universe)

    categories = {
        cat: dict(sorted(counter.items()))
        for cat, counter in sorted(category_counts.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))
    }
    return {
        "baseline": False,
        "new_sids": len(new_sids),
        "new_feed_enabled": new_feed_enabled,
        "new_final_enabled": new_final_enabled,
        "removed_sids": len(removed_sids),
        "removed_were_enabled": removed_were_enabled,
        "rev_changed": len(revised),
        "revised_final_enabled": revised_final_enabled,
        "newly_enabled": len(newly_enabled),
        "newly_disabled": len(newly_disabled),
        "review_sids": review_sids,
        "review_count": len(review_sids),
        "categories": categories,
    }


def insights_bundle(rules, policy: dict, result: dict, tracked_audit: dict, diff: dict, previous_state: Optional[dict] = None) -> dict:
    recommendations = generate_recommendations(rules, policy, result, tracked_audit, diff)
    health = policy_health_report(policy, rules, result, tracked_audit, recommendations)
    impact = build_update_impact(diff, rules, previous_state, tracked_audit)
    return {
        "recommendations": recommendations,
        "policy_health": health,
        "update_impact": impact,
    }
