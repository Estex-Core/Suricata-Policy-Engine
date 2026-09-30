from collections import Counter
from pathlib import Path

import yaml

from profiles import PROFILES

ROOT = Path(__file__).resolve().parents[1]


def get_path(data, path):
    cur = data
    for key in path:
        cur = cur[key]
    return cur


def test_reviewed_balanced_category_baseline_is_stable():
    policy = yaml.safe_load((ROOT / "tuning-policy.yaml").read_text(encoding="utf-8"))
    counts = Counter(cfg.get("mode") for cfg in policy["categories"].values())
    assert counts == {
        "preserve_feed": 24,
        "conditional": 22,
        "asset_based": 5,
        "disable": 2,
    }
    assert policy["categories"]["ET_INFO"]["strategy"] == "default_disabled_with_allowlist"
    assert policy["categories"]["ET_REMOTE_ACCESS"]["strategy"] == "organization_policy"
    assert policy["categories"]["ET_TOR"]["mode"] == "conditional"
    assert policy["categories"]["ET_WEB_SPECIFIC_APPS"]["mode"] == "asset_based"
    assert policy["categories"]["ET_RETIRED"]["mode"] == "disable"


def test_balanced_profile_matches_reviewed_standard_controls():
    policy = yaml.safe_load((ROOT / "tuning-policy.yaml").read_text(encoding="utf-8"))
    balanced = PROFILES["Balanced"]
    assert balanced["recommended"] is True
    changes = balanced["changes"]

    expected_paths = [
        ("defaults", "preserve_dependencies"),
        ("defaults", "dependency_restore", "enabled"),
        ("defaults", "dependency_restore", "only_if_required_by_enabled_rule"),
        ("defaults", "dependency_restore", "run_after_final_policy_resolution"),
        ("assets", "web_server", "enabled"),
        ("organization_policy", "tor", "prohibited"),
        ("organization_policy", "tor", "detection_enabled"),
        ("organization_policy", "remote_access", "default_policy"),
        ("organization_policy", "remote_access", "detection_enabled"),
        ("alert_tuning", "enabled"),
    ]

    for name in ("nginx", "wordpress", "jboss", "exchange", "citrix", "manageengine", "fortinet"):
        expected_paths.append(("assets", "web_specific_apps", name, "enabled"))
    for name in ("file_sharing", "p2p", "chat", "dynamic_dns", "games", "inappropriate_content"):
        expected_paths.extend([
            ("organization_policy", name, "prohibited"),
            ("organization_policy", name, "detection_enabled"),
        ])
    for app in policy["organization_policy"]["remote_access"]["applications"]:
        expected_paths.append(("organization_policy", "remote_access", "applications", app))

    for path in expected_paths:
        assert path in changes, f"Balanced does not own reviewed control: {path}"
        assert changes[path] == get_path(policy, path), f"Balanced drifted from reviewed baseline: {path}"

    # Balanced explicitly owns SCADA OFF per the v2.0.0b4 profile contract, while
    # VoIP/ActiveX remain inventory truth rather than invented profile facts.
    assert changes[("assets", "scada", "enabled")] is False
    for sensitive_asset in ("voip", "activex"):
        assert ("assets", sensitive_asset, "enabled") not in changes


def test_balanced_does_not_overwrite_low_level_guardrails():
    changes = PROFILES["Balanced"]["changes"]
    forbidden_prefixes = {
        "semantic_keep",
        "rule_overrides",
        "suppressions",
        "gpl_logical_category_map",
    }
    assert not any(path and path[0] in forbidden_prefixes for path in changes)
