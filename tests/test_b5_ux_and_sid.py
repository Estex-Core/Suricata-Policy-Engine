from copy import deepcopy
from pathlib import Path
from argparse import Namespace
import json
import sys

import generate_suricata_policy as engine
import tune_rules
import tui

ROOT = Path(__file__).resolve().parents[1]


def test_relative_tracked_baseline_uses_materialized_default(monkeypatch, tmp_path):
    fake = tmp_path / "tracked-rules-baseline.json"
    fake.write_text('{"version": 2, "tracked_rules": {}}\n', encoding="utf-8")
    monkeypatch.setattr(tui, "DEFAULT_TRACKED_BASELINE", fake)
    policy = {"rule_overrides": {"ET_INFO": {"tracked_sid_policy": {"baseline_file": "tracked-rules-baseline.json"}}}}
    resolved = tui.resolve_baseline(policy, tmp_path / "tuning-policy.yaml")
    assert resolved == fake


def test_sid_audit_accounts_for_tracked_sid_missing_from_baseline(tmp_path):
    policy = {
        "rule_overrides": {"ET_INFO": {"tracked_keep_sids": [1234]}},
    }
    rule = engine.Rule(sid=1234, rev=1, msg="ET INFO Test", raw='alert tcp any any -> any any (msg:"ET INFO Test"; sid:1234; rev:1;)', source_enabled=True, category="ET_INFO")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"version": 2, "tracked_rules": {}}), encoding="utf-8")
    audit = tune_rules.audit_tracked_rules({1234: rule}, policy, baseline)
    assert audit["tracked"] == 1
    assert audit["ok"] == []
    assert audit["unbaselined"] == [1234]


def test_database_assets_are_visible_in_tui_inventory():
    policy = tui.load_policy(ROOT / "tuning-policy.yaml")
    rows = tui._asset_overview_rows(policy)
    labels = {label for _key, label, _state, _kind in rows}
    for label in ("Microsoft SQL Server", "MySQL", "MariaDB", "PostgreSQL", "Oracle Database", "SAP MaxDB"):
        assert label in labels


def test_et_sql_preserves_feed_by_default_but_supports_asset_based_database_matching():
    policy = engine.load_policy(ROOT / "tuning-policy.yaml")
    rule = engine.Rule(
        sid=990001, rev=1, msg="ET SQL MySQL XML Functions Scalar XPath Denial of Service",
        raw='alert tcp any any -> any any (msg:"ET SQL MySQL XML Functions Scalar XPath Denial of Service"; sid:990001; rev:1;)',
        source_enabled=True, category="ET_SQL",
    )
    enabled, reason = engine.base_policy_decision(rule, policy, {})
    assert enabled is True and reason == "preserve_feed_state"

    p2 = deepcopy(policy)
    p2["categories"]["ET_SQL"]["mode"] = "asset_based"
    p2["assets"]["database_products"]["mysql"]["enabled"] = False
    enabled, reason = engine.base_policy_decision(rule, p2, {})
    assert enabled is False
    assert "asset_database_disabled:mysql" in reason

    p2["assets"]["database_products"]["mysql"]["enabled"] = True
    rule2 = engine.Rule(
        sid=990001, rev=1, msg=rule.msg, raw=rule.raw, source_enabled=True, category="ET_SQL"
    )
    enabled, reason = engine.base_policy_decision(rule2, p2, {})
    assert enabled is True
    assert "asset_database_enabled:mysql" in reason


def test_check_sids_progress_copy_does_not_claim_responsive():
    src = (ROOT / "src" / "tui.py").read_text(encoding="utf-8")
    assert "SID integrity scan is running — the TUI is responsive." not in src
    assert "The TUI is responsive; no policy or rule files are being changed." not in src


def test_category_editor_keeps_three_primary_controls_visible():
    src = (ROOT / "src" / "tui.py").read_text(encoding="utf-8")
    start = src.index("def category_policy_editor")
    end = src.index("def defaults_editor", start)
    block = src[start:end]
    assert 'Setting("Mode"' in block
    assert 'Setting("Conditional strategy"' in block
    assert 'Setting("Fallback enabled"' in block


def test_alert_tuning_copy_says_detection_stays_enabled():
    src = (ROOT / "src" / "tui.py").read_text(encoding="utf-8")
    assert "This feature controls alert volume only. It does not turn detection rules off." in src
    assert "Detection rules are not disabled by this switch." in src


def test_activate_copy_is_short_and_direct():
    src = (ROOT / "src" / "tui.py").read_text(encoding="utf-8")
    assert "Make the running Suricata use suricata-tuned.rules now." in src
    assert "suricata.rules is NOT changed." in src
    assert "Success is shown only if live Suricata reloads/restarts correctly." in src
