from copy import deepcopy
from pathlib import Path
import tempfile
import yaml
import pytest

import generate_suricata_policy as engine
import profiles
import runtime_paths
import tui

ROOT = Path(__file__).resolve().parents[1]


def test_all_profiles_are_deterministic_about_unknown_categories():
    expected = {
        "Raw": False,
        "Balanced": False,
        "Noisy": False,
        "Strict": True,
        "Lab / Experimental": False,
        "Server": False,
    }
    assert list(profiles.PROFILES) == list(expected)
    for name, disable in expected.items():
        assert profiles.PROFILES[name]["changes"][("defaults", "disable_unknown_categories")] is disable


def test_balanced_keeps_required_nginx_on_scada_off():
    c = profiles.PROFILES["Balanced"]["changes"]
    assert c[("assets", "web_specific_apps", "nginx", "enabled")] is True
    assert c[("assets", "scada", "enabled")] is False


def test_old_persisted_policy_schema_is_migrated_without_overwriting_user_values(tmp_path):
    current = yaml.safe_load((ROOT / "tuning-policy.yaml").read_text(encoding="utf-8"))
    current["categories"].pop("ET_POLICY", None)
    current["assets"].pop("database_products", None)
    current["assets"].pop("feed_products", None)
    current["assets"]["web_specific_apps"]["nginx"]["enabled"] = False  # custom operator value
    path = tmp_path / "tuning-policy.yaml"
    path.write_text(yaml.safe_dump(current, sort_keys=False), encoding="utf-8")

    runtime_paths._upgrade_managed_policy(path)
    upgraded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "ET_POLICY" in upgraded["categories"]
    assert "database_products" in upgraded["assets"]
    assert "feed_products" in upgraded["assets"]
    assert upgraded["assets"]["web_specific_apps"]["nginx"]["enabled"] is False
    assert list(tmp_path.glob("tuning-policy.yaml.pre-schema-*.bak"))


def test_all_profiles_apply_to_old_schema_without_missing_parent(tmp_path):
    old = yaml.safe_load((ROOT / "tuning-policy.yaml").read_text(encoding="utf-8"))
    old["categories"].pop("ET_POLICY", None)
    old["assets"].pop("database_products", None)
    old["assets"].pop("feed_products", None)
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(old, sort_keys=False), encoding="utf-8")
    for name, cfg in profiles.PROFILES.items():
        tui.apply_policy_changes(p, cfg["changes"], source="profile")
        loaded = engine.load_policy(p)
        assert isinstance(loaded, dict), name
        assert "ET_POLICY" in loaded["categories"]


def test_feed_discovery_returns_every_affected_product_value(tmp_path):
    rules = tmp_path / "suricata.rules"
    rules.write_text(
        'alert tcp any any -> any any (msg:"ET WEB_SPECIFIC_APPS A"; metadata: affected_product New_Product_A; sid:1; rev:1;)\n'
        'alert tcp any any -> any any (msg:"ET WEB_SPECIFIC_APPS B"; metadata: affected_product New_Product_B; sid:2; rev:1;)\n'
        'alert tcp any any -> any any (msg:"ET WEB_SPECIFIC_APPS C"; metadata: affected_product New_Product_A; sid:3; rev:1;)\n',
        encoding="utf-8",
    )
    assert tui._discover_feed_products(rules) == [("New_Product_A", 2), ("New_Product_B", 1)]


def test_feed_discovered_exact_asset_fallback_is_used_when_no_curated_matcher_matches():
    policy = engine.load_policy(ROOT / "tuning-policy.yaml")
    policy = deepcopy(policy)
    policy["categories"]["ET_WEB_SPECIFIC_APPS"]["mode"] = "asset_based"
    policy["assets"]["feed_products"] = {
        "future_product": {"enabled": True, "metadata_values": ["Future_Product"]}
    }
    raw = (
        'alert tcp any any -> any any (msg:"ET WEB_SPECIFIC_APPS Future Product issue"; '
        'metadata: affected_product Future_Product; sid:991001; rev:1;)'
    )
    rule = engine.Rule(
        sid=991001, rev=1, msg="ET WEB_SPECIFIC_APPS Future Product issue", raw=raw,
        source_enabled=True, category="ET_WEB_SPECIFIC_APPS",
        metadata=engine.parse_metadata(raw),
    )
    enabled, reason = engine.base_policy_decision(rule, policy, {})
    assert enabled is True
    assert reason.startswith("asset_match_enabled:feed:future_product")


def test_policy_rejects_blank_and_match_everything_regexes():
    policy = engine.load_policy(ROOT / "tuning-policy.yaml")
    for pattern in ("", ".*", "^.*$", ".+", "^.+$"):
        bad = deepcopy(policy)
        bad["assets"]["web_specific_apps"]["nginx"]["msg_regex"] = [pattern]
        with pytest.raises(ValueError):
            engine.validate_policy(bad)


def test_policy_rejects_duplicate_semantic_selector_names():
    policy = engine.load_policy(ROOT / "tuning-policy.yaml")
    bad = deepcopy(policy)
    target = next(k for k, v in bad["rule_overrides"].items() if v.get("semantic_keep"))
    first = deepcopy(bad["rule_overrides"][target]["semantic_keep"][0])
    bad["rule_overrides"][target]["semantic_keep"].append(first)
    with pytest.raises(ValueError):
        engine.validate_policy(bad)


def test_question_mark_is_routed_through_shared_help_key():
    assert tui._is_help_key(ord("?"))
    source = (ROOT / "src" / "tui.py").read_text(encoding="utf-8")
    assert "elif _is_help_key(ch) and help_lines:" in source
    assert 'elif _is_help_key(ch):\n                text_viewer(stdscr,"Semantic Selectors / Help"' in source
    assert 'elif _is_help_key(ch):\n            text_viewer(stdscr,"Suppressions / Help"' in source


def test_organization_policy_has_bottom_selected_description_panel():
    source = (ROOT / "src" / "tui.py").read_text(encoding="utf-8")
    start = source.index("def organization_editor")
    end = source.index("def rule_override_editor", start)
    block = source[start:end]
    assert "selected_detail_descriptions=org_details" in block
    assert "show_selected_description=True" in block
    for label in ("TOR", "File sharing", "P2P", "Chat", "Dynamic DNS", "Games", "Remote access"):
        assert f'"{label}":' in block


def test_alert_tuning_master_switch_is_separate_from_details():
    source = (ROOT / "src" / "tui.py").read_text(encoding="utf-8")
    start = source.index("def alert_tuning_editor")
    end = source.index("def suppressions_editor", start)
    block = source[start:end]
    assert '("Master switch",' in block
    assert '("", "DETAILS")' in block
    assert '("Threshold profiles",' in block
    assert '("Suppressions",' in block
    assert "Detection rules are not disabled by this switch." in block


def test_database_group_label_has_no_sql_slash_and_contains_curated_products():
    labels = dict((name, keys) for name, keys in tui.ASSET_GROUPS)
    assert "Databases" in labels
    assert all("/ SQL" not in name for name, _keys in tui.ASSET_GROUPS)
    assert set(labels["Databases"]) == {"mssql", "mysql", "mariadb", "postgresql", "oracle_database", "sap_maxdb"}


def test_dashboard_and_engine_share_unknown_rule_fallback_semantics():
    policy = engine.load_policy(ROOT / "tuning-policy.yaml")
    rule = engine.Rule(
        sid=999999, rev=1, msg="UNKNOWN CATEGORY rule", raw='alert tcp any any -> any any (msg:"UNKNOWN CATEGORY rule"; sid:999999; rev:1;)',
        source_enabled=True, category=None,
    )
    enabled, reason = engine.base_policy_decision(rule, policy, {})
    assert enabled is True and reason == "unknown_category_preserve_upstream"
    assert any("Unknown rules : PRESERVE FEED STATE" in x for x in tui.compact_policy_summary(ROOT / "tuning-policy.yaml"))

    strict = deepcopy(policy)
    strict["defaults"]["disable_unknown_categories"] = True
    enabled2, reason2 = engine.base_policy_decision(rule, strict, {})
    assert enabled2 is False and reason2 == "unknown_category_disabled"

class _FakeScreen:
    def __init__(self, keys, size=(30, 120)):
        self.keys = list(keys)
        self.size = size
    def getmaxyx(self):
        return self.size
    def getch(self):
        return self.keys.pop(0)
    def refresh(self):
        pass
    def erase(self):
        pass


def test_question_mark_actually_opens_choose_menu_help(monkeypatch):
    calls = []
    monkeypatch.setattr(tui, "draw_header", lambda *a, **k: None)
    monkeypatch.setattr(tui, "safe_addstr", lambda *a, **k: None)
    monkeypatch.setattr(tui, "text_viewer", lambda *a, **k: calls.append((a, k)))
    result = tui.choose_menu(_FakeScreen([ord("?"), ord("q")]), "Test", [("One", "desc")], help_lines=["help"])
    assert result is None
    assert len(calls) == 1


def test_detail_menu_arrow_move_does_not_full_redraw(monkeypatch):
    header_calls = []
    monkeypatch.setattr(tui, "draw_header", lambda *a, **k: header_calls.append(1))
    monkeypatch.setattr(tui, "safe_addstr", lambda *a, **k: None)
    monkeypatch.setattr(tui, "color", lambda *_a, **_k: 0)
    tui.choose_menu(
        _FakeScreen([tui.curses.KEY_DOWN, ord("q")]),
        "Org", [("A", "a"), ("B", "b"), ("C", "c")],
        show_selected_description=True,
        selected_detail_descriptions={"A": "A help", "B": "B help", "C": "C help"},
    )
    assert len(header_calls) == 1


def test_text_viewer_arrow_scroll_does_not_redraw_header(monkeypatch):
    header_calls = []
    monkeypatch.setattr(tui, "draw_header", lambda *a, **k: header_calls.append(1))
    monkeypatch.setattr(tui, "safe_addstr", lambda *a, **k: None)
    lines = [f"line {i}" for i in range(80)]
    tui.text_viewer(_FakeScreen([tui.curses.KEY_DOWN, ord("q")], size=(20, 90)), "Log", lines)
    assert len(header_calls) == 1
