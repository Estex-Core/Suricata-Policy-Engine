from copy import deepcopy
from pathlib import Path

import yaml

import generate_suricata_policy as engine
import tui

ROOT = Path(__file__).resolve().parents[1]


def load_policy():
    return yaml.safe_load((ROOT / "tuning-policy.yaml").read_text(encoding="utf-8"))


def test_asset_catalog_groups_cover_every_configured_asset_once():
    policy = load_policy()
    configured_web = set(policy["assets"]["web_specific_apps"])
    configured_db = set(policy["assets"]["database_products"])
    grouped = [key for _name, keys in tui.ASSET_GROUPS for key in keys if key not in tui.CORE_ASSETS]
    assert len(grouped) == len(set(grouped))
    assert set(grouped) == configured_web | configured_db
    assert len(configured_web) == 51
    assert configured_db == {"mssql", "mysql", "mariadb", "postgresql", "oracle_database", "sap_maxdb"}


def test_asset_catalog_defaults_do_not_invent_environment_assets():
    policy = load_policy()
    enabled = {name for name, cfg in policy["assets"]["web_specific_apps"].items() if cfg.get("enabled")}
    assert enabled == {"nginx"}


def test_games_and_inappropriate_are_org_controlled_and_off_by_default():
    policy = load_policy()
    for cat, key in (("ET_GAMES", "games"), ("ET_INAPPROPRIATE", "inappropriate_content")):
        rule = engine.Rule(sid=999001, rev=1, msg=f"{cat} test", raw="", source_enabled=True, category=cat)
        enabled, reason = engine.base_policy_decision(rule, policy, {})
        assert enabled is False
        assert reason == "conditional_disabled_by_default"

        p2 = deepcopy(policy)
        p2["organization_policy"][key]["detection_enabled"] = True
        enabled, reason = engine.base_policy_decision(rule, p2, {})
        assert enabled is True
        assert reason == "conditional_org_enabled"


def test_org_overview_exposes_new_policy_categories():
    policy = load_policy()
    assert "games" in policy["organization_policy"]
    assert "inappropriate_content" in policy["organization_policy"]
    assert tui._organization_policy_summary(None, False) == "No usage decision + No detection"


def test_remote_access_policy_catalog_was_expanded_from_ruleset_audit():
    policy = load_policy()
    apps = policy["organization_policy"]["remote_access"]["applications"]
    for expected in ("anydesk", "teamviewer", "screenconnect", "zoho_assist", "syncromsp", "centrastage", "netsupport", "simplehelp", "microsoft_rdp"):
        assert expected in apps


def test_organization_policy_category_map_covers_dedicated_usage_categories():
    policy = load_policy()
    expected = {
        "ET_TOR": "tor",
        "ET_FILE_SHARING": "file_sharing",
        "ET_P2P": "p2p",
        "ET_CHAT": "chat",
        "ET_DYN_DNS": "dynamic_dns",
        "ET_GAMES": "games",
        "ET_INAPPROPRIATE": "inappropriate_content",
        "ET_REMOTE_ACCESS": "remote_access",
    }
    assert engine.ORG_POLICY_CATEGORY_MAP == expected
    assert set(expected.values()) <= set(policy["organization_policy"])


def test_security_signal_categories_are_not_org_policy_switches():
    # These categories may intersect with corporate policy, but they are primarily
    # security detections. Organization allow/deny choices must not silently turn
    # them off through the usage-policy layer.
    for category in ("ET_COINMINER", "ET_ADWARE_PUP", "ET_TA_ABUSED_SERVICES"):
        assert category not in engine.ORG_POLICY_CATEGORY_MAP


def test_category_policy_ui_explains_mode_then_strategy():
    src = (ROOT / "src" / "tui.py").read_text(encoding="utf-8")
    assert "Mode = first decision. Strategy = second decision" in src
    assert "CONDITIONAL   -> continue to Strategy" in src
    assert "First-stage category action" in src
    assert "Used only when Mode=CONDITIONAL" in src
