from __future__ import annotations

from argparse import Namespace
from pathlib import Path
import copy
import json

import pytest
import yaml

import generate_suricata_policy as core
import profiles
import tune_rules
import tui

ROOT = Path(__file__).resolve().parents[1]


def _rule(tmp_path: Path, text: str):
    p = tmp_path / "r.rules"
    p.write_text(text + "\n", encoding="utf-8")
    return next(iter(core.load_rules(p).values()))


def test_public_profiles_include_raw_pass_through():
    assert list(profiles.PROFILES) == [
        "Raw", "Balanced", "Noisy", "Strict", "Lab / Experimental", "Server"
    ]


def test_balanced_nginx_on_scada_off():
    c = profiles.PROFILES["Balanced"]["changes"]
    assert c[("assets", "web_specific_apps", "nginx", "enabled")] is True
    assert c[("assets", "web_server", "enabled")] is True
    assert c[("assets", "scada", "enabled")] is False


def test_noisy_preserves_feed_instead_of_resurrecting_vendor_disabled_rule(tmp_path):
    policy = core.load_policy(ROOT / "tuning-policy.yaml")
    # Apply profile patch to an in-memory policy.
    for path, value in profiles.PROFILES["Noisy"]["changes"].items():
        cur = policy
        for key in path[:-1]:
            cur = cur.setdefault(key, {})
        cur[path[-1]] = value
    r = _rule(tmp_path, '# alert tcp any any -> any any (msg:"ET INFO Vendor Disabled"; sid:900001; rev:1;)')
    r.category = core.map_category(r.msg, policy)
    enabled, reason = core.base_policy_decision(r, policy, __import__('collections').Counter())
    assert r.source_enabled is False
    assert enabled is False
    assert reason == "preserve_feed_state"
    assert policy["alert_tuning"]["enabled"] is False


def test_strict_is_high_signal_not_blanket_disable():
    c = profiles.PROFILES["Strict"]["changes"]
    assert c[("categories", "ET_MALWARE", "mode")] == "preserve_feed"
    assert c[("categories", "ET_EXPLOIT", "mode")] == "preserve_feed"
    assert c[("categories", "ET_INFO", "mode")] == "disable"
    assert c[("categories", "ET_POLICY", "mode")] == "disable"
    assert c[("categories", "ET_WEB_SERVER", "mode")] == "asset_based"


def test_lab_adds_training_visibility_but_keeps_tuning():
    c = profiles.PROFILES["Lab / Experimental"]["changes"]
    assert c[("categories", "ET_INFO", "strategy")] == "enabled_by_default_with_alert_tuning"
    assert c[("categories", "ET_INFO", "default_enabled")] is True
    assert c[("alert_tuning", "enabled")] is True


def test_server_profile_server_posture():
    c = profiles.PROFILES["Server"]["changes"]
    assert c[("assets", "web_server", "enabled")] is True
    assert c[("assets", "web_specific_apps", "nginx", "enabled")] is True
    assert c[("assets", "scada", "enabled")] is False
    assert c[("categories", "ET_MOBILE_MALWARE", "mode")] == "disable"
    assert c[("organization_policy", "outbound_database", "detection_enabled")] is True


def test_switching_noisy_to_balanced_resets_category_posture(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_bytes((ROOT / "tuning-policy.yaml").read_bytes())
    tui.apply_policy_changes(p, profiles.PROFILES["Noisy"]["changes"], source="profile")
    assert tui.load_policy(p)["categories"]["ET_INFO"]["mode"] == "preserve_feed"
    tui.apply_policy_changes(p, profiles.PROFILES["Balanced"]["changes"], source="profile")
    cfg = tui.load_policy(p)["categories"]["ET_INFO"]
    assert cfg["mode"] == "conditional"
    assert cfg["strategy"] == "default_disabled_with_allowlist"


def test_et_policy_selective_cloud_storage_can_be_org_disabled(tmp_path):
    policy = core.load_policy(ROOT / "tuning-policy.yaml")
    r = _rule(tmp_path, 'alert http any any -> any any (msg:"ET POLICY File Shared via Zoom"; sid:900010; rev:1;)')
    r.category = core.map_category(r.msg, policy)
    assert r.category == "ET_POLICY"
    enabled, reason = core.organization_policy_selective_decision(r, policy)
    assert enabled is False
    assert reason == "organization_policy_selective_disabled:cloud_storage"


def test_et_policy_unmatched_security_rule_preserves_upstream(tmp_path):
    policy = core.load_policy(ROOT / "tuning-policy.yaml")
    r = _rule(tmp_path, 'alert tcp any any -> any any (msg:"ET POLICY Powershell Execution Bypass Likely Lateral Movement"; sid:900011; rev:1;)')
    r.category = core.map_category(r.msg, policy)
    assert r.category == "ET_POLICY"
    enabled, reason = core.organization_policy_selective_decision(r, policy)
    assert enabled is True
    assert reason == "organization_policy_selective_preserve_upstream"


def test_org_selector_conflict_preserves_upstream(tmp_path):
    policy = core.load_policy(ROOT / "tuning-policy.yaml")
    policy["organization_policy"]["cloud_storage"]["detection_enabled"] = False
    policy["organization_policy"]["cleartext_credentials"]["detection_enabled"] = True
    policy["organization_policy_selectors"] = [
        {"name":"A", "organization_key":"cloud_storage", "msg_contains":["Overlap"]},
        {"name":"B", "organization_key":"cleartext_credentials", "msg_contains":["Overlap"]},
    ]
    r = _rule(tmp_path, 'alert http any any -> any any (msg:"ET POLICY Overlap"; sid:900012; rev:1;)')
    enabled, reason = core.organization_policy_selective_decision(r, policy)
    assert enabled is True
    assert reason.startswith("organization_policy_selector_ambiguous_preserve_upstream:")


def test_invalid_org_selector_reference_rejected():
    policy = core.load_policy(ROOT / "tuning-policy.yaml")
    broken = copy.deepcopy(policy)
    broken["organization_policy_selectors"][0]["organization_key"] = "does_not_exist"
    with pytest.raises(ValueError, match="unknown organization key"):
        core.validate_policy(broken)


def test_deploy_refuses_live_sigfile_override_before_changing_config(monkeypatch, tmp_path):
    candidate = tmp_path / ".candidate.rules"; candidate.write_text("NEW\n")
    candidate_th = tmp_path / ".candidate.th"; candidate_th.write_text("TH\n")
    final = tmp_path / "suricata-tuned.rules"
    final_th = tmp_path / "suricata-tuned.threshold.config"
    config = tmp_path / "suricata.yaml"
    original = f"default-rule-path: {tmp_path}\nrule-files:\n  - suricata.rules\n"
    config.write_text(original)
    monkeypatch.setattr(tune_rules.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tune_rules, "running_suricata_sigfile_overrides", lambda: [str(tmp_path / "suricata.rules")])
    rc = tune_rules.deploy_production(candidate, candidate_th, config, False, final, final_th)
    assert rc == 28
    assert config.read_text() == original
    assert not final.exists()


def test_category_policy_editor_can_open_every_category(monkeypatch, tmp_path):
    p = tmp_path / "policy.yaml"; p.write_bytes((ROOT / "tuning-policy.yaml").read_bytes())
    args = Namespace(policy=p)
    names = list(tui.load_policy(p)["categories"])
    queue = iter(names + [None])
    monkeypatch.setattr(tui, "choose_menu", lambda *a, **k: next(queue))
    monkeypatch.setattr(tui, "edit_settings", lambda *a, **k: None)
    tui.category_policy_editor(object(), args)


def test_category_policy_editor_survives_malformed_conditional_strategy(monkeypatch, tmp_path):
    data = yaml.safe_load((ROOT / "tuning-policy.yaml").read_text())
    data["categories"]["ET_INFO"]["strategy"] = None
    p = tmp_path / "policy.yaml"; p.write_text(yaml.safe_dump(data, sort_keys=False))
    args = Namespace(policy=p)
    queue = iter(["ET_INFO", None])
    monkeypatch.setattr(tui, "choose_menu", lambda *a, **k: next(queue))
    monkeypatch.setattr(tui, "edit_settings", lambda *a, **k: None)
    tui.category_policy_editor(object(), args)


def test_screen_guard_catches_editor_exception(monkeypatch):
    seen = {}
    monkeypatch.setattr(tui, "text_viewer", lambda _s, title, lines, *a, **k: seen.update(title=title, text="\n".join(lines)))
    def boom(*_a):
        raise RuntimeError("category crash")
    tui._run_screen_safely(object(), "Category Policy", boom)
    assert "Error" in seen["title"]
    assert "category crash" in seen["text"]


def test_process_detector_does_not_mistake_policy_engine_for_suricata(monkeypatch):
    # Test the executable-name filter by replacing the /proc iterator input via a
    # tiny fake Path tree would be noisy; instead assert the source-level contract
    # and separately test runtime-option parsing from accepted process rows.
    source = (ROOT / "src" / "tune_rules.py").read_text(encoding="utf-8")
    assert 'if exe == "suricata":' in source
    assert '"suricata" in exe' not in source


def test_runtime_option_parsers(monkeypatch):
    monkeypatch.setattr(tune_rules, "_running_suricata_cmdlines", lambda: [
        ["/usr/bin/suricata", "-c", "/etc/suricata/suricata.yaml", "-S", "/var/lib/suricata/rules/custom.rules"],
        ["/usr/bin/suricata", "--config=/etc/suricata/second.yaml", "--sig-file=/rules/second.rules"],
    ])
    assert tune_rules.running_suricata_config_paths() == [
        "/etc/suricata/suricata.yaml", "/etc/suricata/second.yaml"
    ]
    assert tune_rules.running_suricata_sigfile_overrides() == [
        "/var/lib/suricata/rules/custom.rules", "/rules/second.rules"
    ]


def test_same_basename_different_absolute_sigfile_is_not_accepted(tmp_path):
    expected = tmp_path / "a" / "suricata-tuned.rules"
    other = tmp_path / "b" / "suricata-tuned.rules"
    assert tune_rules._same_rule_target(str(expected), expected)
    assert not tune_rules._same_rule_target(str(other), expected)


def test_deploy_refuses_different_runtime_config(monkeypatch, tmp_path):
    candidate = tmp_path / ".candidate.rules"; candidate.write_text("NEW\n")
    candidate_th = tmp_path / ".candidate.th"; candidate_th.write_text("TH\n")
    final = tmp_path / "suricata-tuned.rules"
    final_th = tmp_path / "suricata-tuned.threshold.config"
    config = tmp_path / "suricata.yaml"
    original = f"default-rule-path: {tmp_path}\nrule-files:\n  - suricata.rules\n"
    config.write_text(original)
    monkeypatch.setattr(tune_rules.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tune_rules, "running_suricata_sigfile_overrides", lambda: [])
    monkeypatch.setattr(tune_rules, "running_suricata_config_paths", lambda: [str(tmp_path / "other.yaml")])
    rc = tune_rules.deploy_production(candidate, candidate_th, config, False, final, final_th)
    assert rc == 29
    assert config.read_text() == original
    assert not final.exists()
