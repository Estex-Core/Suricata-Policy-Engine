from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import generate_suricata_policy as core
import profiles
import rule_explorer
import run_history
import tune_rules
import tui

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "tuning-policy.yaml"


def write_rules(path: Path, rows: list[str]):
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def load_policy():
    return core.load_policy(POLICY)


def test_duplicate_sid_is_rejected(tmp_path):
    f = tmp_path / "r.rules"
    write_rules(f, [
        'alert tcp any any -> any any (msg:"ET INFO One"; sid:1; rev:1;)',
        'alert tcp any any -> any any (msg:"ET INFO Two"; sid:1; rev:1;)',
    ])
    with pytest.raises(ValueError, match="Duplicate SID"):
        core.load_rules(f)


def test_multiline_rule_parses(tmp_path):
    f = tmp_path / "r.rules"
    f.write_text('alert tcp any any -> any any (msg:"ET INFO X"; \\\n sid:10; rev:2;)\n', encoding="utf-8")
    rules = core.load_rules(f)
    assert rules[10].rev == 2
    assert rules[10].msg == "ET INFO X"


def test_logic_hash_ignores_descriptive_fields():
    a = 'alert tcp any any -> any any (msg:"ET INFO X"; content:"abc"; sid:1; rev:1; metadata: affected_product Nginx; reference:cve,2024-1; classtype:trojan-activity;)'
    b = 'alert tcp any any -> any any (msg:"ET INFO X"; content:"abc"; sid:1; rev:9; metadata: affected_product Other; reference:url,example; classtype:misc-activity;)'
    assert core.rule_logic_sha256(a) == core.rule_logic_sha256(b)


def test_logic_hash_changes_on_detection_logic():
    a = 'alert tcp any any -> any any (msg:"ET INFO X"; content:"abc"; sid:1; rev:1;)'
    b = 'alert tcp any any -> any any (msg:"ET INFO X"; content:"xyz"; sid:1; rev:2;)'
    assert core.rule_logic_sha256(a) != core.rule_logic_sha256(b)


def test_nginx_metadata_match_and_false_positive(tmp_path):
    policy = load_policy()
    f = tmp_path / "r.rules"
    write_rules(f, [
        'alert http any any -> any any (msg:"ET WEB_SPECIFIC_APPS Random Product"; metadata: affected_product Nginx, attack_target Server; sid:100; rev:1;)',
        'alert http any any -> any any (msg:"ET WEB_SPECIFIC_APPS Discourse Nginx Configuration"; sid:101; rev:1;)',
    ])
    rules = core.load_rules(f)
    for r in rules.values():
        r.category = core.map_category(r.msg, policy)
    en1, reason1 = core.web_specific_app_decision(rules[100], policy)
    en2, reason2 = core.web_specific_app_decision(rules[101], policy)
    assert en1 is True and "nginx" in reason1.lower()
    assert en2 is False
    assert rules[101].asset_match_score < 80


def test_semantic_selector_survives_new_sid(tmp_path):
    policy = load_policy()
    f = tmp_path / "r.rules"
    write_rules(f, [
        'alert tcp any any -> any any (msg:"ET INFO Powershell Activity Over SMB - Likely Lateral Movement"; sid:9999999; rev:1;)',
    ])
    rules = core.load_rules(f)
    result = tune_rules.apply_policy(rules, policy)
    assert rules[9999999].final_enabled is True
    assert 9999999 in result["semantic_keep"]


def test_flowbit_dependency_restoration(tmp_path):
    policy = load_policy()
    f = tmp_path / "r.rules"
    write_rules(f, [
        'alert tcp any any -> any any (msg:"ET GAMES Setter"; flowbits:set,foo; flowbits:noalert; sid:1; rev:1;)',
        'alert tcp any any -> any any (msg:"ET MALWARE Consumer"; flowbits:isset,foo; sid:2; rev:1;)',
    ])
    rules = core.load_rules(f)
    result = tune_rules.apply_policy(rules, policy)
    assert rules[2].final_enabled is True
    assert rules[1].final_enabled is True
    assert 1 in result["restored_flow"]


def test_xbit_dependency_restoration(tmp_path):
    policy = load_policy()
    f = tmp_path / "r.rules"
    write_rules(f, [
        'alert tcp any any -> any any (msg:"ET GAMES Setter"; xbits:set,foo,track ip_src,expire 60; sid:11; rev:1;)',
        'alert tcp any any -> any any (msg:"ET MALWARE Consumer"; xbits:isset,foo,track ip_src; sid:12; rev:1;)',
    ])
    rules = core.load_rules(f)
    result = tune_rules.apply_policy(rules, policy)
    assert rules[11].final_enabled is True
    assert 11 in result["restored_xbit"]


def test_profiles_keep_asset_truth_except_explicit_profile_contracts():
    # Balanced explicitly defines SCADA=OFF at the user's request. Server also
    # intentionally disables non-server asset families. Other profiles do not
    # manufacture SCADA/VoIP/ActiveX inventory facts.
    assert profiles.PROFILES["Balanced"]["changes"][("assets", "scada", "enabled")] is False
    assert profiles.PROFILES["Server"]["changes"][("assets", "scada", "enabled")] is False
    assert profiles.PROFILES["Server"]["changes"][("assets", "voip", "enabled")] is False
    assert profiles.PROFILES["Server"]["changes"][("assets", "activex", "enabled")] is False
    for name in ("Noisy", "Strict", "Lab / Experimental"):
        paths = set(profiles.PROFILES[name]["changes"])
        assert ("assets", "scada", "enabled") not in paths
        assert ("assets", "voip", "enabled") not in paths
        assert ("assets", "activex", "enabled") not in paths


def test_rule_explorer_filters(tmp_path):
    policy = load_policy()
    f = tmp_path / "r.rules"
    write_rules(f, [
        'alert tcp any any -> any any (msg:"ET MALWARE Cobalt Strike"; reference:cve,2025-1234; sid:201; rev:1;)',
        'alert tcp any any -> any any (msg:"ET INFO Other"; sid:202; rev:1;)',
    ])
    rules = core.load_rules(f)
    tune_rules.apply_policy(rules, policy)
    assert [r.sid for r in rule_explorer.search_rules(rules, "cobalt state:active")] == [201]
    assert [r.sid for r in rule_explorer.search_rules(rules, "sid:202")] == [202]
    assert [r.sid for r in rule_explorer.search_rules(rules, "cve:2025-1234")] == [201]


def test_history_record_resolve_and_prune(tmp_path):
    out = tmp_path / "suricata-tuned.rules"; out.write_text("rule\n")
    th = tmp_path / "threshold"; th.write_text("threshold\n")
    pol = tmp_path / "policy.yaml"; pol.write_text("x: 1\n")
    hdir = tmp_path / "history"
    r1 = run_history.record_run(hdir, output=out, threshold=th, policy=pol, summary={"final_enabled": 1}, keep=2)
    r2 = run_history.record_run(hdir, output=out, threshold=th, policy=pol, deployed=True, summary={"final_enabled": 2}, keep=2)
    r3 = run_history.record_run(hdir, output=out, threshold=th, policy=pol, summary={"final_enabled": 3}, keep=2)
    rows = run_history.list_runs(hdir)
    assert len(rows) == 2
    assert not r1.exists()
    path, manifest = run_history.resolve_run(hdir, "latest")
    assert path.exists() and manifest["summary"]["final_enabled"] == 3


def test_atomic_write_preserves_complete_file(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("old")
    tune_rules.atomic_write_text(p, "new\ncontent\n")
    assert p.read_text() == "new\ncontent\n"
    assert not list(tmp_path.glob(".x.txt.*.tmp"))


def test_yaml_patch_preserves_comments(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("# top\na:\n  enabled: false # keep me\n")
    tui.patch_yaml_value(p, ("a", "enabled"), True)
    text = p.read_text()
    assert "# top" in text and "# keep me" in text
    assert yaml.safe_load(text)["a"]["enabled"] is True


def test_rollback_restores_historical_rules(monkeypatch, tmp_path):
    output = tmp_path / "suricata-tuned.rules"
    output.write_text("CURRENT\n")
    threshold_output = tmp_path / "suricata-tuned.threshold.config"
    threshold_output.write_text("CURRENT-TH\n")
    policy = tmp_path / "policy.yaml"; policy.write_text("x: 1\n")
    hdir = tmp_path / "history"
    oldrules = tmp_path / "old.rules"; oldrules.write_text("OLD\n")
    oldth = tmp_path / "old.th"; oldth.write_text("OLD-TH\n")
    run = run_history.record_run(hdir, output=oldrules, threshold=oldth, policy=policy, deployed=True, keep=3)
    config = tmp_path / "suricata.yaml"
    config.write_text(f"default-rule-path: {tmp_path}\nrule-files:\n  - suricata.rules\nthreshold-file: {tmp_path/'threshold.config'}\n")
    (tmp_path / "threshold.config").write_text("BASE\n")
    monkeypatch.setattr(tune_rules.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tune_rules, "run_suricata_test", lambda *a, **k: 0)
    monkeypatch.setattr(tune_rules, "reload_suricata", lambda *a, **k: 0)
    rc = tune_rules.rollback_history_run(output, threshold_output, config, hdir, run.name, False)
    assert rc == 0
    assert output.read_text() == "OLD\n"
    assert "OLD-TH" in (tmp_path / "threshold.config").read_text()
    assert "suricata-tuned.rules" in config.read_text()


def test_rollback_failure_restores_current(monkeypatch, tmp_path):
    output = tmp_path / "suricata-tuned.rules"; output.write_text("CURRENT\n")
    threshold_output = tmp_path / "suricata-tuned.threshold.config"; threshold_output.write_text("CURRENT-TH\n")
    policy = tmp_path / "policy.yaml"; policy.write_text("x: 1\n")
    hdir = tmp_path / "history"
    oldrules = tmp_path / "old.rules"; oldrules.write_text("OLD\n")
    oldth = tmp_path / "old.th"; oldth.write_text("OLD-TH\n")
    run = run_history.record_run(hdir, output=oldrules, threshold=oldth, policy=policy, deployed=True, keep=3)
    config = tmp_path / "suricata.yaml"
    original_config = f"default-rule-path: {tmp_path}\nrule-files:\n  - suricata.rules\nthreshold-file: {tmp_path/'threshold.config'}\n"
    config.write_text(original_config)
    target = tmp_path / "threshold.config"; target.write_text("BASE\n")
    monkeypatch.setattr(tune_rules.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tune_rules, "run_suricata_test", lambda *a, **k: 9)
    rc = tune_rules.rollback_history_run(output, threshold_output, config, hdir, run.name, False)
    assert rc == 33
    assert output.read_text() == "CURRENT\n"
    assert threshold_output.read_text() == "CURRENT-TH\n"
    assert config.read_text() == original_config
    assert target.read_text() == "BASE\n"


def test_policy_has_unique_tracked_sids_and_valid_modes():
    p = load_policy()
    valid_modes = {"preserve_feed", "keep", "disable", "asset_based", "conditional"}
    for name, cfg in p["categories"].items():
        assert cfg.get("mode") in valid_modes, name
    for cat, cfg in (p.get("rule_overrides") or {}).items():
        sids = [int(x) for x in cfg.get("tracked_keep_sids", [])]
        assert len(sids) == len(set(sids)), cat


def test_policy_org_prohibited_detection_consistency():
    p = load_policy()
    for name, cfg in (p.get("organization_policy") or {}).items():
        if not isinstance(cfg, dict):
            continue
        if cfg.get("prohibited") is True:
            assert cfg.get("detection_enabled") is True, name

def test_deploy_candidate_staging_success(monkeypatch, tmp_path):
    candidate = tmp_path / ".candidate.rules"; candidate.write_text("NEW-RULES\n")
    candidate_th = tmp_path / ".candidate.th"; candidate_th.write_text("NEW-TH\n")
    final = tmp_path / "suricata-tuned.rules"; final.write_text("OLD-RULES\n")
    final_th = tmp_path / "suricata-tuned.threshold.config"; final_th.write_text("OLD-TH\n")
    config = tmp_path / "suricata.yaml"
    prod_th = tmp_path / "threshold.config"; prod_th.write_text("BASE\n")
    config.write_text(f"default-rule-path: {tmp_path}\nrule-files:\n  - suricata.rules\nthreshold-file: {prod_th}\n")
    monkeypatch.setattr(tune_rules.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tune_rules, "run_suricata_test", lambda *a, **k: 0)
    monkeypatch.setattr(tune_rules, "reload_suricata", lambda *a, **k: 0)
    rc = tune_rules.deploy_production(candidate, candidate_th, config, False, final, final_th)
    assert rc == 0
    assert final.read_text() == "NEW-RULES\n"
    assert final_th.read_text() == "NEW-TH\n"
    assert "NEW-TH" in prod_th.read_text()
    assert "suricata-tuned.rules" in config.read_text()


def test_deploy_candidate_failure_restores_previous_artifacts(monkeypatch, tmp_path):
    candidate = tmp_path / ".candidate.rules"; candidate.write_text("NEW-RULES\n")
    candidate_th = tmp_path / ".candidate.th"; candidate_th.write_text("NEW-TH\n")
    final = tmp_path / "suricata-tuned.rules"; final.write_text("OLD-RULES\n")
    final_th = tmp_path / "suricata-tuned.threshold.config"; final_th.write_text("OLD-TH\n")
    config = tmp_path / "suricata.yaml"
    prod_th = tmp_path / "threshold.config"; prod_th.write_text("BASE\n")
    original_config = f"default-rule-path: {tmp_path}\nrule-files:\n  - suricata.rules\nthreshold-file: {prod_th}\n"
    config.write_text(original_config)
    monkeypatch.setattr(tune_rules.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tune_rules, "run_suricata_test", lambda *a, **k: 7)
    rc = tune_rules.deploy_production(candidate, candidate_th, config, False, final, final_th)
    assert rc == 22
    assert final.read_text() == "OLD-RULES\n"
    assert final_th.read_text() == "OLD-TH\n"
    assert prod_th.read_text() == "BASE\n"
    assert config.read_text() == original_config
