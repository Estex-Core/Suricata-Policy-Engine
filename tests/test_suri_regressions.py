"""Regression tests for the Suricata Policy Engine production hotfix.

Run from repository root after applying fix: python3 -m pytest -q
No Suricata binary or production filesystem is accessed by these unit tests.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import generate_suricata_policy as core
import tune_rules as tuner


def _config(tmp_path, names):
    d = tmp_path / "rules"
    d.mkdir(exist_ok=True)
    cfg = tmp_path / "suricata.yaml"
    cfg.write_text("default-rule-path: " + str(d) + "\nrule-files:\n" +
                   "".join("  - " + x + "\n" for x in names) + "outputs:\n  - eve-log:\n      enabled: yes\n")
    return cfg, d / "suricata-tuned.rules"


@pytest.mark.parametrize("names", [
    ["suricata.rules", "suricata-tuned.rules"],
    ["suricata.rules", "suricata.rules"],
    ["suricata-tuned.rules", "suricata-tuned.rules"],
    ["suricata.rules", "suricata-tuned.rules", "suricata.rules"],
])
def test_collapses_duplicate_managed_rules(tmp_path, names):
    cfg, output = _config(tmp_path, names)
    tuner.patch_rule_files(cfg, output)
    entries = tuner.configured_rule_files(cfg)
    assert entries.count("suricata-tuned.rules") == 1
    assert "suricata.rules" not in entries
    assert tuner.config_uses_rule_file(cfg, output)
    assert "outputs:" in cfg.read_text()


def test_preserves_unrelated_rule_files(tmp_path):
    cfg, output = _config(tmp_path, ["local.rules", "suricata.rules", "suricata-tuned.rules", "custom.rules"])
    tuner.patch_rule_files(cfg, output)
    assert tuner.configured_rule_files(cfg) == ["local.rules", "suricata-tuned.rules", "custom.rules"]


def test_patch_is_idempotent(tmp_path):
    cfg, output = _config(tmp_path, ["suricata.rules", "suricata-tuned.rules"])
    assert tuner.patch_rule_files(cfg, output)[1] is True
    before = cfg.read_bytes()
    assert tuner.patch_rule_files(cfg, output)[1] is False
    assert cfg.read_bytes() == before


def test_rejects_complex_config_without_modification(tmp_path):
    cfg, output = _config(tmp_path, ["suricata.rules"])
    cfg.write_text(cfg.read_text().replace("  - suricata.rules", "  - {path: suricata.rules}"))
    before = cfg.read_bytes()
    with pytest.raises(RuntimeError, match="Unsupported"):
        tuner.patch_rule_files(cfg, output)
    assert cfg.read_bytes() == before


def test_rejects_missing_managed_target(tmp_path):
    cfg, output = _config(tmp_path, ["local.rules"])
    with pytest.raises(RuntimeError, match="No managed"):
        tuner.patch_rule_files(cfg, output)


def test_config_uses_exactly_one_reference(tmp_path):
    cfg, output = _config(tmp_path, ["suricata-tuned.rules", "suricata-tuned.rules"])
    assert not tuner.config_uses_rule_file(cfg, output)
    cfg, output = _config(tmp_path, ["suricata-tuned.rules", "suricata.rules"])
    assert not tuner.config_uses_rule_file(cfg, output)


def test_original_replace_mode_collapses_tuned(tmp_path):
    cfg, tuned = _config(tmp_path, ["suricata-tuned.rules", "suricata.rules"])
    original = tuned.with_name("suricata.rules")
    tuner.patch_rule_files(cfg, original, replace_names={"suricata.rules", tuned.name})
    assert tuner.configured_rule_files(cfg) == ["suricata.rules"]
    assert tuner.config_uses_rule_file(cfg, original)


def _rule(sid, *, source_enabled=False, initial_enabled=False, setters=(), getters=()):
    rule = core.Rule(
        sid=sid, rev=1, msg="ET MALWARE example", raw=f"alert tcp any any -> any any (sid:{sid};)",
        source_enabled=source_enabled,
        flow_set=set(setters),
        flow_get=set(getters),
        flow_get_groups=[frozenset({x}) for x in getters],
    )
    rule.initial_enabled = initial_enabled
    return rule


def test_dependency_restoration_all_preserves_coverage():
    rules = {1:_rule(1, source_enabled=True, initial_enabled=True, getters=["testbit"]),
             2:_rule(2, source_enabled=True, setters=["testbit"]),
             3:_rule(3, source_enabled=True, setters=["testbit"])}
    policy = {"defaults": {"preserve_dependencies": True, "dependency_restore": {"enabled": True}}}
    restored, *_ = core.resolve_dependencies(rules, policy)
    assert restored == {2, 3}
    assert all(r.final_enabled for r in rules.values())


def test_optional_minimal_dependency_restoration():
    rules = {1:_rule(1, source_enabled=True, initial_enabled=True, getters=["testbit"]),
             2:_rule(2, source_enabled=True, setters=["testbit"]),
             3:_rule(3, source_enabled=False, setters=["testbit"])}
    policy = {"defaults": {"preserve_dependencies": True, "dependency_restore": {"enabled": True, "producer_selection": "minimal"}}}
    restored, *_ = core.resolve_dependencies(rules, policy)
    assert restored == {2}
    assert rules[2].final_enabled and not rules[3].final_enabled


def test_minimal_does_not_restore_if_producer_already_enabled():
    rules = {1:_rule(1, source_enabled=True, initial_enabled=True, getters=["testbit"]),
             2:_rule(2, source_enabled=True, initial_enabled=True, setters=["testbit"]),
             3:_rule(3, source_enabled=True, setters=["testbit"])}
    policy = {"defaults": {"dependency_restore": {"producer_selection": "minimal"}}}
    restored, *_ = core.resolve_dependencies(rules, policy)
    assert restored == set()
    assert rules[3].final_enabled is False


def test_dependency_invalid_mode_rejected():
    with pytest.raises(ValueError, match="producer_selection"):
        core.validate_policy({"categories": {}, "defaults": {"dependency_restore": {"producer_selection": "random"}}})


def test_category_metadata_fallback_is_exact():
    policy = {"categories": {"ET_MALWARE": {}, "ET_TOR": {}}}
    assert core.map_category("weird newer msg format", policy, {"rule_category": ["et_malware"]}) == "ET_MALWARE"
    assert core.map_category("weird newer msg format", policy, {"attack_target": ["Server"]}) is None
    assert core.map_category("ET TOR entry", policy) == "ET_TOR"


def test_staged_reload_not_mislabeled_live(monkeypatch):
    monkeypatch.setattr(tuner.shutil, "which", lambda name: None)
    monkeypatch.setattr(tuner, "_running_suricata_cmdlines", lambda: [])
    assert tuner.reload_suricata() == 0
    assert tuner.reload_suricata.last_outcome == "staged"


def test_source_feed_duplicate_sids_detected(tmp_path):
    rules = tmp_path / "suricata.rules"
    rules.write_text(
        'alert tcp any any -> any any (msg:"a"; sid:7000001; rev:1;)\n'
        'alert tcp any any -> any any (msg:"b"; sid:7000001; rev:2;)\n'
    )
    with pytest.raises(ValueError, match="Duplicate SID"):
        core.load_rules(rules)


def test_config_refuses_wildcard_rule_sources(tmp_path):
    cfg, output = _config(tmp_path, ["suricata-tuned.rules", "*.rules"])
    assert not tuner.config_uses_rule_file(cfg, output)
