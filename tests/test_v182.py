from __future__ import annotations

from pathlib import Path

import generate_suricata_policy as core
import tune_rules

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "tuning-policy.yaml"


def write_rules(path: Path, rows: list[str]):
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def policy():
    return core.load_policy(POLICY)


def _ja3_rules(tmp_path: Path):
    f = tmp_path / "rules"
    write_rules(f, [
        'alert tls any any -> any any (msg:"ET JA3 Example"; ja3.hash; content:"0123456789abcdef0123456789abcdef"; sid:181; rev:1;)',
    ])
    rules = core.load_rules(f)
    p = policy()
    result = tune_rules.apply_policy(rules, p)
    return p, rules, result


def test_ja3_unset_is_auto_and_allowed(monkeypatch, tmp_path):
    monkeypatch.setattr(tune_rules.shutil, "which", lambda _: None)
    p, rules, result = _ja3_rules(tmp_path)
    conf = tmp_path / "suricata.yaml"
    conf.write_text("app-layer:\n  protocols:\n    tls: {}\n", encoding="utf-8")

    check = tune_rules.policy_validation_preflight(rules, result, p, conf)
    ja3 = next(x for x in check["checks"] if x["name"] == "ja3_fingerprinting")
    assert check["ok"] is True
    assert ja3["state"] == "auto"
    assert ja3["ok"] is True


def test_ja3_explicit_no_still_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(tune_rules.shutil, "which", lambda _: None)
    p, rules, result = _ja3_rules(tmp_path)
    conf = tmp_path / "suricata.yaml"
    conf.write_text("app-layer:\n  protocols:\n    tls:\n      ja3-fingerprints: no\n", encoding="utf-8")

    check = tune_rules.policy_validation_preflight(rules, result, p, conf)
    ja3 = next(x for x in check["checks"] if x["name"] == "ja3_fingerprinting")
    assert check["ok"] is False
    assert ja3["state"] == "disabled"


def test_ja3_strict_mode_requires_explicit_yes(monkeypatch, tmp_path):
    monkeypatch.setattr(tune_rules.shutil, "which", lambda _: None)
    p, rules, result = _ja3_rules(tmp_path)
    p = dict(p)
    p["validation"] = dict(p["validation"], require_explicit_ja3_fingerprinting=True)

    unset = tmp_path / "unset.yaml"
    unset.write_text("app-layer:\n  protocols:\n    tls: {}\n", encoding="utf-8")
    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("app-layer:\n  protocols:\n    tls:\n      ja3-fingerprints: yes\n", encoding="utf-8")

    failed = tune_rules.policy_validation_preflight(rules, result, p, unset)
    assert failed["ok"] is False
    assert any("explicit" in x.lower() for x in failed["failures"])
    assert tune_rules.policy_validation_preflight(rules, result, p, explicit)["ok"] is True


def test_sid_override_inherits_category_profile(tmp_path):
    p = policy()
    p = dict(p)
    p["alert_tuning"] = dict(p["alert_tuning"])
    p["alert_tuning"]["sid_overrides"] = {182: {"count": 2}}

    f = tmp_path / "rules"
    write_rules(f, [
        'alert tcp any any -> any any (msg:"ET HUNTING Partial SID override"; sid:182; rev:1;)',
    ])
    rules = core.load_rules(f)
    tune_rules.apply_policy(rules, p)
    out = tmp_path / "threshold.config"
    result = tune_rules.write_threshold_config(out, rules, p)
    text = out.read_text(encoding="utf-8")

    # ET_HUNTING category profile: limit/by_src/5/300. Only count is overridden.
    assert "sig_id 182" in text
    assert "type limit, track by_src, count 2, seconds 300" in text
    assert result["sid_override_entries"] == 1


def test_duplicate_sid_validation_is_not_configurable():
    p = policy()
    assert "check_duplicate_sid" not in p.get("validation", {})
    settings = tune_rules.validation_settings(p)
    assert "check_duplicate_sid" not in settings


def test_replace_original_mode_is_atomic_and_points_config_back_to_original(monkeypatch, tmp_path):
    import tune_rules
    original = tmp_path / "suricata.rules"
    original.write_text("RAW-FEED\n")
    candidate = tmp_path / ".candidate.rules"
    candidate.write_text("TUNED\n")
    candidate_th = tmp_path / ".candidate.threshold"
    candidate_th.write_text("# BEGIN SURICATA FRIENDLY TUNER MANAGED\n# generated\n# END SURICATA FRIENDLY TUNER MANAGED\n")
    tuned = tmp_path / "suricata-tuned.rules"
    tuned.write_text("OLD-TUNED\n")
    tuned_th = tmp_path / "suricata-tuned.threshold.config"
    tuned_th.write_text("OLD-TH\n")
    prod_th = tmp_path / "threshold.config"
    prod_th.write_text("BASE\n")
    config = tmp_path / "suricata.yaml"
    config.write_text(
        f"default-rule-path: {tmp_path}\n"
        "rule-files:\n  - suricata-tuned.rules\n"
        f"threshold-file: {prod_th}\n"
    )
    monkeypatch.setattr(tune_rules.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tune_rules, "run_suricata_test", lambda *a, **k: 0)
    monkeypatch.setattr(tune_rules, "reload_suricata", lambda *a, **k: 0)
    rc = tune_rules.replace_original_production(
        candidate, candidate_th, original, tuned, tuned_th, config, False
    )
    assert rc == 0
    assert original.read_text() == "TUNED\n"
    assert not tuned.exists()
    assert "- suricata.rules" in config.read_text()
    backups = list((tune_rules.default_state_dir() / "backups").glob("*/original-suricata.rules"))
    assert backups and any(x.read_text() == "RAW-FEED\n" for x in backups)


def test_replace_original_rolls_back_on_production_validation_failure(monkeypatch, tmp_path):
    import tune_rules
    original = tmp_path / "suricata.rules"
    original.write_text("RAW-FEED\n")
    candidate = tmp_path / ".candidate.rules"
    candidate.write_text("TUNED\n")
    candidate_th = tmp_path / ".candidate.threshold"
    candidate_th.write_text("# BEGIN SURICATA FRIENDLY TUNER MANAGED\n# generated\n# END SURICATA FRIENDLY TUNER MANAGED\n")
    tuned = tmp_path / "suricata-tuned.rules"
    tuned.write_text("OLD-TUNED\n")
    tuned_th = tmp_path / "suricata-tuned.threshold.config"
    tuned_th.write_text("OLD-TH\n")
    prod_th = tmp_path / "threshold.config"
    prod_th.write_text("BASE\n")
    config = tmp_path / "suricata.yaml"
    original_config = (
        f"default-rule-path: {tmp_path}\n"
        "rule-files:\n  - suricata-tuned.rules\n"
        f"threshold-file: {prod_th}\n"
    )
    config.write_text(original_config)
    monkeypatch.setattr(tune_rules.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tune_rules, "run_suricata_test", lambda *a, **k: 1)
    monkeypatch.setattr(tune_rules, "reload_suricata", lambda *a, **k: 0)
    rc = tune_rules.replace_original_production(
        candidate, candidate_th, original, tuned, tuned_th, config, False
    )
    assert rc == 27
    assert original.read_text() == "RAW-FEED\n"
    assert tuned.read_text() == "OLD-TUNED\n"
    assert tuned_th.read_text() == "OLD-TH\n"
    assert config.read_text() == original_config
