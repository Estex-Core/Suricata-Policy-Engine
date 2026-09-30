from __future__ import annotations

import json
from pathlib import Path

import generate_suricata_policy as core
import telemetry
import tune_rules

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "tuning-policy.yaml"


def write_rules(path: Path, rows: list[str]):
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def policy():
    return core.load_policy(POLICY)


def test_flowbits_or_expression_restores_known_alternative_producers(tmp_path):
    p = policy()
    f = tmp_path / "rules"
    write_rules(f, [
        'alert tcp any any -> any any (msg:"ET GAMES A"; flowbits:set,user1; flowbits:noalert; sid:1; rev:1;)',
        'alert tcp any any -> any any (msg:"ET GAMES B"; flowbits:set,user2; flowbits:noalert; sid:2; rev:1;)',
        'alert tcp any any -> any any (msg:"ET MALWARE Consumer"; flowbits:isset,user1|user2; sid:3; rev:1;)',
    ])
    rules = core.load_rules(f)
    result = tune_rules.apply_policy(rules, p)
    assert rules[3].flow_get_groups == [frozenset({"user1", "user2"})]
    assert result["missing_flow"] == set()
    assert result["restored_flow"] == {1, 2}


def test_flowbits_or_is_satisfied_when_one_alternative_has_a_producer(tmp_path):
    p = policy()
    f = tmp_path / "rules"
    write_rules(f, [
        'alert tcp any any -> any any (msg:"ET GAMES B"; flowbits:set,user2; flowbits:noalert; sid:2; rev:1;)',
        'alert tcp any any -> any any (msg:"ET MALWARE Consumer"; flowbits:isset,user1|user2; sid:3; rev:1;)',
    ])
    rules = core.load_rules(f)
    result = tune_rules.apply_policy(rules, p)
    assert result["missing_flow"] == set()
    assert result["restored_flow"] == {2}


def test_xbits_host_scope_allows_src_dst_direction_flip(tmp_path):
    p = policy()
    f = tmp_path / "rules"
    write_rules(f, [
        'alert tcp any any -> any any (msg:"ET GAMES Setter"; xbits:set,seen,track ip_dst,expire 60; sid:11; rev:1;)',
        'alert tcp any any -> any any (msg:"ET MALWARE Consumer"; xbits:isset,seen,track ip_src; sid:12; rev:1;)',
    ])
    rules = core.load_rules(f)
    result = tune_rules.apply_policy(rules, p)
    assert result["restored_xbit"] == {11}
    assert result["missing_xbit"] == set()


def test_xbits_incompatible_storage_scope_is_not_restored(tmp_path):
    p = policy()
    f = tmp_path / "rules"
    write_rules(f, [
        'alert tcp any any -> any any (msg:"ET GAMES Pair Setter"; xbits:set,seen,track ip_pair,expire 60; sid:21; rev:1;)',
        'alert tcp any any -> any any (msg:"ET MALWARE Host Consumer"; xbits:isset,seen,track ip_src; sid:22; rev:1;)',
    ])
    rules = core.load_rules(f)
    result = tune_rules.apply_policy(rules, p)
    assert 21 not in result["restored_xbit"]
    assert result["missing_xbit"] == {"seen[host]"}


def test_validation_enforces_dependency_flags_and_ja3_prerequisite(tmp_path, monkeypatch):
    p = policy()
    monkeypatch.setattr(tune_rules.shutil, "which", lambda _: None)
    f = tmp_path / "rules"
    write_rules(f, [
        'alert tls any any -> any any (msg:"ET JA3 Example"; ja3.hash; content:"0123456789abcdef0123456789abcdef"; sid:31; rev:1;)',
    ])
    rules = core.load_rules(f)
    result = tune_rules.apply_policy(rules, p)
    good = tmp_path / "good.yaml"
    good.write_text("app-layer:\n  protocols:\n    tls:\n      ja3-fingerprints: yes\n", encoding="utf-8")
    bad = tmp_path / "bad.yaml"
    bad.write_text("app-layer:\n  protocols:\n    tls:\n      ja3-fingerprints: no\n", encoding="utf-8")

    assert tune_rules.policy_validation_preflight(rules, result, p, good)["ok"] is True
    check = tune_rules.policy_validation_preflight(rules, result, p, bad)
    assert check["ok"] is False
    assert any("JA3" in x for x in check["failures"])

    p2 = dict(p)
    p2["validation"] = dict(p["validation"], check_flowbit_dependencies=False)
    synthetic = dict(result, missing_flow={"missing"})
    check2 = tune_rules.policy_validation_preflight(rules, synthetic, p2, good)
    assert not any("flowbit" in x.lower() for x in check2["failures"])


def test_sid_threshold_override_has_precedence(tmp_path):
    p = policy()
    p = dict(p)
    p["alert_tuning"] = {
        "enabled": True,
        "profiles": {},
        "sid_overrides": {
            41: {"type": "limit", "track": "by_dst", "count": 2, "seconds": 120}
        },
        "suppressions": [],
    }
    f = tmp_path / "rules"
    write_rules(f, [
        'alert tcp any any -> any any (msg:"ET MALWARE Explicit tuning"; sid:41; rev:1;)',
    ])
    rules = core.load_rules(f)
    tune_rules.apply_policy(rules, p)
    out = tmp_path / "threshold.config"
    result = tune_rules.write_threshold_config(out, rules, p)
    text = out.read_text(encoding="utf-8")
    assert "sig_id 41" in text
    assert "track by_dst, count 2, seconds 120" in text
    assert result["sid_override_entries"] == 1


def test_eve_telemetry_is_recommendation_only(tmp_path):
    p = policy()
    p = dict(p)
    p["telemetry"] = {
        "enabled": True,
        "recommendations": {
            "min_alerts": 2,
            "noisy_rate_per_hour": 1,
            "top_n": 10,
            "concentrated_max_unique_sources": 3,
        },
    }
    f = tmp_path / "rules"
    write_rules(f, ['alert tcp any any -> any any (msg:"ET MALWARE Noisy"; sid:51; rev:1;)'])
    rules = core.load_rules(f)
    tune_rules.apply_policy(rules, p)

    eve = tmp_path / "eve.json"
    rows = []
    for i in range(3):
        rows.append({
            "timestamp": f"2026-09-24T10:0{i}:00+00:00",
            "event_type": "alert",
            "src_ip": "10.0.0.5",
            "dest_ip": "192.0.2.10",
            "alert": {"signature_id": 51, "signature": "ET MALWARE Noisy", "action": "allowed"},
        })
    eve.write_text("\n".join(json.dumps(x) for x in rows) + "\n", encoding="utf-8")
    report = telemetry.analyze_eve([eve], rules, p)
    assert report["mode"] == "recommendation-only"
    assert report["alert_events"] == 3
    assert report["recommendations"][0]["sid"] == 51
    assert "not evidence of a false positive" in report["recommendations"][0]["safety_note"]


def _fake_suricata(path: Path, exit_code: int):
    path.write_text(f"#!/bin/sh\nexit {exit_code}\n", encoding="utf-8")
    path.chmod(0o755)


def _minimal_config(path: Path):
    path.write_text(
        "default-rule-path: /tmp\n"
        "rule-files:\n"
        "  - suricata.rules\n"
        "app-layer:\n"
        "  protocols:\n"
        "    tls:\n"
        "      ja3-fingerprints: yes\n",
        encoding="utf-8",
    )


def test_policy_required_suricata_test_stages_then_promotes(monkeypatch, tmp_path):
    p = policy()
    rules_path = tmp_path / "suricata.rules"
    write_rules(rules_path, [
        'alert tcp any any -> any any (msg:"ET MALWARE Test"; sid:61; rev:1;)',
    ])
    output = tmp_path / "suricata-tuned.rules"
    output.write_text("OLD\n", encoding="utf-8")
    conf = tmp_path / "suricata.yaml"
    _minimal_config(conf)
    bindir = tmp_path / "bin"; bindir.mkdir()
    _fake_suricata(bindir / "suricata", 0)
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setattr(tune_rules, "parse_args", lambda: type("Args", (), {
        "rules": rules_path, "policy": POLICY, "output": output, "report": None,
        "threshold_output": None, "state_file": None, "diff_output": None,
        "test": False, "deploy": False, "no_reload": False, "suricata_conf": conf,
        "dry_run": False, "tracked_baseline": ROOT / "src" / "suricata_policy_engine_data" / "tracked-rules-baseline.json",
        "accept_tracked_baseline": False, "preview": False, "no_state_update": True,
        "insights_output": None, "eve": [], "telemetry_output": None,
        "history_dir": None, "history_limit": 5, "history_list": False,
        "rollback": None, "no_lock": True,
    })())
    rc = tune_rules.main()
    assert rc == 0
    assert "sid:61" in output.read_text(encoding="utf-8").replace(" ", "")
    assert not list(tmp_path.glob(".*.candidate.*"))


def test_policy_required_suricata_test_failure_does_not_replace_output(monkeypatch, tmp_path):
    rules_path = tmp_path / "suricata.rules"
    write_rules(rules_path, [
        'alert tcp any any -> any any (msg:"ET MALWARE Test"; sid:62; rev:1;)',
    ])
    output = tmp_path / "suricata-tuned.rules"
    output.write_text("OLD\n", encoding="utf-8")
    conf = tmp_path / "suricata.yaml"
    _minimal_config(conf)
    bindir = tmp_path / "bin"; bindir.mkdir()
    _fake_suricata(bindir / "suricata", 7)
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setattr(tune_rules, "parse_args", lambda: type("Args", (), {
        "rules": rules_path, "policy": POLICY, "output": output, "report": None,
        "threshold_output": None, "state_file": None, "diff_output": None,
        "test": False, "deploy": False, "no_reload": False, "suricata_conf": conf,
        "dry_run": False, "tracked_baseline": ROOT / "src" / "suricata_policy_engine_data" / "tracked-rules-baseline.json",
        "accept_tracked_baseline": False, "preview": False, "no_state_update": True,
        "insights_output": None, "eve": [], "telemetry_output": None,
        "history_dir": None, "history_limit": 5, "history_list": False,
        "rollback": None, "no_lock": True,
    })())
    rc = tune_rules.main()
    assert rc == 7
    assert output.read_text(encoding="utf-8") == "OLD\n"
    assert not list(tmp_path.glob(".*.candidate.*"))
