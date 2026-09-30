from pathlib import Path
from copy import deepcopy
import json

import generate_suricata_policy as core
import profiles
import tune_rules

ROOT = Path(__file__).resolve().parents[1]


def _apply(profile_name: str):
    p = core.load_policy(ROOT / "tuning-policy.yaml")
    p = deepcopy(p)
    for path, value in profiles.PROFILES[profile_name]["changes"].items():
        cur = p
        for key in path[:-1]:
            cur = cur.setdefault(key, {})
        cur[path[-1]] = deepcopy(value)
    return p


def test_raw_profile_is_true_feed_passthrough(tmp_path):
    policy = _apply("Raw")
    assert policy["defaults"]["disable_unknown_categories"] is False
    assert policy["defaults"]["preserve_dependencies"] is False
    assert policy["defaults"]["dependency_restore"]["enabled"] is False
    assert policy["alert_tuning"]["enabled"] is False
    assert all(cfg["mode"] == "preserve_feed" for cfg in policy["categories"].values())

    rules_path = tmp_path / "r.rules"
    rules_path.write_text(
        'alert tcp any any -> any any (msg:"ET MALWARE Enabled"; flowbits:isset,need_me; sid:991101; rev:1;)\n'
        '# alert tcp any any -> any any (msg:"ET INFO Disabled"; flowbits:set,need_me; sid:991102; rev:1;)\n',
        encoding="utf-8",
    )
    rules = core.load_rules(rules_path)
    tune_rules.apply_policy(rules, policy)
    assert rules[991101].final_enabled is True
    assert rules[991102].final_enabled is False
    assert not rules[991102].restored_dependency_types


def test_single_diff_file_contains_details(tmp_path):
    p = tmp_path / "suricata-tuned.diff.txt"
    diff = {
        "baseline": False,
        "new_sids": [1, 2], "removed_sids": [3], "rev_changed": [4],
        "newly_enabled": [5], "newly_disabled": [6],
    }
    returned = tune_rules.write_diff_reports(p, diff)
    assert returned == p
    assert p.exists()
    assert not p.with_suffix(p.suffix + ".json").exists()
    text = p.read_text()
    assert "New SIDs" in text and "1, 2" in text
    assert "Newly disabled" in text and "6" in text


def test_replace_reload_failure_leaves_validated_overwrite(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    original = tmp_path / "suricata.rules"; original.write_text("RAW\n")
    candidate = tmp_path / "candidate.rules"; candidate.write_text("TUNED\n")
    candidate_th = tmp_path / "candidate.threshold"; candidate_th.write_text(
        "# BEGIN SURICATA FRIENDLY TUNER MANAGED\n# END SURICATA FRIENDLY TUNER MANAGED\n"
    )
    tuned = tmp_path / "suricata-tuned.rules"; tuned.write_text("OLD\n")
    internal_th = tmp_path / "internal.threshold"; internal_th.write_text("OLDTH\n")
    prod_th = tmp_path / "threshold.config"; prod_th.write_text("BASE\n")
    conf = tmp_path / "suricata.yaml"; conf.write_text(
        f"default-rule-path: {tmp_path}\nrule-files:\n  - suricata-tuned.rules\nthreshold-file: {prod_th}\n"
    )
    monkeypatch.setattr(tune_rules.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tune_rules, "run_suricata_test", lambda *a, **k: 0)
    monkeypatch.setattr(tune_rules, "reload_suricata", lambda *a, **k: 8)
    rc = tune_rules.replace_original_production(candidate, candidate_th, original, tuned, internal_th, conf, False)
    assert rc == 28
    assert original.read_text() == "TUNED\n"
    assert tuned.read_text() == "TUNED\n"
    assert "- suricata.rules" in conf.read_text()


def test_internal_state_defaults_do_not_clutter_rule_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    state_dir = tune_rules.default_state_dir()
    output = tmp_path / "rules" / "suricata-tuned.rules"
    assert state_dir != output.parent
    assert (state_dir / "last-report.json").parent == state_dir


def test_pcre_inner_double_quote_does_not_hide_sid_and_metadata():
    raw = (
        'alert http $EXTERNAL_NET any -> $HOME_NET any '
        '(msg:"ET PHISHING Common Unhidebody Function Observed in Phishing Landing"; '
        'flow:established,to_client; content:"method="; nocase; '
        'pcre:"/^[\"\']?post/Ri"; classtype:social-engineering; sid:2029732; rev:2; '
        'metadata:affected_product Web_Browsers, tag Phishing;)'
    )
    assert core.option_values(raw, "sid") == ["2029732"]
    assert core.option_values(raw, "rev") == ["2"]
    assert core.parse_metadata(raw)["affected_product"] == ["Web_Browsers"]
