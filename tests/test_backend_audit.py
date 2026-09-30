from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

import generate_suricata_policy as core

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "tuning-policy.yaml"


def test_policy_regex_validation_reports_location(tmp_path):
    data = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    data["rule_overrides"]["ET_INFO"]["semantic_keep"][0]["msg_regex"] = ["("]
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match=r"rule_overrides\.ET_INFO\.semantic_keep\[0\]\.msg_regex\[0\]"):
        core.load_policy(path)


def test_flowbits_setx_is_not_treated_as_suricata_setter():
    setters, getters, groups = core.parse_flowbit_options(
        'alert tcp any any -> any any (flowbits:setx,legacy; flowbits:isset,needed; sid:1;)'
    )
    assert "legacy" not in setters
    assert getters == {"needed"}
    assert groups == [frozenset({"needed"})]


def test_generator_disable_conf_follows_resolved_state_for_message_filter(tmp_path, monkeypatch):
    policy = {
        "categories": {
            "SURICATA": {
                "mode": "conditional",
                "strategy": "message_filter",
                "message_filter": {"disable_contains": ["TRAFFIC-ID:"]},
            }
        },
        "defaults": {"preserve_dependencies": False},
        "assets": {"web_specific_apps": {}},
        "rule_overrides": {},
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
    rules_path = tmp_path / "rules"
    rules_path.write_text(
        'alert ip any any -> any any (msg:"SURICATA TRAFFIC-ID: Example"; sid:10; rev:1;)\n',
        encoding="utf-8",
    )
    out = tmp_path / "generated"
    monkeypatch.setattr(sys, "argv", [
        "generate_suricata_policy.py", "--policy", str(policy_path),
        "--rules", str(rules_path), "--out-dir", str(out),
    ])
    assert core.main() == 0
    lines = [x.strip() for x in (out / "disable.conf").read_text().splitlines() if x.strip() and not x.startswith("#")]
    assert lines == ["10"]


def test_rule_parser_ignores_keyword_lookalikes_inside_quoted_text(tmp_path):
    rules_path = tmp_path / "quoted.rules"
    rules_path.write_text(
        'alert tcp any any -> any any (msg:"mentions sid:999; flowbits:set,fake; metadata affected_product Fake;"; '
        'content:"gid:77; threshold:type limit;"; flowbits:set,real; metadata:affected_product Nginx; sid:123; rev:4;)\n',
        encoding="utf-8",
    )
    rules = core.load_rules(rules_path)
    assert list(rules) == [123]
    rule = rules[123]
    assert rule.rev == 4
    assert rule.flow_set == {"real"}
    assert rule.metadata["affected_product"] == ["Nginx"]


def test_rule_option_parser_preserves_semicolons_inside_quotes():
    raw = 'alert tcp any any -> any any (msg:"semi; colon and \\"quote\\""; content:"a;b"; sid:42; rev:1;)'
    options = core.split_rule_options(raw)
    assert ("sid", "42") in options
    assert core.option_values(raw, "content") == ['"a;b"']


def test_logic_hash_ignores_message_only_drift():
    a = 'alert tcp any any -> any any (msg:"Old wording"; content:"abc"; sid:5; rev:1; metadata:foo bar;)'
    b = 'alert tcp any any -> any any (msg:"New wording"; content:"abc"; sid:5; rev:9; metadata:foo baz;)'
    assert core.rule_logic_sha256(a) == core.rule_logic_sha256(b)
    assert core.rule_raw_sha256(a) != core.rule_raw_sha256(b)


def test_logic_hash_changes_when_detection_semantics_change():
    a = 'alert tcp any any -> any any (msg:"Same"; content:"abc"; sid:5; rev:1;)'
    b = 'alert tcp any any -> any any (msg:"Same"; content:"xyz"; sid:5; rev:2;)'
    assert core.rule_logic_sha256(a) != core.rule_logic_sha256(b)


def test_toggle_is_not_auto_restored_as_guaranteed_flowbit_setter(tmp_path):
    rules_path = tmp_path / "toggle.rules"
    rules_path.write_text(
        '\n'.join([
            'alert tcp any any -> any any (msg:"ET GAMES toggle"; flowbits:toggle,flag; sid:1; rev:1;)',
            'alert tcp any any -> any any (msg:"ET MALWARE consumer"; flowbits:isset,flag; sid:2; rev:1;)',
        ]) + '\n', encoding='utf-8')
    policy = core.load_policy(POLICY)
    rules = core.load_rules(rules_path)
    import tune_rules
    result = tune_rules.apply_policy(rules, policy)
    assert 1 not in result['restored_flow']
    assert result['ambiguous_flow'] == {'flag'}


def test_xbit_toggle_is_reported_ambiguous_not_setter(tmp_path):
    rules_path = tmp_path / "xtoggle.rules"
    rules_path.write_text(
        '\n'.join([
            'alert tcp any any -> any any (msg:"ET GAMES toggle"; xbits:toggle,seen,track ip_src; sid:1; rev:1;)',
            'alert tcp any any -> any any (msg:"ET MALWARE consumer"; xbits:isset,seen,track ip_dst; sid:2; rev:1;)',
        ]) + '\n', encoding='utf-8')
    policy = core.load_policy(POLICY)
    rules = core.load_rules(rules_path)
    import tune_rules
    result = tune_rules.apply_policy(rules, policy)
    assert 1 not in result['restored_xbit']
    assert result['ambiguous_xbit'] == {'seen[host]'}


def test_dependency_graph_exposes_transitive_edges_and_cycle(tmp_path):
    rules_path = tmp_path / "graph.rules"
    rules_path.write_text("\n".join([
        'alert tcp any any -> any any (msg:"ET GAMES A"; flowbits:set,a; flowbits:isset,b; sid:1; rev:1;)',
        'alert tcp any any -> any any (msg:"ET GAMES B"; flowbits:set,b; flowbits:isset,a; sid:2; rev:1;)',
        'alert tcp any any -> any any (msg:"ET MALWARE Seed"; flowbits:isset,a; sid:3; rev:1;)',
    ]) + "\n", encoding="utf-8")
    policy = core.load_policy(POLICY)
    rules = core.load_rules(rules_path)
    import tune_rules
    result = tune_rules.apply_policy(rules, policy)
    graph = result["dependency_graph"]
    assert {1, 2}.issubset(result["restored_flow"])
    assert [1, 2] in graph["cycles"]
    assert any(e["consumer_sid"] == 3 and e["producer_sid"] == 1 for e in graph["restoration_edges"])


def test_asset_matching_identifies_disabled_asset_instead_of_hiding_it(tmp_path):
    policy = core.load_policy(POLICY)
    rules_path = tmp_path / "asset.rules"
    rules_path.write_text(
        'alert http any any -> any any (msg:"ET WEB_SPECIFIC_APPS WordPress RCE"; metadata:affected_product WordPress; sid:80; rev:1;)\n',
        encoding="utf-8",
    )
    rule = core.load_rules(rules_path)[80]
    rule.category = core.map_category(rule.msg, policy)
    enabled, reason = core.web_specific_app_decision(rule, policy)
    assert enabled is False
    assert rule.asset_match_asset == "wordpress"
    assert rule.asset_match_status == "matched_disabled"
    assert "disabled" in reason


def test_asset_matching_tied_top_candidates_require_review(tmp_path):
    policy = {
        "assets": {"web_specific_apps": {
            "a": {"enabled": True, "aliases": ["Same"], "metadata": {}, "msg_regex": [], "match_threshold": 80, "review_threshold": 50},
            "b": {"enabled": True, "aliases": ["Same"], "metadata": {}, "msg_regex": [], "match_threshold": 80, "review_threshold": 50},
        }}
    }
    raw = 'alert http any any -> any any (msg:"ET WEB_SPECIFIC_APPS Same Product"; sid:81; rev:1;)'
    rule = core.Rule(sid=81, rev=1, msg="ET WEB_SPECIFIC_APPS Same Product", raw=raw, source_enabled=True)
    enabled, reason = core.web_specific_app_decision(rule, policy)
    assert enabled is False
    assert rule.asset_review_candidate is True
    assert rule.asset_match_status == "ambiguous"
    assert reason.startswith("asset_review:ambiguous")
