from pathlib import Path
import policy_insights as insights
import generate_suricata_policy as core
import tune_rules

ROOT = Path(__file__).resolve().parents[1]


def test_health_bundle_on_small_ruleset(tmp_path):
    rules_file = tmp_path / "rules"
    rules_file.write_text('alert tcp any any -> any any (msg:"ET MALWARE Demo"; sid:1; rev:1;)\n')
    policy = core.load_policy(ROOT / "tuning-policy.yaml")
    rules = core.load_rules(rules_file)
    result = tune_rules.apply_policy(rules, policy)
    audit = {"missing": [], "logic_changed": [], "category_changed": [], "rev_changed": [], "feed_disabled": [], "ok": [], "tracked": 0}
    cur = tune_rules.current_state(rules, "a", "b")
    diff = tune_rules.compute_diff(None, cur)
    bundle = insights.insights_bundle(rules, policy, result, audit, diff, None)
    assert 0 <= bundle["policy_health"]["score"] <= 100
    assert bundle["update_impact"]["baseline"] is True
    assert bundle["recommendations"]
