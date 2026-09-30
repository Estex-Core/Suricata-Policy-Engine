from pathlib import Path
import generate_suricata_policy as core
import tune_rules
import feed_audit

ROOT = Path(__file__).resolve().parents[1]


def test_feed_audit_reports_unknown_asset_and_dependency(tmp_path):
    rules_path = tmp_path / 'rules'
    rules_path.write_text('\n'.join([
        'alert tcp any any -> any any (msg:"ET BRANDNEW Example"; sid:1; rev:1;)',
        'alert http any any -> any any (msg:"ET WEB_SPECIFIC_APPS WordPress RCE"; metadata:affected_product WordPress; sid:2; rev:1;)',
        'alert tcp any any -> any any (msg:"ET MALWARE Consumer"; flowbits:isset,missing; sid:3; rev:1;)',
    ]) + '\n', encoding='utf-8')
    policy = core.load_policy(ROOT / 'tuning-policy.yaml')
    rules = core.load_rules(rules_path)
    result = tune_rules.apply_policy(rules, policy)
    tracked = {'tracked': 0}
    report = feed_audit.build_feed_audit(rules, policy, result, tracked)
    assert report['summary']['unknown_category_rules'] == 1
    assert report['unknown_category_families']['ET BRANDNEW'] == 1
    assert report['asset_matching']['status_counts']['matched_disabled'] == 1
    assert report['summary']['missing_flowbit_requirements'] == 1
