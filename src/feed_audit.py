#!/usr/bin/env python3
"""Read-only full-feed compatibility audit for Suricata Policy Engine."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import generate_suricata_policy as core
import tune_rules
from runtime_paths import default_policy_path, default_baseline_path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_RULES = Path('/var/lib/suricata/rules/suricata.rules')
DEFAULT_POLICY = default_policy_path(SCRIPT_DIR)


def parse_args():
    p = argparse.ArgumentParser(prog='suricata-policy-engine-audit', description='Read-only feed/policy/dependency audit')
    p.add_argument('--rules', type=Path, default=DEFAULT_RULES)
    p.add_argument('--policy', type=Path, default=DEFAULT_POLICY)
    p.add_argument('--tracked-baseline', type=Path, default=default_baseline_path(SCRIPT_DIR))
    p.add_argument('--output', type=Path, default=Path('suricata-policy-engine-feed-audit.json'))
    p.add_argument('--markdown', type=Path, default=None)
    return p.parse_args()


def unknown_family(msg: str) -> str:
    words = (msg or '').split()
    if not words:
        return 'EMPTY_MSG'
    if words[0] in {'ET', 'GPL'}:
        return ' '.join(words[:2]) if len(words) >= 2 else words[0]
    if words[0] == 'SURICATA':
        return 'SURICATA'
    return ' '.join(words[:2]) if len(words) >= 2 else words[0]


def build_feed_audit(rules, policy, result, tracked):
    source_enabled = sum(1 for r in rules.values() if r.source_enabled)
    final_enabled = sum(1 for r in rules.values() if r.final_enabled)
    unknown = [r for r in rules.values() if r.category is None]
    asset_rules = [r for r in rules.values() if r.category == 'ET_WEB_SPECIFIC_APPS']
    asset_status = Counter(getattr(r, 'asset_match_status', 'not_evaluated') for r in asset_rules)
    category_counts = Counter((r.category or 'UNMAPPED') for r in rules.values())
    metadata_keys = Counter()
    affected_products = Counter()
    for r in rules.values():
        metadata_keys.update(r.metadata.keys())
        affected_products.update(r.metadata.get('affected_product', []))

    graph = result.get('dependency_graph') or core.build_dependency_graph(rules, policy)
    reachable = set(graph.get('reachable_consumer_sids', []))
    reachable_cycles = [c for c in graph.get('cycles', []) if any(sid in reachable for sid in c)]
    reviews = []
    for r in asset_rules:
        if r.asset_review_candidate or getattr(r, 'asset_match_status', '') in {'ambiguous', 'review_required'}:
            reviews.append({
                'sid': r.sid, 'msg': r.msg, 'status': r.asset_match_status,
                'best_asset': r.asset_match_asset, 'score': r.asset_match_score,
                'evidence': r.asset_match_evidence, 'candidates': r.asset_match_candidates,
            })

    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'rules_sha256': None,
        'summary': {
            'parsed_rules': len(rules), 'feed_enabled': source_enabled, 'final_enabled': final_enabled,
            'unknown_category_rules': len(unknown),
            'unknown_category_enabled_rules': sum(1 for r in unknown if r.source_enabled),
            'asset_review_required': len(reviews),
            'flowbit_restored_sids': len(result.get('restored_flow', [])),
            'xbit_restored_sids': len(result.get('restored_xbit', [])),
            'missing_flowbit_requirements': len(result.get('missing_flow', [])),
            'missing_xbit_requirements': len(result.get('missing_xbit', [])),
            'toggle_only_flowbit_requirements': len(result.get('ambiguous_flow', [])),
            'toggle_only_xbit_requirements': len(result.get('ambiguous_xbit', [])),
            'dependency_edges': graph.get('edge_count', 0),
            'dependency_cycles': len(graph.get('cycles', [])),
            'reachable_dependency_cycles': len(reachable_cycles),
        },
        'unknown_category_families': dict(Counter(unknown_family(r.msg) for r in unknown).most_common()),
        'unknown_rules': [{'sid': r.sid, 'enabled': r.source_enabled, 'msg': r.msg} for r in unknown],
        'category_counts': dict(sorted(category_counts.items())),
        'asset_matching': {
            'status_counts': dict(sorted(asset_status.items())),
            'review_required': reviews,
            'matched_disabled': [
                {'sid': r.sid, 'asset': r.asset_match_asset, 'score': r.asset_match_score, 'msg': r.msg,
                 'evidence': r.asset_match_evidence}
                for r in asset_rules if getattr(r, 'asset_match_status', '') == 'matched_disabled'
            ],
            'no_match_count': asset_status.get('no_match', 0),
        },
        'dependencies': {
            'missing_flowbits': sorted(result.get('missing_flow', [])),
            'missing_xbits': sorted(result.get('missing_xbit', [])),
            'toggle_only_flowbits': sorted(result.get('ambiguous_flow', [])),
            'toggle_only_xbits': sorted(result.get('ambiguous_xbit', [])),
            'cycles': graph.get('cycles', []),
            'reachable_cycles': reachable_cycles,
            'restoration_edges': graph.get('restoration_edges', []),
            'requirements': graph.get('requirements', []),
        },
        'tracked_sid_integrity': tracked,
        'metadata_census': {
            'keys': dict(metadata_keys.most_common()),
            'affected_product_top': dict(affected_products.most_common(200)),
        },
    }


def markdown_report(report: dict) -> str:
    s = report['summary']
    lines = [
        '# Suricata Policy Engine — Full Feed Audit', '',
        f"- Parsed rules: **{s['parsed_rules']:,}**",
        f"- Feed enabled: **{s['feed_enabled']:,}**",
        f"- Final enabled: **{s['final_enabled']:,}**",
        f"- Unknown category rules: **{s['unknown_category_rules']:,}**",
        f"- Asset review required: **{s['asset_review_required']:,}**",
        f"- Dependency edges: **{s['dependency_edges']:,}**",
        f"- Dependency cycles: **{s['dependency_cycles']:,}** (reachable: {s['reachable_dependency_cycles']:,})",
        f"- Missing flowbit requirements: **{s['missing_flowbit_requirements']:,}**",
        f"- Missing xbit requirements: **{s['missing_xbit_requirements']:,}**",
        '', '## Unknown category families', ''
    ]
    fam = report['unknown_category_families']
    if fam:
        lines += [f'- `{k}`: {v}' for k, v in list(fam.items())[:100]]
    else:
        lines.append('- None')
    lines += ['', '## Asset matching', '']
    for k, v in report['asset_matching']['status_counts'].items():
        lines.append(f'- `{k}`: {v}')
    lines += ['', '## Dependency integrity', '']
    for key in ('missing_flowbits','missing_xbits','toggle_only_flowbits','toggle_only_xbits'):
        vals = report['dependencies'][key]
        lines.append(f'- {key}: {len(vals)}')
    return '\n'.join(lines) + '\n'


def main():
    args = parse_args()
    if not args.rules.exists():
        raise SystemExit(f'ERROR: rules file not found: {args.rules}')
    policy = core.load_policy(args.policy)
    rules = core.load_rules(args.rules)
    if not rules:
        raise SystemExit('ERROR: no Suricata rules parsed')
    result = tune_rules.apply_policy(rules, policy)
    tracked = tune_rules.audit_tracked_rules(rules, policy, args.tracked_baseline)
    report = build_feed_audit(rules, policy, result, tracked)
    report['rules_sha256'] = core.sha256_file(args.rules)
    report['policy_sha256'] = core.sha256_file(args.policy)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    md = args.markdown or args.output.with_suffix('.md')
    md.write_text(markdown_report(report), encoding='utf-8')
    s = report['summary']
    print(f"Parsed={s['parsed_rules']} unknown={s['unknown_category_rules']} asset_review={s['asset_review_required']} "
          f"dep_edges={s['dependency_edges']} cycles={s['dependency_cycles']} "
          f"missing_flow={s['missing_flowbit_requirements']} missing_xbit={s['missing_xbit_requirements']}")
    print(f'JSON: {args.output}')
    print(f'Markdown: {md}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
