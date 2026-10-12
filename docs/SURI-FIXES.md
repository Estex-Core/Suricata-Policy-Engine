# SuriTuner production rule-loading regression fixes

## What changed

- `patch_rule_files` keeps exactly one managed ruleset entry when `suricata.rules` and/or `suricata-tuned.rules` have both been configured, preserving unrelated rule files. This addresses a likely trigger for the `Duplicate signature` incident. It cannot cure duplicate SIDs inside the source feed or collisions with unrelated files.
- Unrecognized `rule-files` syntax fails closed before editing configuration.
- `config_uses_rule_file` checks for exactly one reference to tuned rules, not merely one-or-more, and refuses simultaneous original `suricata.rules` references.
- Production activation status is recorded as `live`, `staged`, or `not_requested`; a staged deployment no longer incorrectly receives `deployed=true` in history.
- After failed production activation and rollback of files, an additional best-effort live reload of the restored configuration is attempted.
- Optional dependency `producer_selection: minimal` may reduce restored producers, while `all` remains the default to preserve detection breadth. Use minimal **only after traffic-based coverage tests**.
- Explicit metadata `rule_category`/`signature_category` can supplement prefix matching when it exactly equals a configured category. Unknown categories still follow the original fallback policy.
- `tui.py` uses the same metadata-aware category mapping as the core.
- Project version advances to `2.0.0rc3` (release candidate, not a proven production-stable release).
- A read-only `tools/inspect_rule_loading.py` scans effective rule-files and cross-file SID collisions.
- Pytest regression tests and GitHub Actions CI check configuration rewriting, dependency behavior, and metadata fallback.

## Why the sample operational logs matter

The October 2026 JSON log contains 917 `Duplicate signature` messages, 918 `error parsing signature` messages, plus 2 informational lines. One error (SID `2071363`) has no matching duplicate line and requires separate investigation. This is consistent with a duplicate rule load but does not, on its own, prove the root cause. Other possibilities include duplicate entries inside the input feed or collisions with local rule files.

Check active `rule-files` entries, process `-S/--sig-file`, and Suricata startup logs **before** changing production configuration.

## Deployment safety

Run `suricata -T` with the effective production config and inspect the entire combined ruleset. Keep a backup of production configuration, files, and previous live instance state. Apply on a staging sensor first. Unit tests do not substitute for actual Suricata validation.

## Applying patch to an existing checkout

```bash
python3 /path/to/apply_fixes.py --repo /path/to/Suricata-Policy-Engine
cd /path/to/Suricata-Policy-Engine
python3 -m pip install -e . pytest
python3 -m pytest -q tests/test_suri_regressions.py
python3 -m compileall -q src
# On a staging sensor only, validate with real Suricata -T before deployment.
git diff --check
git add pyproject.toml src/tune_rules.py src/generate_suricata_policy.py src/tui.py src/suricata_policy_engine_data/tuning-policy.yaml docs/SURI-FIXES.md docs/INCIDENT-FINDINGS.md tests/test_suri_regressions.py .github/workflows/regression-tests.yml tools/inspect_rule_loading.py
git commit -m 'fix: prevent duplicate Suricata rule loading and harden rollout'
git push origin main
```

Generated `.pre-suri-fix.bak` backup files are placed beside edited source files; they are *not* meant to be committed.
