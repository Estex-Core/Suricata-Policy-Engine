# Contributing

Suricata Policy Engine changes can affect IDS rule state, so changes should be small, reviewable, and regression-tested.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e '.[dev]'
pytest -q
```

## Contribution rules

1. Create a focused branch and keep unrelated cleanup out of behavior-changing commits.
2. Add or update tests for policy-engine changes.
3. Run `python -m compileall -q src tests` and `pytest -q` before opening a PR.
4. For parser/dependency changes, include malformed, duplicate, OR-state, cycle, scope, and missing-producer cases as appropriate.
5. Do not add fixed dependency SIDs; dependency restoration must remain feed-derived and dynamic.
6. Do not auto-enable discovered assets without an explicit administrator inventory decision.
7. Treat ambiguous asset/dependency evidence as reviewable state rather than silently selecting a winner.
8. Preserve safe activation: candidate validation before production changes, with rollback on failure.
9. Do not commit proprietary rulesets, production EVE data, secrets, private network details, generated audit reports, or local runtime state.

## Documentation

Update current docs when behavior changes. Historical material belongs under `docs/archive/` and must be clearly marked as superseded.
