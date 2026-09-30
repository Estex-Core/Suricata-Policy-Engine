# GitHub release checklist — 2.0.0rc2

- [ ] `pytest -q` passes.
- [ ] Root policy matches packaged policy data.
- [ ] Wheel and sdist build cleanly.
- [ ] Clean virtualenv installs the wheel.
- [ ] TUI/CLI/Explorer/Audit entrypoints smoke-test.
- [ ] Old runtime policy migration smoke-test passes.
- [ ] Run `suricata-policy-engine-audit` on the target production feed before production promotion.
- [ ] Create tag `v2.0.0rc2`.
