# Suricata Policy Engine 2.0.0b1

This beta introduces the WebUI/portable delivery model and incorporates the first deep audit of the tuning engine requested for the 2.0 line.

## Delivery modes

- Installed WebUI: `suricata-policy-engine`
- Installed TUI: `suricata-policy-engine-tui`
- Installed automation CLI: `suricata-policy-engine-cli`
- Portable offline WebUI: `suricata-policy-engine-2.0.0b1-portable.pyz`

## Engine corrections

- quote-aware Suricata rule-option parser
- versioned detection-logic hash; message-only drift no longer becomes new v2 logic drift
- documented producer semantics (`set` only for guaranteed positive dependency restoration)
- `toggle` chains surfaced as ambiguous review items
- undocumented `flowbits:setx` removed from setter recognition
- generator enable/disable artifacts derive from resolved policy state
- policy regex/mode/threshold/SID preflight validation

## WebUI

The WebUI is a local operational console with Dashboard, Rules/Explain SID, Policy, Assets, Organization Policy, Tuning, History/Rollback and Settings. It uses the same Python engine as the CLI/TUI.

The current beta intentionally binds to loopback only; it is not a remotely exposed multi-user service.

## Verification

105 regression tests pass. The portable archive has also been smoke-tested against a synthetic ruleset through its real local HTTP API.

See `docs/AUDIT-2.0.0b1.md` for the detailed audit and known scope limitation: the uploaded package did not include the external full 68,876-rule feed, so a fresh whole-feed match-distribution audit still requires that file.
