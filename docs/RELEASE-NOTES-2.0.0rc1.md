# Suricata Policy Engine TUI 2.0.0rc1

This release candidate focuses on TUI correctness, policy-schema migration, operator clarity, feed-aware assets, and engine validation. The WebUI remains out of scope; the supported interactive interface is the TUI.

## TUI and UX

- Organization Policy now shows a bottom-screen explanation for the selected activity.
- Arrow-key navigation avoids full-screen redraws when the viewport does not change; the text viewer caches wrapping and repaints only its body while scrolling.
- `?` / F1 help routing is shared across menu/settings/help-capable editors; Semantic Selectors and Suppressions now use the same handler.
- Category Policy shows the same three primary controls for every category and uses short human labels instead of raw strategy identifiers.
- The confusing `default_disabled_with_allowlist` UI label is now **Off except reviewed exceptions** and explains that exceptions live under Semantic Selectors / Rule Overrides.
- Check SIDs is removed from the TUI. Tracked-SID integrity remains available through Feed Audit and Explain SID.
- Alert Tuning is a dedicated Standard screen. The master ON/OFF switch is visually separate from Threshold Profiles and Suppressions.
- Activate copy is shorter and only claims success after validation and a verified live reload/restart.

## Profiles and migration

- Exactly five profiles: Balanced, Noisy, Strict, Lab / Experimental, Server.
- Balanced explicitly keeps Nginx ON and SCADA OFF.
- Persisted policies from older pipx installs are schema-merged with newly introduced categories/assets without overwriting existing operator values.
- Profile changes are applied as one atomic batch, avoiding partial profile writes and eliminating the previous `Could not find YAML parent: categories.ET_POLICY` failure.
- Unknown/unmapped category behavior is profile-owned: Balanced/Noisy/Lab/Server preserve upstream feed state; Strict disables unknown categories.

## Assets

- The group label is now **Databases** (no `/ SQL`).
- Curated database assets include Microsoft SQL Server, MySQL, MariaDB, PostgreSQL, Oracle Database, and SAP MaxDB.
- **Current feed products** scans the operator's actual `suricata.rules` on demand and lists every `affected_product` metadata value in that feed. Reviewed products use curated matchers; newly observed products can be enabled as exact metadata fallbacks.
- The full-feed scan is not performed merely to draw the Assets menu, preventing unnecessary TUI stalls.

## Engine hardening

- Policy preflight rejects invalid, blank, and common match-everything regexes (`.*`, `^.*$`, `.+`, `^.+$`).
- Duplicate semantic-selector names, selector blocks with no matching criteria, and empty `msg_contains` values are rejected before tuning.
- Existing evidence-driven asset matching, ambiguous-match review behavior, flowbits/xbits dependency graph, toggle-only safeguards, tracked-SID drift, and activation verification remain enabled.

## Validation status

The release tree is covered by backend/TUI/repository tests plus clean-wheel installation/smoke checks. The source workspace does not contain the operator's production ~68k-rule `suricata.rules`, so a claim of a fresh audit of that exact feed is intentionally not made. Use `suricata-policy-engine-audit` on the target Ubuntu host for that environment-specific check.

## Verification

- `149/149` regression tests PASS.
- Clean wheel install and console entrypoints PASS.
- Installed-wheel migration from an intentionally old policy schema PASS.
- Synthetic CLI dry-run, feed audit and dependency-graph smoke tests PASS.
