# Suricata Policy Engine 2.0.0rc1 — Final TUI / Backend Audit

## Fixed defects

1. **Profile upgrade failure** — persisted old policies could lack `categories.ET_POLICY`, `assets.database_products`, or later schema fields. Runtime schema migration now adds only missing defaults and preserves user-set values. YAML patching can also create missing nested mappings.
2. **Partial/slow profile writes** — profiles previously patched and re-parsed the YAML once per field. Profile and multi-setting changes are now applied in-memory and committed atomically after one validation pass.
3. **Database screen missing/empty after upgrade** — same old-schema issue; database schema is now migrated and the group is labeled `Databases`.
4. **Incomplete static asset catalog** — a static list cannot remain exhaustive as ET Open changes. The TUI now scans every `affected_product` value from the current local `suricata.rules` on demand and exposes uncovered values as exact metadata asset fallbacks.
5. **Organization Policy discoverability** — selected-row meaning is displayed in a bottom panel.
6. **Help key inconsistency** — common `?`/F1 handler is used by menu/settings/help-capable editors.
7. **Arrow-key lag** — menu selection and bottom help panels repaint incrementally; Text Viewer caches line wrapping and avoids full header redraw while scrolling.
8. **Category terminology** — operator-facing labels no longer expose `default_disabled_with_allowlist`; the UI says `Off except reviewed exceptions` and names where those exceptions are configured.
9. **Alert Tuning ambiguity** — master ON/OFF is separated from threshold/suppression detail. The UI states clearly that alert tuning changes alert volume, not detection enablement.
10. **Unknown/unmapped behavior** — shown on Dashboard and now deterministic per profile. Strict disables unknown categories; other shipped profiles preserve upstream feed state.
11. **Check SIDs screen** — removed from TUI as requested. Tracked-SID integrity remains an engine/audit capability.

## Backend validation reviewed

- Category modes and conditional strategies.
- Organization selectors and organization-policy references.
- Semantic selectors, unique names, non-empty criteria, regex compilation.
- Asset thresholds, metadata matchers, aliases, regexes, database products, feed-product exact metadata fallbacks.
- Feed-disabled rule safety and force-enable/tracked-SID relationship.
- flowbits/xbits producer-consumer graph, transitive restoration, cycles, OR requirements, toggle-only ambiguity.
- Unknown-category fallback.
- Alert tuning merge behavior.
- Live activation safeguards including Suricata `-S`/`-c` conflicts and live/staged distinction.

## Regex audit

All shipped policy regexes compile successfully. Policy preflight also rejects blank and common universal-match regex forms before tuning. This does not claim that any regex can never become semantically stale when a future feed changes; the read-only feed audit remains the guardrail for feed drift.

## Environment-specific limitation

No production `suricata.rules` file was included in the build workspace. Therefore this release candidate is tested against synthetic/regression fixtures and package smoke tests, but the operator should run the read-only full-feed audit against the exact current feed before promoting the build as production-reviewed.

## Release-candidate verification

- Regression suite: **149/149 PASS**.
- Clean wheel installation: PASS.
- Installed-wheel old-policy schema migration: PASS; existing operator values preserved and a pre-schema backup created.
- Installed TUI environment check: PASS on synthetic rules/config fixture.
- Installed CLI dry-run: PASS.
- Installed read-only Feed Audit: PASS; synthetic dependency graph reported the expected consumer→setter edge.
- Wheel package data: policy/baseline are included and runtime-materializable.
