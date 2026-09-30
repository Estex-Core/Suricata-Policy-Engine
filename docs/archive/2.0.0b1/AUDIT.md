# Tuning Engine Audit — 2.0.0b1

## Scope

This audit reviewed the uploaded 1.0.0 source/package and traced the complete decision path from a raw Suricata rule to final enablement, alert tuning, validation and activation. It covers parsing, SID/revision/message extraction, category mapping, policy modes/strategies, asset matching, semantic selectors, tracked SID guardrails, flowbits/xbits dependencies, drift hashes, threshold generation, SID explanation and production deployment.

The uploaded release does **not** contain the complete 68,876-rule `suricata.rules` feed referenced by earlier project notes. Therefore this audit verifies source logic, policy inventory, package behavior and synthetic regression cases, but it does not claim a fresh rule-by-rule distribution against that external feed. A live-feed audit requires that ruleset as input.

## Decision pipeline

```text
raw rule
  -> quote-aware option parser
  -> SID / REV / MSG / metadata / flowbits / xbits
  -> category mapping
  -> Mode
  -> Strategy (only for CONDITIONAL)
  -> asset / organization decision
  -> semantic keep selectors
  -> tracked SID guardrails / explicit force-enable
  -> recursive deterministic dependency restoration
  -> final_enabled
  -> alert-tuning profile + SID patch
  -> dependency / JA3 / duplicate-SID / Suricata validation
  -> candidate / activation / rollback
```

## Policy inventory

- 52 category policies: 24 `preserve_feed`, 21 `conditional`, 5 `asset_based`, 2 `disable`
- conditional strategies: 8 alert-tuned enabled-by-default, 8 disabled-by-default, 2 allowlist-default-disabled, 1 organization-policy, 1 enabled-by-default, 1 message-filter
- 51 Web-specific application assets; one is enabled in the shipped policy
- 58 policy regex/regex-like matchers across asset and semantic matching
- 4 semantic selectors
- 53 tracked SIDs and 53 v1 baseline entries; sets are aligned exactly
- 11 alert-tuning category profiles; zero shipped SID overrides and zero suppressions

## Important findings and corrections

### 1. Rule-option parsing was too regex-global

The v1 parser searched the entire raw rule for `sid:`, `rev:`, `flowbits:`, `xbits:` and `metadata:` patterns. Text that looks like a keyword can legally occur inside quoted `msg`, `content` or `pcre` strings. 2.0 adds a quote-aware option tokenizer and only interprets actual rule options. Tests cover SID/flowbits/metadata lookalikes and semicolons inside quoted text.

### 2. Logic drift and message drift were not independent

The v1 logic hash removed revision/metadata/reference/classtype but retained `msg`, so a message-only edit could also appear as `logic_changed`. v2 logic hashing excludes identity/descriptive fields (`sid`, `rev`, `msg`, `metadata`, `reference`, `classtype`) while retaining the rule header/action and detection options. Baseline format is versioned: existing v1 baselines continue to use the v1 comparator, while newly accepted baselines use v2.

### 3. Unsupported `flowbits:setx` was considered a setter

`setx` is not a documented Suricata flowbits action. It has been removed from producer recognition.

### 4. `toggle` was unsafe as an automatic dependency producer

`toggle` flips state; it does not guarantee that a positive `isset` prerequisite becomes true. 2.0 auto-restores only deterministic `set` producers. Toggle-only producer chains are reported as ambiguous review items instead of being silently restored.

### 5. Generator artifacts had a second decision model

The main tuner writes the exact `final_enabled` result, but the standalone enable/disable generator used a reason-code allowlist to decide which SIDs belonged in `disable.conf`. Several real disable reasons were not in that list (asset review/no-match and message-filter/organization-policy paths among them). 2.0 derives `disable.conf` directly from resolved policy state: source-enabled + inactive after base policy/overrides.

### 6. Policy regex errors were late failures

2.0 validates engine-bearing policy fields before tuning: modes, conditional strategies, asset thresholds, asset/metadata regexes, semantic regexes, duplicate tracked SIDs and force-enable/tracked relationships. Invalid regex paths are reported precisely.

## Verified semantics

### Category mapping

- `SURICATA` is exact/prefix mapped.
- GPL categories use explicit `gpl_category_mapping` with longest-prefix precedence.
- ET categories use configured category names, also longest-prefix first.
- Unmapped rules preserve upstream state unless `disable_unknown_categories` is explicitly enabled.

### Asset matching

For `ET_WEB_SPECIFIC_APPS`, the matcher considers only enabled assets and scores evidence:

- normalized configured metadata match: 100
- anchored product alias at the start of the category-specific message body: 90
- explicit policy regex: 85
- `attack_target=Server`: +5 corroboration only after a product match

A rule is enabled only at/above `match_threshold`; review-range matches are disabled and surfaced for analyst review. No naive substring asset matching is used.

### Semantic and tracked SID handling

- semantic selectors run before tracked SID guardrails
- fields inside one selector are ANDed; alternatives inside a field are ORed
- semantic keep applies only to source-enabled rules
- tracked SID keep does not resurrect a feed-disabled rule
- force-enable must be explicit and must reference a tracked SID
- missing/revision/message/category/logic/feed-disabled drift is recorded

### flowbits

- positive `isset` creates a dependency
- `isnotset` does not
- `a|b` is an OR requirement
- deterministic `set` producers are indexed dynamically from the current feed
- all known deterministic producer paths for enabled consumers are restored recursively to a fixed point
- toggle-only paths are review items, not auto-restored

### xbits

- positive `isset` creates a dependency
- dependency identity is `(name, storage scope)`
- `ip_src` and `ip_dst` share host scope so direction can legitimately flip between request and response
- `ip_pair` and `tx` remain distinct scopes
- deterministic `set` producers are restored recursively
- toggle-only paths are review items

### Alert tuning

Category profile is the base. A SID override patches that profile instead of replacing the entire profile. Feed-authored inline `threshold` or `detection_filter` options are detected by the quote-aware option parser and are not overridden. Telemetry remains advisory and does not auto-disable/suppress noisy rules.

### Deployment

Recommended activation keeps `suricata.rules` intact, stages the candidate, validates, atomically updates managed files/configuration and reloads. Explicit original-file replacement remains a separate destructive path with backup and rollback.

## WebUI architecture

The new UI follows the operator-console pattern requested from Empire/Starkiller but does not copy their code or visual assets. The WebUI is a presentation layer over the existing Python engine; it does not duplicate policy decisions in JavaScript. Installed and portable/offline modes therefore produce the same decisions as CLI/TUI.

## Verification

- Python compilation: PASS
- complete project regression suite: 105 tests PASS
- quote-aware parser regression: PASS
- v1/v2 logic-hash behavior: PASS
- generator resolved-state regression: PASS
- WebUI uses exact engine + SID explanation: PASS
- production WebUI privilege guard: PASS
- portable local HTTP/API smoke test: PASS
