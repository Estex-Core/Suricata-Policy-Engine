# Changelog

## 2.0.0rc2 — Raw pass-through, verified Replace, lean outputs, real-feed parser fix

- Added a Raw profile that preserves the Suricata feed state exactly until manual policy edits are made.
- Raw disables automatic dependency restoration and generated Alert Tuning so selecting the profile itself is a no-op on rule state.
- Corrected Replace Original semantics: validated tuned content is SHA256-verified after atomic overwrite of `suricata.rules`; reload failure no longer silently undoes the explicitly requested overwrite.
- Moved internal state, history, threshold staging, reports and locks out of the Suricata rules directory; normal visible outputs are now the tuned rules and one text diff report.
- Collapsed the old text+JSON diff pair into one detailed text diff report.
- Fixed quote-aware parsing for Suricata PCRE values containing literal double quotes inside regex character classes.
- Audited the supplied 68,980-rule feed: the previous parser missed 7 SID options, of which one feed-enabled phishing SID (2029732) was unintentionally omitted from the Strict output. The rc2 parser resolves all 68,980/68,980 SID options.
- Added regression coverage for Raw pass-through, PCRE/SID parsing, destructive Replace and lean output behavior.

## 2.0.0rc1 — final TUI/engine hardening

- Fixed old-policy schema migration and `categories.ET_POLICY` profile failures.
- Applied policy changes atomically in one validated batch.
- Added low-latency incremental menu/text scrolling and bottom-panel Organization Policy explanations.
- Standardized `?`/F1 contextual help and removed Check SIDs from the TUI.
- Reworked Alert Tuning into a master switch plus detailed threshold/suppression screens.
- Added on-demand current-feed `affected_product` discovery and renamed the database group to `Databases`.
- Added Dashboard/profile ownership for unknown/unmapped rule behavior.
- Hardened regex/selector preflight validation.

## 2.0.0b5 — TUI responsiveness, SID-baseline fix, consistent category UI, SQL assets

- Cached long-view wrapping and selection-only menu redraws to reduce Arrow-key lag, especially over SSH.
- Category detail screens always show Mode, Conditional Strategy and Fallback controls, with clear applicability notes.
- Fixed Check SIDs baseline resolution in pipx/wheel installs; relative baseline names now resolve to the packaged/materialized baseline instead of incorrectly looking beside `tui.py`.
- Added explicit `unbaselined` tracked-SID state so every tracked SID is accounted for.
- Removed the redundant "TUI is responsive" wording from SID progress screens.
- Added Databases / SQL asset inventory and optional ET_SQL asset-based backend matching for MSSQL, MySQL, MariaDB, PostgreSQL, Oracle Database and SAP MaxDB.
- Simplified Alert Noise and Activate Tuned Rules descriptions.

## 2.0.0b4 — Five profiles, selective organization policy, verified activation

- Reduced the public profile set to exactly Balanced, Noisy, Strict, Lab / Experimental, and Server.
- Balanced explicitly sets Nginx/web-server ON and SCADA OFF; Noisy favors feed visibility; Strict favors high-signal categories; Lab broadens training visibility with tuning; Server applies a server-oriented posture.
- Added conservative `ET_POLICY` semantic Organization Policy for anonymizers, cloud storage, cleartext credentials, and unexpected outbound database access while preserving unmatched security rules upstream.
- Hardened Activate Tuned Rules with runtime `-S` and `-c` checks, exact path verification, live-vs-staged reporting, and fixed false Suricata-process detection.
- Hardened Category Policy so malformed category state or screen exceptions do not terminate the TUI; added all-category regression coverage.
- Expanded regression coverage to 127 passing tests.

## 2.0.0b3 — Dependency graph + evidence asset audit

- Replaced implicit fixed-point dependency restoration with explicit consumer→producer graph traversal while preserving existing restoration semantics.
- Added dependency edge traces, transitive restoration traces, and cycle detection for flowbits/xbits.
- Asset matching now scores enabled and disabled assets, records evidence/candidates, and sends tied strongest matches to review instead of relying on policy iteration order.
- Added read-only `suricata-policy-engine-audit` for full-feed drift, asset, dependency and tracked-SID analysis.
- Added regression tests for transitive cycles, disabled-asset identification, asset ambiguity and feed-audit output.
- GitHub-ready repository cleanup: current docs separated from archived WebUI history, deterministic CI/package smoke checks, issue/PR templates, and packaging metadata cleanup; no tuning-engine behavior changed.

## 2.0.0b2 — TUI-focused audited build

- Restored the terminal UI as the primary `suricata-policy-engine` command.
- Removed the experimental WebUI/portable delivery layer from this build.
- Retained the audited 2.0 backend corrections: quote-aware rule-option parsing, v2 logic hashing, policy preflight validation, generator alignment, and deterministic flowbits/xbits dependency semantics.
- `toggle` remains non-deterministic and is not auto-restored as a guaranteed bit setter.
- `flowbits:setx` remains excluded from documented flowbit setter semantics.
- TUI, CLI, Rule Explorer, policy data, tracked-SID baseline and production validation/rollback paths remain included.

## 2.0.0b1 — WebUI + tuning-engine audit

- Added an Empire/Starkiller-inspired local WebUI as the default command while preserving dedicated TUI and CLI commands.
- Added a portable offline `.pyz` build that embeds WebUI assets, policy data and the YAML runtime; no package installation or Node/npm/CDN is required.
- Kept one Python decision engine for WebUI/TUI/CLI; browser code does not re-implement tuning logic.
- Replaced global rule-option regex extraction with a quote-aware Suricata option tokenizer.
- Versioned tracked-rule logic hashes so v1 baselines remain compatible while v2 separates message-only drift from detection-logic drift.
- Removed undocumented `flowbits:setx` producer handling.
- Stopped treating `toggle` as a guaranteed flowbits/xbits setter; toggle-only chains are surfaced for review and are not auto-restored.
- Fixed standalone generator drift by deriving disable filters from resolved policy state instead of a reason-code allowlist.
- Added policy preflight validation for engine modes/strategies, thresholds, regexes, tracked SID duplicates and force-enable relationships.
- Added loopback-only WebUI binding, Host validation, no-CORS policy, CSP/frame protections and a per-process state-change token.
- Regression suite expanded to 105 passing tests.

## 1.0.0 — Suricata Policy Engine

- Final product name: **Suricata Policy Engine**.
- Clean `src/` project layout and installable source/wheel packages.
- Main command: `suricata-policy-engine`.
- Explain SID input now tells users what a SID is and provides an example.
- Policy Editor visually separates day-to-day settings from Advanced/Expert settings.
- Added dedicated `PROFILES.md`, `POLICY-REFERENCE.md`, and schematic `HOW-IT-WORKS.md`.
- Added CI verification for the reviewed Balanced baseline.
- Renamed runtime state/config paths to the Suricata Policy Engine brand while keeping legacy environment-variable compatibility.

## 18.2.8 - 2026-09-24

- Fixed the Dashboard policy-summary regression by restoring and testing `compact_policy_summary()`.
- Reworded the Dashboard reminder to: `A disabled rule is not necessarily useless.`
- Kept Advanced Settings row descriptions concise while adding richer, practical `About ...` guidance for the selected section.
- Expanded `About Assets` to explain the actual analyst action: turn ON technologies that exist in the monitored environment and leave unused technologies OFF.
- Clarified `About Category Policy` and `About Organization Policy` with practical decision guidance instead of repeating their menu labels.

## 18.2.7

- Clarified Category Policy: Mode is the first-stage category decision; Strategy is used only by CONDITIONAL mode.
- Shortened Advanced Settings descriptions while keeping each description operationally precise.
- Re-audited organization-policy coverage against the full 68,876-rule decision inventory.
- Centralized the eight dedicated usage-policy category mappings: TOR, Remote Access/RMM, File Sharing, P2P, Chat, Dynamic DNS, Games, and Inappropriate Content.
- Added TUI help explaining why security-signal categories such as CoinMiner, Adware/PUP, and TA Abused Services are intentionally not controlled by Organization Policy.

## 18.2.6 - 2026-09-24

- Restored a compact pre-tune policy review; full effective-policy details are now on demand with `D`.
- Replaced the mandatory post-command log dump with a compact tuning result screen; the full in-memory log is available with `L`.
- Simplified Dashboard status, policy and last-tuning sections so the default view fits comfortably on a normal terminal.
- Updated the Dashboard reminder banner to `!!! ____ REMEMBER OFF DOES NOT MEAN USELESS _____ !!! ;)`.
- Kept all logs memory-only; no log files or `logs/` directory are created.

## 18.2.5 - 2026-09-24

- Renamed the pre-tune confirmation action to **Start Tuning**; Enter/T now starts tuning and Esc/q returns.
- Replaced ambiguous post-tune choices with an explained three-way decision: **Keep Without Activating**, **Activate Tuned Rules (Recommended)**, and **Replace Original Rules (! NOT RECOMMENDED)**.
- Added a guarded `--replace-original` production mode that backs up the raw feed, atomically replaces `suricata.rules`, restores the config to the original rule path, validates again, reloads, and rolls back on failure.
- Expanded Effective Policy Summary so every current execution setting is shown for Profile and Custom policies; only the non-executing historical `audit_snapshot` is excluded.
- Refined Advanced Settings descriptions to be operationally precise without becoming verbose.
- Added regression tests for post-tune choice safety, full effective-policy coverage, and safe original-rules replacement.

## 18.2.4 - 2026-09-24

- Reorganized Advanced Settings into four visual groups: Policy & Assets, Detection Logic, Noise Control, and Engine & Validation.
- Added non-selectable section headings and spacing so advanced controls are easier to scan without changing policy behavior.
- Rewrote Advanced Settings descriptions to explain what each section actually controls in clear operational language.
- No tuning-engine behavior changed in this release.

## 18.2.3 - 2026-09-24

- Audited the complete 68,876-rule decision inventory and the current 35,211-rule validation ruleset for asset and organization-policy coverage.
- Expanded the managed ET_WEB_SPECIFIC_APPS asset catalog with verified modern web, enterprise, network/security, DevOps/monitoring, and file-transfer products while preserving metadata-first matching.
- Grouped the larger asset catalog in the TUI so the overview stays readable.
- Added Games and Inappropriate Content as organization-policy categories with safe disabled-by-default behavior.
- Expanded remote-access application policy context from the actual ET_REMOTE_ACCESS ruleset.
- Preserved existing tuning output by default: all newly modeled assets are OFF until explicitly declared present.

## 18.2.2

- Simplified Assets UI to one row per asset; matcher thresholds, aliases, metadata and regex moved one level deeper behind Enter.
- Simplified Organization Policy UI to one human-readable row per activity; usage policy and detection details moved behind Enter.
- Removed raw NOT SET/null-style status from the organization-policy overview.
- Standard and Advanced asset/organization views now share the same compact nested UX.

## 18.2.1
- Returned to the stable 18.2 UX baseline; no setup wizard.
- Advanced Settings warning now uses Enter to continue and Esc/q to go back.
- Replaced the ambiguous `UNDECIDED` display with `NOT SET`.
- Category Policy now shows only controls that can affect the selected mode.
- Removed misleading category-level Alert tuning and Preserve-if-dependency controls from that screen; those remain in their dedicated global sections.
- Added mode-specific subtitles and clearer field help.

## 18.2.0

- Aligned JA3 validation with Suricata semantics: an unset `ja3-fingerprints` value is treated as on-demand/auto, while explicit disablement still fails when JA3 rules are enabled.
- Added optional `require_explicit_ja3_fingerprinting` strict mode for environments that require an explicit `yes`.
- Changed `alert_tuning.sid_overrides` to patch/merge the category threshold profile instead of replacing it wholesale, so partial per-SID overrides inherit unspecified fields.
- Removed the misleading duplicate-SID validation toggle; duplicate SIDs are always rejected as a parser-level safety invariant.
- Added regression coverage for JA3 auto/unset semantics, explicit-JA3 strict mode, per-SID threshold inheritance, and non-configurable duplicate-SID enforcement.

## 18.1.0

- Made `flowbits:isset,a|b` dependency handling OR-aware instead of treating the entire expression as one bit name. Known producer paths are restored without reporting a false missing dependency when at least one alternative exists.
- Made xbit dependency restoration storage-scope aware (`host`, `ip_pair`, `tx`), while allowing the documented `ip_src`/`ip_dst` direction flip within host scope.
- Enforced policy validation controls: unresolved required dependencies block accepted output, JA3-enabled rules require `app-layer.protocols.tls.ja3-fingerprints`, and `require_suricata_test` now triggers a staged `suricata -T` before the final artifact is promoted.
- Added per-SID threshold overrides with precedence over category-wide alert-tuning profiles.
- Added read-only EVE JSON/JSON.GZ telemetry analysis via `--eve`; it produces high-volume SID review candidates but never auto-suppresses or auto-disables detections.
- Added telemetry artifacts to run history and extended Explain SID xbit dependency evidence with compatible storage scopes.
- Expanded regression coverage for OR flowbits, xbit scope compatibility, JA3 prerequisites, SID threshold overrides, and telemetry recommendations.

## 18.0.0

- Check SIDs now shows a live spinner, elapsed time, and explicit scan stages instead of appearing frozen on large feeds.
- SID category normalization reports coarse processed/total progress while scanning.
- Check SIDs keeps the parsed audit in memory for the current screen; Help/Explain navigation no longer forces an automatic full rescan.
- `r` explicitly triggers a fresh SID scan, and accepting a baseline triggers one controlled recheck.
- Explain SID now also shows an in-TUI working indicator while its decision trace is being built.

## 17.0.0

- Added a mandatory pre-tune review screen that shows the exact same Effective Policy Summary as Dashboard `p`.
- `Tune My Rules` now requires explicit `t` confirmation before any tuning subprocess starts; `Enter`, `q`, and `Esc` safely return without running.
- Kept the existing live in-memory progress/log viewer and activation workflow unchanged after confirmation.

## 16.0.0

- Fixed Profile/Custom status UX after Standard or Advanced edits.
- Profiles screen now distinguishes an active profile (`▶`) from the base profile of a Custom policy (`↳`).
- Save confirmations now show the resulting Active Policy immediately.
- Effective policy remains one shared policy; Profile is only a preset/base.

## 15.0.0

- Removed local Asset Discovery; asset context is now explicitly manual/inventory-driven because Suricata sensors commonly run separately from monitored servers.
- Added an Effective Policy Summary to the Dashboard and a `p` shortcut for the full pre-tuning summary.
- The Main Menu now shows the current effective policy label before Tune My Rules is selected.
- The summary reflects the single effective policy after Profile, Standard, and Advanced edits.

## 14.0.0

- Unified Profile, Standard Settings and Advanced Settings around one effective policy.
- Profiles are now explicit base presets; Standard/Advanced edits mark the policy as Custom while preserving the base profile.
- Policy Editor now shows `ACTIVE POLICY`, for example `Custom (based on Balanced Recommended)`.
- Profiles keep a pointer on the base profile even while the effective policy is Custom.


## 13.0.0

- Retained the complete `Tune My Rules` subprocess output in RAM and added scrolling during and after execution; no log file is created.
- Replaced the post-validation TUI wording **Deploy** with the explicit **Activate Tuned Rules** / **Keep Without Activating** choice.
- Added an activation explanation that states the original `suricata.rules` feed file is not overwritten.
- Updated the Tune My Rules menu description and documentation to match the safer activation workflow.

## 12.0.0 - 2026-09-23

- Simplified the final release tree and removed per-version UPGRADE notes and duplicate README files.
- Renamed the main action to **Tune My Rules**.
- Tune My Rules now starts immediately and shows live stage/spinner/elapsed-time output in the TUI.
- Added visual spacing between Profiles and the rest of Standard Settings.
- Added an active-profile pointer and marked `Balanced (Recommended)` as the reviewed project baseline.
- Added Category Policy mode/strategy explanations and contextual `?` help.

## 11.0.0 - 2026-09-23

- Added six transparent starter Profiles.
- Added Rule Explorer and TUI integration with Explain SID.
- Added retained Run History snapshots and Safe Rollback.
- Added candidate-staged production deploys so the live artifact is not overwritten before validation.
- Added atomic writes and an output-directory process lock.
- Added regression tests, parser/dependency/policy invariants, deploy/rollback recovery tests.
- Added pyproject/pipx packaging and console scripts.
- Added GitHub Actions CI/release workflows, release docs, demo GIF, security/contributing docs, and MIT license.

## 10.0.0

- Recommendation Engine, Explain SID++, Policy Health, Update Impact Preview.

## 9.0.0

- Standard/Advanced Policy Editor split and contextual help.

## 8.0.0

- Four-item TUI and complete advanced policy editing.

## 6.0.0

- Metadata-first asset matching, semantic selectors, tracked-SID fingerprints.
