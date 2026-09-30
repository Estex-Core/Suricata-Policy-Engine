# Suricata Policy Engine TUI 2.0.0b4

TUI profile/policy and activation-correctness release.

## Five public profiles

The project now exposes exactly five profiles:

1. **Balanced (Recommended)** — reviewed baseline; web server + Nginx ON, SCADA OFF, alert tuning ON.
2. **Noisy** — preserves nearly every modeled feed category (except retired rules), enables broad policy visibility, and disables alert rate tuning. It does not resurrect upstream-disabled rules.
3. **Strict** — keeps reviewed high-signal threat/protocol families, leaves asset-specific families asset-driven, and disables broad informational/policy/hunting noise.
4. **Lab / Experimental** — SOC/SIEM practice profile with broader ET INFO/TFTP/policy visibility but alert tuning still enabled.
5. **Server** — server-oriented posture with web server + Nginx ON, SCADA/ActiveX/VoIP OFF, reduced lifestyle/client noise, and additional credential/outbound-database visibility.

Profile category posture is deterministic so switching away from Noisy/Strict does not leave stale category modes behind.

## Organization Policy expansion

- Added `ET_POLICY` as a conditional category using `organization_policy_selective`.
- Added conservative semantic Organization Policy families for:
  - anonymizers / privacy networks,
  - cloud storage / sharing,
  - cleartext credentials,
  - unexpected outbound database access.
- Unmatched `ET POLICY` signatures preserve upstream feed state because the category contains both usage-policy and security-relevant detections.
- Conflicting selector decisions preserve upstream and surface ambiguity rather than forcing a decision.
- CoinMiner, Adware/PUP and Abused Services remain outside Organization Policy because they are security signals, not pure usage-policy toggles.

## Activate Tuned Rules correctness

The `A = Activate Tuned Rules` path no longer treats “configuration changed” as equivalent to “live engine switched”.

- Verifies `suricata.yaml` actually resolves `rule-files` to `suricata-tuned.rules`.
- Detects a live Suricata process pinned to another rules file with `-S/--sig-file` and stops before changing production configuration.
- Detects a live Suricata process using a different `-c/--config` and stops instead of editing the wrong YAML.
- Uses a blocking `suricatasc reload-rules` when available and checks the runtime `rule-files` view.
- Falls back to a controlled `suricata.service` restart only when appropriate, then re-checks runtime command-line state.
- Reports **LIVE SWITCH COMPLETED** only after a verified live reload/restart.
- Reports **CONFIG UPDATED, BUT NOT LIVE YET** when no running engine exists.
- Fixed process detection so `suricata-policy-engine` itself is never mistaken for the `suricata` packet engine.
- Absolute `-S` paths must match exactly; same basenames in different directories are no longer considered equivalent.

## Category Policy crash hardening

- Hardened category-policy loading against malformed/non-mapping policy state.
- Normalized missing/invalid display values before rendering.
- Added `organization_policy_selective` to the conditional-strategy editor.
- Wrapped major TUI screens in an error boundary so a screen-level bug returns to the TUI instead of terminating the whole application.
- Added regression coverage that opens every configured category through the Category Policy editor and exercises a malformed conditional strategy.

## Verification

- **127/127 tests PASS** on the final source tree before packaging.
- Includes regression tests for all five profiles, profile switching, selective ET POLICY decisions, Organization Policy conflicts, `-S` activation conflicts, runtime-config conflicts, process identification, and Category Policy stability.

## Important feed limitation

This release still does not claim a new end-to-end audit against the user's current production ~68k-rule `suricata.rules`, because that file is not present in the release workspace. Use `suricata-policy-engine-audit` on the actual feed before calling the beta production-reviewed.
