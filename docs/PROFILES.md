# Profiles

Profiles are reviewed presets for the **same effective policy**. They do not create separate engines and they do not bypass Advanced Settings. Applying a profile writes its owned values into `tuning-policy.yaml`; any later manual change makes the policy `Custom (based on <profile>)`.

Six public profiles are shipped.

## Raw

A pass-through starting point for manual tuning.

- Every modeled category uses `PRESERVE_FEED`.
- Unknown/unmapped categories also preserve upstream state.
- Dependency restoration is OFF so the profile itself cannot resurrect a feed-disabled setter.
- Generated Alert Tuning is OFF.
- Upstream-enabled rules stay enabled and upstream-disabled rules stay disabled.
- After selecting Raw, use Advanced Settings to make only the changes you want (for example, disable SCADA and leave everything else untouched).

The TUI warns that Raw applies no automatic tuning policy. It does **not** mean Suricata has no active rules; it means the Policy Engine is not changing the feed until you edit the policy.

## Balanced (Recommended)

The reviewed day-to-day baseline.

- Generic web-server coverage: **ON**.
- Nginx asset: **ON**.
- SCADA/ICS asset: **OFF** (explicit profile contract).
- Core malware, exploit, phishing, C2, worm, shellcode and related threat families preserve upstream feed state.
- ET INFO remains selective rather than globally enabled.
- TOR and remote-access/RMM are prohibited by default and detection remains enabled.
- Optional usage-policy families stay conservative unless the organization requests visibility.
- Alert tuning and dependency restoration are enabled.
- Unknown/unmapped feed categories preserve their upstream feed state.

The existing reviewed Balanced web-application controls (WordPress, JBoss, Exchange, Citrix, ManageEngine and Fortinet) remain OFF unless explicitly enabled as inventory.

## Noisy

A high-visibility / high-volume profile for environments that intentionally want **most available feed detections**.

- Every modeled category except `ET_RETIRED` is changed to `PRESERVE_FEED`.
- Rules shipped disabled by the upstream feed are **not resurrected** merely because this profile is selected.
- Organization-policy detection switches are broadly enabled.
- Alert tuning is disabled so the profile does not silently rate-limit the extra visibility it requests.
- Required flowbit/xbit dependencies are still restored safely.
- Unknown/unmapped feed categories preserve their upstream feed state.

This profile is appropriate when the SOC explicitly prefers collecting more alert telemetry and accepts substantial noise.

## Strict

A high-signal profile intended to retain the most security-critical families while reducing broad informational, hunting and usage-policy noise.

- Core malware/exploit/phishing/C2/shellcode/worm/compromise families remain feed-driven.
- Important protocol/server attack families remain feed-driven.
- Asset-specific families remain `ASSET_BASED`; Strict does not invent asset inventory.
- Broad informational, policy, hunting and convenience-telemetry families are disabled by profile policy.
- A disabled setter can still be restored when an enabled detection genuinely requires it as a flowbit/xbit dependency.
- Alert tuning remains enabled.
- Unknown/unmapped categories are disabled, matching the profile's high-signal intent.

Strict is intentionally not “disable everything except a SID list”; it keeps reviewed high-signal category families and preserves dependency correctness.

## Lab / Experimental

For SOC practice, detection validation and SIEM testing where useful variety is wanted without the near-firehose behavior of Noisy.

- Starts from the Balanced category posture.
- Enables broader ET INFO and TFTP visibility with alert tuning.
- Enables several organization-policy detection families useful for exercises and SIEM pipelines.
- Keeps alert tuning enabled so repetitive training traffic does not dominate the event stream.
- Does not fabricate SCADA/VoIP/ActiveX inventory.
- Unknown/unmapped feed categories preserve their upstream feed state.

## Server

A server-oriented profile for sensors protecting server workloads.

- Generic web-server and Nginx context are **ON**.
- SCADA/ICS, ActiveX and VoIP are **OFF** by default for this profile.
- Mobile-malware, games and inappropriate-content categories are disabled.
- Client/lifestyle-oriented organization-policy noise is reduced.
- Cleartext-credential and unexpected outbound-database visibility are enabled.
- Core malware/exploit/C2/server detection and dependency restoration remain available.
- Unknown/unmapped feed categories preserve their upstream feed state.

Review application-specific assets after applying Server if the host runs products other than Nginx.

## Profile safety rule

Profiles are starting policy presets, not substitutes for environment knowledge. `PRESERVE_FEED` never means “force-enable an upstream-disabled rule”, and dependency restoration only restores a setter that is actually required by a rule which remains enabled. Review the Effective Policy Summary before tuning.
