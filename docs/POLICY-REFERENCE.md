# Policy Reference

This document defines the terms used by Suricata Policy Engine.

## Category Mode

`Mode` is the **first category-level decision**.

- `PRESERVE_FEED` — preserve the feed's enabled/disabled state. It does not force-enable rules that the feed ships disabled.
- `DISABLE` — disable the category by policy, except for a required dependency or an explicit higher-priority exception.
- `ASSET_BASED` — decide from the declared monitored assets/technologies.
- `CONDITIONAL` — the category needs a second-stage `Strategy` to resolve its state.

## Conditional Strategy

`Strategy` is used **only when Mode is `CONDITIONAL`**.

- `selective` — preserve upstream unless a narrower reviewed semantic/SID decision applies.
- `enabled_by_default` — preserve feed-enabled rules.
- `enabled_by_default_with_alert_tuning` — preserve detection and apply configured alert-rate tuning.
- `disabled_by_default` — keep the category off unless another policy decision enables it.
- `organization_policy` — resolve the whole mapped category from one organization usage/detection decision.
- `organization_policy_selective` — apply Organization Policy only to reviewed semantic families inside a mixed category; unmatched rules preserve upstream state.
- `default_disabled_with_allowlist` — keep only reviewed semantic/SID selections plus required dependencies.
- `message_filter` — preserve the category while filtering configured message families.

## Assets

Assets describe technologies that actually exist in the environment monitored by Suricata. Asset matching is evidence-driven: structured metadata is preferred, then controlled aliases/prefixes and explicit regex fallback. Ambiguous strongest matches are sent to review rather than resolved by YAML ordering.

The Standard Assets screen includes a **Databases** group (Microsoft SQL Server, MySQL, MariaDB, PostgreSQL, Oracle Database and SAP MaxDB). It also provides **Current feed products**, an on-demand census of every `metadata: affected_product ...` value found in the local `suricata.rules`. Reviewed assets use curated matchers; newly observed products can be enabled as exact metadata fallbacks. The shipped profiles keep `ET_SQL` on `PRESERVE_FEED` for safety. Database selections affect ET_SQL decisions only if the operator explicitly changes `ET_SQL` to `ASSET_BASED`.

## Organization Policy

Usage policy and detection policy are separate decisions. Example: `TOR = Prohibited + Detect` means TOR use is forbidden, therefore Suricata should still detect it.

Dedicated policy families include TOR, Remote Access/RMM, File Sharing, P2P, Chat, Dynamic DNS, Games and Inappropriate Content.

The engine also has conservative semantic Organization Policy selectors for mixed `ET POLICY` rules:

- Anonymizers / privacy networks
- Cloud storage / sharing
- Cleartext credentials
- Unexpected outbound database access

`ET POLICY` is intentionally **not** controlled by one global organization switch. It contains both pure usage-policy signatures and security-relevant detections. If no reviewed selector matches, the rule keeps its upstream feed state. Conflicting selector decisions also preserve upstream and are surfaced for review.

Security-signal families such as CoinMiner, Adware/PUP and Abused Services remain outside Organization Policy so allowing a service cannot silently suppress threat detection.

## Semantic Selectors

Meaning-oriented selectors identify important rules from message/metadata patterns instead of relying only on fixed SIDs. They make the policy more resilient when a feed revises or replaces a rule.

## Tracked SID

A tracked SID is a guardrail. The engine fingerprints selected important rules and reports changes to revision, message, category or detection logic. Tracked SIDs are not the primary semantic classification method.

## Rule Override

A precise per-SID exception for cases where category/semantic policy is not sufficient. Force-enable should be rare because it intentionally overrides the feed state.

## flowbits

State attached to a flow. If an enabled consumer requires a `flowbits:isset` value, the engine can restore a compatible required setter even if that setter belongs to a disabled category. OR groups such as `isset,a|b` are resolved as alternatives. `toggle` is not treated as a guaranteed setter.

## xbits

State that can correlate beyond a single flow. Dependency matching includes the xbit name and compatible tracking scope (`host`, `ip_pair`, `tx`, including source/destination direction handling). The explicit dependency graph records consumer→producer edges, transitive restoration and cycles.

## Alert Tuning

Thresholding reduces repeated **alerts** while leaving the detection rule enabled. The Standard **Alert Tuning** screen has a separate master switch for generated threshold/suppression controls; it does not turn detection rules off. Category defaults can be refined with per-SID overrides.

## Suppression

Suppresses alerts for a reviewed SID/IP context. Suppression is more specific than disabling a rule and should be used only when the context is known.

## Activation states

`Activate Tuned Rules` is allowed to report a **live switch** only after the configured rules target is validated and the running Suricata instance is successfully reloaded/restarted.

Before changing production configuration, the engine checks the live Suricata command line for:

- `-S` / `--sig-file` pointing at a different rules file.
- `-c` / `--config` pointing at a different configuration file.

If either conflicts, activation stops instead of claiming success. If no running Suricata instance exists, the result is reported as **staged**, not live.

## Unknown Categories

Unknown/new categories are **PRESERVE FEED STATE** in Raw, Balanced, Noisy, Lab / Experimental, and Server. Strict explicitly sets unknown categories to **DISABLE** so its high-signal posture is deterministic. Raw also disables automatic dependency restoration and Alert Tuning so its starting behavior is a true feed pass-through. The Dashboard shows the active fallback.
