# Suricata Policy Engine 2.0.0b3 — Backend Audit

## What was wrong

### 1. Dependency restoration had no explicit graph
The previous engine reached transitive flowbits/xbits restoration through repeated full-ruleset scans. The final state was often correct, but the engine did not retain an auditable consumer-SID -> producer-SID graph. As a result, dependency cycles, exact restoration paths, and consumer-specific missing requirements were not represented explicitly.

### 2. Web asset matching hid disabled assets and could be order-dependent on ties
The previous matcher considered only enabled `web_specific_apps` when choosing the best candidate. A rule that strongly identified a configured-but-disabled product was therefore reduced to a generic no-enabled-match decision. Also, equally strong matches were resolved implicitly by YAML iteration order rather than being treated as ambiguous.

### 3. There was no one-shot full-feed compatibility audit
The engine had individual warnings/reports, but no read-only command that inventories an entire current feed for unknown category families, evidence-based asset outcomes, dependency graph/cycles/missing producers, metadata drift and tracked-SID integrity in one artifact.

## What changed

- Added explicit static dependency graph generation for flowbits/xbits.
- Dependency graph edges are `consumer_sid -> producer_sid` and retain requirement type/name.
- Dependency restoration now traverses the graph from initially enabled rules and recursively restores reachable producers.
- Added dependency cycle detection (including self-cycles) and restoration-edge trace.
- Existing OR semantics are preserved: all known producer paths for an `isset,a|b` expression remain available so coverage is not silently narrowed.
- Toggle-only dependencies remain review-only because `toggle` does not guarantee the bit becomes set.
- Web asset matching now scores all configured assets, whether enabled or disabled.
- A unique strong disabled-asset match is explicitly reported as `matched_disabled`.
- Equal strongest asset candidates are now `ambiguous` / review-required rather than depending on YAML order.
- Match candidates and evidence are retained on each rule for explainability.
- Added `suricata-policy-engine-audit`, a read-only full-feed audit command.
- Added regression coverage for dependency cycles/transitive restoration, disabled-asset identification, tied asset ambiguity and feed-audit reporting.

## Verification

- Regression suite: 106/106 PASS.
- Wheel build: PASS.
- Installed-wheel import smoke test: PASS.
- Installed-wheel audit smoke test on a synthetic ruleset: PASS.
- Synthetic audit correctly reported a reachable dependency cycle, an unknown category family and a configured disabled-asset match.

## Production-feed limitation

The complete production `suricata.rules` referenced historically (~68k rules) was not present in the uploaded files, so this release does **not** claim a fresh audit result for that exact feed. The new audit command is designed to run against it on the Ubuntu host without changing production rules.

Recommended command:

```bash
sudo /root/.local/bin/suricata-policy-engine-audit \
  --rules /var/lib/suricata/rules/suricata.rules \
  --output /tmp/suricata-policy-engine-feed-audit.json
```

It also writes `/tmp/suricata-policy-engine-feed-audit.md`.
