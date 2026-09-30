# Suricata Policy Engine TUI 2.0.0b5

This beta release focuses on TUI correctness and operator clarity. Backend policy behavior from 2.0.0b4 is preserved except for the new optional database-asset path when an operator explicitly changes `ET_SQL` to `ASSET_BASED`.

## TUI responsiveness

- Long text/log viewers cache wrapped lines instead of re-wrapping the entire document on every Arrow-key press.
- Scrollable menus repaint only the old/new selected rows when the viewport does not move.
- This primarily targets SSH/terminal lag while navigating Category Policy and long viewers.

## Category Policy

Every category detail screen now exposes the same three primary controls:

1. `Mode`
2. `Conditional strategy`
3. `Fallback enabled`

Strategy/fallback values explicitly say when they are inactive, so early categories no longer look incomplete compared with later conditional categories.

## Check SIDs fix

The previous TUI resolver treated a relative `tracked-rules-baseline.json` as if it lived beside `tui.py`. That is correct for neither the packaged data directory nor a normal pipx materialized config. The tuning engine itself used the correct runtime baseline resolver; the defect was in the Check SIDs TUI path.

2.0.0b5 resolves the materialized/package baseline correctly and adds an `unbaselined` state for tracked SIDs that have no stored fingerprint. `OK / unchanged` now means the SID exists, has a baseline entry, and none of the tracked fingerprint fields changed.

## Databases / SQL assets

The Assets screen now includes:

- Microsoft SQL Server
- MySQL
- MariaDB
- PostgreSQL
- Oracle Database
- SAP MaxDB

`ET_SQL` remains `PRESERVE_FEED` in the shipped profiles. Database assets only control ET_SQL rules if the operator explicitly changes that category to `ASSET_BASED`, avoiding accidental loss of SQL exploit coverage.

## Alert Noise wording

The Standard setting now says plainly that it reduces repeated alert spam by generating threshold/suppression controls and **does not disable detection rules**.

## Activate wording

The post-tune `A` description is shortened: use `suricata-tuned.rules` for the live Suricata service, keep `suricata.rules` unchanged, and report success only after validation plus live reload/restart verification succeeds.

## Verification

- 135/135 regression tests PASS.
- Root and packaged policy files are kept identical.
- Wheel installation and packaged baseline/policy resolution are smoke-tested before release packaging.
