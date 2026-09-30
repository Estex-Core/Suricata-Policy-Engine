# Suricata Policy Engine TUI 2.0.0rc2

## Focus

This release candidate adds a true Raw/pass-through profile, separates destructive Replace semantics from normal Activate, reduces visible tuning artifacts to two files, and fixes a real-feed parser edge case discovered while auditing the supplied 68,980-rule Suricata ruleset.

## Raw profile

- Adds **Raw** alongside Balanced, Noisy, Strict, Lab / Experimental, and Server.
- All modeled categories use `PRESERVE_FEED`.
- Unknown/unmapped rules preserve upstream state.
- Automatic dependency restoration is OFF.
- Generated Alert Tuning is OFF.
- Feed-disabled rules remain disabled and feed-enabled rules remain enabled until the operator makes manual Advanced changes.
- The TUI warns that Raw is a pass-through starting point and that manual tuning must be configured explicitly.

## Replace Original

- `R / Replace Original` is now explicitly destructive and semantically distinct from Activate.
- The validated candidate is atomically copied over `suricata.rules`.
- The installed original path is SHA256-verified against the candidate.
- `suricata.yaml` is pointed back to `suricata.rules`.
- A post-install Suricata validation failure restores the backup.
- If validation passes but the live reload/restart fails, the requested file overwrite is kept and the TUI reports that the file changed but the live process may still have the previous in-memory ruleset.

## Lean outputs

Normal visible outputs beside the Suricata ruleset are now only:

- `suricata-tuned.rules`
- `suricata-tuned.diff.txt`

Internal report/state/history/threshold staging/locks are stored under the private application state directory instead of cluttering `/var/lib/suricata/rules`.

The old `.diff.txt.json` sidecar is removed; detailed SID lists are included in the single text diff report.

## Real-feed parser fix

The supplied feed contains PCRE expressions with literal double quotes inside a regex character class, e.g. SID `2029732`. The previous quote-aware tokenizer could treat the inner quote as the end of the PCRE option and therefore fail to see later `sid`, `rev`, and `metadata` options.

Across the supplied 68,980-rule feed, the old tokenizer missed 7 SID options. Six belonged to upstream-disabled rules; one feed-enabled rule, SID `2029732` (`ET PHISHING Common Unhidebody Function Observed in Phishing Landing`), was unintentionally absent from the supplied Strict output. The rc2 parser resolves SID options for all 68,980/68,980 rules.

## Validation

- Regression suite: **154/154 PASS** before packaging.
- Raw profile on the supplied real feed: `53,026` feed-enabled -> `53,026` final, `0` state mismatches, `0` dependency restorations.
- Supplied Strict tuned file: 31,174 exact rule lines from the original feed, 0 fabricated SIDs, 0 upstream-disabled rules resurrected.
- Dependency audit of the supplied tuned file: 761 requirements, 0 missing producers, 0 toggle-only requirements; one handled dependency cycle (`2006396 <-> 2006397`).
