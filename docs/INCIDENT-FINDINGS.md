# October 2026 incident — SuriTuner Suricata parse logs

Source: user-provided JSON log (1,837 JSON lines).

- 917 lines report `Duplicate signature`.
- 918 lines report `error parsing signature`.
- 2 lines are informational Suricata log entries.
- 917 parsed signature errors have matching duplicate-signature messages by SID.
- **One parse error, SID `2071363`, does not have a matching duplicate-signature log line in this provided excerpt.** This is an independently unresolved parse error: actual Suricata version, neighboring warnings, and feed compatibility need checking. It would be unsafe to label every parse error merely secondary.

The presence of `suricata.rules` in error paths and the duplicate messages are **consistent** with duplicate rule loads, but the log by itself cannot establish if the load came from two YAML entries, a `-S` override, an included rules file, or multiple entries inside a feed. Inspect the active Suricata config and rule file inventory before deploying.

This patch prevents a known configuration rewrite path from adding multiple managed entries. It does not rewrite potentially invalid vendor signatures or guarantee compatibility with unknown Suricata releases. Use the read-only diagnostic and `suricata -T` on staging.
