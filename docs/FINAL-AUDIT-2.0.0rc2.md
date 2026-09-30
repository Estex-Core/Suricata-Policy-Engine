# Suricata Policy Engine 2.0.0rc2 — Real Feed & Backend Audit

## Files audited

- `suricata.rules`
- `suricata-tuned.rules`

The tuned file header identifies the source SHA256 as:

`93806e2fe9bcadc4c8d6d9bb0a6b3297cf0edeab97a2d2216990ee2208d02dd0`

That hash matches the uploaded `suricata.rules`, so the tuned artifact was generated from the supplied raw feed.

## Feed counts

| Metric | Raw feed | Supplied Strict tuned file |
|---|---:|---:|
| File size | 45,789,761 bytes | 21,223,482 bytes |
| Unique rules/SIDs | 68,980 | 31,174 |
| Feed-enabled rules | 53,026 | 31,174 |
| Feed-disabled rules | 15,954 | 0 in tuned output |

### Integrity comparison

- Tuned SIDs are a strict subset of the raw feed: **PASS**.
- Extra/fabricated SIDs in tuned output: **0**.
- Tuned rule lines that differ from the corresponding raw rule: **0**.
- Revision mismatches for retained SIDs: **0**.
- Message mismatches for retained SIDs: **0**.
- Upstream-disabled rules resurrected into the supplied tuned output: **0**.
- Feed-enabled rules omitted by Strict/policy decisions: **21,852**.

The supplied Strict output therefore contains original feed rules verbatim rather than rewritten detection logic.

## Parser defect found from the real feed

The pre-rc2 option tokenizer toggled quote state on every unescaped double quote. Suricata PCRE values can contain literal double quotes inside regex character classes. Example from SID `2029732`:

`pcre:"/^["']?post/Ri";`

The inner `"` is regex data, not the end of the option. The old parser swallowed every option after that point and failed to see the SID.

A full 68,980-rule scan found 7 SIDs affected by this parser edge case:

- 2017487 — upstream disabled
- 2029732 — **upstream enabled**
- 2001099 — upstream disabled
- 2001101 — upstream disabled
- 2001102 — upstream disabled
- 2001103 — upstream disabled
- 2019728 — upstream disabled

Only SID `2029732` should have been retained by the Strict `ET_PHISHING` preserve policy and was unintentionally absent from the supplied tuned file.

### rc2 correction

The PCRE tokenizer now treats a quote as the closing PCRE quote only when it is followed by the option terminator. Full-feed verification after the fix:

- Rules scanned: **68,980**
- SID options parsed: **68,980**
- Missing SID parses: **0**
- SID mismatches: **0**

The actual SID `2029732` is now parsed as `ET_PHISHING` and remains enabled under Strict.

## Dependency audit of supplied tuned file

The rc2 engine loaded all 31,174 tuned rules and built the dependency graph:

- Dependency requirements: **761**
- Dependency edges: **9,226**
- Missing flowbit/xbit producers: **0**
- Toggle-only unresolved requirements: **0**
- Dependency cycles: **1**

The cycle is:

- SID 2006396 — `ET MALWARE Socks666 Connect Command Packet`
- SID 2006397 — `ET MALWARE Socks666 Successful Connect Packet Packet`

Cycles are represented explicitly by the graph and do not imply a missing dependency.

## Raw profile verification on the real feed

The new Raw profile was applied in-memory to the supplied 68,980-rule feed using the production engine:

- Feed-enabled: **53,026**
- Raw final-enabled: **53,026**
- Feed/final state mismatches: **0**
- Flowbit restorations: **0**
- Xbit restorations: **0**

This confirms Raw is a true pass-through starting point. Manual Advanced changes are the only policy changes after Raw is selected.

## Why Replace did not happen in the supplied files

The two uploaded files prove that the original file had not been overwritten:

- `suricata.rules`: 68,980 rules, 45.8 MB
- `suricata-tuned.rules`: 31,174 rules, 21.2 MB

The original SHA256 still equals the source hash recorded in the tuned artifact header. Therefore the old Replace workflow did not leave the tuned content installed at `suricata.rules`.

A likely cause in the previous semantics was rollback after a later reload/restart failure: Replace mixed “overwrite the file” and “successfully reload the live engine” into one transaction, so a reload problem could restore the raw feed. rc2 separates these outcomes.

### rc2 Replace contract

1. Candidate must already pass Suricata validation.
2. Back up original `suricata.rules` and production config.
3. Atomically overwrite `suricata.rules` with the candidate.
4. Verify candidate SHA256 equals installed `suricata.rules` SHA256.
5. Point `rule-files` to the original `suricata.rules` path.
6. Validate the production configuration again.
7. If validation fails, restore the backup.
8. If validation succeeds, the overwrite is committed.
9. If the subsequent live reload fails, report it separately; do not silently undo the explicitly requested validated overwrite.

## Output cleanup

The rules directory is no longer used for engine-internal state. Normal visible generated artifacts are:

- `suricata-tuned.rules`
- `suricata-tuned.diff.txt`

Internal report JSON, comparison state, threshold staging, history snapshots and process locks are stored in the private application state directory. The text diff now includes detailed SID lists, so no `.diff.txt.json` sidecar is generated.

## Regression result

Pre-package suite after the rc2 changes: **154/154 PASS**.
