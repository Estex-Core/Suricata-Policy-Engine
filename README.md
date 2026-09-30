# Suricata Policy Engine

**Suricata Policy Engine 2.0.0rc2** is a release-candidate, TUI-first Policy-as-Code engine for tuning Suricata rulesets with explicit policy, asset context, semantic selectors, tracked-SID guardrails, stateful dependency restoration, alert tuning, validation, and safe activation.

The project does **not** ship a fixed "golden ruleset." It reapplies policy to a fresh Suricata feed so upstream rule updates remain part of the workflow.

> **Status:** Release Candidate. This release was regression-tested and audited against a real 68,980-rule Suricata/ET feed supplied for validation. Re-run Feed Audit whenever the upstream feed materially changes.

## Highlights

- TUI-first operator workflow; CLI, Rule Explorer and read-only Feed Audit are also included.
- Low-latency SSH-friendly scrolling, contextual `?` help, and bottom-panel explanations for policy screens.
- Category modes: `PRESERVE_FEED`, `DISABLE`, `ASSET_BASED`, `CONDITIONAL`.
- Evidence-driven asset matching using metadata first, then controlled aliases/regex fallback, including a dedicated Databases inventory plus an on-demand census of every `affected_product` value in the operator's current `suricata.rules`.
- Organization policy for usage-sensitive categories plus conservative semantic selectors inside mixed `ET POLICY` rules, without suppressing unrelated threat detections.
- Semantic selectors plus tracked-SID drift guardrails, with Check SIDs, Explain SID and Feed Audit views.
- Explicit `flowbits` / `xbits` dependency graph with transitive restoration, cycle detection, OR semantics, and restoration trace.
- Ambiguous/toggle-only dependencies are surfaced for review rather than forced on.
- Alert tuning and per-SID overrides without auto-disabling noisy detections.
- Candidate staging, `suricata -T`, atomic activation, runtime `-S`/`-c` conflict detection, live-vs-staged verification, and rollback safeguards.
- Read-only full-feed audit for category drift, asset evidence, dependency issues, and tracked-SID integrity.
- Six operator profiles: **Raw**, **Balanced**, **Noisy**, **Strict**, **Lab / Experimental**, and **Server**. Raw is a true feed pass-through starting point for manual tuning.

## Requirements

- Linux (Ubuntu is the primary tested operator environment)
- Python 3.10+
- `pipx` for the recommended installation workflow
- Suricata for production validation/activation workflows

## Quick start

Clone or download the repository, then from the repository root:

```bash
sudo apt update
sudo apt install -y python3 pipx
pipx install .
```

Start the TUI:

```bash
sudo ~/.local/bin/suricata-policy-engine
```

If you intentionally installed the package with `sudo pipx install .`, the executable is normally under `/root/.local/bin/` instead.

### Other commands

```bash
suricata-policy-engine-tui
suricata-policy-engine-cli --help
suricata-policy-engine-explore --help
suricata-policy-engine-audit --help
```

## Read-only full-feed audit

Run this before trusting a materially changed feed:

```bash
sudo ~/.local/bin/suricata-policy-engine-audit \
  --rules /var/lib/suricata/rules/suricata.rules \
  --output /tmp/suricata-policy-engine-feed-audit.json
```

The audit does **not** deploy or rewrite production rules. It reports unknown category families, asset-match evidence/ambiguity, disabled-asset matches, dependency edges/cycles/missing producers, metadata inventory, and tracked-SID integrity. A Markdown report is written alongside the JSON report.

## Decision model

```text
Fresh feed
  -> Category / Mode
  -> Strategy (only when CONDITIONAL)
  -> Asset / Organization policy
  -> Semantic selectors / tracked SID exceptions
  -> flowbits / xbits dependency restoration
  -> Alert tuning
  -> Validation
  -> Tuned ruleset
```

For the detailed model, see [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md).

## Safety model

The recommended production path keeps the original `suricata.rules` intact and activates `suricata-tuned.rules` only after validation. The destructive Replace action instead overwrites `suricata.rules` itself after backup, SHA256 verification and validation. Internal state/history is stored outside the rules directory; normal visible tuner outputs are `suricata-tuned.rules` and `suricata-tuned.diff.txt`.

A disabled rule is not necessarily useless. Policy decisions should remain explainable, reviewable, and reversible.

## Development

Create a virtual environment and install the project in editable mode with development dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e '.[dev]'
pytest -q
```

The 2.0.0rc2 tree is regression-tested across engine, TUI, profile migration, dynamic feed-product discovery, regex/selector validation, activation safeguards, dependency graphs, and packaging. CI runs the suite across Python 3.10–3.13 and performs a clean-wheel package smoke test.

## Repository layout

```text
.github/                CI, release workflow, security/contribution templates
src/                    engine, TUI, audit, explorer, telemetry
src/suricata_policy_engine_data/
                        packaged policy/baseline data
tests/                  regression and invariant tests
docs/                   current architecture/policy documentation
tuning-policy.yaml      reference/default policy
pyproject.toml           package metadata and console scripts
```

## Documentation

- [Documentation index](docs/README.md)
- [How it works](docs/HOW-IT-WORKS.md)
- [Policy reference](docs/POLICY-REFERENCE.md)
- [Profiles](docs/PROFILES.md)
- [Release notes 2.0.0rc2](docs/RELEASE-NOTES-2.0.0rc2.md)
- [Backend audit 2.0.0b3](docs/BACKEND-AUDIT-2.0.0b3.md)
- [Current release notes](RELEASE-NOTES.md)

Historical WebUI/portable documentation is retained under `docs/archive/` only for project history; it is not the current supported interface.

## Contributing and security

See [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md) before submitting changes. Security-sensitive issues should follow [.github/SECURITY.md](.github/SECURITY.md) and should not disclose exploit details in a public issue.

## License

MIT — see [LICENSE](LICENSE).
