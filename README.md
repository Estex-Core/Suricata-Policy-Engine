# Suricata Policy Engine

A policy-driven engine for tuning Suricata rulesets with safe automation, threat-hunting profiles, dependency-aware optimization, and explainable security decisions.
You tell me what you have or want, i narrow down the rules

## Overview

Have you ever update the suricata rules and wondered that do i really need 60k rule ?! Either the network is not that vast or the resources for every alert is not enough ! or even i have 500 rules for a device that i event don't have!

Here comes the SuriTuner 😁

Suricata Policy Engine helps security teams manage large Suricata rulesets without manually editing thousands of signatures.

The engine applies explicit policies based on rule categories, asset context, semantic selectors, dependencies, and security requirements to generate optimized rulesets.

It does not provide a fixed "golden ruleset". Instead, policies are reapplied to updated Suricata feeds so upstream rule changes remain part of the workflow.

## Features

- Policy-based Suricata ruleset tuning
- Balanced, Strict, Raw, Noisy, and Lab profiles
- Semantic rule classification and selection
- Threat-hunting focused optimization
- Flowbits and xbits dependency restoration
- Asset-aware rule management
- Rule validation before activation
- Safe deployment and rollback workflow
- Explainable tuning decisions

## Installation

### Requirements

- Linux (Ubuntu recommended)
- Python 3.10+
- Suricata
- pipx

### Quick Install

Clone the repository:

```bash
git clone https://github.com/Estex-Core/Suricata-Policy-Engine.git

cd Suricata-Policy-Engine
```

Install:

```bash
sudo ./install.sh
```

Verify:

```bash
suricata-policy-engine --help
```

## Usage

Main commands:

```bash
suricata-policy-engine
```

Additional tools:

```bash
suricata-policy-engine-tui
suricata-policy-engine-cli --help
suricata-policy-engine-audit --help
suricata-policy-engine-explore --help
```


## Safety Model

The engine does not overwrite the original Suricata ruleset by default.

Generated rulesets can be reviewed, validated, activated, and rolled back safely.

The workflow is designed to keep security decisions:

- Reviewable
- Explainable
- Reversible

## Architecture

Decision flow:

```
Suricata Feed
      |
      v
Policy Evaluation
      |
      v
Category & Semantic Analysis
      |
      v
Asset Context
      |
      v
Dependency Restoration
      |
      v
Validation
      |
      v
Optimized Ruleset
```

## Development

For contributors:

```bash
python3 -m venv .venv

source .venv/bin/activate

pip install -e .
```

Run tests:

```bash
pytest
```

## Documentation

- [Documentation index](docs/README.md)
- [How it works](docs/HOW-IT-WORKS.md)
- [Policy reference](docs/POLICY-REFERENCE.md)
- [Profiles](docs/PROFILES.md)
- [Release notes 2.0.0rc2](docs/RELEASE-NOTES-2.0.0rc2.md)
- [Backend audit 2.0.0b3](docs/BACKEND-AUDIT-2.0.0b3.md)
- [Current release notes](RELEASE-NOTES.md)
  
## Contributing

Contributions, improvements, and security feedback are welcome.

Please review project guidelines before submitting changes.

## License

MIT License
