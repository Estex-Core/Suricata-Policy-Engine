# Suricata Policy Engine

A policy-driven engine for tuning Suricata rulesets with safe automation, threat-hunting profiles, dependency-aware optimization, and explainable security decisions.

## Overview

Have you ever updated your Suricata rules and wondered:

"Do I really need all 60,000 rules?"

Maybe your network is not that large.
Maybe the available resources are not enough for every alert.
Or maybe you have hundreds of rules enabled for products that do not even exist in your environment.

This is where **SuriTuner** comes in. 😁

SuriTuner is a policy-driven engine that helps you tune Suricata rulesets with safe automation, threat-hunting profiles, dependency-aware optimization, and explainable security decisions.

Tell SuriTuner what you actually have — it helps narrow down what you actually need.

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

Main command:

```bash
suricata-policy-engine
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

```text
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


## Documentation

- [How it works](docs/HOW-IT-WORKS.md)
- [Policy reference](docs/POLICY-REFERENCE.md)
- [Profiles](docs/PROFILES.md)

## Contributing

Contributions, improvements, and security feedback are welcome.

Please review project guidelines before submitting changes.

## License

MIT License
