# Suricata Policy Engine

A policy-driven engine for intelligent Suricata ruleset tuning with threat-hunting profiles, dependency-aware optimization, and safe rule management.

## Overview

Suricata Policy Engine helps security teams manage large Suricata rulesets by applying explicit policies instead of manually editing signatures.

The engine analyzes rule categories, assets, dependencies, and security context to create optimized rulesets while preserving important detections.

It does not provide a fixed "golden ruleset". Instead, it reapplies policies to updated Suricata feeds, allowing upstream rule updates to remain part of the workflow.

## Key Features

- Policy-based Suricata ruleset tuning
- Balanced, Strict, Raw, Noisy, and Lab profiles
- Semantic rule classification and selection
- Threat-hunting focused optimization
- Flowbits and xbits dependency restoration
- Asset-aware rule management
- Rule validation and audit workflow
- Safe activation and rollback support
- Explainable policy decisions

## Installation

### Requirements

- Linux
- Python 3.10+
- Suricata
- pipx (recommended)

### Install

```bash
git clone https://github.com/Estex-Core/Suricata-Policy-Engine.git

cd Suricata-Policy-Engine

sudo apt install python3 pipx

pipx install .
```

## Usage

Start the engine:

```bash
suricata-policy-engine --help
```

Available workflows include:

- Ruleset tuning
- Feed auditing
- Policy evaluation
- Rule exploration
- Validation before activation

## Profiles

### Raw
Keeps the original Suricata feed as a baseline.

### Balanced
Production-oriented tuning focused on reducing noise while maintaining important detections.

### Strict
Aggressive filtering for environments requiring lower alert volume.

### Noisy
Maximum visibility for hunting and investigation environments.

### Lab
Experimental profile for testing new policies.

## Safety Model

The engine keeps the original Suricata ruleset unchanged until validation is completed.

Generated rulesets can be reviewed, tested, activated, or rolled back safely.

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

## Documentation

Detailed architecture, policy references, and usage guides are available in the `docs/` directory.

## Contributing

Contributions, improvements, and security feedback are welcome.

Please review the contribution and security guidelines before submitting changes.

## License

MIT License
