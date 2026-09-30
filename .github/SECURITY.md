# Security Policy

Suricata Policy Engine changes IDS rule selection and can update production Suricata configuration. Treat policy changes like code changes: review diffs, validate candidates with `suricata -T`, and use staged activation/rollback where possible.

## Reporting a vulnerability

Do not publish exploit details, credentials, private rules, or production network data in a public issue. Prefer a private GitHub Security Advisory for the repository when available.

When reporting a security issue, include the affected version, a minimal sanitized reproduction, the expected security boundary, and the observed behavior.

## Operational scope

A successful engine run does not prove that a policy is appropriate for every environment. Asset inventory, organization policy, current feed compatibility, and Suricata configuration remain administrator-controlled inputs.
