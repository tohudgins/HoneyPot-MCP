# Documentation

An index of the documentation, grouped by what you are trying to do.

## Understand

| Read this | When |
|---|---|
| [../README.md](../README.md) | You want to know what the project is, in a page. |
| [REFERENCE.md](REFERENCE.md) | You want the detailed product reference: engines, tools, honeytokens, integrations and configuration. |
| [RESULTS.md](RESULTS.md) | You want the evidence: what the sensors captured in five days on a public IP, and what running them live exposed. |
| [../KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md) | You want to know what does not work, and why. Fixed items are not listed; the history is in the changelog. |
| [screenshots/](screenshots/) | You want the images: generated demo-stack screenshots and, under `real-run/`, captures from the live deployment. |

## Deploy

| Read this | When |
|---|---|
| [DEPLOY.md](DEPLOY.md) | You are putting it on a VPS: hardening, firewall, tokens, Grafana, leaving it unattended, taking a backup, and analysing it afterwards. |
| [HARDENING.md](HARDENING.md) | You want the threat model: what a compromised honeypot can and cannot reach, and the residual risks. |

## Verify

| Read this | When |
|---|---|
| [FIELD_TEST.md](FIELD_TEST.md) | You want to reproduce the verification: real clients against every engine, every MCP tool against live data, an independent SQL oracle and a prompt-injection test. |

The scripts it describes are in `scripts/`: `field_test.py`, `field_test_tools.py`, `field_test_ops.py`,
`field_test_oracle.py`, `field_test_injection.py`, and `analyze_backup.py` for reports on a backup.

## Contribute

| Read this | When |
|---|---|
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | You are sending a change: setup, checks, and the project's non-obvious rules. |
| [../CLAUDE.md](../CLAUDE.md) | You are changing the code: architecture, invariants and development notes. |
| [../CHANGELOG.md](../CHANGELOG.md) | You want the reasoning behind a change, with the measurement that motivated it. |
| [../SECURITY.md](../SECURITY.md) | You found a vulnerability, or want the threat model for the control plane. |
