# Documentation

| Read this | When |
|---|---|
| [RESULTS.md](RESULTS.md) | You want to know what the honeypots saw in five days on the public internet, and what running them live taught the project. Start here. |
| [DEPLOY.md](DEPLOY.md) | You are putting it on a VPS: hardening, firewall, tokens, Grafana, leaving it unattended, taking a backup, and analysing it afterwards (analysis mode). |
| [FIELD_TEST.md](FIELD_TEST.md) | You want to reproduce the verification: real clients against every engine, every MCP tool against live data, an independent SQL oracle, and a prompt-injection test. |
| [HARDENING.md](HARDENING.md) | You want the threat model: what a compromised honeypot can and cannot reach, and the residual risks. |
| [../KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md) | You want to know what does not work, and why. Fixed items are not listed; the history is in the changelog. |
| [../CHANGELOG.md](../CHANGELOG.md) | You want the reasoning behind a change, with the measurement that motivated it. |
| [../CLAUDE.md](../CLAUDE.md) | You are changing the code: architecture, invariants, and the failure modes already paid for. |
| [screenshots/](screenshots/) | Demo-stack screenshots (generated, reproducible) and, under `real-run/`, three captured from the live deployment. |

The reproducible checks live in `scripts/`: `field_test.py`, `field_test_tools.py`, `field_test_ops.py`,
`field_test_oracle.py`, `field_test_injection.py` and `analyze_backup.py`.
