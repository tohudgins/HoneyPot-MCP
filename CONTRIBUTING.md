# Contributing

Thanks for looking. This document covers the things that are specific to this
project — the general "fork, branch, PR" flow is what you'd expect.

## Setup

```bash
git clone https://github.com/tohudgins/HoneyPot-MCP.git
cd HoneyPot-MCP
uv sync --extra dev          # or: pip install -e ".[dev]"
```

`--extra dev` is required. Without it, `pytest`/`ruff`/`mypy` land outside the
virtualenv and `uv run pytest` silently falls through to whatever is on PATH.

```bash
uv run pytest tests/unit/ -q          # fast; milliseconds each
uv run pytest tests/integration/ -q   # binds real ports; seconds each
uv run ruff check src/ tests/
uv run ruff format src/ tests/
uv run mypy src/
```

All four are blocking in CI, plus a job that runs the suite against a real
PostgreSQL.

## The rules that aren't obvious

Most of what follows exists because it was learned the hard way. Architecture
details live in [CLAUDE.md](CLAUDE.md).

**Engines never write to the database.** Push events through
`submit_event(PendingEvent(...))`. A direct `get_session()` write from an engine
bypasses suppression, honeytoken correlation and webhook delivery.

**Tool responses go into a model's context window, so size is correctness.**
List tools return digests, detail tools expand one record, and bulk output goes
to a file. A single HTTP alert can carry 64 KB of captured body — a 200-row
query that inlines payloads can consume an entire context in one call.

**Fingerprint consistency is a feature.** An engine that reports one version in
one field and behaves like another version elsewhere is detectable, which
defeats the point. Keep one version constant per engine and derive everything
from it. New or changed wire formats should be checked with
`nmap -sV --version-intensity 9` and the real client library, and pinned in
`tests/unit/test_protocol_fidelity.py`.

**ATT&CK tactics must be correct.** Analysts know the framework; a technique
under the wrong tactic discredits everything else on the page. If you add an
event type, add its mapping in `intel/mitre.py` — an unmapped capture is
invisible in the dashboards.

**Alembic revision ids must be ≤ 32 characters.** `alembic_version.version_num`
is `VARCHAR(32)`. SQLite ignores the limit and PostgreSQL enforces it, so an
over-length id passes locally and breaks production. There's a test for it.

**Migrations must be idempotent**, guarding with `inspect()` before adding or
dropping. A regression test asserts `init_db()` never falls back to
`create_all()` on boot, which keeps that signal meaningful.

**New aiohttp servers must import `http_identity` and set their own `Server`
header.** aiohttp's default advertises Python and aiohttp, including on
protocol-level errors that no middleware can reach.

**State-changing tools should call `record_action()`.** The control plane is
driven by a language model; "what did the agent do?" needs an answer.

## Adding things

- **A honeypot engine** — subclass `HoneypotEngine`, register in
  `engines/__init__.py:get_engine()`.
- **A honeytoken type** — subclass `HoneytokenProvider`, register in
  `tokens/__init__.py`, add the enum value plus a migration.
- **An MCP tool module** — add an `import` line at the bottom of `server.py`, or
  the `@mcp.tool` decorators never run and the tools don't exist.

## Testing expectations

New behaviour needs a test. Prefer assertions about *why* something must hold
over exact values — the existing tests for risk scoring assert ordering and
band reachability rather than specific numbers, so the weights stay tunable.

If you're fixing a bug, add the test that would have caught it first.

## Security

Please don't file vulnerabilities as public issues — see
[SECURITY.md](SECURITY.md).

## Releasing

Publishing is tag-driven and deliberately manual — a PyPI version number can
never be reused, and a container tag is public the moment it lands.

1. Bump `version` in `pyproject.toml` **and** `__version__` in
   `src/honeypot_mcp/__init__.py`. A test asserts they match; the release
   workflow additionally refuses to publish if the git tag disagrees.
2. Update `CHANGELOG.md`.
3. Tag and push:

   ```bash
   git tag v0.2.0 && git push origin v0.2.0
   ```

`.github/workflows/release.yml` then builds the sdist and wheel, runs
`twine check --strict`, **installs the wheel into a clean environment outside
the source tree and asserts the bundled presets and console asset are present**,
publishes to PyPI via trusted publishing, and pushes a multi-arch
(amd64 + arm64) image to GHCR.

That smoke test exists because a wheel that omits its data files installs
perfectly and then fails at runtime: the console returns 500 and the bundled
suppression presets silently disappear. Both have happened.

**One-time setup** before the first release:

- PyPI: configure a [trusted publisher](https://pypi.org/manage/account/publishing/)
  for this repository and the `pypi` environment (no API token is stored).
- GitHub: create a `pypi` environment under Settings → Environments if you want
  a manual approval gate on publishes.

Use `workflow_dispatch` with `publish_pypi` off for a dry run — it builds and
verifies everything without publishing.
