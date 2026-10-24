"""Packaging regressions: what `pip install` / `pipx install` / the container image would ship.

The failure these guard against is silent: the wheel builds, installs and imports, then misbehaves
at runtime because a data file, a dependency extra or a link is missing. Nothing here builds a
wheel (the build needs the network for build isolation); `release.yml` builds and smoke-tests the
real artifacts on every supported Python, and these checks keep its inputs honest offline.
"""

from __future__ import annotations

import re
import tomllib
from importlib import import_module
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())
PACKAGE = ROOT / "src" / "honeypot_mcp"


def test_every_wheel_artifact_glob_matches_a_file():
    # An artifacts glob that matches nothing is the "wheel is missing its data files" bug.
    artifacts = PYPROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]["artifacts"]
    assert artifacts
    for pattern in artifacts:
        assert list(ROOT.glob(pattern)), f"wheel artifact glob matches no file: {pattern}"


def test_every_packaged_data_directory_is_covered_by_an_artifact_glob():
    # The reverse direction: a data directory added to the package without a glob.
    artifacts = PYPROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]["artifacts"]
    covered = {path for pattern in artifacts for path in ROOT.glob(pattern) if path.is_file()}
    data = {
        path
        for path in PACKAGE.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix not in {".py", ".pyc", ".mako"}
        and path.name != "py.typed"
    }
    assert data, "no data files found: the package layout changed"
    assert data <= covered, f"data files not covered by an artifact glob: {sorted(data - covered)}"


def test_wheel_selects_the_package_and_migrations_are_inside_it():
    assert PYPROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        "src/honeypot_mcp"
    ]
    # Alembic runs from the installed package (`script_location` is resolved with
    # importlib.resources); a repo-root `alembic.ini` is not part of the wheel.
    assert (PACKAGE / "migrations" / "env.py").is_file()
    assert (PACKAGE / "migrations" / "script.py.mako").is_file()
    assert list((PACKAGE / "migrations" / "versions").glob("0*.py"))


def test_console_script_resolves_to_an_importable_callable():
    target = PYPROJECT["project"]["scripts"]["honeypot-mcp"]
    module_name, _, attribute = target.partition(":")
    assert callable(getattr(import_module(module_name), attribute))


def test_typed_classifier_is_backed_by_a_py_typed_marker():
    if "Typing :: Typed" in PYPROJECT["project"]["classifiers"]:
        assert (PACKAGE / "py.typed").is_file()


def test_metadata_a_package_index_requires():
    project = PYPROJECT["project"]
    assert project["requires-python"] == ">=3.11,<3.15"
    assert project["license"] == "MIT" and project["license-files"] == ["LICENSE"]
    assert (ROOT / "LICENSE").is_file()
    assert project["keywords"] and project["urls"]["Homepage"].startswith("https://")
    # Every supported interpreter has a classifier (and nothing beyond the declared range).
    versions = {
        c.rsplit(" ", 1)[-1]
        for c in project["classifiers"]
        if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", c)
    }
    assert versions == {"3.11", "3.12", "3.13", "3.14"}
    # The README is built into the metadata by the readme hook, as Markdown.
    assert project["dynamic"] == ["readme"] and "readme" not in project
    hook = PYPROJECT["tool"]["hatch"]["metadata"]["hooks"]["fancy-pypi-readme"]
    assert hook["content-type"] == "text/markdown"
    assert "hatch-fancy-pypi-readme" in " ".join(PYPROJECT["build-system"]["requires"])


def test_readme_has_no_repo_relative_link_left_after_the_metadata_rewrite():
    # PyPI renders the README off GitHub, where `docs/REFERENCE.md` and the screenshots resolve
    # to nothing. Apply the same substitutions the build applies and look for what is left.
    hook = PYPROJECT["tool"]["hatch"]["metadata"]["hooks"]["fancy-pypi-readme"]
    text = (ROOT / hook["fragments"][0]["path"]).read_text()
    for substitution in hook["substitutions"]:
        text = re.sub(substitution["pattern"], substitution["replacement"], text)
    relative = re.findall(r"\]\((?!https?://|#|mailto:)[^)]*\)", text)
    relative += re.findall(r"""(?:src|href)=["'](?!https?://|#|mailto:)[^"']*""", text)
    assert not relative, f"README links that stay repo-relative on PyPI: {relative}"


def test_sdist_is_a_whitelist_that_leaves_local_state_out():
    sdist = PYPROJECT["tool"]["hatch"]["build"]["targets"]["sdist"]
    included = sdist["include"]
    for needed in ("/src", "/tests", "/README.md", "/LICENSE", "/alembic.ini", "/uv.lock"):
        assert needed in included, f"sdist must carry {needed}"
    # Files hatch would otherwise pick up because .gitignore does not name them.
    for local_state in (".hypothesis", ".claude", "reports", ".serena"):
        assert not any(entry.lstrip("/").startswith(local_state) for entry in included)
    for entry in included:
        assert (ROOT / entry.lstrip("/")).exists(), f"sdist include is missing on disk: {entry}"


def _lock_package(name: str) -> dict:
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    return next(p for p in lock["package"] if p["name"] == name)


def test_image_installs_the_forensics_extra_from_the_hashed_lock():
    dockerfile = (ROOT / "docker" / "Dockerfile.mcp").read_text()
    export = re.search(r"uv export[^\n]*", dockerfile)
    assert export, "the image no longer exports the lock"
    assert "--extra forensics" in export.group(0), "sample_scan would be unavailable in the image"
    assert "--no-dev" in export.group(0) and "--frozen" in export.group(0)
    assert "--require-hashes" in dockerfile


def test_image_python_has_prebuilt_yara_wheels_for_both_architectures():
    # `pip install --no-deps --require-hashes` must not compile: yara-python needs a manylinux
    # wheel for the image's interpreter on amd64 and arm64 (the release builds both).
    base = re.search(
        r"^FROM python:(\d+)\.(\d+)", (ROOT / "docker" / "Dockerfile.mcp").read_text(), re.M
    )
    assert base
    tag = f"cp{base.group(1)}{base.group(2)}"
    wheels = " ".join(w["url"] for w in _lock_package("yara-python")["wheels"])
    for arch in ("x86_64", "aarch64"):
        assert re.search(rf"-{tag}-{tag}-manylinux[^ ]*{arch}\.whl", wheels), (tag, arch)


def test_forensics_extra_names_a_yara_engine_for_every_supported_python():
    extra = " ".join(PYPROJECT["project"]["optional-dependencies"]["forensics"])
    assert "yara-python" in extra and "yara-x" in extra
    assert "python_version < '3.14'" in extra and "python_version >= '3.14'" in extra


@pytest.fixture(scope="module")
def release() -> dict:
    return yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())


def test_release_triggers_only_on_final_tags_and_cannot_publish_from_a_branch(release):
    # PyYAML reads the bare key `on` as the boolean True.
    triggers = release.get("on", release.get(True))
    assert triggers["push"] == {"tags": ["v[0-9]+.[0-9]+.[0-9]+"]}
    assert "branches" not in triggers["push"]
    assert triggers["workflow_dispatch"] is None, (
        "a dispatch input could re-enable branch publishing"
    )


def test_release_publishing_jobs_are_gated_on_a_tag_and_an_environment(release):
    jobs = release["jobs"]
    for name in ("pypi", "container"):
        job = jobs[name]
        assert job["if"] == "github.ref_type == 'tag'", name
        assert "environment" in job, name
        assert {"check-version", "build", "smoke"} <= set(job["needs"]), name
    assert jobs["pypi"]["permissions"] == {"id-token": "write"}
    # Trusted publishing: no stored PyPI token, no secret other than the ephemeral GITHUB_TOKEN.
    secrets = set(re.findall(r"secrets\.(\w+)", yaml.safe_dump(release)))
    assert secrets <= {"GITHUB_TOKEN"}, secrets
    # Nothing outside the two publishing jobs may ask for write access.
    for name in ("check-version", "build", "smoke"):
        assert "permissions" not in jobs[name]
    assert release["permissions"] == {"contents": "read"}


def test_release_smoke_checks_the_installed_wheel_outside_the_source_tree(release):
    smoke = release["jobs"]["smoke"]
    assert smoke["strategy"]["matrix"]["python"] == ["3.11", "3.12", "3.13", "3.14"]
    script = yaml.safe_dump(smoke)
    for needle in (
        "forensics",  # YARA backend on every Python
        "alembic_version",  # migrations stamped, not the create_all fallback
        "samples.load_rules",
        "grafana.list_dashboards",
        "_handle_index",
        "suppression_list()",
        "py.typed",
        "list_tools",  # the console script speaks MCP
        "cd /tmp/elsewhere",
    ):
        assert needle in script, needle


def test_release_refuses_a_tag_or_runtime_version_that_disagrees_with_pyproject(release):
    script = release["jobs"]["check-version"]["steps"][1]["run"]
    assert "GITHUB_REF_NAME" in script and "__version__" in script and "exit 1" in script
