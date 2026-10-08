"""Build the compose stack's Cowrie persona filesystem, inside the Cowrie image.

Run by the `cowrie-persona-init` service before `cowrie-ssh` starts. It loads the
two stdlib-only modules that define the personas and the filesystem rewrite
straight from their files (the honeypot_mcp package is not installed in the Cowrie
image), reads Cowrie's own bundled `fs.pickle`, rewrites it for the persona, and
writes the result into the shared `cowrie-persona` volume.

Persona and hostname come from the environment so that the compose file is the one
place that chooses them:  PERSONA (a key of ssh_personas._PERSONAS), COWRIE_HOSTNAME.
"""

import importlib.util
import os
import sys
from pathlib import Path

SRC = Path("/hp-src")
BASE = Path("/cowrie/cowrie-git/src/cowrie/data/fs.pickle")
OUT = Path("/persona/fs.pickle")


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SRC / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    personas = load("ssh_personas")
    cowrie_fs = load("cowrie_fs")
    persona_id = os.environ.get("PERSONA", "ubuntu_22_04")
    hostname = os.environ.get("COWRIE_HOSTNAME", "ubuntu-server")
    persona = personas._PERSONAS[persona_id]
    built = cowrie_fs.build_persona_fs(BASE.read_bytes(), persona, hostname, f"compose:{hostname}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(built)
    OUT.chmod(0o644)
    print(f"wrote {OUT} ({len(built)} bytes) for persona={persona_id} hostname={hostname}")
    # The container-side fingerprint hardening, imported first by Python via PYTHONPATH.
    patch = OUT.parent / "patch" / "sitecustomize.py"
    patch.parent.mkdir(parents=True, exist_ok=True)
    patch.write_bytes((SRC / "cowrie_sitecustomize.py").read_bytes())
    patch.chmod(0o644)
    patch.parent.chmod(0o755)
    print(f"wrote {patch}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
