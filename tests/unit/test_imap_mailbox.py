"""The IMAP parsing and formatting helpers, tested directly against the RFC 3501 grammar.

These are the parts a real mail client is least forgiving about: one wrong parenthesis in a
BODYSTRUCTURE and Thunderbird shows an empty message, one wrong octet count in a literal and
the whole session desyncs. Expected strings are the ones Dovecot produces for the same input.
"""

import pytest

from honeypot_mcp.engines import imap_mailbox as m

PLAIN = (
    b"From: Ann Lee <ann@corp.local>\r\nTo: bob@corp.local\r\nSubject: Hello there\r\n"
    b"Date: Mon, 05 Oct 2026 10:00:00 +0000\r\nMessage-ID: <a1@corp.local>\r\n"
    b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nline one\r\nline two\r\n"
)

MULTI = (
    b"From: a@x.example\r\nTo: b@y.example\r\nSubject: =?utf-8?q?caf=C3=A9?=\r\n"
    b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=BND\r\n\r\n"
    b"--BND\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
    b"caf=C3=A9 =\r\nlatte\r\n"
    b'--BND\r\nContent-Type: application/octet-stream; name="a.bin"\r\n'
    b'Content-Disposition: attachment; filename="a.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
    b"AAECAwQF\r\n--BND--\r\n"
)


# ── sequence sets ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("text", "largest", "expected"),
    [
        ("3", 5, [3]), ("1:3", 5, [1, 2, 3]), ("1,4,7:9", 9, [1, 4, 7, 8, 9]),
        ("*", 4, [4]),  # `*` is the largest number, not "everything"
        ("1:*", 3, [1, 2, 3]), ("2:*", 1, [1]),  # a range past the end still matches the last
        ("5:2", 6, [2, 3, 4, 5]),  # reversed range means the same
        ("0", 5, []), ("9", 5, []), ("", 5, []), ("a,b", 5, []), ("1:x", 5, []),
        ("\u0663", 5, []),  # int() would accept Arabic-Indic digits
        ("*", 0, []),
    ],
)  # fmt: skip
def test_sequence_sets(text, largest, expected):
    assert m.parse_seqset(text, largest) == expected


def test_valid_seqset_separates_bad_syntax_from_no_match():
    assert m.valid_seqset("1:5,7,9:*") and m.valid_seqset("*")
    assert not m.valid_seqset("") and not m.valid_seqset("1:") and not m.valid_seqset("a")


def test_uid_sets_resolve_against_the_messages_actual_uids():
    uids = [3, 7, 8, 12]
    assert m.uid_set_to_seqnums("7:8", uids) == [2, 3]
    assert m.uid_set_to_seqnums("*", uids) == [4]  # `*` is the highest UID
    assert m.uid_set_to_seqnums("4:6", uids) == []  # UIDs that were never assigned


# ── FETCH items ──────────────────────────────────────────────────────────────


def test_fetch_items_keep_bracketed_sections_whole_and_expand_macros():
    assert m.tokenize_fetch_items("FLAGS") == ["FLAGS"]
    assert m.tokenize_fetch_items("(UID FLAGS BODY.PEEK[HEADER.FIELDS (From Subject)])") == [
        "UID", "FLAGS", "BODY.PEEK[HEADER.FIELDS (From Subject)]",
    ]  # fmt: skip
    assert m.tokenize_fetch_items("FAST") == ["FLAGS", "INTERNALDATE", "RFC822.SIZE"]
    assert m.tokenize_fetch_items("all")[-1] == "ENVELOPE"
    assert m.tokenize_fetch_items("FULL")[-1] == "BODY"


def test_body_items_parse_section_peek_and_partial():
    assert m.parse_body_item("BODY[]") == (False, "", None)
    assert m.parse_body_item("body.peek[HEADER]") == (True, "HEADER", None)
    assert m.parse_body_item("BODY.PEEK[1.2]<0.1024>") == (True, "1.2", (0, 1024))
    assert m.parse_body_item("BODY[TEXT]<100>") == (False, "TEXT", (100, None))
    assert m.parse_body_item("FLAGS") is None


# ── strings and ENVELOPE ─────────────────────────────────────────────────────


def test_strings_are_quoted_escaped_or_sent_as_literals():
    assert m.imap_string(None) == "NIL" and m.imap_string("") == '""'
    assert m.imap_string('a "b" \\c') == '"a \\"b\\" \\\\c"'
    # non-ASCII cannot be quoted: a literal whose length is the UTF-8 byte count
    assert m.imap_string("café") == "{5}\r\ncafé"
    assert m.imap_string("two\r\nlines").startswith("{")  # CR/LF never inside quotes


def test_envelope_matches_what_dovecot_sends():
    assert m.build_envelope(PLAIN) == (
        '("Mon, 05 Oct 2026 10:00:00 +0000" "Hello there" '
        '(("Ann Lee" NIL "ann" "corp.local")) (("Ann Lee" NIL "ann" "corp.local")) '
        '(("Ann Lee" NIL "ann" "corp.local")) ((NIL NIL "bob" "corp.local")) NIL NIL NIL "<a1@corp.local>")'
    )  # Sender and Reply-To fall back to From when absent


def test_envelope_keeps_encoded_words_and_survives_commas_in_display_names():
    assert '"=?utf-8?q?caf=C3=A9?="' in m.build_envelope(MULTI)
    raw = b'From: "Doe, John" <j@x.example>\r\nTo: a@b.example\r\nSubject: s\r\n\r\nbody'
    assert '(("Doe, John" NIL "j" "x.example"))' in m.build_envelope(raw)
    assert m.build_envelope(b"\r\n").count("NIL") >= 8  # a header-less message does not crash


# ── BODYSTRUCTURE ────────────────────────────────────────────────────────────


def test_a_plain_message_has_dovecots_bodystructure():
    assert m.build_bodystructure(PLAIN) == (
        '("TEXT" "PLAIN" ("CHARSET" "us-ascii") NIL NIL "7BIT" 20 2 NIL NIL NIL NIL)'
    )
    assert m.build_bodystructure(PLAIN, extended=False) == (
        '("TEXT" "PLAIN" ("CHARSET" "us-ascii") NIL NIL "7BIT" 20 2)'
    )


def test_a_multipart_reports_encoded_sizes_and_dispositions():
    structure = m.build_bodystructure(MULTI)
    assert structure.startswith('(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "QUOTED-PRINTABLE" ')
    # the base64 part's size is its encoded text; the CRLF before the boundary belongs to the
    # boundary, not to the part
    assert (
        '"BASE64" 8 ' in structure
        and '"QUOTED-PRINTABLE" 18 1 ' in structure
        and '("ATTACHMENT" ("FILENAME" "a.bin"))' in structure
    )
    assert structure.rstrip(")").count('"MIXED"') == 1
    assert structure.count("(") == structure.count(")")


def test_message_parts_and_delivery_status_do_not_break_the_structure():
    from honeypot_mcp.engines.mail_message import build_dsn

    notice = build_dsn(
        hostname="mail.corp.local", queue_id="4F2A", sender="a@corp.local",
        failed=[("x@nowhere.invalid", "Host not found")],
        original_headers="From: a@corp.local\r\nTo: x@nowhere.invalid",
    )  # fmt: skip
    structure = m.build_bodystructure(notice)
    assert '"REPORT"' in structure and '"DELIVERY-STATUS"' in structure
    assert structure.count("(") == structure.count(")")
    wrapped = (
        b"From: a@x.example\r\nContent-Type: message/rfc822\r\n\r\n"
        b"From: in@x.example\r\nSubject: inner\r\n\r\ninner body\r\n"
    )
    assert '"MESSAGE" "RFC822"' in m.build_bodystructure(wrapped)


def test_pathological_nesting_is_cut_off_not_followed():
    nested = (
        b"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
        + b"--b\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" * 400
    )
    assert m.build_bodystructure(nested).count("(") < 5000


# ── sections ─────────────────────────────────────────────────────────────────


def test_sections_of_a_flat_message():
    header, body = PLAIN.split(b"\r\n\r\n", 1)
    assert m.fetch_section(PLAIN, "", None) == PLAIN
    assert m.fetch_section(PLAIN, "HEADER", None) == header + b"\r\n\r\n"
    assert m.fetch_section(PLAIN, "TEXT", None) == body
    assert m.fetch_section(PLAIN, "", (0, 10)) == PLAIN[:10]
    assert m.fetch_section(PLAIN, "TEXT", (5, None)) == body[5:]
    assert m.fetch_section(PLAIN, "HEADER", (10**6, 5)) == b""


def test_header_fields_selects_and_excludes_and_keeps_folded_lines():
    raw = b"Subject: a\r\n folded\r\nFrom: x@y.example\r\nTo: z@y.example\r\n\r\nbody"
    assert m.fetch_section(raw, "HEADER.FIELDS (subject FROM)", None) == (
        b"Subject: a\r\n folded\r\nFrom: x@y.example\r\n\r\n"
    )
    assert m.fetch_section(raw, "HEADER.FIELDS.NOT (Subject)", None) == (
        b"From: x@y.example\r\nTo: z@y.example\r\n\r\n"
    )
    assert m.fetch_section(raw, "HEADER.FIELDS (Nothing)", None) == b"\r\n"


def test_numbered_parts_return_the_bytes_as_stored_not_decoded():
    """BODY[1] of a quoted-printable part is the quoted-printable text; decoding it would
    corrupt an attachment the client then decodes itself."""
    assert m.fetch_section(MULTI, "1", None).startswith(b"caf=C3=A9 =")
    assert m.fetch_section(MULTI, "2", None).strip() == b"AAECAwQF"
    assert b"Content-Disposition: attachment" in m.fetch_section(MULTI, "2.MIME", None)
    assert m.fetch_section(MULTI, "3", None) == b"" and m.fetch_section(MULTI, "1.9", None) == b""
    assert m.fetch_section(MULTI, "garbage[", None) == b""


def test_a_single_part_message_is_part_one():
    assert m.fetch_section(PLAIN, "1", None) == b"line one\r\nline two\r\n"


# ── SEARCH ───────────────────────────────────────────────────────────────────


def _hit(criteria: str, flags=frozenset(), raw=PLAIN, seq=1, uid=1, count=3, largest=3):
    return m.matches_search(
        raw, seq, uid, set(flags), m.tokenize_search(criteria), count=count, largest_uid=largest
    )


def test_search_keys_flags_headers_and_text():
    assert _hit("ALL") and _hit("UNSEEN") and not _hit("SEEN")
    assert _hit("SEEN", {"\\Seen"}) and _hit("DELETED", {"\\Deleted"})
    assert _hit('SUBJECT "hello"') and not _hit('SUBJECT "absent"')
    assert _hit("FROM ann") and _hit("TO bob") and _hit('HEADER Message-ID "a1@"')
    assert _hit("BODY line") and not _hit("BODY bob@corp.local")  # BODY ignores headers
    assert _hit("TEXT bob@corp.local")  # TEXT does not
    assert _hit("LARGER 10") and _hit("SMALLER 100000") and not _hit("SMALLER 10")


def test_search_boolean_structure_not_or_and_parentheses():
    assert _hit("NOT SEEN") and not _hit("NOT UNSEEN")
    assert _hit("OR SEEN UNSEEN") and not _hit("OR SEEN DELETED")
    assert _hit("(FROM ann SUBJECT hello)") and not _hit("(FROM ann SUBJECT nope)")
    assert _hit("OR (FROM nobody) (TO bob)") and not _hit("NOT OR FROM ann TO bob")
    assert _hit("UNSEEN NOT DELETED FROM ann")  # implicit AND


def test_search_by_sequence_uid_and_date():
    assert _hit("2:3", seq=2) and not _hit("2:3", seq=1) and _hit("*", seq=3)
    assert _hit("UID 5:*", uid=5, largest=9) and not _hit("UID 6", uid=5, largest=9)
    assert _hit("SINCE 01-Oct-2026") and not _hit("SINCE 06-Oct-2026")
    assert _hit("BEFORE 06-Oct-2026") and _hit("ON 05-Oct-2026") and not _hit("ON 04-Oct-2026")


@pytest.mark.parametrize(
    "bad", ["NOSUCHKEY", "FROM", "OR SEEN", "(SEEN", "SINCE yesterday", "LARGER x", "UID !"]
)
def test_invalid_search_syntax_is_an_error_not_a_silent_match(bad):
    with pytest.raises(m.SearchError):
        m.validate_search(m.tokenize_search(bad))
    with pytest.raises(m.SearchError):
        m.validate_search([])


def test_search_tokenizer_honours_quotes_and_splits_parentheses():
    assert m.tokenize_search('SUBJECT "two words" (SEEN)') == [
        "SUBJECT",
        "two words",
        "(",
        "SEEN",
        ")",
    ]
    assert m.tokenize_search(r'FROM "a \"q\" b"') == ["FROM", 'a "q" b']


def test_internaldate_is_a_valid_imap_date_even_without_a_date_header():
    assert m.internaldate(PLAIN) == "05-Oct-2026 10:00:00 +0000"
    assert len(m.internaldate(b"Subject: x\r\n\r\n")) == len("05-Oct-2026 10:00:00 +0000")
