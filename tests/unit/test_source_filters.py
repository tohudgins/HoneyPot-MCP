"""Address filters and scopes used to set sources aside from analysis results."""

from __future__ import annotations

import pytest

from honeypot_mcp.tools._sources import (
    MAX_FILTERS,
    make_matcher,
    parse_source_filters,
    source_scope,
)


def test_addresses_and_ranges_parse_and_a_bare_address_is_a_single_host():
    networks, errors = parse_source_filters(["203.0.113.7", " 198.51.100.0/24 ", "2001:db8::/32"])
    assert errors == []
    assert [str(n) for n in networks] == ["203.0.113.7/32", "198.51.100.0/24", "2001:db8::/32"]


def test_a_typo_is_an_error_not_an_empty_filter():
    networks, errors = parse_source_filters(["203.0.113.7", "203.0.113.700", "bogus"])
    assert len(networks) == 1
    assert len(errors) == 2 and "203.0.113.700" in errors[0] and "bogus" in errors[1]


def test_blank_entries_are_ignored_and_none_is_empty():
    assert parse_source_filters(None) == ([], [])
    assert parse_source_filters(["", "  "]) == ([], [])


def test_a_filter_list_is_bounded():
    _networks, errors = parse_source_filters(["203.0.113.1"] * (MAX_FILTERS + 1))
    assert any("at most" in e for e in errors)


def test_matcher_follows_networks_and_never_confuses_address_families():
    networks, _ = parse_source_filters(["198.51.100.0/24", "::1"])
    matches = make_matcher(networks)
    assert matches("198.51.100.77") and matches("::1")
    assert not matches("198.51.101.1") and not matches("127.0.0.1")
    assert not matches("not-an-ip"), "an unparseable source is never silently excluded"


@pytest.mark.parametrize(
    ("address", "scope"),
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("10.1.2.3", "private"),
        ("192.168.0.9", "private"),
        ("169.254.10.10", "link_local"),
        ("224.0.0.1", "multicast"),
        ("100.64.0.1", "other_non_public"),
        ("8.8.8.8", "public"),
        ("nonsense", "unparseable"),
    ],
)
def test_source_scope_comes_from_the_address_not_from_a_list_of_names(address, scope):
    assert source_scope(address) == scope
