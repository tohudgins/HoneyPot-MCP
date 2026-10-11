"""The honeypot host's firewall ruleset: what it must expose, hide and refuse to render.

The behavioural proof (real packets through a real kernel) is in
`tests/integration/test_firewall_rules.py`; these pin the properties of the text that make a
wrong ruleset impossible to produce: the operator cannot be locked out by a typo, the control
plane can never be listed as a honeypot port, and every mode keeps the invariants the sandbox
depends on.
"""

from __future__ import annotations

import re

import pytest

from honeypot_mcp.hardening.firewall import (
    FirewallError,
    FirewallSpec,
    Redirect,
    parse_ports,
    render,
)


def _spec(**overrides) -> FirewallSpec:
    tcp, udp, redirects = parse_ports("3389,80>8080,110>1110")
    base = {
        "admin_port": 2200,
        "tcp_ports": tcp,
        "udp_ports": udp,
        "redirects": redirects,
        "docker_ports": (22, 23),
    }
    return FirewallSpec(**{**base, **overrides})


def _chain(text: str, name: str) -> str:
    match = re.search(rf"\tchain {name} \{{\n(.*?)\n\t\}}", text, re.S)
    assert match, f"no {name} chain"
    return match.group(1)


def test_parse_ports_reads_redirects_protocols_and_dedupes():
    assert parse_ports("3389,80>8080,110>1110,5060/udp,3389") == (
        (1110, 3389, 8080),
        (5060,),
        (Redirect(80, 8080, "tcp"), Redirect(110, 1110, "tcp")),
    )
    assert parse_ports("") == ((), (), ())
    assert parse_ports("53>5353/udp") == ((), (5353,), (Redirect(53, 5353, "udp"),))


@pytest.mark.parametrize("bad", ["abc", "80>", "0", "70000", "80>99999", "80/icmp", "80>>81"])
def test_unreadable_or_out_of_range_port_specs_are_refused(bad):
    with pytest.raises(FirewallError):
        parse_ports(bad)


def test_input_is_default_drop_and_opens_only_the_admin_port_and_the_engine_ports():
    text = render(_spec())
    chain = _chain(text, "input")
    assert "policy drop" in chain
    accepted_ports = set(re.findall(r"tcp dport (\d+|\{[^}]*\}) accept", chain))
    assert accepted_ports == {"2200", "{ 3389 }"}
    # 1110 and 8080 exist only because 110 and 80 are redirected to them
    redirected = set(re.findall(r"tcp dport (\{[^}]*\}) ct status dnat accept", chain))
    assert redirected == {"{ 1110, 8080 }"}
    # The control plane, metrics and the console are not listed anywhere in the ruleset.
    for port in ("8000", "9090", "8090", "8888", "2375", "22 "):
        assert not re.search(rf"dport[^\n]*\b{port.strip()}\b", chain), port
    assert "udp dport" not in chain, "no UDP honeypot, no UDP rule"


def test_a_port_that_exists_only_as_a_redirect_target_is_not_reachable_directly():
    """A scan of the whole port range against the live droplet found 8080, 1110, 1143, 1389, 2121,
    4445 and 8873 open beside 80, 110, 143, ...: the post-redirect ports were accepted for any
    packet. A real host does not answer POP3 on both 110 and 1110, so the decoy was fingerprintable
    by a port scan alone. The redirect targets are accepted only for redirected packets."""
    chain = _chain(render(_spec()), "input")
    for target in ("1110", "8080"):
        unconditional = re.findall(rf"tcp dport [^\n]*\b{target}\b[^\n]*accept", chain)
        assert unconditional and all("ct status dnat" in line for line in unconditional), target
    # A port that is public in its own right stays reachable without the redirect.
    assert re.search(r"tcp dport \{ 3389 \} accept", chain)
    # Same for UDP: SNMP's 161>1161
    udp = _chain(render(_spec(udp_ports=(1161,), redirects=(Redirect(161, 1161, "udp"),))), "input")
    assert "udp dport { 1161 } ct status dnat accept" in udp


def test_privileged_public_ports_are_redirected_only_when_addressed_to_this_host():
    text = render(_spec())
    pre = _chain(text, "prerouting")
    assert "fib daddr type local tcp dport 80 redirect to :8080" in pre
    assert "fib daddr type local tcp dport 110 redirect to :1110" in pre
    # Every redirect carries the local-address guard (a bare `tcp dport 80 redirect` also caught
    # containers' outbound web requests).
    assert all("fib daddr type local" in line for line in pre.splitlines()[1:])
    assert "prerouting" not in render(_spec(redirects=(), tcp_ports=(3389,)))


def test_admin_ssh_is_rate_limited_per_source_before_it_is_accepted():
    chain = _chain(render(_spec()), "input")
    lines = chain.splitlines()
    first_accept = next(
        i for i, line in enumerate(lines) if re.search(r"tcp dport 2200 accept", line)
    )
    meters = [i for i, line in enumerate(lines) if "add @ssh_v" in line]
    assert len(meters) == 2 and max(meters) < first_accept
    assert "limit rate over 6/minute" in chain


def test_an_admin_allow_list_drops_everyone_else_and_keeps_the_operator_reachable():
    text = render(_spec(admin_allow=("203.0.113.9", "2001:db8::/32", "198.51.100.0/24")))
    chain = _chain(text, "input")
    assert "elements = { 203.0.113.9/32, 198.51.100.0/24 }" in text
    assert "elements = { 2001:db8::/32 }" in text
    assert "tcp dport 2200 ip saddr @admin_v4 accept" in chain
    assert "tcp dport 2200 ip6 saddr @admin_v6 accept" in chain
    assert chain.splitlines().index("\t\ttcp dport 2200 drop") > chain.splitlines().index(
        "\t\ttcp dport 2200 ip saddr @admin_v4 accept"
    )
    assert "tcp dport 2200 accept" not in chain
    # A v4-only allow-list renders no v6 set.
    assert "admin_v6" not in render(_spec(admin_allow=("203.0.113.9",)))


@pytest.mark.parametrize("bad", ["not-an-ip", "203.0.113.999", "10.0.0.0/33"])
def test_a_bad_allow_list_entry_is_refused_not_silently_dropped(bad):
    with pytest.raises(FirewallError):
        render(_spec(admin_allow=(bad,)))


def test_containers_may_not_open_new_connections_to_the_host_or_out_by_default():
    text = render(_spec())
    for bridge in ("docker0", "br-*"):
        assert f'iifname "{bridge}" ct state new drop' in _chain(text, "input")
        assert f'iifname "{bridge}" ct state new drop' in _chain(text, "forward")
    assert "kbytes/second" not in text, "closed mode has no egress budget to render"


def test_limited_egress_allows_web_to_public_space_only_and_caps_rate_and_bandwidth():
    text = render(_spec(docker_egress="limited", dns_servers=("67.207.67.2", "2606:4700::1111")))
    forward = _chain(text, "forward")
    for bridge in ("docker0", "br-*"):
        rules = [line.strip() for line in forward.splitlines() if f'iifname "{bridge}"' in line]
        joined = "\n".join(rules)
        # Order is the policy: bandwidth ceiling, then DNS to the configured resolver, then the
        # ban on non-public space, then the web ports, then default deny.
        position = {
            key: joined.index(key)
            for key in (
                "kbytes/second drop",
                "ip daddr { 67.207.67.2 } th dport 53 accept",
                "ip daddr { 0.0.0.0/8",
                "tcp dport { 80, 443 } limit rate 30/minute burst 30 packets accept",
                "ct state new drop",
            )
        }
        assert list(position.values()) == sorted(position.values()), joined
    for private in (
        "10.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    ):
        assert private in forward
    assert "ip6 daddr != 2000::/3 drop" in forward
    # The cloud metadata service (169.254.169.254) is inside the banned link-local range.
    assert "169.254.0.0/16" in forward


def test_limited_egress_without_a_resolver_is_refused():
    """Without DNS Cowrie cannot resolve the hosts an attacker tells it to download from, so the
    mode would silently capture nothing."""
    with pytest.raises(FirewallError, match="resolver"):
        render(_spec(docker_egress="limited"))
    with pytest.raises(FirewallError, match="resolver"):
        render(_spec(docker_egress="limited", dns_servers=("2606:4700::1111",)))


def test_unknown_egress_mode_is_refused():
    with pytest.raises(FirewallError, match="closed or limited"):
        render(_spec(docker_egress="open"))


def test_the_service_user_can_only_answer_resolve_and_open_https():
    out = _chain(render(_spec(dns_servers=("203.0.113.53",))), "output")
    assert 'meta skuid "honeypot" ct state established,related accept' in out
    assert 'meta skuid "honeypot" tcp dport { 443 } ct state new accept' in out
    assert 'meta skuid "honeypot" ip daddr { 203.0.113.53 } th dport 53 accept' in out
    assert out.strip().splitlines()[-1].strip().startswith('meta skuid "honeypot" counter reject')
    # Without a configured resolver (systemd-resolved's loopback stub) there is no DNS rule.
    assert "th dport 53" not in _chain(render(_spec()), "output")


def test_it_only_ever_touches_its_own_table_so_dockers_rules_survive():
    text = render(_spec())
    assert "flush ruleset" not in text
    assert text.count("delete table inet hp_fw") == 1
    assert re.findall(r"^table (\S+ \S+)", text, re.M) == ["inet hp_fw", "inet hp_fw"]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"admin_port": 0}, "out of range"),
        ({"admin_port": 70000}, "out of range"),
        ({"tcp_ports": (2200, 8080)}, "management port"),
        ({"redirects": (Redirect(2200, 8080),)}, "hijack"),
        ({"redirects": (Redirect(80, 9999),)}, "nothing is allowed to listen"),
        ({"redirects": (Redirect(80, 8080), Redirect(80, 3389))}, "redirected twice"),
        ({"docker_ports": (8080,)}, "Docker-published"),
        ({"service_user": "Robert'); drop"}, "valid account name"),
        ({"service_user": "has space"}, "valid account name"),
        ({"dns_servers": ("not-an-ip",)}, "not an IP"),
    ],
)
def test_a_ruleset_that_would_strand_the_operator_or_inject_text_is_refused(kwargs, message):
    with pytest.raises(FirewallError, match=message):
        render(_spec(**kwargs))


def test_the_admin_port_cannot_share_a_docker_published_honeypot_port():
    with pytest.raises(FirewallError, match="both 22"):
        render(_spec(admin_port=22, tcp_ports=(), redirects=(), docker_ports=(22,)))


def test_rendering_is_deterministic_and_order_independent():
    a = render(_spec(tcp_ports=(8080, 1110, 3389)))
    b = render(_spec(tcp_ports=(3389, 8080, 1110, 8080)))
    assert a == b


# ── the command-line entry point the host-hardening script calls ──────────────────────────────


def test_the_cli_renders_the_same_ruleset_as_the_library(capsys):
    from honeypot_mcp.hardening.firewall import main

    argv = ["--admin-port", "2200", "--ports", "3389,80>8080,110>1110", "--docker-ports", "22,23"]
    assert main(argv) == 0
    assert capsys.readouterr().out == render(_spec(docker_ports=(22, 23)))


def test_the_cli_writes_a_file_and_reports_the_ports_the_world_will_see_listening(tmp_path, capsys):
    from honeypot_mcp.hardening.firewall import main

    out = tmp_path / "hp.nft"
    argv = ["--admin-port", "2200", "--ports", "3389,80>8080,5060/udp", "--docker-ports", "22,23"]
    assert main([*argv, "--out", str(out)]) == 0
    assert out.read_text().startswith("#!/usr/sbin/nft -f")
    assert main([*argv, "--print-listen"]) == 0
    # preflight reads this list: engine ports after the redirect, Docker's published ports, UDP last
    assert capsys.readouterr().out.strip() == "3389,8080,22,23,5060/udp"


@pytest.mark.parametrize(
    "argv",
    [
        ["--admin-port", "2200", "--ports", "2200"],  # a honeypot on the admin port
        ["--admin-port", "2200", "--docker-ports", "22,abc"],  # not a port number
        ["--admin-port", "2200", "--egress", "limited"],  # limited egress needs a resolver
        ["--admin-port", "2200", "--ports", "banana"],
        ["--admin-port", "2200", "--admin-allow", "not-an-address"],
    ],
)
def test_a_bad_specification_exits_2_and_prints_the_reason_without_writing_anything(
    argv, tmp_path, capsys
):
    from honeypot_mcp.hardening.firewall import main

    out = tmp_path / "hp.nft"
    assert main([*argv, "--out", str(out)]) == 2
    assert "firewall:" in capsys.readouterr().err
    assert not out.exists(), "a rejected ruleset must never be written where it could be loaded"
