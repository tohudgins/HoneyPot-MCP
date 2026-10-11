"""The host firewall for a public honeypot VPS, rendered as an nftables ruleset.

A honeypot host is attacked on purpose, so the firewall has a different job from a normal
server's: let the *intended* decoy ports through, and make everything else (the control plane,
metrics, the admin SSH port, anything an upgrade starts listening on tomorrow) unreachable, and
make a compromised honeypot unable to attack anyone else.

What the ruleset does, by chain:

``input`` (policy drop)
    Loopback, established traffic and the ICMP a host needs, then the admin SSH port (rate
    limited per source, and optionally restricted to an allow-list of addresses), then exactly the
    ports the in-process engines listen on. Nothing else: not the MCP control port, not metrics,
    not a service somebody installs later.
``prerouting`` (nat)
    Redirects privileged public ports (80, 110, ...) to the unprivileged ports the engines
    listen on. The service runs without ``CAP_NET_BIND_SERVICE``, so it cannot bind below 1024.
``forward``
    Containers may answer connections made to them but may not start any: a compromised Cowrie
    cannot reach out to scan, relay or fetch tooling. (Docker's own rules decide what may reach
    a container; this table only adds the outbound ban, and a drop here is final whatever
    Docker's chains say.)
``output``
    The unprivileged service user may only answer connections made to it, resolve names, and
    open new HTTPS connections (alert webhooks, threat-intel lookups). A compromised service
    process cannot scan, brute-force or reach a database on the network. Root, the admin
    session and apt are unrestricted.

Only this module's own table (``inet hp_fw``) is created and deleted, so Docker's tables and
anything else on the host are left alone, and the file is safe to load repeatedly (the
``table`` / ``delete table`` pair is the idempotent idiom).

Docker-published ports (the Cowrie SSH and Telnet honeypots) never reach the ``input`` chain:
Docker DNATs them in ``prerouting`` and they are *forwarded* to the container, so they need no
rule here. Run the daemon with ``"userland-proxy": false`` so no ``docker-proxy`` listens on
them in the host namespace.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

TABLE = "hp_fw"

_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_PORT_SPEC = re.compile(r"^(?P<pub>\d{1,5})(?:>(?P<to>\d{1,5}))?(?:/(?P<proto>tcp|udp))?$")

# ICMP/ICMPv6 a host must keep answering to work on the internet: path-MTU discovery and
# neighbour discovery break connectivity silently when dropped.
_ICMP_OK = "destination-unreachable, time-exceeded, parameter-problem"
_ICMPV6_OK = (
    "destination-unreachable, packet-too-big, time-exceeded, parameter-problem, "
    "nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert"
)

# Admin SSH: at most this many new connections per source per minute. A person logging in uses
# one; a password sprayer that found the port is cut off after a handful.
_SSH_NEW_PER_MINUTE = 6

_BRIDGES = ("docker0", "br-*")
# Container egress ceiling and new-connection budget in "limited" mode.
_EGRESS_KBYTES_PER_SECOND = 512
_EGRESS_NEW_PER_MINUTE = 30
# Everything a container must never reach: private, loopback, link-local (includes the cloud
# metadata address), carrier-grade NAT, benchmarking, multicast and reserved space.
_NON_PUBLIC_V4 = (
    "0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, "
    "192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3"
)


def _safe_ips(values: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for value in values:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        out.append(value)
    return out


class FirewallError(ValueError):
    """The requested ruleset would be wrong or would lock the operator out."""


@dataclass(frozen=True)
class Redirect:
    """Public port `public` is redirected to the port `to` an engine really listens on."""

    public: int
    to: int
    proto: str = "tcp"


@dataclass(frozen=True)
class FirewallSpec:
    admin_port: int
    # Ports the in-process engines listen on (after any redirect), reachable from anywhere.
    tcp_ports: tuple[int, ...] = ()
    udp_ports: tuple[int, ...] = ()
    redirects: tuple[Redirect, ...] = ()
    # Source addresses (CIDRs) allowed to reach the admin port. Empty: anyone, rate limited.
    admin_allow: tuple[str, ...] = ()
    service_user: str = "honeypot"
    # New outbound connections the service user may make (webhooks, threat intel).
    egress_tcp_ports: tuple[int, ...] = (443,)
    # Resolvers the service user may query when the host does not resolve through a loopback
    # stub (systemd-resolved at 127.0.0.53 needs no rule).
    dns_servers: tuple[str, ...] = ()
    docker_bridges: bool = True
    # Informational: ports Docker publishes (Cowrie). Checked for collisions, never rendered.
    docker_ports: tuple[int, ...] = field(default=())
    # "closed": containers may not start connections. "limited": they may fetch from public web
    # servers only (malware-sample capture), rate limited, never to private space or the
    # metadata service. Pair with COWRIE_ALLOW_EGRESS=true in the service's environment.
    docker_egress: str = "closed"
    docker_egress_ports: tuple[int, ...] = (80, 443)


def _valid_port(port: int, what: str) -> int:
    if not 1 <= port <= 65535:
        raise FirewallError(f"{what}: port {port} is out of range")
    return port


def parse_ports(spec: str) -> tuple[tuple[int, ...], tuple[int, ...], tuple[Redirect, ...]]:
    """`"3389,80>8080,110>1110,5060/udp"` -> (tcp listen ports, udp listen ports, redirects).

    `A>B` means the world connects to A and the engine listens on B; a bare `P` is both.
    The default protocol is tcp; `/udp` selects UDP.
    """
    tcp: list[int] = []
    udp: list[int] = []
    redirects: list[Redirect] = []
    for raw in (item.strip() for item in spec.split(",")):
        if not raw:
            continue
        match = _PORT_SPEC.match(raw)
        if match is None:
            raise FirewallError(f"cannot read port spec {raw!r} (expected 80, 80>8080, 5060/udp)")
        public = _valid_port(int(match["pub"]), raw)
        proto = match["proto"] or "tcp"
        listen = _valid_port(int(match["to"]), raw) if match["to"] else public
        if match["to"] and listen != public:
            redirects.append(Redirect(public, listen, proto))
        (tcp if proto == "tcp" else udp).append(listen)
    return tuple(sorted(set(tcp))), tuple(sorted(set(udp))), tuple(redirects)


def _cidrs(values: tuple[str, ...], what: str) -> tuple[list[str], list[str]]:
    v4: list[str] = []
    v6: list[str] = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise FirewallError(f"{what}: {value!r} is not an address or CIDR") from exc
        (v4 if network.version == 4 else v6).append(str(network))
    return v4, v6


def validate(spec: FirewallSpec) -> None:
    """Raise `FirewallError` for a ruleset that is wrong or would strand the operator."""
    if spec.docker_egress not in ("closed", "limited"):
        raise FirewallError(f"docker egress mode {spec.docker_egress!r} is not closed or limited")
    if spec.docker_egress == "limited":
        if not spec.docker_egress_ports:
            raise FirewallError("limited container egress needs at least one allowed port")
        for port in spec.docker_egress_ports:
            _valid_port(port, "container egress ports")
        if not any(ipaddress.ip_address(s).version == 4 for s in _safe_ips(spec.dns_servers)):
            raise FirewallError(
                "limited container egress needs the IPv4 resolver(s) the containers use "
                "(--dns), or Cowrie cannot resolve the hosts it is told to download from"
            )
    _valid_port(spec.admin_port, "admin port")
    if spec.admin_port == 22 and spec.docker_ports and 22 in spec.docker_ports:
        raise FirewallError(
            "the admin SSH port and a Docker-published honeypot port are both 22: move the "
            "admin sshd first"
        )
    if not _USER.match(spec.service_user):
        raise FirewallError(f"service user {spec.service_user!r} is not a valid account name")

    listening = set(spec.tcp_ports) | set(spec.udp_ports)
    for port in (*spec.tcp_ports, *spec.udp_ports, *spec.egress_tcp_ports):
        _valid_port(port, "port list")
    if spec.admin_port in spec.tcp_ports:
        raise FirewallError(
            f"admin SSH port {spec.admin_port} is also an open honeypot port: the honeypot would "
            "answer on your management port"
        )
    for redirect in spec.redirects:
        _valid_port(redirect.public, "redirect")
        _valid_port(redirect.to, "redirect")
        if redirect.proto not in ("tcp", "udp"):
            raise FirewallError(f"redirect protocol {redirect.proto!r} is not tcp or udp")
        if redirect.public == spec.admin_port and redirect.proto == "tcp":
            raise FirewallError(f"redirecting port {redirect.public} would hijack admin SSH")
        ports = spec.tcp_ports if redirect.proto == "tcp" else spec.udp_ports
        if redirect.to not in ports:
            raise FirewallError(
                f"{redirect.public}>{redirect.to} redirects to a port nothing is allowed to "
                "listen on"
            )
    seen: set[tuple[str, int]] = set()
    for redirect in spec.redirects:
        key = (redirect.proto, redirect.public)
        if key in seen:
            raise FirewallError(f"port {redirect.public}/{redirect.proto} is redirected twice")
        seen.add(key)
    clash = set(spec.docker_ports) & listening
    if clash:
        raise FirewallError(
            f"port(s) {sorted(clash)} are both Docker-published and listened on by an "
            "in-process engine"
        )
    _cidrs(spec.admin_allow, "admin allow-list")
    for server in spec.dns_servers:
        try:
            ipaddress.ip_address(server)
        except ValueError as exc:
            raise FirewallError(f"DNS server {server!r} is not an IP address") from exc


def _set_list(items: list[int] | tuple[int, ...]) -> str:
    return ", ".join(str(item) for item in sorted(set(items)))


def render(spec: FirewallSpec) -> str:
    """The complete nftables ruleset for `spec` (loadable with `nft -f`)."""
    validate(spec)
    allow4, allow6 = _cidrs(spec.admin_allow, "admin allow-list")
    admin = spec.admin_port
    lines: list[str] = [
        "#!/usr/sbin/nft -f",
        "# Generated by honeypot_mcp.hardening.firewall. Do not edit: re-render instead.",
        f"table inet {TABLE}",
        f"delete table inet {TABLE}",
        f"table inet {TABLE} {{",
    ]

    # Per-source meters for new admin SSH connections.
    for family, kind in (("v4", "ipv4_addr"), ("v6", "ipv6_addr")):
        lines += [
            f"\tset ssh_{family} {{",
            f"\t\ttype {kind}",
            "\t\tflags dynamic, timeout",
            "\t\ttimeout 10m",
            "\t\tsize 8192",
            "\t}",
        ]
    for family, kind, networks in (("v4", "ipv4_addr", allow4), ("v6", "ipv6_addr", allow6)):
        if networks:
            lines += [
                f"\tset admin_{family} {{",
                f"\t\ttype {kind}",
                "\t\tflags interval",
                f"\t\telements = {{ {', '.join(networks)} }}",
                "\t}",
            ]

    lines += [
        "\tchain input {",
        "\t\ttype filter hook input priority -10; policy drop;",
        '\t\tiifname "lo" accept',
        "\t\tct state invalid drop",
        "\t\tct state established,related accept",
        *(
            # A compromised container is not a trusted neighbour: it may not open new
            # connections to the host itself (admin sshd, the engines, anything else).
            f'\t\tiifname "{bridge}" ct state new drop'
            for bridge in (_BRIDGES if spec.docker_bridges else ())
        ),
        f"\t\tmeta l4proto icmp icmp type {{ {_ICMP_OK} }} accept",
        "\t\tmeta l4proto icmp icmp type echo-request limit rate 5/second burst 10 packets accept",
        f"\t\tmeta l4proto ipv6-icmp icmpv6 type {{ {_ICMPV6_OK} }} accept",
        "\t\tmeta l4proto ipv6-icmp icmpv6 type echo-request "
        "limit rate 5/second burst 10 packets accept",
    ]
    rate = f"limit rate over {_SSH_NEW_PER_MINUTE}/minute burst {_SSH_NEW_PER_MINUTE} packets"
    lines += [
        f"\t\ttcp dport {admin} ct state new add @ssh_v4 {{ ip saddr {rate} }} drop",
        f"\t\ttcp dport {admin} ct state new add @ssh_v6 {{ ip6 saddr {rate} }} drop",
    ]
    if allow4 or allow6:
        if allow4:
            lines.append(f"\t\ttcp dport {admin} ip saddr @admin_v4 accept")
        if allow6:
            lines.append(f"\t\ttcp dport {admin} ip6 saddr @admin_v6 accept")
        lines.append(f"\t\ttcp dport {admin} drop")
    else:
        lines.append(f"\t\ttcp dport {admin} accept")
    # A port an engine listens on only because a public port is redirected to it (80>8080) must be
    # reachable through the redirect and not directly: accepted unconditionally, a scan of the whole
    # port range finds 8080 open beside 80, and a real host never answers POP3 on both 110 and 1110.
    # `ct status dnat` is set on redirected packets and never on a direct connection.
    for proto, ports in (("tcp", spec.tcp_ports), ("udp", spec.udp_ports)):
        targets = {r.to for r in spec.redirects if r.proto == proto}
        direct = [p for p in ports if p not in targets]
        redirected = [p for p in ports if p in targets]
        if direct:
            lines.append(f"\t\t{proto} dport {{ {_set_list(direct)} }} accept")
        if redirected:
            lines.append(f"\t\t{proto} dport {{ {_set_list(redirected)} }} ct status dnat accept")
    lines.append("\t}")

    if spec.redirects:
        lines += [
            "\tchain prerouting {",
            "\t\ttype nat hook prerouting priority dstnat; policy accept;",
        ]
        for redirect in sorted(spec.redirects, key=lambda r: (r.proto, r.public)):
            # `fib daddr type local`: only traffic addressed to this host. Without it the rule
            # also caught a container's outbound web requests (port 80 -> the local engine) and
            # defeated the limited-egress mode.
            lines.append(
                f"\t\tfib daddr type local {redirect.proto} dport {redirect.public} "
                f"redirect to :{redirect.to}"
            )
        lines.append("\t}")

    lines += ["\tchain forward {", "\t\ttype filter hook forward priority -10; policy accept;"]
    if spec.docker_bridges:
        for bridge in _BRIDGES:
            if spec.docker_egress == "limited":
                # A hard ceiling on what a container may send, so a hijacked Cowrie is a poor
                # DoS participant. Downloads are *inbound* to the container and unaffected;
                # interactive sessions are a few kilobytes a second.
                lines.append(
                    f'\t\tiifname "{bridge}" limit rate over {_EGRESS_KBYTES_PER_SECOND} '
                    "kbytes/second drop"
                )
                # The resolvers come first: a provider's resolver can sit in private space, and
                # it is listed explicitly. Only DNS to it, nothing else.
                resolvers = [s for s in spec.dns_servers if ipaddress.ip_address(s).version == 4]
                if resolvers:
                    lines.append(
                        f'\t\tiifname "{bridge}" ct state new ip daddr {{ {", ".join(resolvers)} }} '
                        "th dport 53 accept"
                    )
                lines += [
                    # Never toward private space, the host's neighbours or the cloud metadata
                    # service (169.254.169.254), whatever the attacker's URL says.
                    f'\t\tiifname "{bridge}" ct state new ip daddr {{ {_NON_PUBLIC_V4} }} drop',
                    f'\t\tiifname "{bridge}" ct state new ip6 daddr != 2000::/3 drop',
                    f'\t\tiifname "{bridge}" ct state new tcp dport '
                    f"{{ {_set_list(spec.docker_egress_ports)} }} "
                    f"limit rate {_EGRESS_NEW_PER_MINUTE}/minute burst "
                    f"{_EGRESS_NEW_PER_MINUTE} packets accept",
                ]
            lines.append(f'\t\tiifname "{bridge}" ct state new drop')
    lines.append("\t}")

    user = spec.service_user
    lines += [
        "\tchain output {",
        "\t\ttype filter hook output priority -10; policy accept;",
        '\t\toifname "lo" accept',
        f'\t\tmeta skuid "{user}" ct state established,related accept',
    ]
    if spec.egress_tcp_ports:
        lines.append(
            f'\t\tmeta skuid "{user}" tcp dport {{ {_set_list(spec.egress_tcp_ports)} }} '
            "ct state new accept"
        )
    dns4 = [s for s in spec.dns_servers if ipaddress.ip_address(s).version == 4]
    dns6 = [s for s in spec.dns_servers if ipaddress.ip_address(s).version == 6]
    for fam, servers in (("ip", dns4), ("ip6", dns6)):
        if servers:
            lines.append(
                f'\t\tmeta skuid "{user}" {fam} daddr {{ {", ".join(servers)} }} th dport 53 accept'
            )
    lines += [
        f'\t\tmeta skuid "{user}" counter reject with icmpx type admin-prohibited',
        "\t}",
        "}",
    ]
    return "\n".join(lines) + "\n"


def listen_ports(spec: FirewallSpec) -> str:
    """The ports that listen publicly once this ruleset is loaded, as `preflight --listen-ports`
    reads them: the engines' own ports (after any redirect), the Docker-published ports, and
    `/udp` where a UDP engine is planned. The admin port is passed to preflight separately."""
    parts = [str(port) for port in spec.tcp_ports]
    parts += [str(port) for port in spec.docker_ports if port not in spec.tcp_ports]
    parts += [f"{port}/udp" for port in spec.udp_ports]
    return ",".join(parts)


def main(argv: list[str] | None = None) -> int:
    """`python -m honeypot_mcp.hardening.firewall ...` prints (or writes) the ruleset.

    The host-hardening script calls this so the ports in the firewall are the ports the operator
    named once, validated by the same code the tests pin.
    """
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Render the honeypot host firewall (nftables)")
    parser.add_argument("--admin-port", type=int, required=True, help="admin SSH port")
    parser.add_argument(
        "--ports", default="", help='honeypot ports: "3389,80>8080,110>1110,5060/udp"'
    )
    parser.add_argument(
        "--admin-allow", default="", help="comma list of CIDRs allowed to admin SSH"
    )
    parser.add_argument("--docker-ports", default="", help="ports Docker publishes (Cowrie)")
    parser.add_argument("--service-user", default="honeypot")
    parser.add_argument("--egress", choices=("closed", "limited"), default="closed")
    parser.add_argument("--egress-ports", default="80,443", help="ports containers may fetch from")
    parser.add_argument(
        "--dns", default="", help="comma list of resolvers (needed for limited egress)"
    )
    parser.add_argument("--out", help="write here instead of stdout")
    parser.add_argument(
        "--print-listen",
        action="store_true",
        help="print the ports that will listen publicly, in `preflight --listen-ports` syntax",
    )
    args = parser.parse_args(argv)

    def split(value: str) -> tuple[str, ...]:
        return tuple(item.strip() for item in value.split(",") if item.strip())

    try:
        tcp, udp, redirects = parse_ports(args.ports)
        spec = FirewallSpec(
            admin_port=args.admin_port,
            tcp_ports=tcp,
            udp_ports=udp,
            redirects=redirects,
            admin_allow=split(args.admin_allow),
            service_user=args.service_user,
            dns_servers=split(args.dns),
            docker_ports=tuple(int(p) for p in split(args.docker_ports)),
            docker_egress=args.egress,
            docker_egress_ports=tuple(int(p) for p in split(args.egress_ports)),
        )
        text = render(spec)
        if args.print_listen:
            sys.stdout.write(listen_ports(spec) + "\n")
            return 0
    except (FirewallError, ValueError) as exc:
        print(f"firewall: {exc}", file=sys.stderr)
        return 2
    if args.out:
        with open(args.out, "w") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
