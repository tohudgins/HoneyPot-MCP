"""What each engine actually is, in one place.

Three separate features need to reason about engines rather than just run them:
`honeypot_templates` lists them, `planner` picks a coherent set, and `coverage`
works out what they can detect. Before this registry each of those carried its
own copy of the facts, and `honeypot_templates` had already drifted — it still
described fourteen types after five more had shipped, so a model asking "what
can I deploy?" was told a stale answer with no error anywhere.

The fields exist to answer specific questions:

* `os_family` — coherence. A Windows SMB decoy next to an LDAP decoy answering
  `dc=corp,dc=local` is consistent; the same SMB decoy beside an Ubuntu SSH
  persona claiming the same hostname is a tell. Deception fails on mismatched
  detail more often than on missing detail.
* `roles` — how a natural-language description ("we run a customer portal and a
  Postgres warehouse") becomes a sensor list without hardcoding phrasings.
* `captures_credentials_as` — which `service` value a planted credential must
  carry to cross-reference here. A credential token planted for a service that
  is not deployed can never fire, which is silent and common.
* `signature_events` — the coverage map's input. These are the event types the
  engine emits that carry analytic weight, fed through `intel.mitre` so
  coverage is derived from the real ATT&CK mappings rather than a second,
  drifting list.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

OSFamily = Literal["windows", "linux", "network", "neutral"]


@dataclass(frozen=True)
class EngineCapability:
    type: str
    display_name: str
    default_port: int
    real_world_port: int
    os_family: OSFamily
    roles: tuple[str, ...]
    summary: str
    signature_events: tuple[str, ...]
    config_options: tuple[str, ...] = ()
    requires_docker: bool = False
    captures_credentials_as: str | None = None
    # Sensors that are unconvincing on their own. An LDAP server with no
    # Windows file share behind it is not a domain; an RDP port with no SMB is
    # a lone Windows box on an otherwise-Linux estate.
    pairs_well_with: tuple[str, ...] = ()
    notes: str = ""


_CAPABILITIES: tuple[EngineCapability, ...] = (
    EngineCapability(
        type="ssh",
        display_name="SSH (Cowrie)",
        default_port=2222,
        real_world_port=22,
        os_family="linux",
        roles=("remote_access", "linux"),
        summary=(
            "Full-interaction shell. Captures credentials, every command typed, and "
            "malware pulled in with wget/curl or pushed over SCP."
        ),
        signature_events=(
            "ssh_login_failed",
            "ssh_login_success",
            "ssh_command_input",
            "ssh_file_download",
            "ssh_file_upload",
            "ssh_port_forward",
        ),
        config_options=("fake_hostname", "fake_kernel", "ssh_persona", "telnet_enabled"),
        requires_docker=True,
        captures_credentials_as="ssh",
        pairs_well_with=("http", "postgresql"),
        notes="The highest-value sensor on the public internet by volume and by depth.",
    ),
    EngineCapability(
        type="telnet",
        display_name="Telnet (Cowrie)",
        default_port=2323,
        real_world_port=23,
        os_family="linux",
        roles=("remote_access", "iot"),
        summary=(
            "Same Cowrie shell over Telnet. Catches the Mirai-class botnet population "
            "that ignores SSH entirely and sprays factory default credentials."
        ),
        signature_events=(
            "telnet_login_failed",
            "telnet_login_success",
            "telnet_command_input",
            "telnet_file_download",
        ),
        config_options=("fake_hostname", "fake_kernel", "ssh_persona"),
        requires_docker=True,
        captures_credentials_as="telnet",
        notes="Fills faster than SSH on a public IP.",
    ),
    EngineCapability(
        type="http",
        display_name="HTTP / HTTPS",
        default_port=8080,
        real_world_port=80,
        os_family="neutral",
        roles=("web", "public_facing"),
        summary=(
            "Web server with rotating personas, realistic robots.txt/favicon, decoy "
            "admin panels and .env files, session tracking, and exploit-signature "
            "matching across path, query, headers and body."
        ),
        signature_events=(
            "http_exploit_attempt",
            "http_credential_submit",
            "http_active_recon",
            "http_decoy_served",
            "http_probe",
        ),
        config_options=("endpoints", "persona", "tls"),
        captures_credentials_as="http",
        pairs_well_with=("mysql", "postgresql"),
        notes="The natural place to plant an AWS key or a .env decoy.",
    ),
    EngineCapability(
        type="smtp",
        display_name="SMTP",
        default_port=2525,
        real_world_port=25,
        os_family="neutral",
        roles=("mail", "public_facing"),
        summary="Mail server with STARTTLS. Captures AUTH credentials, relay attempts, and message bodies.",
        signature_events=("smtp_auth_attempt", "smtp_open_relay", "smtp_message_received"),
        config_options=("fake_banner", "fake_domain", "tls"),
        captures_credentials_as="smtp",
        notes="Also the trigger surface for db_row canary email addresses.",
    ),
    EngineCapability(
        type="ftp",
        display_name="FTP",
        default_port=2121,
        real_world_port=21,
        os_family="neutral",
        roles=("file_transfer",),
        summary="Captures login attempts, anonymous access, directory listings and upload attempts.",
        signature_events=("ftp_login_attempt", "ftp_anonymous_login", "ftp_file_upload"),
        config_options=("fake_banner", "fake_users"),
        captures_credentials_as="ftp",
    ),
    EngineCapability(
        type="dns",
        display_name="DNS",
        default_port=5353,
        real_world_port=53,
        os_family="network",
        roles=("infrastructure",),
        summary=(
            "Classifies zone-transfer attempts, version.bind fingerprinting, ANY-query "
            "amplification probes and high-entropy labels that indicate tunnelling."
        ),
        signature_events=(
            "dns_zone_transfer",
            "dns_tunneling_suspected",
            "dns_any_query",
            "dns_version_probe",
        ),
        config_options=("fake_soa", "zones"),
    ),
    EngineCapability(
        type="rdp",
        display_name="RDP",
        default_port=3389,
        real_world_port=3389,
        os_family="windows",
        roles=("remote_access", "windows"),
        summary=(
            "Parses the X.224 connection request and extracts the leaked "
            "`mstshash` cookie, which nearly every RDP client and brute-force tool "
            "sends in the clear."
        ),
        signature_events=("rdp_handshake", "rdp_connection"),
        config_options=("fake_hostname",),
        pairs_well_with=("smb", "ldap"),
        notes="One of the largest brute-force categories on the internet.",
    ),
    EngineCapability(
        type="vnc",
        display_name="VNC",
        default_port=5900,
        real_world_port=5900,
        os_family="neutral",
        roles=("remote_access",),
        summary="RFB 3.8 handshake with VNC Auth. Captures the DES challenge/response for offline analysis.",
        signature_events=("vnc_auth_attempt", "vnc_handshake"),
        captures_credentials_as="vnc",
    ),
    EngineCapability(
        type="smb",
        display_name="SMB / file share",
        default_port=445,
        real_world_port=445,
        os_family="windows",
        roles=("file_share", "windows"),
        summary=(
            "Negotiates SMB1/SMB2 and flags EternalBlue and DoublePulsar patterns. "
            "The top ransomware initial-access surface."
        ),
        signature_events=("smb_exploit_attempt", "smb_session_setup", "smb_negotiate"),
        pairs_well_with=("rdp", "ldap"),
        notes="The natural place to plant a decoy document.",
    ),
    EngineCapability(
        type="ldap",
        display_name="LDAP / directory",
        default_port=1389,
        real_world_port=389,
        os_family="windows",
        roles=("directory", "windows"),
        summary=(
            "Captures simple-bind credentials in the clear with the full DN, and "
            "catches Log4Shell's second stage as a JNDI-shaped search."
        ),
        signature_events=(
            "ldap_bind_attempt",
            "ldap_jndi_lookup",
            "ldap_anonymous_bind",
            "ldap_search",
        ),
        config_options=("base_dn",),
        captures_credentials_as="ldap",
        pairs_well_with=("smb", "rdp"),
        notes="A directory with no file share or RDP behind it is not a convincing domain.",
    ),
    EngineCapability(
        type="mysql",
        display_name="MySQL",
        default_port=3306,
        real_world_port=3306,
        os_family="neutral",
        roles=("database",),
        summary=(
            "Full handshake with scramble verification, then classifies post-auth "
            "queries — UDF loads, INTO OUTFILE writes, LOAD_FILE reads."
        ),
        signature_events=(
            "mysql_login_attempt",
            "mysql_udf_rce",
            "mysql_outfile_write",
            "mysql_file_read",
        ),
        captures_credentials_as="mysql",
        pairs_well_with=("http",),
    ),
    EngineCapability(
        type="postgresql",
        display_name="PostgreSQL",
        default_port=5432,
        real_world_port=5432,
        os_family="neutral",
        roles=("database",),
        summary=(
            "Forces cleartext auth so the password is capturable, accepts the login, "
            "then classifies COPY … FROM PROGRAM (RCE), large-object file writes and recon."
        ),
        signature_events=(
            "postgresql_login_attempt",
            "postgresql_copy_program_rce",
            "postgresql_file_access",
        ),
        captures_credentials_as="postgresql",
        pairs_well_with=("http",),
    ),
    EngineCapability(
        type="mssql",
        display_name="Microsoft SQL Server",
        default_port=1433,
        real_world_port=1433,
        os_family="windows",
        roles=("database", "windows"),
        summary="TDS PRELOGIN + Login7, de-obfuscating the password from the wire.",
        signature_events=("mssql_login_attempt",),
        captures_credentials_as="mssql",
        pairs_well_with=("smb", "rdp"),
    ),
    EngineCapability(
        type="mongodb",
        display_name="MongoDB",
        default_port=27017,
        real_world_port=27017,
        os_family="neutral",
        roles=("database",),
        summary=(
            "Answers isMaster/buildInfo believably, then flags dropDatabase and "
            "ransom notes — the exposed-Mongo extortion pattern."
        ),
        signature_events=("mongodb_ransom_note", "mongodb_destructive", "mongodb_command"),
    ),
    EngineCapability(
        type="redis",
        display_name="Redis",
        default_port=6379,
        real_world_port=6379,
        os_family="neutral",
        roles=("database", "cache"),
        summary=(
            "Full RESP2/RESP3 with HELLO. Captures AUTH attempts and the CONFIG SET / "
            "module-load / replica-of chains used to turn Redis into RCE."
        ),
        signature_events=(
            "redis_auth_attempt",
            "redis_config_set",
            "redis_eval",
            "redis_module_load",
        ),
        captures_credentials_as="redis",
    ),
    EngineCapability(
        type="elasticsearch",
        display_name="Elasticsearch",
        default_port=9200,
        real_world_port=9200,
        os_family="neutral",
        roles=("database", "search"),
        summary="Unauthenticated cluster mock. Recon probes are separated from actual data-exfil queries.",
        signature_events=("elasticsearch_data_access", "elasticsearch_query_probe"),
    ),
    EngineCapability(
        type="memcached",
        display_name="Memcached",
        default_port=11211,
        real_world_port=11211,
        os_family="neutral",
        roles=("cache",),
        summary=(
            "Detects reflector reconnaissance and amplification staging — a large "
            "`set` followed by a `get` of the same key — plus destructive flush_all."
        ),
        signature_events=(
            "memcached_amplification_attempt",
            "memcached_flush_all",
            "memcached_stats_probe",
        ),
        notes="Never amplifies; records the intent without joining the DDoS.",
    ),
    EngineCapability(
        type="snmp",
        display_name="SNMP",
        default_port=1161,
        real_world_port=161,
        os_family="network",
        roles=("infrastructure", "network_device"),
        summary=(
            "UDP agent presenting as network kit. Community strings arrive in the "
            "clear, so every request is a credential capture; SetRequest is a "
            "configuration-change attempt."
        ),
        signature_events=(
            "snmp_default_community",
            "snmp_community_attempt",
            "snmp_set_request",
            "snmp_bulk_request",
        ),
        captures_credentials_as="snmp",
        notes="Pairs with DNS to make a believable network-infrastructure segment.",
    ),
    EngineCapability(
        type="docker_api",
        display_name="Docker Engine API",
        default_port=2375,
        real_world_port=2375,
        os_family="linux",
        roles=("container", "cloud"),
        summary=(
            "Unauthenticated daemon. Names the specific escape indicators in a "
            "container-create — host root bind, privileged, host PID namespace, "
            "mining image — and separates them from ordinary container use."
        ),
        signature_events=(
            "docker_api_container_escape",
            "docker_api_exec",
            "docker_api_image_pull",
            "docker_api_enumerate",
        ),
        notes="An exposed daemon is host compromise, not a foothold.",
    ),
    EngineCapability(
        type="imap",
        display_name="IMAP",
        default_port=1143,
        real_world_port=143,
        os_family="neutral",
        roles=("mail", "public_facing"),
        summary=(
            "Cleartext mailbox login on the unencrypted port. Advertises a real "
            "Dovecot capability set *without* LOGINDISABLED, so credential-stuffing "
            "bots actually send the password instead of being forced to STARTTLS."
        ),
        signature_events=("imap_login_attempt", "imap_mailbox_access", "imap_auth_attempt"),
        config_options=("fake_banner",),
        captures_credentials_as="imap",
        pairs_well_with=("smtp",),
        notes="Mail access is how credential stuffing cashes out — it owns password resets everywhere else.",
    ),
    EngineCapability(
        type="sip",
        display_name="SIP / VoIP",
        default_port=5060,
        real_world_port=5060,
        os_family="neutral",
        roles=("voip", "public_facing"),
        summary=(
            "Asterisk-flavoured PBX on tcp+udp. Separates SIPVicious-style scanning "
            "from extension enumeration from actual toll fraud, and captures the "
            "digest response against a known nonce."
        ),
        signature_events=(
            "sip_toll_fraud_attempt",
            "sip_register_attempt",
            "sip_extension_probe",
            "sip_scan",
        ),
        captures_credentials_as="sip",
        notes="One of the few services where the attacker's motive is immediate revenue.",
    ),
    EngineCapability(
        type="rsync",
        display_name="rsync daemon",
        default_port=8873,
        real_world_port=873,
        os_family="linux",
        roles=("file_transfer", "backup"),
        summary=(
            "Exposed backup daemon. Module enumeration is the whole discovery phase "
            "in one command, and an open module means the next step is bulk file copy."
        ),
        signature_events=(
            "rsync_anonymous_access",
            "rsync_module_enumeration",
            "rsync_file_request",
            "rsync_auth_attempt",
        ),
        captures_credentials_as="rsync",
        notes="Backup servers are the usual victim, so the exposure is the archive itself.",
    ),
    EngineCapability(
        type="nfs",
        display_name="NFS",
        default_port=2049,
        real_world_port=2049,
        os_family="linux",
        roles=("file_share",),
        summary=(
            "ONC RPC with MOUNT and portmapper. `showmount -e` discloses the export "
            "list, and a mount of a world-exported share is treated as the breach it is."
        ),
        signature_events=(
            "nfs_mount_attempt",
            "nfs_export_enumeration",
            "nfs_portmap_dump",
            "nfs_request",
        ),
        notes="An export shared to * with no_root_squash is data loss and often RCE.",
    ),
)

BY_TYPE: dict[str, EngineCapability] = {c.type: c for c in _CAPABILITIES}


def all_capabilities() -> tuple[EngineCapability, ...]:
    return _CAPABILITIES


def by_role(role: str) -> list[EngineCapability]:
    return [c for c in _CAPABILITIES if role in c.roles]


def credential_services() -> dict[str, str]:
    """`{engine type: service label a planted credential must use}`."""
    return {c.type: c.captures_credentials_as for c in _CAPABILITIES if c.captures_credentials_as}


@dataclass(frozen=True)
class EnvironmentProfile:
    """A named shape of estate, and the sensors that make it believable."""

    id: str
    display_name: str
    description: str
    os_family: OSFamily
    core: tuple[str, ...]
    optional: tuple[str, ...] = field(default=())
    hostname_prefix: str = "srv"
    domain: str | None = None


_PROFILES: tuple[EnvironmentProfile, ...] = (
    EnvironmentProfile(
        id="corporate_windows",
        display_name="Corporate Windows / Active Directory",
        description=(
            "A Windows estate: file shares, a domain controller, remote desktop and "
            "SQL Server. The classic ransomware target shape."
        ),
        os_family="windows",
        core=("smb", "rdp", "ldap"),
        optional=("mssql", "http", "ftp"),
        hostname_prefix="corp",
        domain="corp.local",
    ),
    EnvironmentProfile(
        id="linux_web",
        display_name="Linux web application",
        description="A public web application on Linux with a database behind it and SSH for admin.",
        os_family="linux",
        core=("http", "ssh", "postgresql"),
        optional=("redis", "mysql", "ftp", "imap", "rsync"),
        hostname_prefix="web",
    ),
    EnvironmentProfile(
        id="cloud_native",
        display_name="Cloud-native / container platform",
        description=(
            "Container workloads with an exposed runtime and API surface — the shape "
            "cryptomining campaigns hunt for."
        ),
        os_family="linux",
        core=("docker_api", "http", "ssh"),
        optional=("elasticsearch", "redis", "postgresql"),
        hostname_prefix="node",
    ),
    EnvironmentProfile(
        id="data_platform",
        display_name="Data platform / analytics",
        description="A database-heavy estate: warehouse, search cluster and cache.",
        os_family="linux",
        core=("postgresql", "elasticsearch", "redis"),
        optional=("mongodb", "mysql", "ssh", "memcached"),
        hostname_prefix="data",
    ),
    EnvironmentProfile(
        id="network_edge",
        display_name="Network edge / infrastructure",
        description="Routers, switches and DNS — the management plane of a network segment.",
        os_family="network",
        core=("snmp", "dns", "telnet"),
        optional=("ssh", "ftp", "http"),
        hostname_prefix="net",
    ),
    EnvironmentProfile(
        id="mixed_enterprise",
        display_name="Mixed enterprise",
        description=(
            "Broad coverage across Windows, Linux, web and data. Use when the estate "
            "is varied or unknown — widest ATT&CK coverage per sensor deployed."
        ),
        os_family="neutral",
        core=("ssh", "http", "smb", "rdp", "postgresql"),
        optional=(
            "ldap",
            "mysql",
            "redis",
            "docker_api",
            "telnet",
            "snmp",
            "imap",
            "nfs",
            "sip",
        ),
        hostname_prefix="srv",
        domain="corp.local",
    ),
)

PROFILES: dict[str, EnvironmentProfile] = {p.id: p for p in _PROFILES}


def all_profiles() -> tuple[EnvironmentProfile, ...]:
    return _PROFILES
