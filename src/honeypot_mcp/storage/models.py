from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Store enum values (lowercase) not names in the DB
_ev = lambda e: [m.value for m in e]  # noqa: E731


class Base(DeclarativeBase):
    pass


class HoneypotType(str, enum.Enum):
    SSH = "ssh"
    HTTP = "http"
    SMTP = "smtp"
    FTP = "ftp"
    DNS = "dns"
    RDP = "rdp"
    VNC = "vnc"
    REDIS = "redis"
    MYSQL = "mysql"
    ELASTICSEARCH = "elasticsearch"
    SMB = "smb"
    POSTGRESQL = "postgresql"
    MONGODB = "mongodb"
    MSSQL = "mssql"
    TELNET = "telnet"
    MEMCACHED = "memcached"
    SNMP = "snmp"
    LDAP = "ldap"
    DOCKER_API = "docker_api"
    IMAP = "imap"
    SIP = "sip"
    RSYNC = "rsync"
    NFS = "nfs"
    POP3 = "pop3"
    KUBERNETES = "kubernetes"


class HoneypotStatus(str, enum.Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    PAUSED = "paused"
    ERROR = "error"


class AlertSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertDisposition(str, enum.Enum):
    """What an analyst concluded about an alert.

    `benign` is distinct from `false_positive`: a false positive means the
    detection was wrong, while benign means it fired correctly on activity that
    turned out to be authorised (a pentest, an asset scan). Conflating them
    makes detection-tuning metrics meaningless.
    """

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    DUPLICATE = "duplicate"


class HoneytokenType(str, enum.Enum):
    API_KEY = "api_key"
    CANARY_URL = "canary_url"
    CREDENTIAL = "credential"
    FILE = "file"
    SSH_KEY = "ssh_key"  # planted private key — fingerprint match on SSH auth
    JWT = "jwt"  # planted bearer token — jti match on HTTP Authorization header
    DB_ROW = "db_row"  # planted database row with canary email — match on SMTP RCPT TO
    # Cloud-era tokens. Kubeconfig + Slack webhook trigger via the existing
    # canary callback. Azure + GCP credentials are decoy-only unless the
    # operator wires their cloud audit log forwarding to /cloud-event.
    KUBECONFIG = "kubeconfig"
    SLACK_WEBHOOK = "slack_webhook"
    AZURE_CREDENTIAL = "azure_credential"
    GCP_SERVICE_ACCOUNT = "gcp_service_account"


class HoneytokenStatus(str, enum.Enum):
    ACTIVE = "active"
    TRIGGERED = "triggered"
    REVOKED = "revoked"


class Honeypot(Base):
    __tablename__ = "honeypots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    type: Mapped[HoneypotType] = mapped_column(
        Enum(HoneypotType, values_callable=_ev), nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[HoneypotStatus] = mapped_column(
        Enum(HoneypotStatus, values_callable=_ev), default=HoneypotStatus.STOPPED, nullable=False
    )
    container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    alerts: Mapped[list[Alert]] = relationship("Alert", back_populates="honeypot")


class Alert(Base):
    __tablename__ = "alerts"

    # Composite indexes for how alerts are actually queried. Every triage call
    # filters by a time window and usually a severity or an IP; the individual
    # column indexes below can't serve those pairs, so a busy deployment ends
    # up scanning. Severity had no index at all despite being filterable.
    __table_args__ = (
        Index("ix_alerts_timestamp_severity", "timestamp", "severity"),
        Index("ix_alerts_source_ip_timestamp", "source_ip", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    honeypot_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("honeypots.id", ondelete="SET NULL"), nullable=True
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, values_callable=_ev), default=AlertSeverity.MEDIUM, nullable=False
    )
    acknowledged: Mapped[bool] = mapped_column(default=False)
    # Triage outcome. A bare `acknowledged` flag records that somebody looked,
    # but not what they concluded — so a shift can't hand over, and nobody can
    # answer "what are we dismissing, and should we suppress it instead?".
    disposition: Mapped[AlertDisposition | None] = mapped_column(
        Enum(AlertDisposition, values_callable=_ev), nullable=True
    )
    triage_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    triaged_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    honeypot: Mapped[Honeypot | None] = relationship("Honeypot", back_populates="alerts")


class Honeytoken(Base):
    __tablename__ = "honeytokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[HoneytokenType] = mapped_column(
        Enum(HoneytokenType, values_callable=_ev), nullable=False
    )
    label: Mapped[str] = mapped_column(String(256), nullable=False)
    token_value: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)
    status: Mapped[HoneytokenStatus] = mapped_column(
        Enum(HoneytokenStatus, values_callable=_ev), default=HoneytokenStatus.ACTIVE, nullable=False
    )
    token_meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trigger_metadata: Mapped[dict] = mapped_column(JSON, default=dict)

    trigger_events: Mapped[list[AttackerEvent]] = relationship(
        "AttackerEvent", back_populates="honeytoken"
    )


class AttackerEvent(Base):
    __tablename__ = "attacker_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    alert_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    honeytoken_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("honeytokens.id", ondelete="SET NULL"), nullable=True
    )
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    honeytoken: Mapped[Honeytoken | None] = relationship(
        "Honeytoken", back_populates="trigger_events"
    )


class Subscription(Base):
    """Outbound webhook subscription. Delivers alerts that meet the severity
    threshold to the configured URL in one of several SIEM-native formats."""

    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    severity_threshold: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, values_callable=_ev),
        default=AlertSeverity.MEDIUM,
        nullable=False,
    )
    # Output format. Determines both the body shape and the auth scheme:
    #   json         — raw JSON envelope (HMAC-signed via X-HoneyPot-Signature)
    #   splunk_hec   — Splunk HTTP Event Collector envelope + Splunk token auth
    #   elastic_ecs  — Elastic Common Schema field re-mapping (Bulk-input ready)
    #   cef          — ArcSight CEF text format (works against QRadar too)
    #   syslog       — RFC 5424 framed message over UDP/TCP (URL scheme picks transport)
    format: Mapped[str] = mapped_column(
        String(32), default="json", nullable=False, server_default="json"
    )
    hmac_secret: Mapped[str | None] = mapped_column(String(256), nullable=True)
    active: Mapped[bool] = mapped_column(default=True)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    delivery_count: Mapped[int] = mapped_column(Integer, default=0)
    last_delivery_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SuppressionRule(Base):
    """Drop or rate-limit incoming events that match the IP / event-type pattern.

    `ip_pattern` accepts an exact IP, a CIDR (e.g. 10.0.0.0/8), or empty for any.
    `event_type_pattern` accepts an exact name or a glob (e.g. ssh_*) or empty.
    `action` is `drop` or `rate_limit`. Rate-limited rules collapse N events
    within `rate_limit_window_seconds` into one alert."""

    __tablename__ = "suppression_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    ip_pattern: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_type_pattern: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action: Mapped[str] = mapped_column(String(16), default="drop", nullable=False)
    rate_limit_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rate_limit_window_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    active: Mapped[bool] = mapped_column(default=True)
    suppressed_count: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AttackerProfile(Base):
    __tablename__ = "attacker_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, unique=True, index=True)
    country: Mapped[str | None] = mapped_column(String(64), nullable=True)
    country_code: Mapped[str | None] = mapped_column(String(4), nullable=True)
    city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    asn: Mapped[str | None] = mapped_column(String(128), nullable=True)
    org: Mapped[str | None] = mapped_column(String(256), nullable=True)
    vt_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AuditLog(Base):
    """Record of every state-changing control-plane action.

    Matters more here than in a conventional tool: the control plane is driven
    by a language model, so "what did the agent actually do?" is a question an
    operator will need answered after the fact. `alerts_prune` can delete
    months of evidence and previously left no trace that it ran.

    Deliberately append-only — nothing in the codebase updates or deletes these
    rows, and the retention sweep does not touch them.
    """

    __tablename__ = "audit_log"

    __table_args__ = (Index("ix_audit_log_timestamp_tool", "timestamp", "tool"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tool: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Human-readable one-liner: "deployed ssh honeypot 'web-01' on port 2222".
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    # Arguments as supplied, minus anything secret (see tools/_audit.py).
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="ok")
    # What the action touched, so an operator can filter to one honeypot/token.
    target: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
