"""Live operations console — a self-hosted view of what the sensors are seeing.

Grafana covers historical dashboards; this is the wall display. It answers the
three questions an analyst asks on walking up to a screen — *is everything up,
is anything on fire, what just happened* — with no login, no provisioning, and
no query language.

Read-only by construction. The console serves GET routes only and never
mutates state: the control plane is the MCP interface, and a page that anyone
on the network can load must not be able to stop a honeypot.
"""

from honeypot_mcp.console.server import build_console_app, start_console_server

__all__ = ["build_console_app", "start_console_server"]
