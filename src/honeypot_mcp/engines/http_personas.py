"""HTTP server personas — fingerprint-resistance for the HTTP honeypot.

A persona is a coherent bundle of (Server header, X-Powered-By, session
cookie name, 404 page, response-timing characteristics) that makes a
honeypot look like a specific real-world stack rather than the same
hardcoded Apache-on-Ubuntu signature on every deploy.

One persona is picked at deploy time and persisted in the honeypot's
`config` dict, so it stays stable across restarts. Two honeypots in the
same project will (with high probability) pick different personas, so a
scanner that hits both can't pivot off identical headers to mark them
both as honeypots.

Add a new persona by appending to `_PERSONAS`. Keep the field bundle
internally consistent — for instance, an Nginx persona must NOT advertise
`X-Powered-By: PHP/...` because real Nginx setups rarely do.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class HTTPPersona:
    id: str
    server_header: str
    x_powered_by: str | None
    cookie_name: str
    not_found_template: str
    # Extra headers always sent (e.g. X-Frame-Options for IIS).
    extra_headers: tuple[tuple[str, str], ...]
    # Response timing jitter range in milliseconds — uniform random delay
    # before sending the response. Real servers don't reply in sub-ms.
    jitter_ms_min: int
    jitter_ms_max: int

    def render_not_found(self, host: str) -> str:
        return self.not_found_template.format(
            server=self.server_header,
            host=host or "localhost",
        )


# Apache 2.x classic 404. The `address` line embeds the Server header,
# which is what real Apache does — varying it would be a fingerprint.
_APACHE_404 = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>{server} Server at {host} Port 80</address>
</body></html>
"""

_NGINX_404 = """<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>{server}</center>
</body>
</html>
"""

_IIS_404 = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS 10.0 Detailed Error - 404.0 - Not Found</title>
<style type="text/css"><!--
body{{margin:0;font-size:.7em;font-family:Verdana,Arial,Helvetica,sans-serif;background:#EEEEEE;}}
fieldset{{padding:0 15px 10px 15px;}}
h1{{font-size:2.4em;margin:0;color:#FFF;}}
h2{{font-size:1.7em;margin:0;color:#CC0000;}}
h3{{font-size:1.2em;margin:10px 0 0 0;color:#000000;}}
#header{{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS",Verdana,sans-serif;color:#FFF;background-color:#5C87B2;}}
--></style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
<div class="content-container"><fieldset>
<h2>404 - File or directory not found.</h2>
<h3>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</h3>
</fieldset></div>
</div>
</body>
</html>
"""


_PERSONAS: dict[str, HTTPPersona] = {
    "apache_ubuntu": HTTPPersona(
        id="apache_ubuntu",
        server_header="Apache/2.4.41 (Ubuntu)",
        x_powered_by="PHP/7.4.33",
        cookie_name="PHPSESSID",
        not_found_template=_APACHE_404,
        extra_headers=(),
        jitter_ms_min=15,
        jitter_ms_max=120,
    ),
    "apache_centos": HTTPPersona(
        id="apache_centos",
        server_header="Apache/2.4.37 (centos)",
        x_powered_by="PHP/7.2.24",
        cookie_name="PHPSESSID",
        not_found_template=_APACHE_404,
        extra_headers=(),
        jitter_ms_min=20,
        jitter_ms_max=140,
    ),
    "nginx_stable": HTTPPersona(
        id="nginx_stable",
        server_header="nginx/1.18.0",
        x_powered_by=None,
        cookie_name="PHPSESSID",
        not_found_template=_NGINX_404,
        extra_headers=(),
        jitter_ms_min=10,
        jitter_ms_max=90,
    ),
    "nginx_recent": HTTPPersona(
        id="nginx_recent",
        server_header="nginx/1.22.1",
        x_powered_by=None,
        cookie_name="PHPSESSID",
        not_found_template=_NGINX_404,
        extra_headers=(),
        jitter_ms_min=10,
        jitter_ms_max=80,
    ),
    "iis_windows": HTTPPersona(
        id="iis_windows",
        server_header="Microsoft-IIS/10.0",
        x_powered_by="ASP.NET",
        cookie_name="ASP.NET_SessionId",
        not_found_template=_IIS_404,
        extra_headers=(("X-AspNet-Version", "4.0.30319"),),
        jitter_ms_min=25,
        jitter_ms_max=180,
    ),
}


def get_persona(persona_id: str | None) -> HTTPPersona:
    """Look up a persona by id. Falls back to apache_ubuntu for unknown ids
    so an old config row (or a typo) doesn't crash the engine."""
    if persona_id and persona_id in _PERSONAS:
        return _PERSONAS[persona_id]
    return _PERSONAS["apache_ubuntu"]


def pick_random_persona_id() -> str:
    """Use `secrets` rather than `random` — not security-critical, but the
    same RNG used elsewhere in the project for consistency."""
    return secrets.choice(list(_PERSONAS.keys()))


def all_persona_ids() -> list[str]:
    return list(_PERSONAS.keys())
