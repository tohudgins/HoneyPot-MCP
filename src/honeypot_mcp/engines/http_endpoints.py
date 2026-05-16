"""Realistic well-known HTTP endpoints.

Real web servers always serve `/robots.txt`, `/favicon.ico`, `/sitemap.xml`,
and `/.well-known/security.txt` — even if they're empty or minimal. A honeypot
that 404s on these is fingerprintable in a single curl. The content here is
persona-aware where it matters (security.txt contact email picks up the
persona's identity); the rest is generic but plausible.

`robots.txt` deliberately *advertises* the honeypot's sensitive paths — that's
the realistic move (most public webapps disallow `/admin/`, `/api/` etc. in
robots.txt because robots.txt is for honest crawlers; attackers always read
it specifically for the disallowed list). This points the scanner at exactly
the bait we want them to find.
"""

from __future__ import annotations

# Minimal valid 1x1 transparent ICO (favicons used to be required by every
# browser, so an empty/missing one was suspicious — even a tiny one is fine).
# 16x16 transparent BMP-style ICO with a 1-bit mask.
_FAVICON_ICO = (
    b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x18\x00"
    b"\x68\x03\x00\x00\x16\x00\x00\x00"
    b"\x28\x00\x00\x00\x10\x00\x00\x00\x20\x00\x00\x00\x01\x00\x18\x00"
    b"\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00" + b"\xff" * (16 * 16 * 3) + b"\x00" * (16 * 4)
)


def get_favicon() -> bytes:
    return _FAVICON_ICO


def get_robots_txt() -> str:
    """Disallow paths that point attackers exactly at our bait."""
    return (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /api/\n"
        "Disallow: /backup/\n"
        "Disallow: /config/\n"
        "Disallow: /phpmyadmin/\n"
        "Disallow: /wp-admin/\n"
        "Disallow: /.env\n"
        "Disallow: /.git/\n"
        "\n"
        "Sitemap: /sitemap.xml\n"
    )


def get_sitemap_xml(host: str) -> str:
    """Minimal valid sitemap. Real sites have one; absence is a tell."""
    base = f"https://{host}" if host else "https://localhost"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <url>\n    <loc>{base}/</loc>\n    <priority>1.0</priority>\n  </url>\n"
        f"  <url>\n    <loc>{base}/login</loc>\n    <priority>0.6</priority>\n  </url>\n"
        f"  <url>\n    <loc>{base}/about</loc>\n    <priority>0.4</priority>\n  </url>\n"
        "</urlset>\n"
    )


def get_security_txt(host: str) -> str:
    """draft-foudil-securitytxt-style contact info. Lots of public webapps
    have this; absence is a passable but not conclusive tell."""
    domain = host.split(":")[0] if host else "localhost"
    return (
        f"Contact: mailto:security@{domain}\n"
        "Expires: 2027-12-31T23:59:59Z\n"
        "Preferred-Languages: en\n"
        f"Canonical: https://{domain}/.well-known/security.txt\n"
        "Policy: https://example.com/security-policy\n"
    )


# ── API attack-surface endpoints ────────────────────────────────────────
# Modern scanners (Nuclei, Garak, custom GraphQL probes) target API surfaces,
# not just /admin. A honeypot that returns a believable response to these
# probes captures the tool family, payload, and target.


def get_openid_configuration(host: str) -> str:
    """OAuth/OIDC well-known discovery document. Real auth providers always
    serve this; a 404 here is a tell. Returns a complete, valid-looking
    configuration that points at our own bait endpoints."""
    domain = host.split(":")[0] if host else "localhost"
    base = f"https://{domain}"
    import json as _json

    return _json.dumps(
        {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "userinfo_endpoint": f"{base}/oauth/userinfo",
            "jwks_uri": f"{base}/oauth/jwks",
            "registration_endpoint": f"{base}/oauth/register",
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
            "response_types_supported": ["code", "token", "id_token"],
            "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "claims_supported": ["sub", "iss", "name", "email", "email_verified"],
        },
        separators=(",", ":"),
    )


def get_swagger_json(host: str) -> str:
    """OpenAPI/Swagger spec. Catches scanners that look for `/swagger.json`,
    `/api/docs`, `/openapi.json`. The spec advertises plausible CRUD endpoints
    on /api/v1 so the scanner has paths to follow."""
    domain = host.split(":")[0] if host else "localhost"
    import json as _json

    return _json.dumps(
        {
            "openapi": "3.0.3",
            "info": {"title": "Internal API", "version": "1.4.2"},
            "servers": [{"url": f"https://{domain}/api/v1"}],
            "paths": {
                "/users": {
                    "get": {"summary": "List users"},
                    "post": {"summary": "Create user"},
                },
                "/users/{id}": {
                    "get": {"summary": "Get user"},
                    "delete": {"summary": "Delete user"},
                },
                "/auth/login": {"post": {"summary": "Authenticate"}},
                "/auth/refresh": {"post": {"summary": "Refresh token"}},
                "/admin/audit": {"get": {"summary": "Audit log"}},
            },
        },
        separators=(",", ":"),
    )


def get_graphql_introspection() -> str:
    """GraphQL introspection-style response. Scanners that POST an
    introspection query expect this shape. We return a minimal but
    valid `__schema` block that advertises a small attack surface."""
    import json as _json

    return _json.dumps(
        {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [
                                {"name": "user", "type": {"name": "User"}},
                                {"name": "users", "type": {"name": "[User]"}},
                                {"name": "currentUser", "type": {"name": "User"}},
                            ],
                        },
                        {
                            "name": "User",
                            "kind": "OBJECT",
                            "fields": [
                                {"name": "id", "type": {"name": "ID!"}},
                                {"name": "email", "type": {"name": "String"}},
                                {"name": "role", "type": {"name": "String"}},
                            ],
                        },
                        {
                            "name": "Mutation",
                            "kind": "OBJECT",
                            "fields": [
                                {"name": "login", "type": {"name": "AuthPayload"}},
                                {"name": "createUser", "type": {"name": "User"}},
                            ],
                        },
                    ],
                }
            }
        },
        separators=(",", ":"),
    )


def get_graphql_error() -> str:
    """For non-introspection GraphQL probes — return a believable
    'query parse error' that a real GraphQL server would emit."""
    import json as _json

    return _json.dumps(
        {
            "errors": [
                {
                    "message": "Syntax Error: Unexpected token",
                    "locations": [{"line": 1, "column": 1}],
                }
            ]
        },
        separators=(",", ":"),
    )
