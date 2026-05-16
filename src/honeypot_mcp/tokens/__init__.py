"""Token provider registry — maps HoneytokenType to its provider instance."""

from __future__ import annotations

from honeypot_mcp.storage.models import HoneytokenType
from honeypot_mcp.tokens.base import HoneytokenProvider

_providers: dict[HoneytokenType, HoneytokenProvider] = {}


def get_provider(token_type: HoneytokenType) -> HoneytokenProvider:
    if token_type not in _providers:
        if token_type == HoneytokenType.API_KEY:
            from honeypot_mcp.tokens.api_key import APIKeyProvider

            _providers[token_type] = APIKeyProvider()
        elif token_type == HoneytokenType.CANARY_URL:
            from honeypot_mcp.tokens.canary_url import CanaryURLProvider

            _providers[token_type] = CanaryURLProvider()
        elif token_type == HoneytokenType.CREDENTIAL:
            from honeypot_mcp.tokens.credential import CredentialProvider

            _providers[token_type] = CredentialProvider()
        elif token_type == HoneytokenType.FILE:
            from honeypot_mcp.tokens.file_token import FileTokenProvider

            _providers[token_type] = FileTokenProvider()
        elif token_type == HoneytokenType.SSH_KEY:
            from honeypot_mcp.tokens.ssh_key import SSHKeyProvider

            _providers[token_type] = SSHKeyProvider()
        elif token_type == HoneytokenType.JWT:
            from honeypot_mcp.tokens.jwt import JWTProvider

            _providers[token_type] = JWTProvider()
        elif token_type == HoneytokenType.DB_ROW:
            from honeypot_mcp.tokens.db_row import DBRowProvider

            _providers[token_type] = DBRowProvider()
        else:
            raise ValueError(f"No provider registered for token type: {token_type}")
    return _providers[token_type]
