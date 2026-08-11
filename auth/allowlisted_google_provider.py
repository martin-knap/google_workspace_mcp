"""Google OAuth provider with an exact, fail-closed user email allowlist."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.providers.google import GoogleProvider
from mcp.server.auth.provider import (
    AuthorizationCode,
    OAuthClientInformationFull,
    OAuthToken,
    TokenError,
)


logger = logging.getLogger(__name__)


def parse_allowed_emails(raw: str | Iterable[str] | None) -> frozenset[str]:
    """Return normalized exact emails; domains and wildcard entries are rejected."""
    values = raw.split(",") if isinstance(raw, str) else list(raw or [])
    normalized: set[str] = set()
    for value in values:
        email = str(value).strip().lower()
        if not email:
            continue
        if "*" in email or email.startswith("@") or email.count("@") != 1:
            raise ValueError(
                "WORKSPACE_MCP_ALLOWED_EMAILS accepts exact email addresses only"
            )
        normalized.add(email)
    return frozenset(normalized)


def verified_email(access_token: AccessToken | None) -> str | None:
    if access_token is None:
        return None
    claims = getattr(access_token, "claims", None) or {}
    email = str(claims.get("email") or "").strip().lower()
    is_verified = claims.get("email_verified")
    if not email or is_verified not in (True, "true", "True", 1, "1"):
        return None
    return email


class AllowlistedGoogleProvider(GoogleProvider):
    """Reject Google identities outside an exact allowlist at token issuance and use."""

    def __init__(
        self,
        *,
        allowed_emails: str | Iterable[str] | None = None,
        require_email_allowlist: bool = False,
        **kwargs: Any,
    ) -> None:
        self.allowed_emails = parse_allowed_emails(allowed_emails)
        if require_email_allowlist and not self.allowed_emails:
            raise ValueError(
                "WORKSPACE_MCP_REQUIRE_EMAIL_ALLOWLIST=true requires at least one "
                "exact email in WORKSPACE_MCP_ALLOWED_EMAILS"
            )
        super().__init__(**kwargs)

    def _is_allowed(self, access_token: AccessToken | None) -> bool:
        if not self.allowed_emails:
            return True
        email = verified_email(access_token)
        return email is not None and email in self.allowed_emails

    async def load_access_token(self, token: str) -> AccessToken | None:
        access_token = await super().load_access_token(token)
        if access_token is None or not self._is_allowed(access_token):
            logger.warning("Google OAuth token rejected by exact email allowlist")
            return None
        return access_token

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        if self.allowed_emails:
            code_model = await self._code_store.get(key=authorization_code.code)
            if code_model is not None:
                upstream_token = code_model.idp_tokens.get("access_token")
                access_token = (
                    await self._token_validator.verify_token(upstream_token)
                    if upstream_token
                    else None
                )
                if not self._is_allowed(access_token):
                    await self._code_store.delete(key=authorization_code.code)
                    logger.warning(
                        "Google OAuth authorization rejected by exact email allowlist"
                    )
                    raise TokenError(
                        "invalid_grant", "Google account is not allowed for this MCP"
                    )
        return await super().exchange_authorization_code(client, authorization_code)
