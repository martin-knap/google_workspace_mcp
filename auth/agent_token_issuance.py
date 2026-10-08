"""Issue OAuth proxy tokens to a trusted agent client for a user who already signed in.

The Flatbee Slack agent runs on Claude Managed Agents; its MCP credentials live in an
Anthropic vault that refreshes them on its own. The OAuth proxy rotates its refresh
tokens on every use, so the vault cannot share a token with the user's claude.ai
connector. What it can share is the Google sign-in underneath: this module finds the
user's existing Google refresh token, gets a fresh Google access token with it, and
runs the proxy's normal authorization-code exchange for the agent's DCR client. The
result is a new, independent FastMCP token pair bound to the same Google grant, issued,
stored and encrypted exactly as an interactive login would be. Nobody signs in twice
and no existing token is touched.

Google refresh tokens are bound to the OAuth client that issued them, so only grants
made through this server's upstream Google client are usable: the proxy's upstream
token store, and credential-store entries issued to the same client.
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable

import httpx
from mcp.server.auth.provider import AuthorizationCode

logger = logging.getLogger(__name__)

GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
UPSTREAM_COLLECTION = "mcp-upstream-tokens"
CODE_TTL_SECONDS = 60


class IssuanceError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class GoogleGrant:
    """A Google refresh token usable with this server's upstream client."""

    refresh_token: str
    scopes: tuple[str, ...]
    created_at: float
    source: str  # "upstream" | "credential_store"


def email_from_id_token(id_token: str | None) -> str | None:
    """Unverified read of the email claim; only used to pick candidates.

    The identity is verified afterwards against Google with a fresh access token.
    """
    if not id_token or id_token.count(".") != 2:
        return None
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None
    email = str(claims.get("email") or "").strip().lower()
    return email or None


def rank_grants(candidates: Iterable[GoogleGrant]) -> list[GoogleGrant]:
    """Most scopes first, then newest. Distinct refresh tokens only."""
    seen: set[str] = set()
    out: list[GoogleGrant] = []
    for c in sorted(
        candidates, key=lambda g: (len(g.scopes), g.created_at), reverse=True
    ):
        if c.refresh_token not in seen:
            seen.add(c.refresh_token)
            out.append(c)
    return out


def pick_grant(candidates: Iterable[GoogleGrant]) -> GoogleGrant | None:
    ranked = rank_grants(candidates)
    return ranked[0] if ranked else None


class GrantRevoked(Exception):
    """Google rejected this refresh token (revoked, expired, password change)."""


async def upstream_grants(
    provider: Any, email: str, list_keys: Callable[[], Awaitable[list[str]]]
) -> list[GoogleGrant]:
    """Grants from the proxy's upstream token store whose id_token names this email."""
    grants: list[GoogleGrant] = []
    for key in await list_keys():
        try:
            token_set = await provider._upstream_token_store.get(key=key)
        except (
            Exception
        ) as exc:  # undecryptable or stale schema: skip, never fail the request
            logger.debug("skip upstream token %s: %s", key[:8], exc)
            continue
        if token_set is None or not token_set.refresh_token:
            continue
        if (
            email_from_id_token((token_set.raw_token_data or {}).get("id_token"))
            != email
        ):
            continue
        grants.append(
            GoogleGrant(
                refresh_token=token_set.refresh_token,
                scopes=tuple(sorted((token_set.scope or "").split())),
                created_at=float(token_set.created_at or 0),
                source="upstream",
            )
        )
    return grants


def credential_store_grant(
    credentials: Any, upstream_client_id: str
) -> GoogleGrant | None:
    """A credential-store entry is usable only if it was issued to the proxy's Google client."""
    if credentials is None or not getattr(credentials, "refresh_token", None):
        return None
    if getattr(credentials, "client_id", None) != upstream_client_id:
        return None
    return GoogleGrant(
        refresh_token=credentials.refresh_token,
        scopes=tuple(sorted(credentials.scopes or [])),
        created_at=0.0,
        source="credential_store",
    )


async def refresh_google(
    provider: Any, grant: GoogleGrant, http: httpx.AsyncClient
) -> dict[str, Any]:
    """Fresh Google tokens for the grant, shaped like the proxy's idp_tokens."""
    secret = (
        provider._upstream_client_secret.get_secret_value()
        if provider._upstream_client_secret
        else None
    )
    data = {
        "grant_type": "refresh_token",
        "refresh_token": grant.refresh_token,
        "client_id": provider._upstream_client_id,
    }
    if secret:
        data["client_secret"] = secret
    try:
        resp = await http.post(GOOGLE_TOKEN_URI, data=data, timeout=20)
    except httpx.HTTPError as exc:
        raise IssuanceError(
            502, f"Google token endpoint unreachable: {type(exc).__name__}"
        ) from exc
    if resp.status_code in (400, 401):
        raise GrantRevoked(resp.status_code)
    if resp.status_code != 200:
        raise IssuanceError(502, f"Google token endpoint returned {resp.status_code}")
    tokens = resp.json()
    # Google does not return the refresh token on refresh; it stays valid and is shared.
    tokens.setdefault("refresh_token", grant.refresh_token)
    if "scope" not in tokens:
        tokens["scope"] = " ".join(grant.scopes)
    return tokens


async def issue_client_tokens(
    provider: Any,
    *,
    email: str,
    client_id: str,
    allowed_client_ids: Iterable[str],
    list_upstream_keys: Callable[[], Awaitable[list[str]]],
    credential_lookup: Callable[[str], Any],
    http: httpx.AsyncClient,
) -> dict[str, Any]:
    email = email.strip().lower()
    if not email.endswith("@flatbee.cz"):
        raise IssuanceError(400, "email must be a @flatbee.cz address")
    if client_id not in set(allowed_client_ids):
        raise IssuanceError(403, "client is not allowed to receive issued tokens")
    client = await provider.get_client(client_id)
    if client is None or not client.redirect_uris:
        raise IssuanceError(404, "unknown client")

    candidates = await upstream_grants(provider, email, list_upstream_keys)
    stored = credential_store_grant(
        credential_lookup(email), provider._upstream_client_id
    )
    if stored:
        candidates.append(stored)
    ranked = rank_grants(candidates)
    if not ranked:
        raise IssuanceError(404, "no existing Google sign-in for this user")

    # A revoked or stale grant must not hide a working one: try them in rank order.
    grant = idp_tokens = None
    for candidate in ranked:
        try:
            idp_tokens = await refresh_google(provider, candidate, http)
        except GrantRevoked:
            logger.info(
                "skip revoked Google grant for %s (source=%s)", email, candidate.source
            )
            continue
        grant = candidate
        break
    if grant is None or idp_tokens is None:
        raise IssuanceError(
            404, "no usable Google sign-in for this user; the user must sign in again"
        )

    # The candidate came from an unverified claim; Google decides who the token belongs to.
    verified = await provider._token_validator.verify_token(idp_tokens["access_token"])
    if verified is None:
        raise IssuanceError(502, "Google identity verification failed")
    claims = getattr(verified, "claims", None) or {}
    if str(claims.get("email") or "").strip().lower() != email or claims.get(
        "email_verified"
    ) not in (True, "true", "True", 1, "1"):
        raise IssuanceError(409, "Google grant does not belong to the requested user")

    # Run the proxy's own code exchange so storage, encryption, JTI mappings and
    # refresh rotation are exactly those of an interactive login.
    from fastmcp.server.auth.oauth_proxy.models import ClientCode

    code = secrets.token_urlsafe(32)
    now = time.time()
    scopes = sorted(set((idp_tokens.get("scope") or "").split()))
    redirect_uri = str(client.redirect_uris[0])
    await provider._code_store.put(
        key=code,
        value=ClientCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=None,  # the exchange runs in-process; no /token PKCE step
            code_challenge_method="S256",
            scopes=scopes,
            idp_tokens=idp_tokens,
            expires_at=now + CODE_TTL_SECONDS,
            created_at=now,
        ),
        ttl=CODE_TTL_SECONDS,
    )
    from mcp.server.auth.provider import TokenError

    try:
        token = await provider.exchange_authorization_code(
            client,
            AuthorizationCode(
                code=code,
                scopes=scopes,
                expires_at=now + CODE_TTL_SECONDS,
                client_id=client_id,
                code_challenge="",
                redirect_uri=redirect_uri,
                redirect_uri_provided_explicitly=True,
            ),
        )
    except TokenError as exc:  # e.g. the exact email allowlist rejects this account
        raise IssuanceError(
            403, f"sign-in not allowed: {exc.error_description or exc.error}"
        ) from exc
    logger.info(
        "issued agent tokens for %s to client %s (grant source=%s, scopes=%d)",
        email,
        client_id,
        grant.source,
        len(scopes),
    )
    return {
        "access_token": token.access_token,
        "refresh_token": token.refresh_token,
        "expires_in": token.expires_in,
        "token_type": token.token_type,
        "scope": token.scope,
        "user_email": email,
        "grant_source": grant.source,
    }
