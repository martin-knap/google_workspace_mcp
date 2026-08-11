from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.providers.google import GoogleProvider

from auth.allowlisted_google_provider import (
    AllowlistedGoogleProvider,
    parse_allowed_emails,
    verified_email,
)
from auth.scopes import (
    CLOUD_VISION_SCOPE,
    DRIVE_READONLY_SCOPE,
    get_scopes_for_tools,
)


def access_token(email: str, verified: object = True) -> AccessToken:
    return AccessToken(
        token="test-token",
        client_id="google-user",
        scopes=["openid"],
        claims={"email": email, "email_verified": verified},
    )


def provider_with_allowlist(*emails: str) -> AllowlistedGoogleProvider:
    provider = object.__new__(AllowlistedGoogleProvider)
    provider.allowed_emails = parse_allowed_emails(emails)
    return provider


def test_parse_allowed_emails_is_exact_and_normalized():
    assert parse_allowed_emails(" AI@Flatbee.cz, michal.kniha@flatbee.cz ") == {
        "ai@flatbee.cz",
        "michal.kniha@flatbee.cz",
    }
    with pytest.raises(ValueError, match="exact email"):
        parse_allowed_emails("*@flatbee.cz")
    with pytest.raises(ValueError, match="exact email"):
        parse_allowed_emails("@flatbee.cz")


def test_verified_email_requires_google_verification():
    assert verified_email(access_token("AI@Flatbee.cz")) == "ai@flatbee.cz"
    assert verified_email(access_token("ai@flatbee.cz", False)) is None
    assert verified_email(access_token("ai@flatbee.cz", None)) is None


def test_flatbee_ops_requests_only_required_google_read_scopes():
    scopes = set(get_scopes_for_tools(["flatbee_ops"]))
    assert DRIVE_READONLY_SCOPE in scopes
    assert CLOUD_VISION_SCOPE in scopes
    assert "https://www.googleapis.com/auth/drive" not in scopes


def test_provider_requires_nonempty_allowlist_when_fail_closed():
    with pytest.raises(ValueError, match="requires at least one"):
        AllowlistedGoogleProvider(
            allowed_emails="",
            require_email_allowlist=True,
            client_id="client",
            client_secret="secret",
            base_url="https://example.test",
        )


@pytest.mark.asyncio
async def test_load_access_token_rejects_non_allowlisted_identity(monkeypatch):
    provider = provider_with_allowlist("ai@flatbee.cz")

    async def fake_load(_self, _token):
        return access_token("intruder@example.com")

    monkeypatch.setattr(GoogleProvider, "load_access_token", fake_load)
    assert await provider.load_access_token("reference-token") is None


@pytest.mark.asyncio
async def test_load_access_token_accepts_allowlisted_identity(monkeypatch):
    provider = provider_with_allowlist("ai@flatbee.cz")

    async def fake_load(_self, _token):
        return access_token("AI@Flatbee.cz")

    monkeypatch.setattr(GoogleProvider, "load_access_token", fake_load)
    result = await provider.load_access_token("reference-token")
    assert verified_email(result) == "ai@flatbee.cz"


@pytest.mark.asyncio
async def test_exchange_rejects_before_fastmcp_token_is_issued():
    provider = provider_with_allowlist("ai@flatbee.cz")

    class Store:
        deleted = False

        async def get(self, key):
            return SimpleNamespace(idp_tokens={"access_token": "google-token"})

        async def delete(self, key):
            self.deleted = True

    class Validator:
        async def verify_token(self, token):
            return access_token("intruder@example.com")

    store = Store()
    provider._code_store = store
    provider._token_validator = Validator()
    with pytest.raises(Exception, match="not allowed"):
        await provider.exchange_authorization_code(
            SimpleNamespace(), SimpleNamespace(code="client-code")
        )
    assert store.deleted is True
