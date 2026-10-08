import base64
import json
import time
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from fastmcp.server.auth.oauth_proxy.models import UpstreamTokenSet
from fastmcp.server.auth.providers.google import GoogleProvider
from key_value.aio.stores.memory import MemoryStore
from mcp.shared.auth import OAuthClientInformationFull

from auth.agent_token_issuance import (
    UPSTREAM_COLLECTION,
    GoogleGrant,
    IssuanceError,
    credential_store_grant,
    email_from_id_token,
    issue_client_tokens,
    pick_grant,
)

EMAIL = "jakub.chodura@flatbee.cz"
AGENT_CLIENT = "agent-client"


def id_token(email: str) -> str:
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'none'})}.{b64({'email': email})}.sig"


def google_transport(calls: list, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(dict(httpx.QueryParams(request.content.decode())))
        if status != 200:
            return httpx.Response(status, json={"error": "invalid_grant"})
        return httpx.Response(
            200,
            json={
                "access_token": "ya29.fresh",
                "expires_in": 3599,
                "scope": "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.readonly",
                "token_type": "Bearer",
            },
        )

    return httpx.MockTransport(handler)


class FakeValidator:
    def __init__(self, email=EMAIL, verified=True):
        self.email, self.verified = email, verified

    async def verify_token(self, token):
        return SimpleNamespace(claims={"email": self.email, "email_verified": self.verified, "sub": "123"})


# ───────────────────────── helpers


def test_email_from_id_token():
    assert email_from_id_token(id_token("A@Flatbee.cz")) == "a@flatbee.cz"
    assert email_from_id_token("garbage") is None
    assert email_from_id_token(None) is None


def test_pick_grant_prefers_more_scopes_then_newest():
    a = GoogleGrant("r1", ("a",), 10.0, "upstream")
    b = GoogleGrant("r2", ("a", "b"), 1.0, "upstream")
    c = GoogleGrant("r3", ("a", "b"), 5.0, "upstream")
    assert pick_grant([a, b, c]) is c
    assert pick_grant([]) is None


def test_credential_store_grant_requires_same_google_client():
    creds = SimpleNamespace(refresh_token="r", client_id="other", scopes=["x"])
    assert credential_store_grant(creds, "proxy-client") is None
    creds.client_id = "proxy-client"
    assert credential_store_grant(creds, "proxy-client").refresh_token == "r"
    assert credential_store_grant(None, "proxy-client") is None


# ───────────────────────── against a real FastMCP GoogleProvider


@pytest_asyncio.fixture
async def provider():
    p = GoogleProvider(
        client_id="proxy-client",
        client_secret="proxy-secret-long-enough-for-derivation",
        base_url="https://mcp.example.test",
        jwt_signing_key="test-signing-key-that-is-long-enough",
        client_storage=MemoryStore(),
    )
    p.set_mcp_path("/mcp")  # initialises the JWT issuer, as server start-up does
    p._token_validator = FakeValidator()
    await p.register_client(
        OAuthClientInformationFull(
            client_id=AGENT_CLIENT,
            redirect_uris=["https://agent.example.test/oauth/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        )
    )
    return p


async def put_upstream(provider, email, refresh="google-refresh", scope="openid drive.readonly", created=1.0):
    key = f"up-{email}-{created}"
    await provider._upstream_token_store.put(
        key=key,
        value=UpstreamTokenSet(
            upstream_token_id=key,
            access_token="ya29.old",
            refresh_token=refresh,
            refresh_token_expires_at=None,
            expires_at=time.time() - 10,
            token_type="Bearer",
            scope=scope,
            client_id="claude-ai-client",
            created_at=created,
            raw_token_data={"id_token": id_token(email)},
        ),
        ttl=3600,
    )
    return key


def keys_of(provider):
    async def list_keys():
        store = provider._client_storage
        while hasattr(store, "key_value"):
            store = store.key_value
        return await store.keys(collection=UPSTREAM_COLLECTION)

    return list_keys


async def issue(provider, calls, *, email=EMAIL, client_id=AGENT_CLIENT, creds=None, status=200):
    async with httpx.AsyncClient(transport=google_transport(calls, status)) as http:
        return await issue_client_tokens(
            provider,
            email=email,
            client_id=client_id,
            allowed_client_ids=[AGENT_CLIENT],
            list_upstream_keys=keys_of(provider),
            credential_lookup=lambda e: creds,
            http=http,
        )


@pytest.mark.asyncio
async def test_issues_a_token_the_proxy_accepts_and_shares_the_google_grant(provider):
    await put_upstream(provider, EMAIL, refresh="google-refresh")
    calls = []
    out = await issue(provider, calls)

    # Google was refreshed with the user's existing grant through the proxy's client.
    assert calls[0]["refresh_token"] == "google-refresh"
    assert calls[0]["client_id"] == "proxy-client"
    assert out["refresh_token"] and out["access_token"]
    assert out["grant_source"] == "upstream"

    # The proxy itself accepts the issued access token (JWT -> JTI -> upstream -> validator).
    access = await provider.load_access_token(out["access_token"])
    assert access is not None
    assert access.claims["email"] == EMAIL  # the upstream identity the proxy resolved

    # The issued refresh token is registered like one from an interactive login.
    refresh = await provider.load_refresh_token(
        await provider.get_client(AGENT_CLIENT), out["refresh_token"]
    )
    assert refresh is not None


@pytest.mark.asyncio
async def test_existing_upstream_sets_are_untouched(provider):
    key = await put_upstream(provider, EMAIL)
    before = await provider._upstream_token_store.get(key=key)
    await issue(provider, [])
    after = await provider._upstream_token_store.get(key=key)
    assert after == before


@pytest.mark.asyncio
async def test_unknown_or_foreign_users_and_clients_are_refused(provider):
    await put_upstream(provider, "someone@flatbee.cz")
    with pytest.raises(IssuanceError) as e:
        await issue(provider, [])
    assert e.value.status == 404

    with pytest.raises(IssuanceError) as e:
        await issue(provider, [], email="x@gmail.com")
    assert e.value.status == 400

    await put_upstream(provider, EMAIL)
    with pytest.raises(IssuanceError) as e:
        await issue(provider, [], client_id="claude-ai-client")
    assert e.value.status == 403


@pytest.mark.asyncio
async def test_google_must_confirm_the_identity(provider):
    await put_upstream(provider, EMAIL)
    provider._token_validator = FakeValidator(email="other@flatbee.cz")
    with pytest.raises(IssuanceError) as e:
        await issue(provider, [])
    assert e.value.status == 409

    provider._token_validator = FakeValidator(verified=False)
    with pytest.raises(IssuanceError):
        await issue(provider, [])


@pytest.mark.asyncio
async def test_revoked_google_grant_asks_for_sign_in(provider):
    await put_upstream(provider, EMAIL)
    with pytest.raises(IssuanceError) as e:
        await issue(provider, [], status=400)
    assert e.value.status == 409


@pytest.mark.asyncio
async def test_credential_store_grant_is_used_when_no_upstream_session(provider):
    creds = SimpleNamespace(refresh_token="stored-refresh", client_id="proxy-client", scopes=["openid", "gmail.readonly"])
    calls = []
    out = await issue(provider, calls, creds=creds)
    assert calls[0]["refresh_token"] == "stored-refresh"
    assert out["grant_source"] == "credential_store"
