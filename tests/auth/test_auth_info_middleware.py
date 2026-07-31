from types import SimpleNamespace

import pytest

from auth.auth_info_middleware import AuthInfoMiddleware
from auth.gateway_identity import GatewayIdentityError


class _FakeFastMCPContext:
    def __init__(self):
        self.state = {}
        self.state_serializable = {}
        self.deleted_state = []
        self.session_id = "session-123"

    async def set_state(self, key, value, serializable=True):
        self.state[key] = value
        self.state_serializable[key] = serializable

    async def get_state(self, key):
        return self.state.get(key)

    async def delete_state(self, key):
        self.deleted_state.append(key)
        self.state.pop(key, None)
        self.state_serializable.pop(key, None)


@pytest.mark.asyncio
async def test_on_call_tool_includes_authorization_header_for_bearer_auth(
    monkeypatch,
):
    middleware = AuthInfoMiddleware()
    fastmcp_context = _FakeFastMCPContext()
    context = SimpleNamespace(fastmcp_context=fastmcp_context)
    observed = {}

    monkeypatch.setattr("auth.auth_info_middleware.get_access_token", lambda: None)

    def fake_get_http_headers(*args, **kwargs):
        observed["args"] = args
        observed["kwargs"] = kwargs
        return {"authorization": "Bearer ya29.token"}

    monkeypatch.setattr(
        "auth.auth_info_middleware.get_http_headers",
        fake_get_http_headers,
    )

    class _FakeProvider:
        async def verify_token(self, token):
            observed["token"] = token
            return SimpleNamespace(
                email="user@example.com",
                claims={"email": "user@example.com"},
                client_id="google",
                scopes=["scope-a"],
                expires_at=1234567890,
                sub="user@example.com",
            )

    monkeypatch.setattr("core.server.get_auth_provider", lambda: _FakeProvider())

    async def _noop_ensure_session(*args, **kwargs):
        return None

    monkeypatch.setattr(
        "auth.auth_info_middleware.ensure_session_from_access_token",
        _noop_ensure_session,
    )

    async def call_next(ctx):
        assert ctx is context
        return "ok"

    result = await middleware.on_call_tool(context, call_next)

    assert result == "ok"
    assert observed["args"] == ()
    assert observed["kwargs"] == {"include": {"authorization"}}
    assert observed["token"] == "ya29.token"
    assert fastmcp_context.state["authenticated_user_email"] == "user@example.com"
    assert fastmcp_context.state["authenticated_via"] == "bearer_token"
    assert fastmcp_context.state_serializable["authenticated_user_email"] is False
    assert fastmcp_context.state_serializable["authenticated_via"] is False
    assert fastmcp_context.state_serializable["access_token"] is False
    assert fastmcp_context.state_serializable["user_email"] is False
    assert fastmcp_context.state_serializable["username"] is False
    assert fastmcp_context.state_serializable["auth_provider_type"] is False
    assert fastmcp_context.state_serializable["token_type"] is False


@pytest.mark.asyncio
async def test_fastmcp_oauth_identity_is_request_scoped(monkeypatch):
    middleware = AuthInfoMiddleware()
    fastmcp_context = _FakeFastMCPContext()
    context = SimpleNamespace(fastmcp_context=fastmcp_context)
    access_token = SimpleNamespace(
        email="passthrough@local",
        claims={"email": "passthrough@local"},
    )

    monkeypatch.setattr(
        "auth.auth_info_middleware.get_access_token", lambda: access_token
    )
    monkeypatch.setattr(
        "auth.auth_info_middleware.get_http_headers",
        lambda *args, **kwargs: pytest.fail(
            "fastmcp_oauth path must not fall through to bearer header parsing"
        ),
    )

    await middleware._process_request_for_auth(context)

    assert fastmcp_context.state["authenticated_user_email"] == "passthrough@local"
    assert fastmcp_context.state["authenticated_via"] == "fastmcp_oauth"
    assert fastmcp_context.state["access_token"] is access_token
    assert fastmcp_context.state_serializable["authenticated_user_email"] is False
    assert fastmcp_context.state_serializable["authenticated_via"] is False
    assert fastmcp_context.state_serializable["access_token"] is False


@pytest.mark.asyncio
async def test_gateway_identity_is_request_scoped_and_clears_stale_state(monkeypatch):
    middleware = AuthInfoMiddleware()
    fastmcp_context = _FakeFastMCPContext()
    fastmcp_context.state.update(
        {
            "authenticated_user_email": "stale@example.com",
            "authenticated_via": "mcp_session_binding",
        }
    )
    context = SimpleNamespace(fastmcp_context=fastmcp_context)

    monkeypatch.setattr(
        "auth.auth_info_middleware.is_trust_gateway_identity", lambda: True
    )
    monkeypatch.setattr(
        "auth.auth_info_middleware.get_oauth_config",
        lambda: SimpleNamespace(gateway_identity_header="x-gateway-assertion"),
    )
    monkeypatch.setattr(
        "auth.auth_info_middleware.get_http_headers",
        lambda **kwargs: (
            {"x-gateway-assertion": "signed.jwt"}
            if kwargs == {"include": {"x-gateway-assertion"}}
            else {}
        ),
    )
    monkeypatch.setattr(
        "auth.auth_info_middleware.extract_email_from_assertion",
        lambda assertion: "verified@example.com" if assertion == "signed.jwt" else None,
    )
    monkeypatch.setattr(
        "auth.auth_info_middleware.get_access_token",
        lambda: pytest.fail("gateway mode must not inspect legacy access tokens"),
    )

    await middleware._process_request_for_auth(context)

    assert fastmcp_context.state["authenticated_user_email"] == "verified@example.com"
    assert fastmcp_context.state["authenticated_via"] == "gateway_assertion"
    assert fastmcp_context.state_serializable["authenticated_user_email"] is False
    assert fastmcp_context.state_serializable["authenticated_via"] is False
    assert "authenticated_user_email" in fastmcp_context.deleted_state
    assert "authenticated_via" in fastmcp_context.deleted_state


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "verified_email"),
    [
        ({}, None),
        ({"x-gateway-assertion": "invalid.jwt"}, None),
    ],
)
async def test_gateway_identity_failure_does_not_fall_back(
    monkeypatch, headers, verified_email
):
    middleware = AuthInfoMiddleware()
    fastmcp_context = _FakeFastMCPContext()
    fastmcp_context.state["authenticated_user_email"] = "stale@example.com"
    context = SimpleNamespace(fastmcp_context=fastmcp_context)

    monkeypatch.setattr(
        "auth.auth_info_middleware.is_trust_gateway_identity", lambda: True
    )
    monkeypatch.setattr(
        "auth.auth_info_middleware.get_oauth_config",
        lambda: SimpleNamespace(gateway_identity_header="x-gateway-assertion"),
    )
    monkeypatch.setattr(
        "auth.auth_info_middleware.get_http_headers",
        lambda **kwargs: headers,
    )
    monkeypatch.setattr(
        "auth.auth_info_middleware.extract_email_from_assertion",
        lambda assertion: verified_email,
    )
    monkeypatch.setattr(
        "auth.auth_info_middleware.get_access_token",
        lambda: pytest.fail("gateway mode must not inspect legacy access tokens"),
    )

    with pytest.raises(GatewayIdentityError):
        await middleware._process_request_for_auth(context)

    assert "authenticated_user_email" not in fastmcp_context.state


@pytest.mark.asyncio
async def test_on_call_tool_requests_authorization_header_when_default_headers_are_empty(
    monkeypatch,
):
    middleware = AuthInfoMiddleware()
    fastmcp_context = _FakeFastMCPContext()
    context = SimpleNamespace(fastmcp_context=fastmcp_context)
    observed = {"calls": []}

    monkeypatch.setattr("auth.auth_info_middleware.get_access_token", lambda: None)

    def fake_get_http_headers(*args, **kwargs):
        observed["calls"].append({"args": args, "kwargs": kwargs})
        if kwargs == {"include": {"authorization"}}:
            return {"authorization": "Bearer ya29.token"}
        return {}

    monkeypatch.setattr(
        "auth.auth_info_middleware.get_http_headers",
        fake_get_http_headers,
    )

    class _FakeProvider:
        async def verify_token(self, token):
            observed["token"] = token
            return SimpleNamespace(
                email="user@example.com",
                claims={"email": "user@example.com"},
                client_id="google",
                scopes=["scope-a"],
                expires_at=1234567890,
                sub="user@example.com",
            )

    monkeypatch.setattr("core.server.get_auth_provider", lambda: _FakeProvider())

    async def _noop_ensure_session(*args, **kwargs):
        return None

    monkeypatch.setattr(
        "auth.auth_info_middleware.ensure_session_from_access_token",
        _noop_ensure_session,
    )

    async def call_next(ctx):
        assert ctx is context
        return "ok"

    result = await middleware.on_call_tool(context, call_next)

    assert result == "ok"
    assert observed["calls"] == [
        {"args": (), "kwargs": {}},
        {"args": (), "kwargs": {"include": {"authorization"}}},
    ]
    assert observed["token"] == "ya29.token"
    assert fastmcp_context.state["authenticated_user_email"] == "user@example.com"
    assert fastmcp_context.state["authenticated_via"] == "bearer_token"
    assert fastmcp_context.state_serializable["authenticated_user_email"] is False
    assert fastmcp_context.state_serializable["authenticated_via"] is False
