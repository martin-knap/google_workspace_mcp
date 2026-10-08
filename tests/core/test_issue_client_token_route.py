import json
import sys
import types
from types import SimpleNamespace

import pytest
from starlette.requests import Request

import core.server as server_module


def make_request(body: dict, auth: str | None) -> Request:
    headers = [(b"content-type", b"application/json")]
    if auth is not None:
        headers.append((b"authorization", auth.encode("latin-1")))
    payload = json.dumps(body).encode()

    async def receive():
        return {"type": "http.request", "body": payload, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/admin/issue-client-token",
            "headers": headers,
        },
        receive,
    )


@pytest.mark.asyncio
async def test_disabled_without_dedicated_bearer_and_client_allowlist(monkeypatch):
    monkeypatch.delenv("WORKSPACE_MCP_ISSUE_TOKEN_BEARER", raising=False)
    monkeypatch.setenv(
        "WORKSPACE_MCP_ADMIN_BEARER", "the-import-secret"
    )  # must not be enough
    monkeypatch.setenv("WORKSPACE_MCP_ISSUE_TOKEN_CLIENT_IDS", "agent")
    resp = await server_module.admin_issue_client_token(
        make_request({}, "Bearer the-import-secret")
    )
    assert resp.status_code == 503


@pytest.mark.asyncio
@pytest.mark.parametrize("auth", [None, "Bearer wrong", "Bearer \xe9\xe8", "secret"])
async def test_rejects_bad_bearers_with_401(monkeypatch, auth):
    monkeypatch.setenv("WORKSPACE_MCP_ISSUE_TOKEN_BEARER", "secret")
    monkeypatch.setenv("WORKSPACE_MCP_ISSUE_TOKEN_CLIENT_IDS", "agent")
    resp = await server_module.admin_issue_client_token(make_request({}, auth))
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_maps_issuance_errors_without_leaking_details(monkeypatch):
    from auth.agent_token_issuance import IssuanceError

    monkeypatch.setenv("WORKSPACE_MCP_ISSUE_TOKEN_BEARER", "secret")
    monkeypatch.setenv("WORKSPACE_MCP_ISSUE_TOKEN_CLIENT_IDS", "agent")
    monkeypatch.setattr(
        server_module,
        "get_auth_provider",
        lambda: SimpleNamespace(exchange_authorization_code=None),
    )

    async def refuse(*a, **k):
        raise IssuanceError(404, "no existing Google sign-in for this user")

    monkeypatch.setattr("auth.agent_token_issuance.issue_client_tokens", refuse)
    resp = await server_module.admin_issue_client_token(
        make_request({"email": "a@flatbee.cz", "client_id": "agent"}, "Bearer secret")
    )
    assert resp.status_code == 404
    assert json.loads(resp.body) == {
        "error": "no existing Google sign-in for this user"
    }


@pytest.mark.asyncio
async def test_lists_upstream_keys_from_postgres(monkeypatch):
    queries = []

    class FakeConn:
        async def fetch(self, sql, collection):
            queries.append((sql, collection))
            return [{"key": "k1"}, {"key": "k2"}]

        async def close(self):
            pass

    async def connect(dsn):
        assert dsn == "postgresql://u:p@localhost/db"
        return FakeConn()

    monkeypatch.setitem(sys.modules, "asyncpg", types.SimpleNamespace(connect=connect))
    monkeypatch.setenv(
        "WORKSPACE_MCP_OAUTH_PROXY_POSTGRES_DSN", "postgresql://u:p@localhost/db"
    )
    monkeypatch.setenv("WORKSPACE_MCP_OAUTH_PROXY_POSTGRES_TABLE", "fastmcp_oauth_kv")
    # Encryption wrapper around a store without keys(), like FernetEncryptionWrapper(PostgreSQLStore).
    provider = SimpleNamespace(
        _client_storage=SimpleNamespace(key_value=SimpleNamespace())
    )

    keys = await server_module._list_upstream_token_keys(provider)
    assert keys == ["k1", "k2"]
    assert queries == [
        (
            "SELECT key FROM fastmcp_oauth_kv WHERE collection = $1",
            "mcp-upstream-tokens",
        )
    ]


@pytest.mark.asyncio
async def test_rejects_unsafe_table_names(monkeypatch):
    monkeypatch.setitem(sys.modules, "asyncpg", types.SimpleNamespace(connect=None))
    monkeypatch.setenv("WORKSPACE_MCP_OAUTH_PROXY_POSTGRES_DSN", "postgresql://x")
    monkeypatch.setenv("WORKSPACE_MCP_OAUTH_PROXY_POSTGRES_TABLE", "kv; drop table x")
    provider = SimpleNamespace(_client_storage=SimpleNamespace())
    with pytest.raises(ValueError):
        await server_module._list_upstream_token_keys(provider)
