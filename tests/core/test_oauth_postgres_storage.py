"""Tests for the PostgreSQL-backed OAuth 2.1 client_storage backend.

These tests exercise the postgres/postgresql branch added to
`core.server.configure_server_for_http`. They run entirely against
mocked stand-ins for `PostgreSQLStore` so no real Postgres is required.
"""

from types import SimpleNamespace

import sys

import pytest

import core.server as server_module


class _FakePostgreSQLStore:
    """Stand-in for ``key_value.aio.stores.postgresql.PostgreSQLStore``.

    Records the construction kwargs so tests can assert how the server
    branch invoked it.
    """

    instances: list["_FakePostgreSQLStore"] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        _FakePostgreSQLStore.instances.append(self)


def _install_fake_postgres_module(monkeypatch):
    """Install a fake ``key_value.aio.stores.postgresql`` module exposing FakeStore."""

    _FakePostgreSQLStore.instances = []
    fake_module = SimpleNamespace(PostgreSQLStore=_FakePostgreSQLStore)
    monkeypatch.setitem(
        sys.modules, "key_value.aio.stores.postgresql", fake_module
    )
    return _FakePostgreSQLStore


def _common_monkeypatches(monkeypatch, captured):
    class FakeGoogleProvider:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.client_registration_options = SimpleNamespace(
                valid_scopes=kwargs.get("valid_scopes"),
                default_scopes=None,
            )
            default_scope = " ".join(kwargs.get("required_scopes", []))
            self._default_scope_str = default_scope
            self._cimd_manager = SimpleNamespace(default_scope=default_scope)

    monkeypatch.setattr(server_module, "get_transport_mode", lambda: "streamable-http")
    monkeypatch.setattr(server_module, "GoogleProvider", FakeGoogleProvider)
    monkeypatch.setattr(
        server_module,
        "get_current_scopes",
        lambda: [
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid",
        ],
    )
    monkeypatch.setattr(server_module, "set_auth_provider", lambda provider: None)
    monkeypatch.setattr(server_module, "_auth_provider", server_module._auth_provider)
    monkeypatch.setattr(server_module.server, "auth", server_module.server.auth)

    monkeypatch.setattr(
        "auth.oauth_config.get_oauth_config",
        lambda: SimpleNamespace(
            is_oauth21_enabled=lambda: True,
            is_configured=lambda: True,
            is_public_client=lambda: False,
            is_external_oauth21_provider=lambda: False,
            client_id="client-id",
            client_secret="client-secret",
            get_oauth_base_url=lambda: "https://workspace-mcp.example.test",
            redirect_path="/oauth2callback",
        ),
    )


def test_postgres_storage_backend_wraps_fake_store_with_fernet(monkeypatch):
    """STORAGE_BACKEND=postgres + DSN should yield Fernet-wrapped PostgreSQLStore."""
    captured: dict = {}
    fake_cls = _install_fake_postgres_module(monkeypatch)
    _common_monkeypatches(monkeypatch, captured)

    monkeypatch.setenv("WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND", "postgres")
    monkeypatch.setenv(
        "WORKSPACE_MCP_OAUTH_PROXY_POSTGRES_DSN", "postgresql://test/x"
    )
    monkeypatch.delenv("WORKSPACE_MCP_OAUTH_PROXY_POSTGRES_TABLE", raising=False)
    monkeypatch.delenv("WORKSPACE_MCP_OAUTH_PROXY_VALKEY_HOST", raising=False)

    server_module.configure_server_for_http()

    # The configure code wraps the store with FernetEncryptionWrapper before
    # passing it to GoogleProvider.
    from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

    client_storage = captured["client_storage"]
    assert isinstance(client_storage, FernetEncryptionWrapper)

    # The inner store must be our fake PostgreSQLStore, constructed with the
    # expected kwargs.
    assert len(fake_cls.instances) == 1
    inner_store = fake_cls.instances[0]
    # FernetEncryptionWrapper stores the wrapped key/value store as a public
    # attribute named ``key_value`` (per py-key-value-aio wrappers API).
    assert getattr(client_storage, "key_value", None) is inner_store

    assert inner_store.kwargs == {
        "url": "postgresql://test/x",
        "table_name": "fastmcp_oauth_kv",
        "auto_create": True,
    }


def test_postgres_storage_backend_respects_custom_table(monkeypatch):
    captured: dict = {}
    fake_cls = _install_fake_postgres_module(monkeypatch)
    _common_monkeypatches(monkeypatch, captured)

    monkeypatch.setenv("WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND", "postgresql")
    monkeypatch.setenv(
        "WORKSPACE_MCP_OAUTH_PROXY_POSTGRES_DSN", "postgresql://test/x"
    )
    monkeypatch.setenv(
        "WORKSPACE_MCP_OAUTH_PROXY_POSTGRES_TABLE", "custom_oauth_kv"
    )
    monkeypatch.delenv("WORKSPACE_MCP_OAUTH_PROXY_VALKEY_HOST", raising=False)

    server_module.configure_server_for_http()

    assert len(fake_cls.instances) == 1
    assert fake_cls.instances[0].kwargs["table_name"] == "custom_oauth_kv"


def test_postgres_storage_backend_with_empty_dsn_falls_back(monkeypatch, caplog):
    """STORAGE_BACKEND=postgres but empty DSN should fall back without raising."""
    captured: dict = {}
    fake_cls = _install_fake_postgres_module(monkeypatch)
    _common_monkeypatches(monkeypatch, captured)

    monkeypatch.setenv("WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND", "postgres")
    monkeypatch.delenv("WORKSPACE_MCP_OAUTH_PROXY_POSTGRES_DSN", raising=False)
    monkeypatch.delenv("WORKSPACE_MCP_OAUTH_PROXY_VALKEY_HOST", raising=False)

    with caplog.at_level("WARNING", logger=server_module.logger.name):
        server_module.configure_server_for_http()

    # Store was never instantiated.
    assert fake_cls.instances == []
    # Provider got client_storage=None so FastMCP falls back to in-memory.
    assert captured["client_storage"] is None
    # The branch logs a warning explaining the fallback.
    assert any(
        "WORKSPACE_MCP_OAUTH_PROXY_POSTGRES_DSN is empty" in record.getMessage()
        for record in caplog.records
    )


def test_postgres_storage_backend_missing_dependency_falls_back(monkeypatch, caplog):
    """When py-key-value-aio[postgresql] is not installed, fall back gracefully."""
    captured: dict = {}
    _common_monkeypatches(monkeypatch, captured)

    # Simulate ImportError by removing any cached module and inserting one that
    # raises on attribute access via a meta finder. The simplest stable way is
    # to insert a module placeholder that re-raises ImportError when imported.
    # However, `from key_value.aio.stores.postgresql import PostgreSQLStore`
    # in the server branch will follow normal import semantics: if we pre-set
    # the module in sys.modules to None, Python raises ImportError on import.
    monkeypatch.setitem(sys.modules, "key_value.aio.stores.postgresql", None)

    monkeypatch.setenv("WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND", "postgres")
    monkeypatch.setenv(
        "WORKSPACE_MCP_OAUTH_PROXY_POSTGRES_DSN", "postgresql://test/x"
    )
    monkeypatch.delenv("WORKSPACE_MCP_OAUTH_PROXY_VALKEY_HOST", raising=False)

    with caplog.at_level("WARNING", logger=server_module.logger.name):
        server_module.configure_server_for_http()

    assert captured["client_storage"] is None
    assert any(
        "py-key-value-aio[postgresql] is not installed" in record.getMessage()
        for record in caplog.records
    )
