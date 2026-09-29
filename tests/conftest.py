import pytest

from auth.oauth_config import reload_oauth_config


@pytest.fixture(autouse=True)
def _reset_oauth_config():
    """Rebuild the OAuth config singleton after each test.

    Tests that set env vars and reload the config would otherwise leave a
    singleton built from their env (stateless mode, transport, OAuth 2.1) for
    every test that follows. As an argument-free autouse fixture this tears
    down after ``monkeypatch`` has restored the env, so the rebuild sees it.
    """
    yield
    reload_oauth_config()
