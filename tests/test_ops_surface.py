from __future__ import annotations

import asyncio
from types import SimpleNamespace

from core.ops_surface import is_visible, make_ops_surface_check, token_email


class Tool(SimpleNamespace):
    pass


class Resource(SimpleNamespace):
    pass


def _ctx(email, component):
    token = SimpleNamespace(email=None, claims={"email": email}) if email else None
    return SimpleNamespace(token=token, component=component)


def test_restricted_user_sees_only_ops_tools():
    check = make_ops_surface_check({"jakub@flatbee.cz"}, {"search_gmail_messages"})
    assert asyncio.run(check(_ctx("Jakub@flatbee.cz", Tool(name="ops_project_brief"))))
    assert asyncio.run(
        check(_ctx("jakub@flatbee.cz", Tool(name="search_gmail_messages")))
    )
    assert not asyncio.run(check(_ctx("jakub@flatbee.cz", Tool(name="create_doc"))))


def test_other_users_and_anonymous_are_untouched():
    check = make_ops_surface_check({"jakub@flatbee.cz"}, set())
    assert asyncio.run(check(_ctx("dusan@flatbee.cz", Tool(name="create_doc"))))
    assert asyncio.run(check(_ctx(None, Tool(name="create_doc"))))


def test_resources_and_prompts_pass_through():
    check = make_ops_surface_check({"jakub@flatbee.cz"}, set())
    assert asyncio.run(check(_ctx("jakub@flatbee.cz", Resource(name="drive://x"))))


def test_env_driven_sets(monkeypatch):
    monkeypatch.setenv("WORKSPACE_MCP_OPS_ONLY_EMAILS", "a@x.cz, B@x.cz")
    monkeypatch.setenv(
        "WORKSPACE_MCP_OPS_ONLY_EXTRA_TOOLS", "ops_doctor,get_drive_file_content"
    )
    check = make_ops_surface_check()
    assert asyncio.run(check(_ctx("b@x.cz", Tool(name="get_drive_file_content"))))
    assert not asyncio.run(check(_ctx("b@x.cz", Tool(name="list_calendars"))))


def test_helpers():
    assert token_email(SimpleNamespace(email="X@Y.cz")) == "x@y.cz"
    assert token_email(None) is None
    assert is_visible("ops_x", "u@x", {"u@x"}, set())
    assert not is_visible("gmail", "u@x", {"u@x"}, set())
