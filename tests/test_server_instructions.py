from __future__ import annotations

import importlib

import core.server as core_server


def _reload_with_env(monkeypatch, **env):
    for key in (
        "WORKSPACE_MCP_SERVER_INSTRUCTIONS",
        "WORKSPACE_MCP_SERVER_INSTRUCTIONS_FILE",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return core_server._load_operator_instructions()


def test_operator_instructions_from_file_win_over_inline(monkeypatch, tmp_path):
    path = tmp_path / "instructions.md"
    path.write_text("Prefer ops_project_brief first.\n", encoding="utf-8")
    text = _reload_with_env(
        monkeypatch,
        WORKSPACE_MCP_SERVER_INSTRUCTIONS="inline text",
        WORKSPACE_MCP_SERVER_INSTRUCTIONS_FILE=str(path),
    )
    assert text == "Prefer ops_project_brief first."


def test_operator_instructions_inline_and_missing_file(monkeypatch, tmp_path):
    text = _reload_with_env(
        monkeypatch,
        WORKSPACE_MCP_SERVER_INSTRUCTIONS="inline text",
        WORKSPACE_MCP_SERVER_INSTRUCTIONS_FILE=str(tmp_path / "missing.md"),
    )
    assert text == "inline text"
    assert _reload_with_env(monkeypatch) is None


def test_operator_instructions_are_bounded(monkeypatch):
    text = _reload_with_env(monkeypatch, WORKSPACE_MCP_SERVER_INSTRUCTIONS="x" * 9000)
    assert text is not None and len(text) == 8000


def test_module_exposes_loader():
    assert callable(importlib.import_module("core.server")._load_operator_instructions)
