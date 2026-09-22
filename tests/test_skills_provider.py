from __future__ import annotations

import asyncio

from fastmcp import Client, FastMCP

from core.skills_provider import register_skills_provider, skill_main_file, skills_roots

SKILL = """---
name: flatbee-ops
description: Flatbee playbook
---
# Flatbee Ops
Call ops_project_brief first.
"""


def _skills_dir(tmp_path):
    root = tmp_path / "skills"
    (root / "flatbee-ops").mkdir(parents=True)
    (root / "flatbee-ops" / "SKILL.md").write_text(SKILL, encoding="utf-8")
    (root / "not-a-skill").mkdir()
    return root


def test_roots_and_main_file(monkeypatch, tmp_path):
    root = _skills_dir(tmp_path)
    monkeypatch.setenv("WORKSPACE_MCP_SKILLS_DIR", f"{root}, {tmp_path / 'missing'}")
    assert skills_roots() == [root]
    assert skill_main_file("flatbee-ops") == root / "flatbee-ops" / "SKILL.md"
    assert skill_main_file("../etc") is None
    assert skill_main_file("nope") is None


def test_provider_serves_skill_resource(monkeypatch, tmp_path):
    root = _skills_dir(tmp_path)
    monkeypatch.setenv("WORKSPACE_MCP_SKILLS_DIR", str(root))
    server = FastMCP("t")
    assert register_skills_provider(server) == 1

    async def run():
        async with Client(server) as client:
            resources = await client.list_resources()
            uris = {str(r.uri) for r in resources}
            assert "skill://flatbee-ops/SKILL.md" in uris
            content = await client.read_resource("skill://flatbee-ops/SKILL.md")
            return content[0].text

    assert "Call ops_project_brief first." in asyncio.run(run())


def test_provider_is_noop_without_config(monkeypatch):
    monkeypatch.delenv("WORKSPACE_MCP_SKILLS_DIR", raising=False)
    assert register_skills_provider(FastMCP("t")) == 0
