"""Serve Agent Skills (SKILL.md folders) as MCP resources.

Skills are exposed with the `skill://{name}/SKILL.md` URI convention that FastMCP's
SkillsDirectoryProvider implements, so clients that understand MCP-served skills
(Claude Code, Codex, goose, …) can discover the Flatbee operating playbook straight
from the connector. Configure WORKSPACE_MCP_SKILLS_DIR with one or more directories
(comma-separated); each subfolder containing SKILL.md becomes one skill.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def skills_roots() -> list[Path]:
    raw = os.getenv("WORKSPACE_MCP_SKILLS_DIR", "")
    roots = [Path(item.strip()).expanduser() for item in raw.split(",") if item.strip()]
    return [root for root in roots if root.is_dir()]


def skill_main_file(skill_name: str) -> Path | None:
    """Locate `{root}/{skill_name}/SKILL.md` across configured roots (first wins)."""
    if not skill_name or "/" in skill_name or skill_name.startswith("."):
        return None
    for root in skills_roots():
        candidate = root / skill_name / "SKILL.md"
        if candidate.is_file():
            return candidate
    return None


def register_skills_provider(server) -> int:
    """Attach a SkillsDirectoryProvider when roots are configured. Returns skill count."""
    roots = skills_roots()
    if not roots:
        return 0
    from fastmcp.server.providers.skills import SkillsDirectoryProvider

    provider = SkillsDirectoryProvider(roots=roots, reload=True)
    server.add_provider(provider)
    count = len(provider.providers)
    logger.info(
        "Skills provider enabled: %d skill(s) from %s",
        count,
        ", ".join(str(root) for root in roots),
    )
    return count
