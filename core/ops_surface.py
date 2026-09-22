"""Per-user tool surface: show only the curated Flatbee `ops_*` tools to selected users.

claude.ai does not defer connector tools, so every exposed tool schema lands in the
model's context and tool choice gets worse as the catalog grows. Business users who
already have native Gmail/Drive/Calendar connectors only need the `ops_*` surface.
Configure WORKSPACE_MCP_OPS_ONLY_EMAILS (comma-separated) and optionally
WORKSPACE_MCP_OPS_ONLY_EXTRA_TOOLS (tool names still visible to those users).
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from typing import Any

OPS_PREFIX = "ops_"


def _csv_env(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def ops_only_emails() -> set[str]:
    return _csv_env("WORKSPACE_MCP_OPS_ONLY_EMAILS")


def ops_only_extra_tools() -> set[str]:
    return {name for name in _csv_env("WORKSPACE_MCP_OPS_ONLY_EXTRA_TOOLS")}


def token_email(token: Any) -> str | None:
    """Email of the authenticated principal, as AuthInfoMiddleware derives it."""
    if token is None:
        return None
    email = getattr(token, "email", None)
    if not email and hasattr(token, "claims"):
        claims = getattr(token, "claims", None) or {}
        email = claims.get("email") if isinstance(claims, dict) else None
    return str(email).strip().lower() if email else None


def is_visible(
    tool_name: str, email: str | None, restricted: set[str], extra: set[str]
) -> bool:
    """Pure decision: restricted users see `ops_*` plus explicitly allowed tools."""
    if not email or email not in restricted:
        return True
    return tool_name.startswith(OPS_PREFIX) or tool_name in extra


def make_ops_surface_check(
    restricted: set[str] | None = None, extra: set[str] | None = None
) -> Callable[[Any], Awaitable[bool]]:
    """Build a FastMCP AuthCheck: `async (AuthContext) -> bool`.

    Only tools are filtered; resources and prompts pass through. Reads the env at call
    time when no explicit sets are given so a restart is not needed to add a user.
    """

    async def check(ctx: Any) -> bool:
        component = getattr(ctx, "component", None)
        name = getattr(component, "name", None)
        if not isinstance(name, str):
            return True
        # Components other than tools (resources, prompts) are not part of the surface.
        component_type = type(component).__name__.lower()
        if "tool" not in component_type and not name.startswith(OPS_PREFIX):
            if "resource" in component_type or "prompt" in component_type:
                return True
        users = restricted if restricted is not None else ops_only_emails()
        allowed = extra if extra is not None else ops_only_extra_tools()
        return is_visible(
            name, token_email(getattr(ctx, "token", None)), users, allowed
        )

    return check
