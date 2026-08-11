"""A small company-level MCP surface over the Flatbee data platform."""

from __future__ import annotations

import asyncio
import os
import re
from functools import lru_cache
from typing import Any

from mcp.types import ToolAnnotations

from auth.service_decorator import _get_auth_context
from core.server import server
from gdrive.drive_tools import get_drive_file_content
from semantic.semantic_tools import semantic_search_drive_docs

from .clients import graphiti_search, twenty_query
from .store import OpsStore


READ_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
PREPARE_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)
EXECUTE_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)

OPS_CAPABILITIES = [
    {
        "tool": "ops_capabilities",
        "mode": "read",
        "purpose": "List the curated Flatbee operator surface.",
    },
    {
        "tool": "ops_doctor",
        "mode": "read",
        "purpose": "Check configured backends and authenticated actor.",
    },
    {
        "tool": "ops_semantic_search",
        "mode": "read",
        "purpose": "Search governed Drive/OCR evidence with project filters and live Drive timestamps.",
    },
    {
        "tool": "ops_document_read",
        "mode": "read",
        "purpose": "Read one Drive document; Office files use AnyDoc and PDFs use the PDF/OCR router.",
    },
    {
        "tool": "ops_twenty_query",
        "mode": "read",
        "purpose": "Bounded exact reads over approved Twenty objects and filters.",
    },
    {
        "tool": "ops_graph_search",
        "mode": "read",
        "purpose": "Search Graphiti entities, relationships and source episodes.",
    },
    {
        "tool": "ops_workflows_list",
        "mode": "read",
        "purpose": "List active versioned read workflows.",
    },
    {
        "tool": "ops_workflow_prepare",
        "mode": "prepare",
        "purpose": "Prepare an immutable workflow create/update plan.",
    },
    {
        "tool": "ops_action_get",
        "mode": "read",
        "purpose": "Inspect one actor-bound action plan.",
    },
    {
        "tool": "ops_action_execute",
        "mode": "write",
        "purpose": "Apply exactly one confirmed workflow plan.",
    },
    {
        "tool": "ops_workflow_run",
        "mode": "read",
        "purpose": "Run one active bounded read workflow.",
    },
]

ALLOWED_STEP_TYPES = {
    "semantic_search",
    "document_read",
    "twenty_query",
    "graph_search",
}
WORKFLOW_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")


@lru_cache(maxsize=1)
def _store() -> OpsStore:
    return OpsStore()


def _allowed_emails() -> set[str]:
    raw = os.getenv("WORKSPACE_MCP_ALLOWED_EMAILS", "").strip() or os.getenv(
        "FLATBEE_OPS_ALLOWED_EMAILS",
        "michal.kniha@flatbee.cz,ai@flatbee.cz,dusan.kniha@flatbee.cz,"
        "jakub.chodura@flatbee.cz,ludmila.slancova@flatbee.cz",
    )
    return {value.strip().lower() for value in raw.split(",") if value.strip()}


async def _actor(tool_name: str) -> str:
    authenticated_user, _auth_method, _session_id = await _get_auth_context(tool_name)
    email = str(authenticated_user or "").strip().lower()
    if not email or email not in _allowed_emails():
        raise PermissionError(
            "Flatbee Ops is restricted to the exact configured email allowlist"
        )
    return email


def _validate_project_code(project_code: str) -> str:
    value = project_code.strip().upper()
    if not re.fullmatch(r"[A-Z]{1,8}\d{1,4}", value):
        raise ValueError(
            "project_code must be a canonical code such as P22, H83 or PERN22"
        )
    return value


def _validate_workflow_definition(steps: list[dict[str, Any]]) -> dict[str, Any]:
    if not 1 <= len(steps) <= 12:
        raise ValueError("A workflow must contain 1 to 12 steps")
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(steps, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"Workflow step {index} must be an object")
        kind = str(raw.get("type") or "").strip()
        if kind not in ALLOWED_STEP_TYPES:
            raise ValueError(f"Workflow step {index} has unsupported type {kind!r}")
        arguments = raw.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise ValueError(f"Workflow step {index} arguments must be an object")
        normalized.append({"type": kind, "arguments": arguments})
    return {"steps": normalized}


def _template(value: Any, inputs: dict[str, Any]) -> Any:
    if isinstance(value, str):
        match = re.fullmatch(r"\$\{input\.([a-zA-Z0-9_]+)\}", value)
        return inputs.get(match.group(1)) if match else value
    if isinstance(value, list):
        return [_template(item, inputs) for item in value]
    if isinstance(value, dict):
        return {key: _template(item, inputs) for key, item in value.items()}
    return value


async def _run_step(kind: str, arguments: dict[str, Any]) -> Any:
    if kind == "semantic_search":
        return await semantic_search_drive_docs(**arguments)
    if kind == "document_read":
        return await get_drive_file_content(**arguments)
    if kind == "twenty_query":
        return await twenty_query(**arguments)
    if kind == "graph_search":
        return await graphiti_search(**arguments)
    raise ValueError(f"Unsupported workflow step: {kind}")


@server.tool(annotations=READ_ANNOTATIONS)
async def ops_capabilities() -> dict[str, Any]:
    """List the curated Flatbee Ops tools and source-of-truth routing rules."""
    await _actor("ops_capabilities")
    return {
        "ok": True,
        "count": len(OPS_CAPABILITIES),
        "tools": OPS_CAPABILITIES,
        "routing": {
            "twenty": "current exact structured truth and counts",
            "workspace": "Drive/OCR source evidence; AnyDoc for Office documents",
            "graphiti": "relationships, aliases and temporal context",
            "writes": "immutable actor-bound plan, exact plan-id confirmation, read-back",
        },
    }


@server.tool(annotations=READ_ANNOTATIONS)
async def ops_doctor(live: bool = False) -> dict[str, Any]:
    """Check Flatbee Ops configuration; optional live calls are read-only."""
    actor = await _actor("ops_doctor")
    configured = {
        "twenty": bool(os.getenv("TWENTY_BASE_URL") and os.getenv("TWENTY_API_KEY")),
        "graphiti": bool(
            os.getenv("GRAPHITI_MCP_URL", "https://graphiti.flatbee.cz/mcp")
            and os.getenv("GRAPHITI_MCP_SERVICE_TOKEN")
        ),
        "workflow_store": str(_store().path),
    }
    checks: dict[str, Any] = {}
    if live:
        calls = await asyncio.gather(
            twenty_query("projects", limit=1),
            graphiti_search("Flatbee project", limit=1),
            return_exceptions=True,
        )
        checks = {
            "twenty": {
                "ok": not isinstance(calls[0], Exception),
                "error": str(calls[0]) if isinstance(calls[0], Exception) else None,
            },
            "graphiti": {
                "ok": not isinstance(calls[1], Exception),
                "error": str(calls[1]) if isinstance(calls[1], Exception) else None,
            },
        }
    return {
        "ok": all(bool(configured[key]) for key in ("twenty", "graphiti")),
        "actor": actor,
        "configured": configured,
        "live": checks,
    }


@server.tool(annotations=READ_ANNOTATIONS)
async def ops_semantic_search(
    query: str,
    project_code: str | None = None,
    doc_type: str | None = None,
    limit: int = 5,
    require_hard_verify: bool = False,
) -> str:
    """Search Drive/OCR evidence with live timestamps; exact counts still come from Twenty."""
    await _actor("ops_semantic_search")
    code = _validate_project_code(project_code) if project_code else None
    return await semantic_search_drive_docs(
        query=query,
        project_code=code,
        doc_type=doc_type,
        limit=max(1, min(int(limit), 20)),
        require_hard_verify=require_hard_verify,
        prefer_authoritative=True,
        deduplicate=True,
    )


@server.tool(annotations=READ_ANNOTATIONS)
async def ops_document_read(file_id: str) -> str:
    """Read one Drive document through the Workspace PDF/AnyDoc parser."""
    await _actor("ops_document_read")
    return await get_drive_file_content(file_id=file_id)


@server.tool(annotations=READ_ANNOTATIONS)
async def ops_twenty_query(
    object_name: str,
    filters: dict[str, str] | None = None,
    project_code: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Read an approved Twenty object with bounded exact-match filters."""
    await _actor("ops_twenty_query")
    clean = dict(filters or {})
    if project_code:
        clean["projectCode"] = _validate_project_code(project_code)
    return await twenty_query(object_name, clean, limit)


@server.tool(annotations=READ_ANNOTATIONS)
async def ops_graph_search(
    query: str, project_code: str | None = None, limit: int = 10
) -> dict[str, Any]:
    """Search Graphiti for relationships and temporal context, including source episodes."""
    await _actor("ops_graph_search")
    code = _validate_project_code(project_code) if project_code else None
    return await graphiti_search(query, code, limit)


@server.tool(annotations=READ_ANNOTATIONS)
async def ops_workflows_list() -> dict[str, Any]:
    """List active, versioned Flatbee read workflows."""
    await _actor("ops_workflows_list")
    workflows = await asyncio.to_thread(_store().list_workflows)
    return {"ok": True, "count": len(workflows), "workflows": workflows}


@server.tool(annotations=PREPARE_ANNOTATIONS)
async def ops_workflow_prepare(
    name: str,
    description: str,
    steps: list[dict[str, Any]],
    ttl_seconds: int = 900,
) -> dict[str, Any]:
    """Prepare a workflow create/update without changing the active registry."""
    actor = await _actor("ops_workflow_prepare")
    if not WORKFLOW_NAME_RE.fullmatch(name):
        raise ValueError("name must match ^[a-z][a-z0-9_]{2,63}$")
    definition = _validate_workflow_definition(steps)
    payload = {
        "name": name,
        "description": description.strip()[:500],
        "definition": definition,
    }
    plan = await asyncio.to_thread(
        _store().prepare,
        actor,
        "workflow.upsert",
        f"Activate workflow {name} with {len(steps)} bounded read steps",
        payload,
        ttl_seconds,
    )
    return {
        "ok": True,
        "executed": False,
        "requires_confirmation": True,
        "confirmation": (
            "Call ops_action_execute with plan_id and confirmation both equal "
            "to this plan id."
        ),
        "plan": plan,
    }


@server.tool(annotations=READ_ANNOTATIONS)
async def ops_action_get(plan_id: str) -> dict[str, Any]:
    """Inspect one immutable action plan owned by the authenticated actor."""
    actor = await _actor("ops_action_get")
    plan = await asyncio.to_thread(_store().get_plan, plan_id, actor)
    return {"ok": True, "plan": plan}


@server.tool(annotations=EXECUTE_ANNOTATIONS)
async def ops_action_execute(plan_id: str, confirmation: str) -> dict[str, Any]:
    """Execute one actor-bound plan once; confirmation must exactly equal plan_id."""
    actor = await _actor("ops_action_execute")
    return await asyncio.to_thread(
        _store().execute_workflow_upsert, plan_id, actor, confirmation
    )


@server.tool(annotations=READ_ANNOTATIONS)
async def ops_workflow_run(
    name: str, inputs: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Run one active workflow. MVP workflows may contain read-only bounded step types only."""
    await _actor("ops_workflow_run")
    workflow = await asyncio.to_thread(_store().get_workflow, name)
    resolved_inputs = inputs or {}
    results = []
    for index, step in enumerate(workflow["definition"]["steps"], start=1):
        arguments = _template(step["arguments"], resolved_inputs)
        try:
            output = await _run_step(step["type"], arguments)
            results.append(
                {
                    "step": index,
                    "type": step["type"],
                    "ok": True,
                    "output": output,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "step": index,
                    "type": step["type"],
                    "ok": False,
                    "error": str(exc),
                }
            )
            break
    return {
        "ok": all(item["ok"] for item in results),
        "workflow": name,
        "version": workflow["version"],
        "definition_hash": workflow["definition_hash"],
        "results": results,
    }
