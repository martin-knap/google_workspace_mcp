"""Bounded backend clients used by the Flatbee operator tools."""

from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx
from fastmcp import Client


TWENTY_OBJECT_FILTERS: dict[str, set[str]] = {
    "projects": {
        "id",
        "projectCode",
        "businessStatus",
        "lifecyclePhase",
        "documentControlState",
    },
    "documents": {
        "id",
        "projectCode",
        "sourceFileId",
        "docType",
        "docFamily",
        "processState",
        "lifecyclePhase",
    },
    "dataQualityIssues": {
        "id",
        "projectCode",
        "status",
        "severity",
        "issueType",
        "sourceEvidence",
    },
    "lifecycleMilestones": {"id", "projectCode", "code", "status", "phase"},
    "lifecycleTasks": {"id", "projectCode", "code", "status", "phase"},
    "units": {"id", "projectCode", "unitNumber", "unitType", "status"},
    "leases": {"id", "projectCode", "status", "tenantName", "unitNumber"},
    "invoices": {"id", "projectCode", "status", "invoiceNumber"},
    "financings": {"id", "projectCode", "status", "financingType"},
    "unitSales": {"id", "projectCode", "status", "unitNumber"},
}


def _twenty_base_url() -> str:
    value = os.getenv("TWENTY_BASE_URL", "").strip().rstrip("/")
    if not value:
        raise RuntimeError("TWENTY_BASE_URL is not configured")
    return value


def _twenty_api_key() -> str:
    value = os.getenv("TWENTY_API_KEY", "").strip()
    if not value:
        raise RuntimeError("TWENTY_API_KEY is not configured")
    return value


def _unwrap_records(
    payload: Any, object_name: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    data = payload.get("data", payload) if isinstance(payload, dict) else payload
    if isinstance(data, dict):
        records = data.get(object_name, data.get("records", []))
        page_info = (
            data.get("pageInfo")
            or (payload.get("pageInfo") if isinstance(payload, dict) else None)
            or {}
        )
    else:
        records, page_info = data, {}
    page_info = dict(page_info) if isinstance(page_info, dict) else {}
    if isinstance(payload, dict) and payload.get("totalCount") is not None:
        page_info.setdefault("totalCount", payload["totalCount"])
    return (
        [item for item in records if isinstance(item, dict)]
        if isinstance(records, list)
        else []
    ), page_info


async def twenty_query(
    object_name: str,
    filters: dict[str, str] | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    if object_name not in TWENTY_OBJECT_FILTERS:
        raise ValueError(f"Unsupported Twenty object {object_name!r}")
    filters = filters or {}
    unsupported = sorted(set(filters) - TWENTY_OBJECT_FILTERS[object_name])
    if unsupported:
        raise ValueError(
            f"Unsupported filters for {object_name}: {', '.join(unsupported)}"
        )
    clean = {
        key: str(value).strip()
        for key, value in filters.items()
        if value is not None and str(value).strip()
    }
    # Keep the agent-facing response bounded. Depth 1 expands every relation
    # and can turn a small query into hundreds of kilobytes of nested records.
    params: dict[str, Any] = {"limit": max(1, min(int(limit), 100)), "depth": 0}
    if clean:
        params["filter"] = ",".join(
            f"{key}[eq]:{value}" for key, value in clean.items()
        )
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(
            f"{_twenty_base_url()}/rest/{object_name}",
            params=params,
            headers={
                "Authorization": f"Bearer {_twenty_api_key()}",
                "Accept": "application/json",
            },
        )
    response.raise_for_status()
    records, page_info = _unwrap_records(response.json(), object_name)
    total = page_info.get("totalCount") or page_info.get("total")
    return {
        "object": object_name,
        "filters": clean,
        "count": len(records),
        "total_count": total,
        "truncated": bool(total is not None and int(total) > len(records)),
        "records": records,
    }


def _mcp_payload(result: Any) -> Any:
    structured = getattr(result, "structured_content", None)
    if structured is not None:
        if isinstance(structured, dict) and set(structured) == {"result"}:
            nested = structured["result"]
            if isinstance(nested, str):
                try:
                    return json.loads(nested)
                except json.JSONDecodeError:
                    return nested
        return structured
    content = getattr(result, "content", None) or []
    texts = [
        getattr(item, "text", "") for item in content if getattr(item, "text", None)
    ]
    if len(texts) == 1:
        try:
            return json.loads(texts[0])
        except json.JSONDecodeError:
            return texts[0]
    return texts


async def graphiti_search(
    query: str, project_code: str | None = None, limit: int = 10
) -> dict[str, Any]:
    url = os.getenv("GRAPHITI_MCP_URL", "https://graphiti.flatbee.cz/mcp").strip()
    token = os.getenv("GRAPHITI_MCP_SERVICE_TOKEN", "").strip()
    if not token:
        raise RuntimeError("GRAPHITI_MCP_SERVICE_TOKEN is not configured")
    routed_query = f"Project {project_code}: {query}" if project_code else query
    async with Client(url, auth=token, timeout=45) as client:
        result = await client.call_tool(
            "search_advanced",
            {
                "query": routed_query,
                "num_results": max(1, min(int(limit), 20)),
                "include_nodes": True,
                "include_edges": True,
                "include_episodes": True,
                "include_communities": False,
            },
        )
    payload = _mcp_payload(result)
    if not project_code:
        return {"query": routed_query, "result": payload}

    scoped, dropped = _scope_graphiti_payload(payload, project_code)
    return {
        "query": routed_query,
        "project_scope": project_code,
        "scope_mode": "explicit_project_token",
        "dropped_out_of_scope": dropped,
        "result": scoped,
    }


def _scope_graphiti_payload(
    payload: Any, project_code: str
) -> tuple[Any, dict[str, int]]:
    """Keep only Graphiti hits that explicitly carry the requested project code.

    The current graph uses one shared group id, so query relevance alone is not
    a hard project boundary. Precision is safer than returning plausible but
    unrelated context in a project workspace.
    """
    if not isinstance(payload, dict):
        return payload, {}

    code = project_code.strip().upper()
    token = re.compile(rf"(?<![A-Z0-9]){re.escape(code)}(?![A-Z0-9])")
    scoped: dict[str, Any] = {}
    dropped: dict[str, int] = {}
    for category, value in payload.items():
        if not isinstance(value, list):
            scoped[category] = value
            continue
        kept = [
            item
            for item in value
            if token.search(json.dumps(item, ensure_ascii=False).upper())
        ]
        scoped[category] = kept
        if len(kept) != len(value):
            dropped[category] = len(value) - len(kept)
    return scoped, dropped
