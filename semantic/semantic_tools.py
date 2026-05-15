"""Semantic retrieval tools for indexed Flatbee Drive/OCR documents."""

import asyncio
import json
import logging
import os
from typing import Any, Optional

import httpx
import psycopg
from fastmcp.exceptions import ToolError
from googleapiclient.errors import HttpError
from mcp.types import ToolAnnotations
from psycopg.rows import dict_row

from auth.service_decorator import require_google_service
from core.server import server
from core.utils import handle_http_errors

logger = logging.getLogger(__name__)

DEFAULT_DATABASE_URL = "postgresql://metabase@127.0.0.1:5432/db_flatbee"
DEFAULT_EMBEDDING_MODEL = "text-embedding-3-large"
DEFAULT_EMBEDDING_DIMENSIONS = 1536
MAX_LIMIT = 20
MAX_CANDIDATES = 120
MAX_ACCESS_CHECK_ROWS = 80
DEFAULT_ACL_BYPASS_EMAILS = {
    "ai@flatbee.cz",
    "jakub.chodura@flatbee.cz",
    "michal.kniha@flatbee.cz",
    "dusan.kniha@flatbee.cz",
}


def _database_url() -> str:
    return (
        os.getenv("FLATBEE_RETRIEVAL_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or os.getenv("POSTGRES_DSN")
        or DEFAULT_DATABASE_URL
    )


def _openai_api_key() -> str:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise ToolError(
            "OPENAI_API_KEY is not configured. Set it in the Workspace MCP runtime "
            "environment before using semantic_search_drive_docs."
        )
    return api_key


def _embedding_model() -> str:
    return os.getenv("OPENAI_EMBEDDING_MODEL", DEFAULT_EMBEDDING_MODEL).strip()


def _embedding_dimensions() -> int:
    raw = os.getenv("OPENAI_EMBEDDING_DIMENSIONS", str(DEFAULT_EMBEDDING_DIMENSIONS))
    try:
        dimensions = int(raw)
    except ValueError as exc:
        raise ToolError(f"Invalid OPENAI_EMBEDDING_DIMENSIONS value: {raw!r}") from exc
    if dimensions != DEFAULT_EMBEDDING_DIMENSIONS:
        raise ToolError(
            "Flatbee agent_retrieval.document_chunks.embedding is vector(1536); "
            f"got OPENAI_EMBEDDING_DIMENSIONS={dimensions}."
        )
    return dimensions


def _vector_literal(vector: list[float]) -> str:
    return "[" + ",".join(f"{value:.12g}" for value in vector) + "]"


async def _embed_query(query: str) -> tuple[str, str, int, int]:
    model = _embedding_model()
    dimensions = _embedding_dimensions()
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    payload = {
        "model": model,
        "input": query,
        "dimensions": dimensions,
        "encoding_format": "float",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{base_url}/embeddings",
            headers={
                "Authorization": f"Bearer {_openai_api_key()}",
                "Content-Type": "application/json",
            },
            json=payload,
        )

    if response.status_code >= 400:
        body = response.text[:1000]
        raise ToolError(
            f"OpenAI embeddings request failed: {response.status_code} {body}"
        )

    data = response.json()
    embedding = data.get("data", [{}])[0].get("embedding")
    if not isinstance(embedding, list) or len(embedding) != dimensions:
        raise ToolError(
            f"OpenAI returned an invalid embedding length; expected {dimensions}."
        )
    usage = data.get("usage") or {}
    return (
        _vector_literal(embedding),
        data.get("model") or model,
        dimensions,
        int(usage.get("total_tokens") or usage.get("prompt_tokens") or 0),
    )


def _clamp_limit(limit: int) -> int:
    try:
        parsed = int(limit)
    except (TypeError, ValueError) as exc:
        raise ToolError("limit must be an integer") from exc
    return max(1, min(parsed, MAX_LIMIT))


def _acl_bypass_emails() -> set[str]:
    raw = os.getenv("SEMANTIC_SEARCH_ACL_BYPASS_EMAILS")
    if raw is None:
        return set(DEFAULT_ACL_BYPASS_EMAILS)
    return {email.strip().lower() for email in raw.split(",") if email.strip()}


def _should_bypass_drive_acl(user_google_email: str) -> bool:
    return user_google_email.strip().lower() in _acl_bypass_emails()


def _add_filter(
    clauses: list[str],
    params: list[Any],
    sql: str,
    values: list[str],
) -> None:
    clean_values = [value.strip() for value in values if value and value.strip()]
    if not clean_values:
        return
    clauses.append(sql)
    params.extend(clean_values)


def _search_rows(
    *,
    query: str,
    query_vector: str,
    project_code: Optional[str],
    doc_type: Optional[str],
    folder_path: Optional[str],
    relevance: Optional[str],
    limit: int,
    require_hard_verify: bool,
    prefer_authoritative: bool,
    deduplicate: bool,
) -> list[dict[str, Any]]:
    where = ["d.status = 'ready'"]
    params: list[Any] = []
    _add_filter(
        where,
        params,
        "(d.project_code = %s OR d.project_code ILIKE (%s || '_%%') OR d.folder_path ILIKE ('%%' || %s || '%%'))",
        [project_code or "", project_code or "", project_code or ""],
    )
    _add_filter(
        where,
        params,
        "(d.document_class = %s OR d.source_type = %s OR d.metadata->>'doc_type' = %s OR c.metadata->>'doc_type' = %s)",
        [doc_type or "", doc_type or "", doc_type or "", doc_type or ""],
    )
    _add_filter(
        where,
        params,
        "d.folder_path ILIKE ('%%' || %s || '%%')",
        [folder_path or ""],
    )
    _add_filter(
        where,
        params,
        "(d.metadata->>'relevance' = %s OR c.metadata->>'relevance' = %s)",
        [relevance or "", relevance or ""],
    )

    where_sql = " AND ".join(where)
    candidate_limit = min(max(limit * 6, 40), MAX_CANDIDATES)

    sql = f"""
WITH vector_ranked AS (
    SELECT
        c.chunk_id,
        row_number() OVER (ORDER BY c.embedding <=> %s::vector) AS vector_rank,
        1 - (c.embedding <=> %s::vector) AS vector_score
    FROM agent_retrieval.document_chunks c
    JOIN agent_retrieval.documents d ON d.document_id = c.document_id
    WHERE {where_sql}
      AND c.embedding IS NOT NULL
    ORDER BY c.embedding <=> %s::vector
    LIMIT %s
),
text_ranked AS (
    SELECT
        c.chunk_id,
        row_number() OVER (
            ORDER BY ts_rank_cd(c.chunk_tsv, websearch_to_tsquery('simple', %s)) DESC
        ) AS text_rank,
        ts_rank_cd(c.chunk_tsv, websearch_to_tsquery('simple', %s)) AS text_score
    FROM agent_retrieval.document_chunks c
    JOIN agent_retrieval.documents d ON d.document_id = c.document_id
    WHERE {where_sql}
      AND c.chunk_tsv @@ websearch_to_tsquery('simple', %s)
    ORDER BY ts_rank_cd(c.chunk_tsv, websearch_to_tsquery('simple', %s)) DESC
    LIMIT %s
),
ranked AS (
    SELECT
        COALESCE(v.chunk_id, t.chunk_id) AS chunk_id,
        v.vector_rank,
        v.vector_score,
        t.text_rank,
        t.text_score,
        COALESCE(1.0 / (60 + v.vector_rank), 0) * 0.72
          + COALESCE(1.0 / (60 + t.text_rank), 0) * 0.28 AS combined_score
    FROM vector_ranked v
    FULL OUTER JOIN text_ranked t USING (chunk_id)
),
scored AS (
    SELECT
        r.*,
        c.document_id,
        d.metadata->>'version_group_key' AS version_group_key,
        CASE
          WHEN d.metadata->>'current_winner_document_id' ~ '^[0-9]+$'
            THEN (d.metadata->>'current_winner_document_id')::bigint
          ELSE NULL
        END AS current_winner_document_id,
        CASE
          WHEN %s THEN (
            CASE
              WHEN COALESCE((d.metadata->>'current_version')::boolean, false) THEN 0.0060
              ELSE 0
            END
            + CASE
              WHEN d.metadata->>'current_winner_document_id' ~ '^[0-9]+$'
                   AND d.document_id = (d.metadata->>'current_winner_document_id')::bigint THEN 0.0060
              ELSE 0
            END
            + CASE
              WHEN COALESCE((d.metadata->>'canonical_document')::boolean, d.is_canonical, true) THEN 0.0015
              ELSE -0.0060
            END
          )
          ELSE 0
        END AS authority_score
    FROM ranked r
    JOIN agent_retrieval.document_chunks c ON c.chunk_id = r.chunk_id
    JOIN agent_retrieval.documents d ON d.document_id = c.document_id
),
deduped AS (
    SELECT
        s.*,
        row_number() OVER (
            PARTITION BY CASE WHEN %s THEN COALESCE(s.document_id, s.document_id) ELSE s.chunk_id END
            ORDER BY s.combined_score + s.authority_score DESC, s.combined_score DESC, s.vector_score DESC NULLS LAST
        ) AS chunk_group_rank,
        row_number() OVER (
            PARTITION BY CASE WHEN %s THEN COALESCE(d.canonical_document_id, d.document_id) ELSE s.chunk_id END
            ORDER BY s.combined_score + s.authority_score DESC, s.combined_score DESC, s.vector_score DESC NULLS LAST
        ) AS canonical_group_rank,
        row_number() OVER (
            PARTITION BY CASE
              WHEN %s THEN COALESCE(s.version_group_key, 'document:' || COALESCE(d.canonical_document_id, d.document_id)::text)
              ELSE 'chunk:' || s.chunk_id::text
            END
            ORDER BY
              CASE WHEN s.current_winner_document_id IS NOT NULL AND d.document_id = s.current_winner_document_id THEN 1 ELSE 0 END DESC,
              s.combined_score + s.authority_score DESC,
              s.combined_score DESC,
              s.vector_score DESC NULLS LAST
        ) AS version_group_rank
    FROM scored s
    JOIN agent_retrieval.documents d ON d.document_id = s.document_id
)
SELECT
    dd.combined_score + dd.authority_score AS combined_score,
    dd.combined_score AS retrieval_score,
    dd.authority_score,
    dd.vector_score,
    dd.text_score,
    dd.vector_rank,
    dd.text_rank,
    c.chunk_id,
    c.document_id,
    c.chunk_index,
    c.chunk_text,
    c.section_path,
    c.page_number,
    c.page_start,
    c.page_end,
    c.metadata AS chunk_metadata,
    d.drive_file_id,
    d.drive_web_url,
    d.file_name,
    d.folder_path,
    d.project_code,
    d.source_type,
    d.document_class,
    d.canonical_document_id,
    d.is_canonical,
    dd.version_group_key,
    dd.current_winner_document_id,
    d.metadata AS document_metadata,
    CASE
      WHEN %s THEN (
        SELECT jsonb_agg(
          jsonb_build_object(
            'page_number', p.page_number,
            'snippet', left(regexp_replace(p.page_text, '\\s+', ' ', 'g'), 1200)
          )
          ORDER BY p.page_number
        )
        FROM agent_retrieval.document_pages p
        WHERE p.document_id = c.document_id
          AND p.page_number BETWEEN
            COALESCE(c.page_start, c.page_number, 1)
            AND COALESCE(c.page_end, c.page_number, c.page_start, 1)
      )
      ELSE NULL
    END AS verification_pages
FROM deduped dd
JOIN agent_retrieval.document_chunks c ON c.chunk_id = dd.chunk_id
JOIN agent_retrieval.documents d ON d.document_id = c.document_id
WHERE (NOT %s OR (dd.canonical_group_rank = 1 AND dd.version_group_rank = 1))
ORDER BY combined_score DESC, dd.combined_score DESC, dd.vector_score DESC NULLS LAST
LIMIT %s;
"""
    sql_params: list[Any] = [query_vector, query_vector]
    sql_params.extend(params)
    sql_params.append(query_vector)
    sql_params.append(candidate_limit)
    sql_params.extend([query, query])
    sql_params.extend(params)
    sql_params.extend(
        [
            query,
            query,
            candidate_limit,
            prefer_authoritative,
            deduplicate,
            deduplicate,
            deduplicate,
            require_hard_verify,
            deduplicate,
            limit,
        ]
    )

    with psycopg.connect(_database_url(), row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, sql_params)
            return list(cur.fetchall())


def _metadata_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


async def _drive_file_accessible(
    service: Any,
    file_id: str,
    access_cache: dict[str, bool],
) -> bool:
    """Return whether the authenticated Drive user can read file metadata."""
    if not file_id:
        return False
    if file_id in access_cache:
        return access_cache[file_id]

    try:
        await asyncio.to_thread(
            service.files()
            .get(
                fileId=file_id,
                fields="id",
                supportsAllDrives=True,
            )
            .execute
        )
        access_cache[file_id] = True
        return True
    except HttpError as exc:
        status = getattr(getattr(exc, "resp", None), "status", None)
        if status in {403, 404}:
            logger.info(
                "semantic_search_drive_docs filtered inaccessible Drive file_id=%s status=%s",
                file_id,
                status,
            )
            access_cache[file_id] = False
            return False
        raise ToolError(
            f"Drive access verification failed for an indexed result: HTTP {status or 'unknown'}"
        ) from exc


async def _filter_rows_by_drive_access(
    service: Any,
    rows: list[dict[str, Any]],
    limit: int,
) -> tuple[list[dict[str, Any]], int]:
    accessible: list[dict[str, Any]] = []
    filtered_count = 0
    access_cache: dict[str, bool] = {}

    for row in rows:
        file_id = (row.get("drive_file_id") or "").strip()
        if await _drive_file_accessible(service, file_id, access_cache):
            accessible.append(row)
            if len(accessible) >= limit:
                break
        else:
            filtered_count += 1

    return accessible, filtered_count


SNIPPET_MAX_CHARS = 400
VERIFICATION_MAX_CHARS = 200
VERIFICATION_OVERLAP_DROP_THRESHOLD = 0.7


def _trim_snippet(text: str, max_chars: int) -> str:
    """Collapse whitespace and trim to max_chars, preserving a leading page anchor."""
    cleaned = " ".join((text or "").split())
    if len(cleaned) <= max_chars:
        return cleaned
    anchor = ""
    remainder = cleaned
    if cleaned.startswith("[[page"):
        end = cleaned.find("]]")
        if end != -1:
            anchor = cleaned[: end + 2]
            remainder = cleaned[end + 2 :].lstrip()
    budget = max_chars - (len(anchor) + 1 if anchor else 0) - 3
    if budget <= 0:
        return (anchor + "..." if anchor else cleaned[: max_chars - 3].rstrip() + "...")
    trimmed = remainder[:budget].rstrip() + "..."
    return f"{anchor} {trimmed}" if anchor else trimmed


def _verification_overlap(snippet: str, verification: str) -> float:
    """Return fraction of verification tokens already present in snippet."""
    snippet_tokens = set((snippet or "").lower().split())
    verification_tokens = (verification or "").lower().split()
    if not verification_tokens:
        return 1.0
    overlap = sum(1 for tok in verification_tokens if tok in snippet_tokens)
    return overlap / len(verification_tokens)


def _format_result(row: dict[str, Any], index: int, require_hard_verify: bool) -> str:
    chunk_text = _trim_snippet(row.get("chunk_text") or "", SNIPPET_MAX_CHARS)

    metadata = _metadata_dict(row.get("document_metadata"))
    project_code = (
        row.get("project_code") or metadata.get("project_code") or "unknown"
    )
    lines = [f"{index}. {row.get('file_name') or 'Untitled document'}"]
    if row.get("drive_web_url"):
        lines.append(f"   url={row['drive_web_url']}")

    flag_bits = [f"project={project_code}"]
    if (
        metadata.get("current_version") is not None
        or metadata.get("canonical_document") is not None
    ):
        flag_bits.append(
            f"canonical={metadata.get('canonical_document', row.get('is_canonical'))}"
        )
        flag_bits.append(f"current={metadata.get('current_version')}")
    page = row.get("page_number") or row.get("page_start")
    if page:
        page_end = row.get("page_end")
        page_text = f"{page}-{page_end}" if page_end and page_end != page else str(page)
        flag_bits.append(f"page={page_text}")
    lines.append("   " + " ".join(flag_bits))

    lines.append(f"   snippet: {chunk_text}")

    pages = row.get("verification_pages")
    if require_hard_verify and pages:
        if isinstance(pages, str):
            pages = json.loads(pages)
        verify_bits = []
        for page_row in pages[:3]:
            snippet = _trim_snippet(
                page_row.get("snippet") or "", VERIFICATION_MAX_CHARS
            )
            if not snippet:
                continue
            if (
                _verification_overlap(chunk_text, snippet)
                >= VERIFICATION_OVERLAP_DROP_THRESHOLD
            ):
                continue
            verify_bits.append(f"p.{page_row.get('page_number')}: {snippet}")
        if verify_bits:
            lines.append("   verification: " + " | ".join(verify_bits))
    return "\n".join(lines)


@server.tool(
    title="Semantic Search Drive Docs",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
@handle_http_errors(
    "semantic_search_drive_docs", is_read_only=True, service_type="semantic"
)
@require_google_service("drive", "drive_read")
async def semantic_search_drive_docs(
    service,
    query: str,
    project_code: Optional[str] = None,
    doc_type: Optional[str] = None,
    folder_path: Optional[str] = None,
    relevance: Optional[str] = None,
    limit: int = 3,
    require_hard_verify: bool = False,
    prefer_authoritative: bool = True,
    deduplicate: bool = True,
    user_google_email: str = "",
) -> str:
    """
    Search the indexed Flatbee Drive/OCR corpus using OpenAI embeddings plus
    Postgres full-text ranking.

    Args:
        query: Natural-language search query.
        project_code: Optional exact project code filter, e.g. P22 or H83.
        doc_type: Optional document type/source filter.
        folder_path: Optional folder-path substring filter.
        relevance: Optional relevance metadata filter.
        limit: Number of results to return (default 3, capped at 20).
        require_hard_verify: Include page-level verification snippets when available.
        prefer_authoritative: Prefer explicit canonical/current metadata written by
            the retrieval index resolver. Disable for raw ranking/debugging.
        deduplicate: Return only the best chunk per canonical document group.
        user_google_email: Google account whose Drive OAuth token is used to verify
            per-result file access before snippets are returned. Trusted internal
            accounts in SEMANTIC_SEARCH_ACL_BYPASS_EMAILS bypass this filter.
    """
    if not query or not query.strip():
        raise ToolError("query is required")

    safe_limit = _clamp_limit(limit)
    stripped_query = query.strip()
    query_vector, model, dimensions, token_count = await _embed_query(stripped_query)
    prefilter_limit = min(max(safe_limit * 4, safe_limit), MAX_ACCESS_CHECK_ROWS)
    candidate_rows = await asyncio.to_thread(
        _search_rows,
        query=stripped_query,
        query_vector=query_vector,
        project_code=project_code,
        doc_type=doc_type,
        folder_path=folder_path,
        relevance=relevance,
        limit=prefilter_limit,
        require_hard_verify=require_hard_verify,
        prefer_authoritative=prefer_authoritative,
        deduplicate=deduplicate,
    )
    acl_bypassed = _should_bypass_drive_acl(user_google_email)
    if acl_bypassed:
        rows = candidate_rows[:safe_limit]
        filtered_count = 0
    else:
        rows, filtered_count = await _filter_rows_by_drive_access(
            service,
            candidate_rows,
            safe_limit,
        )
    if not rows:
        filters = {
            "project_code": project_code,
            "doc_type": doc_type,
            "folder_path": folder_path,
            "relevance": relevance,
        }
        active = {k: v for k, v in filters.items() if v}
        suffix = (
            f" {filtered_count} indexed result(s) were hidden by Drive access checks."
            if filtered_count
            else ""
        )
        return f"No semantic retrieval results for query={query!r}, filters={active}.{suffix}"

    # Embedding model / ACL diagnostics are intentionally omitted from the model-facing
    # payload to keep token usage low. Surface them via logs only.
    logger.debug(
        "semantic_search_drive_docs query=%r embedding_model=%s dimensions=%s tokens=%s "
        "drive_access_checked_for=%s drive_acl_bypassed=%s hidden_by_drive_acl=%s",
        stripped_query,
        model,
        dimensions,
        token_count,
        user_google_email or "authenticated_user",
        acl_bypassed,
        filtered_count,
    )
    header = f"Found {len(rows)} results for {stripped_query!r}."
    return "\n\n".join(
        [header]
        + [
            _format_result(row, index, require_hard_verify)
            for index, row in enumerate(rows, start=1)
        ]
    )
