"""Semantic retrieval tools for indexed Flatbee Drive/OCR documents."""

import asyncio
import json
import logging
import math
import os
import re
from dataclasses import dataclass
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
DEFAULT_TWENTY_RECORD_URL_TEMPLATE = "{base}/object/document/{id}"

# Full-text branch of the hybrid search. "legacy" is the original
# websearch_to_tsquery AND-of-all-words match, which almost never fires for
# sentence-shaped questions. "idf" ORs the informative query words, weights
# them by inverse document frequency from agent_retrieval.term_stats, and
# matches accent-insensitively with a cheap prefix stand-in for Czech/Slovak
# inflection.
TEXT_BRANCH_ENV = "SEMANTIC_TEXT_BRANCH"
TEXT_BRANCH_MODES = ("legacy", "idf")
# Stays "legacy" until idf matches it on every original retrieval_eval case:
# on 2026-09-22 idf passed 39/40 original (legacy 38/40) and 10/12
# natural-language cases (legacy 9/12), but lost h92_lizalek_share_source.
DEFAULT_TEXT_BRANCH = "legacy"
# Reciprocal-rank-fusion weights (vector, text) per text branch mode.
RRF_WEIGHTS = {
    "legacy": (0.72, 0.28),
    "idf": (0.72, 0.28),
}
# Words present in more than this share of documents carry no signal
# ("smlouva", "praha", "dne") and would only flood the OR query.
IDF_MAX_DOC_FRACTION = 0.30
IDF_MIN_TERM_LENGTH = 3
IDF_MAX_QUERY_TERMS = 12
# Accent/inflection variants resolved per query word, most frequent first.
IDF_MAX_TERM_VARIANTS = 24
# Question and function words (unaccented, 3+ letters; "byt" stays searchable
# because it means "apartment" far more often than "to be" here). Corpus IDF rates them
# as rare because contracts seldom ask questions, so without this list
# "jaká"/"kolik"/"which" would outweigh the words that carry the question.
QUERY_STOPWORDS = frozenset(
    """
    aka ake akej aku aky akych ako ale ano bol bola bolo byl byla byli bylo
    jak jaka jake jakem jakou jaky jakych jako jeho jej jeji jsem jsme jsou
    kde kdo koho kolik kolko komu kdy kedy kto ktera ktere kterou ktery kterych
    ktora ktore ktoru ktory ktorych mam mame maji mat muze mozu moze mozno nebo
    alebo pod nad pre pri pro proc preco kvuli podle podla mezi medzi tak tam
    tedy ten tento tato toto tyto teda uz jiz vsak vsech vsetky ktorom ktorem
    najdi najdite najit najst dokument dokumentu dokumenty dokumente
    the and are was were for from with that this these those into about what
    which who whom whose when where why how does did doing has have had can
    could should would will any all each every find show list give document
    documents
    """.split()
)
PREFIX_MIN_TERM_LENGTH = 5
PREFIX_MIN_STEM_LENGTH = 4
# After stripping an ending, long stems are cut to leave out the last few
# letters of the word as well: Czech/Slovak stems alternate there
# (Lízálek/Lízálka, výpověď/výpovědní), so a shorter prefix still matches.
PREFIX_TRUNCATE_TAIL = 3
PREFIX_TRUNCATE_MIN_LENGTH = 5
# How a term's document frequency is estimated from its variants: "max"
# assumes inflected forms co-occur in the same documents (a lower bound on
# the union), "sum" assumes they never do (an upper bound).
IDF_GROUP_DF = "max"
# Common Czech/Slovak inflectional endings (unaccented), longest first. Only
# one is stripped, and only while the stem keeps PREFIX_MIN_STEM_LENGTH chars.
PREFIX_STRIP_SUFFIXES = (
    "iach",
    "eho",
    "emu",
    "ych",
    "ymi",
    "ami",
    "ach",
    "ho",
    "mu",
    "ou",
    "em",
    "ej",
    "om",
    "ov",
    "ch",
    "a",
    "e",
    "i",
    "o",
    "u",
    "y",
)


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


def _twenty_base_url() -> Optional[str]:
    base = os.getenv("TWENTY_BASE_URL", "").strip()
    return base.rstrip("/") or None


def _twenty_api_key() -> Optional[str]:
    api_key = os.getenv("TWENTY_API_KEY", "").strip()
    return api_key or None


def _twenty_record_url(record_id: Optional[str]) -> Optional[str]:
    """Build a Twenty CRM record URL for a document, or None if Twenty
    linking is not configured (TWENTY_BASE_URL unset) or there is no
    known record id for this result."""
    base = _twenty_base_url()
    if not base or not record_id:
        return None
    template = os.getenv(
        "TWENTY_RECORD_URL_TEMPLATE", DEFAULT_TWENTY_RECORD_URL_TEMPLATE
    )
    return template.format(base=base, id=record_id)


def _lookup_twenty_document_ids_sql(drive_file_ids: list[str]) -> dict[str, str]:
    """Map drive_file_id -> Twenty document record id via the
    registry.twenty_document snapshot table, which sonar/stages/twenty_sync.py
    upserts keyed on the same file id it writes to Twenty as sourceFileId."""
    if not drive_file_ids:
        return {}
    sql = (
        "SELECT source_file_id, twenty_document_id "
        "FROM registry.twenty_document "
        "WHERE source_file_id = ANY(%s)"
    )
    with psycopg.connect(_database_url(), row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, [drive_file_ids])
            return {
                row["source_file_id"]: row["twenty_document_id"]
                for row in cur.fetchall()
                if row.get("source_file_id") and row.get("twenty_document_id")
            }


async def _lookup_twenty_document_ids_rest(drive_file_ids: list[str]) -> dict[str, str]:
    """Fallback batch lookup via the Twenty REST API, used only when the
    registry.twenty_document snapshot table is unavailable. Requires both
    TWENTY_BASE_URL and TWENTY_API_KEY."""
    base = _twenty_base_url()
    api_key = _twenty_api_key()
    if not base or not api_key or not drive_file_ids:
        return {}

    params = {
        "filter": f"sourceFileId[in]:{','.join(drive_file_ids)}",
        "limit": len(drive_file_ids),
        "depth": 0,
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"{base}/rest/documents",
                params=params,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("Twenty REST document lookup failed: %s", exc)
        return {}

    data = payload.get("data", payload) if isinstance(payload, dict) else payload
    records = data.get("documents", data) if isinstance(data, dict) else data
    if not isinstance(records, list):
        return {}
    return {
        record["sourceFileId"]: record["id"]
        for record in records
        if isinstance(record, dict) and record.get("sourceFileId") and record.get("id")
    }


async def _lookup_twenty_document_ids(drive_file_ids: list[str]) -> dict[str, str]:
    """Resolve Twenty document record ids for a batch of drive_file_ids.
    Silently returns {} (no Twenty links surfaced) when TWENTY_BASE_URL is
    not configured, so the tool behaves exactly as before by default."""
    unique_ids = sorted({file_id for file_id in drive_file_ids if file_id})
    if not unique_ids or not _twenty_base_url():
        return {}
    try:
        return await asyncio.to_thread(_lookup_twenty_document_ids_sql, unique_ids)
    except psycopg.Error as exc:
        logger.info(
            "registry.twenty_document lookup failed (%s); falling back to Twenty REST",
            exc,
        )
        return await _lookup_twenty_document_ids_rest(unique_ids)


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


@dataclass(frozen=True)
class QueryTerm:
    """One informative query word: its unaccented form and optional prefix stem."""

    term: str
    stem: Optional[str]


@dataclass(frozen=True)
class IdfTextPlan:
    """Resolved full-text query for the idf branch.

    ``match_query`` ORs every term group and drives the GIN candidate lookup;
    ``term_queries``/``idfs`` score each matching chunk as
    SUM(idf_t * ts_rank_cd(chunk_tsv, term_query_t)).
    """

    match_query: str
    term_queries: tuple[str, ...]
    idfs: tuple[float, ...]
    terms: tuple[str, ...]


def _text_branch_mode() -> str:
    raw = os.getenv(TEXT_BRANCH_ENV, "").strip().lower()
    if not raw:
        return DEFAULT_TEXT_BRANCH
    if raw not in TEXT_BRANCH_MODES:
        logger.warning(
            "Unknown %s=%r; using %s", TEXT_BRANCH_ENV, raw, DEFAULT_TEXT_BRANCH
        )
        return DEFAULT_TEXT_BRANCH
    return raw


def _prefix_stem(term: str) -> Optional[str]:
    """Return a prefix stem for inflected words, or None to match exactly.

    Czech and Slovak inflect heavily (pokuta/pokuty/pokutou, úvěr/úvěru) and
    the 'simple' text search config does no stemming. Stripping one common
    ending from words of PREFIX_MIN_TERM_LENGTH+ letters, shortening long
    stems by PREFIX_TRUNCATE_TAIL letters and matching the rest as a prefix is
    a cheap approximation that needs no dictionary. The term_stats variant
    lookup (capped at IDF_MAX_TERM_VARIANTS, IDF-weighted) bounds the noise a
    short prefix brings in.
    """
    if len(term) < PREFIX_MIN_TERM_LENGTH or not term.isalpha():
        return None
    stem = term
    for suffix in PREFIX_STRIP_SUFFIXES:
        if term.endswith(suffix) and len(term) - len(suffix) >= PREFIX_MIN_STEM_LENGTH:
            stem = term[: -len(suffix)]
            break
    if PREFIX_TRUNCATE_TAIL:
        keep = max(PREFIX_TRUNCATE_MIN_LENGTH, len(term) - PREFIX_TRUNCATE_TAIL)
        stem = stem[:keep]
    return stem


def _select_query_terms(
    lexemes: list[str], exclude: frozenset[str] = frozenset()
) -> list[QueryTerm]:
    """Pick candidate terms from unaccented query lexemes, in query order.

    ``exclude`` holds words a SQL filter already enforces (the project code):
    inside the filtered scope they match nearly everything, yet corpus-wide
    IDF rates them as informative.
    """
    seen: set[str] = set(exclude)
    terms: list[QueryTerm] = []
    for lexeme in lexemes:
        term = (lexeme or "").strip().lower()
        if len(term) < IDF_MIN_TERM_LENGTH or term in seen or term in QUERY_STOPWORDS:
            continue
        # Pure punctuation or numbers with separators ("285/8") rarely occur
        # verbatim in OCR text; plain numbers ("2023") are kept.
        if not re.fullmatch(r"[\w.]+", term):
            continue
        seen.add(term)
        terms.append(QueryTerm(term=term, stem=_prefix_stem(term)))
    return terms


def _term_resolution_sql(terms: list[QueryTerm]) -> tuple[str, list[Any]]:
    """Build one UNION ALL lookup of term_stats variants per query term.

    Each branch uses the text_pattern_ops index on lexeme_unaccent for both the
    exact (accent-insensitive) match and the prefix match. Stems are alphabetic
    only, so they need no LIKE escaping.
    """
    parts: list[str] = []
    params: list[Any] = []
    for index, term in enumerate(terms):
        params.append(index)
        if term.stem:
            condition = "(s.lexeme_unaccent = %s OR s.lexeme_unaccent LIKE %s)"
            params.extend([term.term, term.stem + "%"])
        else:
            condition = "s.lexeme_unaccent = %s"
            params.append(term.term)
        params.append(term.term)
        parts.append(
            f"""(
    SELECT %s::int AS term_index, s.lexeme, s.doc_count, s.total_docs
    FROM agent_retrieval.term_stats s
    WHERE {condition}
    ORDER BY (s.lexeme_unaccent = %s) DESC, s.doc_count DESC, s.lexeme
    LIMIT {IDF_MAX_TERM_VARIANTS}
)"""
        )
    return "\nUNION ALL\n".join(parts), params


def _tsquery_lexeme(lexeme: str, *, prefix: bool = False) -> str:
    escaped = lexeme.replace("\\", "\\\\").replace("'", "''")
    return f"'{escaped}'" + (":*" if prefix else "")


def _idf(doc_count: int, total_docs: int) -> float:
    return math.log((total_docs + 1) / (doc_count + 1)) + 1.0


def _plan_idf_text_query(
    terms: list[QueryTerm], rows: list[dict[str, Any]]
) -> Optional[IdfTextPlan]:
    """Turn resolved term_stats variants into weighted per-term tsqueries.

    A term's document frequency is estimated from its variants' frequencies
    (see IDF_GROUP_DF), capped at the corpus size.
    """
    variants: dict[int, list[tuple[str, int]]] = {}
    total_docs = 0
    for row in rows:
        index = int(row["term_index"])
        variants.setdefault(index, []).append(
            (str(row["lexeme"]), int(row["doc_count"]))
        )
        total_docs = max(total_docs, int(row["total_docs"] or 0))
    if total_docs <= 0:
        return None

    max_doc_count = IDF_MAX_DOC_FRACTION * total_docs
    weighted: list[tuple[float, int, str, str]] = []
    for index, term in enumerate(terms):
        term_variants = variants.get(index)
        if not term_variants:
            continue
        counts = [count for _, count in term_variants]
        doc_count = max(counts) if IDF_GROUP_DF == "max" else sum(counts)
        doc_count = min(total_docs, doc_count)
        if doc_count > max_doc_count:
            continue
        lexemes = [_tsquery_lexeme(lexeme) for lexeme, _ in term_variants]
        if term.stem:
            # Native prefix match also covers lexemes indexed after the last
            # term_stats refresh (unaccented spellings only).
            lexemes.append(_tsquery_lexeme(term.stem, prefix=True))
        weighted.append(
            (_idf(doc_count, total_docs), index, term.term, " | ".join(lexemes))
        )

    if not weighted:
        return None
    weighted.sort(key=lambda item: (-item[0], item[1]))
    kept = sorted(weighted[:IDF_MAX_QUERY_TERMS], key=lambda item: item[1])
    return IdfTextPlan(
        match_query=" | ".join(f"({query})" for _, _, _, query in kept),
        term_queries=tuple(query for _, _, _, query in kept),
        idfs=tuple(round(idf, 6) for idf, _, _, _ in kept),
        terms=tuple(term for _, _, term, _ in kept),
    )


def _resolve_idf_text_plan(
    cur: Any, query: str, project_code: Optional[str] = None
) -> Optional[IdfTextPlan]:
    """Tokenize the query in Postgres and resolve its terms against term_stats."""
    cur.execute(
        """
SELECT l.lexeme
FROM unnest(to_tsvector('simple', unaccent(%s))) AS l(lexeme, positions, weights)
ORDER BY l.positions[1]
""",
        [query],
    )
    exclude = (
        frozenset({project_code.strip().lower()})
        if project_code and project_code.strip()
        else frozenset()
    )
    terms = _select_query_terms([row["lexeme"] for row in cur.fetchall()], exclude)
    if not terms:
        return None
    sql, params = _term_resolution_sql(terms)
    cur.execute(sql, params)
    return _plan_idf_text_query(terms, list(cur.fetchall()))


def _text_ranked_cte(
    *,
    mode: str,
    query: str,
    where_sql: str,
    where_params: list[Any],
    candidate_limit: int,
    plan: Optional[IdfTextPlan],
) -> tuple[str, list[Any]]:
    """SQL and parameters for the text_ranked CTE of the hybrid search."""
    if mode == "legacy":
        sql = f"""text_ranked AS (
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
)"""
        return sql, [query, query, *where_params, query, query, candidate_limit]

    if plan is None:
        # Nothing informative to match; the vector branch carries the query.
        return (
            """text_ranked AS (
    SELECT NULL::bigint AS chunk_id, NULL::bigint AS text_rank, NULL::float8 AS text_score
    WHERE false
)""",
            [],
        )

    # ts_rank_cd normalization 32 maps a rank r to r/(r+1): a saturating
    # term-frequency curve, so repeating one word cannot outweigh matching a
    # second, rarer word.
    sql = f"""text_matches AS (
    SELECT c.chunk_id, c.chunk_tsv
    FROM agent_retrieval.document_chunks c
    JOIN agent_retrieval.documents d ON d.document_id = c.document_id
    WHERE {where_sql}
      AND c.chunk_tsv @@ %s::tsquery
),
text_scored AS (
    SELECT
        m.chunk_id,
        SUM(t.idf * ts_rank_cd(m.chunk_tsv, t.term_query, 32)) AS text_score
    FROM text_matches m
    CROSS JOIN unnest(%s::tsquery[], %s::float8[]) AS t(term_query, idf)
    WHERE m.chunk_tsv @@ t.term_query
    GROUP BY m.chunk_id
),
text_ranked AS (
    SELECT
        chunk_id,
        row_number() OVER (ORDER BY text_score DESC, chunk_id) AS text_rank,
        text_score
    FROM text_scored
    ORDER BY text_score DESC, chunk_id
    LIMIT %s
)"""
    params = [
        *where_params,
        plan.match_query,
        list(plan.term_queries),
        list(plan.idfs),
        candidate_limit,
    ]
    return sql, params


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
    mode = _text_branch_mode()

    with psycopg.connect(_database_url(), row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            plan: Optional[IdfTextPlan] = None
            if mode == "idf":
                try:
                    plan = _resolve_idf_text_plan(cur, query, project_code)
                except psycopg.errors.UndefinedTable:
                    # term_stats not created yet: degrade to the legacy match.
                    conn.rollback()
                    logger.warning(
                        "agent_retrieval.term_stats missing; using legacy text branch"
                    )
                    mode = "legacy"
            text_ranked_sql, text_params = _text_ranked_cte(
                mode=mode,
                query=query,
                where_sql=where_sql,
                where_params=params,
                candidate_limit=candidate_limit,
                plan=plan,
            )
            sql = _hybrid_search_sql(
                where_sql=where_sql, text_ranked_sql=text_ranked_sql, mode=mode
            )
            sql_params = _hybrid_search_params(
                query=query,
                query_vector=query_vector,
                where_params=params,
                candidate_limit=candidate_limit,
                text_params=text_params,
                prefer_authoritative=prefer_authoritative,
                deduplicate=deduplicate,
                require_hard_verify=require_hard_verify,
                limit=limit,
            )
            cur.execute(sql, sql_params)
            return list(cur.fetchall())


def _hybrid_search_sql(*, where_sql: str, text_ranked_sql: str, mode: str) -> str:
    vector_weight, text_weight = (float(weight) for weight in RRF_WEIGHTS[mode])
    return f"""
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
{text_ranked_sql},
ranked AS (
    SELECT
        COALESCE(v.chunk_id, t.chunk_id) AS chunk_id,
        v.vector_rank,
        v.vector_score,
        t.text_rank,
        t.text_score,
        COALESCE(1.0 / (60 + v.vector_rank), 0) * {vector_weight}
          + COALESCE(1.0 / (60 + t.text_rank), 0) * {text_weight} AS combined_score
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
            -- extraction_quality is the structured extractor's confidence in
            -- its own fields, not evidence that a document is current or
            -- authoritative. Treat any successful extraction as a mild
            -- "business document" prior; a high/medium split used to swing
            -- scores more than the explicit current-version signal did.
            + CASE
              WHEN d.metadata->>'extraction_quality' IN ('high', 'medium') THEN 0.0030
              ELSE 0
            END
            -- Copies kept in archive folders (ARCHIV, 99_ARCHIV, 98_ARCHIVE)
            -- are superseded working material; prefer the live folder copy.
            + CASE
              WHEN d.folder_path ~* '(^|/)[0-9]*_?archiv' THEN -0.0040
              ELSE 0
            END
            + CASE
              WHEN d.file_name ~* '\\mdraft\\M|neaktu' THEN -0.0060
              ELSE 0
            END
          )
          ELSE 0
        END AS authority_score,
        -- A bounded filename signal helps explicit source requests without
        -- overpowering semantic/text relevance for ordinary questions.
        LEAST(
          GREATEST(
            word_similarity(
              lower(normalize(COALESCE(d.file_name, ''), NFC)),
              lower(normalize(%s, NFC))
            ) - 0.25,
            0
          ) * 0.02,
          0.008
        ) AS filename_score
    FROM ranked r
    JOIN agent_retrieval.document_chunks c ON c.chunk_id = r.chunk_id
    JOIN agent_retrieval.documents d ON d.document_id = c.document_id
),
deduped AS (
    SELECT
        s.*,
        row_number() OVER (
            PARTITION BY CASE WHEN %s THEN COALESCE(s.document_id, s.document_id) ELSE s.chunk_id END
            ORDER BY s.combined_score + s.authority_score + s.filename_score DESC, s.combined_score DESC, s.vector_score DESC NULLS LAST
        ) AS chunk_group_rank,
        row_number() OVER (
            PARTITION BY CASE WHEN %s THEN COALESCE(d.canonical_document_id, d.document_id) ELSE s.chunk_id END
            ORDER BY s.combined_score + s.authority_score + s.filename_score DESC, s.combined_score DESC, s.vector_score DESC NULLS LAST
        ) AS canonical_group_rank,
        row_number() OVER (
            PARTITION BY CASE
              WHEN %s THEN COALESCE(s.version_group_key, 'document:' || COALESCE(d.canonical_document_id, d.document_id)::text)
              ELSE 'chunk:' || s.chunk_id::text
            END
            ORDER BY
              CASE WHEN s.current_winner_document_id IS NOT NULL AND d.document_id = s.current_winner_document_id THEN 1 ELSE 0 END DESC,
              s.combined_score + s.authority_score + s.filename_score DESC,
              s.combined_score DESC,
              s.vector_score DESC NULLS LAST
        ) AS version_group_rank
    FROM scored s
    JOIN agent_retrieval.documents d ON d.document_id = s.document_id
)
SELECT
    dd.combined_score + dd.authority_score + dd.filename_score AS combined_score,
    dd.combined_score AS retrieval_score,
    dd.authority_score,
    dd.filename_score,
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


def _hybrid_search_params(
    *,
    query: str,
    query_vector: str,
    where_params: list[Any],
    candidate_limit: int,
    text_params: list[Any],
    prefer_authoritative: bool,
    deduplicate: bool,
    require_hard_verify: bool,
    limit: int,
) -> list[Any]:
    sql_params: list[Any] = [query_vector, query_vector]
    sql_params.extend(where_params)
    sql_params.append(query_vector)
    sql_params.append(candidate_limit)
    sql_params.extend(text_params)
    sql_params.extend(
        [
            prefer_authoritative,
            query,
            deduplicate,
            deduplicate,
            deduplicate,
            require_hard_verify,
            deduplicate,
            limit,
        ]
    )
    return sql_params


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


async def _drive_file_metadata(
    service: Any,
    file_id: str,
    metadata_cache: dict[str, Optional[dict[str, Any]]],
) -> Optional[dict[str, Any]]:
    """Return live Drive timestamps, or None when the file is inaccessible."""
    if not file_id:
        return None
    if file_id in metadata_cache:
        return metadata_cache[file_id]

    try:
        metadata = await asyncio.to_thread(
            service.files()
            .get(
                fileId=file_id,
                fields="id,createdTime,modifiedTime",
                supportsAllDrives=True,
            )
            .execute
        )
        normalized = metadata if isinstance(metadata, dict) else {"id": file_id}
        metadata_cache[file_id] = normalized
        return normalized
    except HttpError as exc:
        status = getattr(getattr(exc, "resp", None), "status", None)
        if status in {403, 404}:
            logger.info(
                "semantic_search_drive_docs Drive metadata unavailable file_id=%s status=%s",
                file_id,
                status,
            )
            metadata_cache[file_id] = None
            return None
        raise ToolError(
            f"Drive access verification failed for an indexed result: HTTP {status or 'unknown'}"
        ) from exc


def _attach_drive_metadata(row: dict[str, Any], metadata: dict[str, Any]) -> None:
    row["drive_created_time"] = metadata.get("createdTime")
    row["drive_modified_time"] = metadata.get("modifiedTime")


async def _filter_rows_by_drive_access(
    service: Any,
    rows: list[dict[str, Any]],
    limit: int,
) -> tuple[list[dict[str, Any]], int]:
    accessible: list[dict[str, Any]] = []
    filtered_count = 0
    metadata_cache: dict[str, Optional[dict[str, Any]]] = {}

    for row in rows:
        file_id = (row.get("drive_file_id") or "").strip()
        metadata = await _drive_file_metadata(service, file_id, metadata_cache)
        if metadata is not None:
            _attach_drive_metadata(row, metadata)
            accessible.append(row)
            if len(accessible) >= limit:
                break
        else:
            filtered_count += 1

    return accessible, filtered_count


async def _enrich_rows_with_drive_metadata(
    service: Any,
    rows: list[dict[str, Any]],
) -> None:
    """Add live Drive timestamps without changing trusted-account ACL behavior."""
    # Internal DB-only smoke checks deliberately call the undecorated function
    # without a Google service. Real MCP calls always receive one from the auth
    # wrapper, so only the smoke path skips live metadata enrichment.
    if service is None:
        logger.info(
            "semantic_search_drive_docs skipped Drive metadata enrichment "
            "because no Drive service was supplied"
        )
        return

    metadata_cache: dict[str, Optional[dict[str, Any]]] = {}
    for row in rows:
        file_id = (row.get("drive_file_id") or "").strip()
        metadata = await _drive_file_metadata(service, file_id, metadata_cache)
        if metadata is not None:
            _attach_drive_metadata(row, metadata)


SNIPPET_MAX_CHARS = 400
VERIFICATION_MAX_CHARS = 200
VERIFICATION_OVERLAP_DROP_THRESHOLD = 0.7
UNIT_DECLARATION_TYPE_RE = re.compile(
    r"\b(residential_byt|commercial_nebytova|other)\s+\d+/\d+\b",
    re.IGNORECASE,
)
UNIT_DECLARATION_RE = re.compile(
    r"Units declared:\s*(\d+)\s*:\s*(.*?)(?:\nCommon areas:|\nShare check:|\nSource:|$)",
    re.IGNORECASE | re.DOTALL,
)
UNIT_DECLARATION_HIDDEN_TAIL_RE = re.compile(
    r"(?:\.{3}|…)\s*\+\s*(\d+)\s+(?:ďalších|dalších|dalsich|additional)\b",
    re.IGNORECASE,
)


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
        return anchor + "..." if anchor else cleaned[: max_chars - 3].rstrip() + "..."
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


def _unit_declaration_summary(text: str) -> Optional[str]:
    """Return a compact typed-unit count from structured owner declarations."""
    match = UNIT_DECLARATION_RE.search(text or "")
    if not match:
        return None

    total = int(match.group(1))
    unit_blob = match.group(2)
    counts: dict[str, int] = {}
    last_type: Optional[str] = None
    for unit_type in UNIT_DECLARATION_TYPE_RE.findall(unit_blob):
        normalized = unit_type.lower()
        counts[normalized] = counts.get(normalized, 0) + 1
        last_type = normalized

    hidden_match = UNIT_DECLARATION_HIDDEN_TAIL_RE.search(unit_blob)
    inferred_hidden = 0
    if hidden_match and last_type:
        inferred_hidden = int(hidden_match.group(1))
        counts[last_type] = counts.get(last_type, 0) + inferred_hidden

    if not counts:
        return f"unit_summary: total={total}"

    typed_total = sum(counts.values())
    parts = [f"{unit_type}={counts[unit_type]}" for unit_type in sorted(counts)]
    if inferred_hidden:
        parts.append(f"inferred_from_truncated_tail={inferred_hidden}")
    if typed_total != total:
        parts.append(f"typed_total={typed_total}")
    return f"unit_summary: total={total}; " + "; ".join(parts)


def _format_result(row: dict[str, Any], index: int, require_hard_verify: bool) -> str:
    raw_chunk_text = row.get("chunk_text") or ""
    chunk_text = _trim_snippet(raw_chunk_text, SNIPPET_MAX_CHARS)

    metadata = _metadata_dict(row.get("document_metadata"))
    project_code = row.get("project_code") or metadata.get("project_code") or "unknown"
    lines = [f"{index}. {row.get('file_name') or 'Untitled document'}"]
    if row.get("drive_web_url"):
        lines.append(f"   url={row['drive_web_url']}")
    twenty_url = _twenty_record_url(row.get("twenty_document_id"))
    if twenty_url:
        lines.append(f"   twenty={twenty_url}")

    timestamp_bits = []
    if row.get("drive_created_time"):
        timestamp_bits.append(f"createdTime={row['drive_created_time']}")
    if row.get("drive_modified_time"):
        timestamp_bits.append(f"modifiedTime={row['drive_modified_time']}")
    if timestamp_bits:
        lines.append("   " + " ".join(timestamp_bits))

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

    unit_summary = _unit_declaration_summary(raw_chunk_text)
    if unit_summary:
        lines.append(f"   {unit_summary}")

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
    Postgres full-text ranking. Every accessible result includes live Google
    Drive createdTime and modifiedTime metadata for deterministic recency checks.

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
        await _enrich_rows_with_drive_metadata(service, rows)
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

    twenty_ids = await _lookup_twenty_document_ids(
        [row.get("drive_file_id") for row in rows]
    )
    for row in rows:
        row["twenty_document_id"] = twenty_ids.get(row.get("drive_file_id") or "")

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
