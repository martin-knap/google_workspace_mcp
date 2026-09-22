"""Tests for the full-text branch of the hybrid semantic search.

The idf branch tokenizes the query in Postgres, resolves accent-insensitive
and prefix variants from agent_retrieval.term_stats, and scores chunks by
SUM(idf * ts_rank_cd). These tests cover the pure planning helpers, the SQL
builders (placeholder/parameter alignment in particular) and the database
call sequence of _search_rows in both modes, without a real database.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import psycopg
import pytest

from semantic import semantic_tools as st
from semantic.semantic_tools import (
    IdfTextPlan,
    QueryTerm,
    _hybrid_search_params,
    _hybrid_search_sql,
    _idf,
    _plan_idf_text_query,
    _prefix_stem,
    _select_query_terms,
    _term_resolution_sql,
    _text_branch_mode,
    _text_ranked_cte,
    _tsquery_lexeme,
)


def _placeholders(sql: str) -> int:
    """Count psycopg %s placeholders, ignoring %% literal escapes."""
    return len(re.findall(r"%s", sql.replace("%%", "")))


def _row(index: int, lexeme: str, doc_count: int, total_docs: int = 1000) -> dict:
    return {
        "term_index": index,
        "lexeme": lexeme,
        "doc_count": doc_count,
        "total_docs": total_docs,
    }


# ------------------------------------------------------------------ mode flag


def test_text_branch_defaults_to_configured_default(monkeypatch):
    monkeypatch.delenv("SEMANTIC_TEXT_BRANCH", raising=False)
    assert _text_branch_mode() == st.DEFAULT_TEXT_BRANCH


@pytest.mark.parametrize("raw,expected", [("idf", "idf"), (" LEGACY ", "legacy")])
def test_text_branch_reads_env(monkeypatch, raw, expected):
    monkeypatch.setenv("SEMANTIC_TEXT_BRANCH", raw)
    assert _text_branch_mode() == expected


def test_unknown_text_branch_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("SEMANTIC_TEXT_BRANCH", "bm25")
    assert _text_branch_mode() == st.DEFAULT_TEXT_BRANCH


# ---------------------------------------------------------------- tokenizing


@pytest.mark.parametrize(
    "term,stem",
    [
        ("pokuta", "pokut"),  # ending stripped: pokuta/pokuty/pokutou
        ("kauce", "kauc"),
        ("predcasneho", "predcasn"),  # "eho" stripped, then tail-truncated
        ("lizalka", "lizal"),  # matches Lízálek despite the mobile "e"
        ("brandleovej", "brandleo"),  # Slovak "-ej" still reaches Brändleová
        ("uver", None),  # too short for prefix matching
        ("pern22", None),  # not alphabetic: exact match only
    ],
)
def test_prefix_stem(term, stem):
    assert _prefix_stem(term) == stem


def test_prefix_stem_never_shorter_than_minimum():
    for term in ("kauce", "lhuta", "trzni", "odmenu", "hodnota"):
        stem = _prefix_stem(term)
        assert stem is not None
        assert len(stem) >= st.PREFIX_MIN_STEM_LENGTH
        assert term.startswith(stem)


def test_select_query_terms_drops_noise_and_keeps_order():
    lexemes = [
        "jaka",
        "je",
        "smluvni",
        "pokuta",
        "v",
        "pern22",
        "285/8",
        "2023",
        "pokuta",
        "byt",
    ]
    terms = _select_query_terms(lexemes, exclude=frozenset({"pern22"}))
    assert [t.term for t in terms] == ["smluvni", "pokuta", "2023", "byt"]
    assert terms[1] == QueryTerm(term="pokuta", stem="pokut")
    assert terms[2].stem is None


def test_select_query_terms_filters_question_words_in_all_languages():
    lexemes = ["kolik", "ktory", "which", "does", "kauce"]
    assert [t.term for t in _select_query_terms(lexemes)] == ["kauce"]


# ------------------------------------------------------------ term resolution


def test_term_resolution_sql_params_align_with_placeholders():
    terms = [QueryTerm("pokuta", "pokut"), QueryTerm("ltv", None)]
    sql, params = _term_resolution_sql(terms)
    assert _placeholders(sql) == len(params)
    assert sql.count("UNION ALL") == 1
    # Per branch: index, exact term, [prefix pattern], exact term for ORDER BY.
    assert params == [0, "pokuta", "pokut%", "pokuta", 1, "ltv", "ltv"]
    assert f"LIMIT {st.IDF_MAX_TERM_VARIANTS}" in sql


def test_tsquery_lexeme_escapes_quotes_and_backslashes():
    assert _tsquery_lexeme("o'neil") == "'o''neil'"
    assert _tsquery_lexeme("a\\b") == "'a\\\\b'"
    assert _tsquery_lexeme("pokut", prefix=True) == "'pokut':*"


def test_idf_decreases_with_document_frequency():
    assert _idf(1, 1000) > _idf(100, 1000) > _idf(900, 1000) > 0


def test_plan_weights_rare_terms_and_drops_common_ones():
    terms = [
        QueryTerm("smlouva", "smlouv"),
        QueryTerm("kauce", "kauc"),
        QueryTerm("ltv", None),
        QueryTerm("neznamy", "nezna"),
    ]
    rows = [
        _row(0, "smlouva", 800),  # above IDF_MAX_DOC_FRACTION: dropped
        _row(1, "kauce", 40),
        _row(1, "kauci", 25),
        _row(2, "ltv", 5),
        # term 3 has no variants in term_stats: skipped
    ]
    plan = _plan_idf_text_query(terms, rows)
    assert plan is not None
    assert plan.terms == ("kauce", "ltv")
    kauce_idf, ltv_idf = plan.idfs
    assert ltv_idf > kauce_idf
    # Group df uses the most frequent variant (IDF_GROUP_DF = "max").
    assert kauce_idf == pytest.approx(_idf(40, 1000), abs=1e-6)
    assert plan.term_queries[0] == "'kauce' | 'kauci' | 'kauc':*"
    assert plan.term_queries[1] == "'ltv'"
    assert plan.match_query == "('kauce' | 'kauci' | 'kauc':*) | ('ltv')"


def test_plan_keeps_only_the_most_informative_terms(monkeypatch):
    monkeypatch.setattr(st, "IDF_MAX_QUERY_TERMS", 2)
    terms = [QueryTerm(f"term{i}", None) for i in range(4)]
    rows = [_row(i, f"term{i}", count) for i, count in enumerate([50, 5, 200, 10])]
    plan = _plan_idf_text_query(terms, rows)
    assert plan is not None
    # The two rarest terms survive, reported in query order.
    assert plan.terms == ("term1", "term3")


def test_plan_is_none_without_term_stats_rows():
    assert _plan_idf_text_query([QueryTerm("kauce", "kauc")], []) is None


# ----------------------------------------------------------------- SQL build

WHERE_SQL = "d.status = 'ready' AND (d.project_code = %s)"
WHERE_PARAMS = ["NS6"]
PLAN = IdfTextPlan(
    match_query="('kauce' | 'kauc':*) | ('ltv')",
    term_queries=("'kauce' | 'kauc':*", "'ltv'"),
    idfs=(3.2, 4.3),
    terms=("kauce", "ltv"),
)


@pytest.mark.parametrize(
    "mode,plan",
    [("legacy", None), ("idf", PLAN), ("idf", None)],
)
def test_full_hybrid_sql_placeholders_match_params(mode, plan):
    text_sql, text_params = _text_ranked_cte(
        mode=mode,
        query="kolik je kauce",
        where_sql=WHERE_SQL,
        where_params=WHERE_PARAMS,
        candidate_limit=72,
        plan=plan,
    )
    sql = _hybrid_search_sql(where_sql=WHERE_SQL, text_ranked_sql=text_sql, mode=mode)
    params = _hybrid_search_params(
        query="kolik je kauce",
        query_vector="[0.1,0.2]",
        where_params=WHERE_PARAMS,
        candidate_limit=72,
        text_params=text_params,
        prefer_authoritative=True,
        deduplicate=True,
        require_hard_verify=False,
        limit=12,
    )
    assert _placeholders(sql) == len(params)
    assert "text_ranked AS (" in sql


def test_legacy_cte_keeps_websearch_and_mode_weights():
    text_sql, params = _text_ranked_cte(
        mode="legacy",
        query="q",
        where_sql=WHERE_SQL,
        where_params=WHERE_PARAMS,
        candidate_limit=40,
        plan=None,
    )
    assert "websearch_to_tsquery('simple', %s)" in text_sql
    assert params == ["q", "q", "NS6", "q", "q", 40]
    sql = _hybrid_search_sql(
        where_sql=WHERE_SQL, text_ranked_sql=text_sql, mode="legacy"
    )
    vector_weight, text_weight = st.RRF_WEIGHTS["legacy"]
    assert f"* {float(vector_weight)}" in sql
    assert f"* {float(text_weight)}" in sql


def test_idf_cte_scores_weighted_terms_with_saturation():
    text_sql, params = _text_ranked_cte(
        mode="idf",
        query="q",
        where_sql=WHERE_SQL,
        where_params=WHERE_PARAMS,
        candidate_limit=40,
        plan=PLAN,
    )
    assert "websearch_to_tsquery" not in text_sql
    assert "SUM(t.idf * ts_rank_cd(m.chunk_tsv, t.term_query, 32))" in text_sql
    assert "c.chunk_tsv @@ %s::tsquery" in text_sql
    assert params == [
        "NS6",
        PLAN.match_query,
        list(PLAN.term_queries),
        list(PLAN.idfs),
        40,
    ]


def test_idf_cte_without_plan_is_empty():
    text_sql, params = _text_ranked_cte(
        mode="idf",
        query="q",
        where_sql=WHERE_SQL,
        where_params=WHERE_PARAMS,
        candidate_limit=40,
        plan=None,
    )
    assert "WHERE false" in text_sql
    assert params == []


# --------------------------------------------------------- _search_rows (DB)


class _FakeCursor:
    """Answers the tokenization, term_stats and search queries in order."""

    def __init__(self, *, missing_term_stats: bool = False):
        self.executed: list[tuple[str, list]] = []
        self.missing_term_stats = missing_term_stats
        self._result: list[dict] = []

    def execute(self, sql, params):
        self.executed.append((sql, list(params)))
        if "to_tsvector('simple', unaccent(%s))" in sql:
            self._result = [{"lexeme": "kolik"}, {"lexeme": "kauce"}, {"lexeme": "ns6"}]
        elif "agent_retrieval.term_stats" in sql:
            if self.missing_term_stats:
                raise psycopg.errors.UndefinedTable("relation does not exist")
            self._result = [_row(0, "kauce", 40), _row(0, "kauci", 25)]
        else:
            assert _placeholders(sql) == len(params)
            self._result = [{"chunk_id": 1}]

    def fetchall(self):
        return self._result


def _run_search(monkeypatch, mode: str, cursor: _FakeCursor):
    monkeypatch.setenv("SEMANTIC_TEXT_BRANCH", mode)
    conn = MagicMock()

    @contextmanager
    def _cursor():
        yield cursor

    conn.cursor.side_effect = _cursor
    conn.__enter__.return_value = conn
    with patch.object(st.psycopg, "connect", return_value=conn):
        rows = st._search_rows(
            query="kolik je kauce NS6",
            query_vector="[0.1]",
            project_code="NS6",
            doc_type=None,
            folder_path=None,
            relevance=None,
            limit=12,
            require_hard_verify=False,
            prefer_authoritative=True,
            deduplicate=True,
        )
    return rows, conn


def test_search_rows_idf_resolves_terms_then_searches(monkeypatch):
    cursor = _FakeCursor()
    rows, _ = _run_search(monkeypatch, "idf", cursor)
    assert rows == [{"chunk_id": 1}]
    assert len(cursor.executed) == 3
    resolution_sql, resolution_params = cursor.executed[1]
    # "kolik" is a question word and "ns6" the filtered project code.
    assert resolution_params == [0, "kauce", "kauc%", "kauce"]
    search_sql, search_params = cursor.executed[2]
    assert "ts_rank_cd(m.chunk_tsv, t.term_query, 32)" in search_sql
    assert "('kauce' | 'kauci' | 'kauc':*)" in search_params
    assert ["'kauce' | 'kauci' | 'kauc':*"] in search_params


def test_search_rows_legacy_runs_a_single_query(monkeypatch):
    cursor = _FakeCursor()
    rows, _ = _run_search(monkeypatch, "legacy", cursor)
    assert rows == [{"chunk_id": 1}]
    assert len(cursor.executed) == 1
    assert "websearch_to_tsquery" in cursor.executed[0][0]


def test_search_rows_idf_falls_back_to_legacy_without_term_stats(monkeypatch):
    cursor = _FakeCursor(missing_term_stats=True)
    rows, conn = _run_search(monkeypatch, "idf", cursor)
    assert rows == [{"chunk_id": 1}]
    conn.rollback.assert_called_once()
    assert "websearch_to_tsquery" in cursor.executed[-1][0]
