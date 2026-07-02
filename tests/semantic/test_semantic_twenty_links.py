"""Tests for the Twenty CRM record-linking added to semantic_search_drive_docs.

semantic_search_drive_docs indexes raw Drive/OCR chunks and used to only ever
point back at the raw Drive file. These tests cover the drive_file_id ->
Twenty document record id mapping (SQL-first, REST fallback) and the
"twenty=" line it adds to formatted results, without touching a real
database or the network.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import psycopg
import pytest

from semantic.semantic_tools import (
    DEFAULT_TWENTY_RECORD_URL_TEMPLATE,
    _format_result,
    _lookup_twenty_document_ids,
    _lookup_twenty_document_ids_rest,
    _twenty_record_url,
)


def _mock_row(**overrides) -> dict:
    row = {
        "file_name": "Najemni smlouva byt 412.pdf",
        "drive_web_url": "https://drive.google.com/file/d/1abc/view",
        "drive_file_id": "1abc",
        "project_code": "P22",
        "chunk_text": "some contract text",
        "document_metadata": {},
    }
    row.update(overrides)
    return row


# --------------------------------------------------------------------- URL


def test_twenty_record_url_disabled_when_base_url_unset(monkeypatch):
    monkeypatch.delenv("TWENTY_BASE_URL", raising=False)
    assert _twenty_record_url("rec-123") is None


def test_twenty_record_url_none_when_no_record_id(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://twenty.example.com")
    assert _twenty_record_url(None) is None
    assert _twenty_record_url("") is None


def test_twenty_record_url_uses_default_template(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://twenty.example.com/")
    monkeypatch.delenv("TWENTY_RECORD_URL_TEMPLATE", raising=False)
    assert DEFAULT_TWENTY_RECORD_URL_TEMPLATE == "{base}/object/document/{id}"
    assert (
        _twenty_record_url("rec-123")
        == "https://twenty.example.com/object/document/rec-123"
    )


def test_twenty_record_url_honors_custom_template(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://twenty.example.com")
    monkeypatch.setenv("TWENTY_RECORD_URL_TEMPLATE", "{base}/documents/{id}/show")
    assert (
        _twenty_record_url("rec-123")
        == "https://twenty.example.com/documents/rec-123/show"
    )


# --------------------------------------------------------------- formatting


def test_format_result_adds_twenty_line_after_url(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://twenty.example.com")
    row = _mock_row(twenty_document_id="rec-123")

    payload = _format_result(row, 1, require_hard_verify=False)
    lines = payload.splitlines()

    url_idx = next(i for i, line in enumerate(lines) if line.strip().startswith("url="))
    assert lines[url_idx + 1].strip() == (
        "twenty=https://twenty.example.com/object/document/rec-123"
    )


def test_format_result_omits_twenty_line_without_mapping(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://twenty.example.com")
    row = _mock_row()  # no twenty_document_id key at all

    payload = _format_result(row, 1, require_hard_verify=False)
    assert "twenty=" not in payload


def test_format_result_omits_twenty_line_when_feature_disabled(monkeypatch):
    monkeypatch.delenv("TWENTY_BASE_URL", raising=False)
    row = _mock_row(twenty_document_id="rec-123")

    payload = _format_result(row, 1, require_hard_verify=False)
    assert "twenty=" not in payload


# ------------------------------------------------------------------- lookup


@pytest.mark.asyncio
async def test_lookup_returns_empty_when_twenty_base_url_unset(monkeypatch):
    monkeypatch.delenv("TWENTY_BASE_URL", raising=False)

    with patch("semantic.semantic_tools._lookup_twenty_document_ids_sql") as mock_sql:
        result = await _lookup_twenty_document_ids(["file-1", "file-2"])

    assert result == {}
    mock_sql.assert_not_called()


@pytest.mark.asyncio
async def test_lookup_uses_sql_mapping_when_available(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://twenty.example.com")

    with (
        patch(
            "semantic.semantic_tools._lookup_twenty_document_ids_sql",
            return_value={"file-1": "rec-1"},
        ) as mock_sql,
        patch(
            "semantic.semantic_tools._lookup_twenty_document_ids_rest",
            new_callable=AsyncMock,
        ) as mock_rest,
    ):
        result = await _lookup_twenty_document_ids(["file-1", "file-2", ""])

    assert result == {"file-1": "rec-1"}
    mock_sql.assert_called_once_with(["file-1", "file-2"])
    mock_rest.assert_not_called()


@pytest.mark.asyncio
async def test_lookup_falls_back_to_rest_when_sql_table_missing(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://twenty.example.com")

    with (
        patch(
            "semantic.semantic_tools._lookup_twenty_document_ids_sql",
            side_effect=psycopg.errors.UndefinedTable("relation does not exist"),
        ),
        patch(
            "semantic.semantic_tools._lookup_twenty_document_ids_rest",
            new_callable=AsyncMock,
            return_value={"file-1": "rec-1"},
        ) as mock_rest,
    ):
        result = await _lookup_twenty_document_ids(["file-1"])

    assert result == {"file-1": "rec-1"}
    mock_rest.assert_called_once_with(["file-1"])


@pytest.mark.asyncio
async def test_rest_lookup_returns_empty_without_api_key(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://twenty.example.com")
    monkeypatch.delenv("TWENTY_API_KEY", raising=False)

    result = await _lookup_twenty_document_ids_rest(["file-1"])
    assert result == {}


@pytest.mark.asyncio
async def test_rest_lookup_parses_documents_payload(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://twenty.example.com")
    monkeypatch.setenv("TWENTY_API_KEY", "secret-key")

    mock_response = AsyncMock()
    mock_response.raise_for_status = lambda: None
    mock_response.json = lambda: {
        "data": {
            "documents": [
                {"id": "rec-1", "sourceFileId": "file-1"},
                {"id": "rec-2", "sourceFileId": "file-2"},
                {"id": "rec-3"},  # missing sourceFileId -> ignored
            ]
        }
    }

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("semantic.semantic_tools.httpx.AsyncClient", return_value=mock_client):
        result = await _lookup_twenty_document_ids_rest(["file-1", "file-2"])

    assert result == {"file-1": "rec-1", "file-2": "rec-2"}
    called_params = mock_client.get.call_args.kwargs["params"]
    assert called_params["filter"] == "sourceFileId[in]:file-1,file-2"


@pytest.mark.asyncio
async def test_rest_lookup_returns_empty_on_http_error(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://twenty.example.com")
    monkeypatch.setenv("TWENTY_API_KEY", "secret-key")

    import httpx

    mock_client = AsyncMock()
    mock_client.get.side_effect = httpx.ConnectError("boom")
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("semantic.semantic_tools.httpx.AsyncClient", return_value=mock_client):
        result = await _lookup_twenty_document_ids_rest(["file-1"])

    assert result == {}
