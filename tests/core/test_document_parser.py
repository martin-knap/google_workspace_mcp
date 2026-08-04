from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from core import document_parser


def test_anydoc_converts_office_bytes_to_markdown(monkeypatch):
    calls = []
    fake_anydoc = SimpleNamespace(
        to_markdown_bytes=lambda data, format: (
            calls.append((data, format)) or "# Report"
        )
    )
    monkeypatch.setitem(sys.modules, "anydoc", fake_anydoc)
    monkeypatch.setattr(document_parser, "_package_version", lambda _name: "0.1.2")

    parsed = document_parser.parse_document_bytes(
        b"office-bytes",
        mime_type=(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ),
        file_name="report.docx",
    )

    assert calls == [(b"office-bytes", "docx")]
    assert parsed.markdown == "# Report"
    assert parsed.backend == "anydoc"
    assert parsed.detected_format == "docx"


def test_pdf_page_flags_are_authoritative_and_one_based(monkeypatch):
    fake_pdf_inspector = SimpleNamespace(
        process_pdf_bytes=lambda _data: SimpleNamespace(
            page_count=3,
            pdf_type="TextBased",
            confidence=0.95,
            has_encoding_issues=False,
            is_complex_layout=False,
        ),
        extract_pages_markdown_bytes=lambda _data: SimpleNamespace(
            pages=[
                SimpleNamespace(page=0, markdown="first", needs_ocr=False),
                SimpleNamespace(page=1, markdown="", needs_ocr=True),
                SimpleNamespace(page=2, markdown="third", needs_ocr=False),
            ],
            pages_needing_ocr=[2],
            is_complex=False,
        ),
    )
    monkeypatch.setitem(sys.modules, "pdf_inspector", fake_pdf_inspector)
    monkeypatch.setattr(document_parser, "_package_version", lambda _name: "0.2.6")

    parsed = document_parser.parse_document_bytes(
        b"%PDF fixture", mime_type="application/pdf", file_name="mixed.pdf"
    )

    assert parsed.pages_needing_ocr == (2,)
    assert [page["page"] for page in parsed.pages] == [1, 2, 3]
    assert parsed.pdf_type == "mixed"
    assert "<!-- Page 1 -->" in parsed.markdown
    assert "<!-- Page 3 -->" in parsed.markdown


def test_encoding_issue_routes_every_pdf_page_to_ocr(monkeypatch):
    fake_pdf_inspector = SimpleNamespace(
        process_pdf_bytes=lambda _data: SimpleNamespace(
            page_count=2,
            pdf_type="TextBased",
            confidence=0.8,
            has_encoding_issues=True,
            is_complex_layout=False,
        ),
        extract_pages_markdown_bytes=lambda _data: SimpleNamespace(
            pages=[
                SimpleNamespace(page=0, markdown="broken", needs_ocr=False),
                SimpleNamespace(page=1, markdown="broken", needs_ocr=False),
            ],
            pages_needing_ocr=[],
            is_complex=False,
        ),
    )
    monkeypatch.setitem(sys.modules, "pdf_inspector", fake_pdf_inspector)

    parsed = document_parser.parse_document_bytes(
        b"%PDF fixture", mime_type="application/pdf"
    )

    assert parsed.pages_needing_ocr == (1, 2)


def test_document_size_limit_is_enforced_before_parser_import(monkeypatch):
    monkeypatch.setenv("WORKSPACE_MCP_MAX_PARSE_BYTES", "4")

    with pytest.raises(ValueError, match="too large"):
        document_parser.parse_document_bytes(
            b"12345", mime_type="text/csv", file_name="data.csv"
        )


def test_unsupported_type_fails_explicitly():
    with pytest.raises(ValueError, match="Unsupported document type"):
        document_parser.parse_document_bytes(
            b"binary", mime_type="application/octet-stream", file_name="blob.bin"
        )
