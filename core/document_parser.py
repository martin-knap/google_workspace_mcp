"""Bounded Markdown extraction for PDF and Office document bytes.

PDFs are handled directly by ``pdf-inspector`` so callers can route only the
pages that need OCR. Other supported document formats are converted by
``anydoc``. Keeping the two paths explicit avoids anydoc's bundled PDF backend
becoming the PDF routing contract by accident.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
import os
from pathlib import Path


PDF_MIME_TYPE = "application/pdf"
DEFAULT_MAX_DOCUMENT_BYTES = 64 * 1024 * 1024

ANYDOC_FORMAT_BY_MIME = {
    "application/msword": "doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.ms-powerpoint": "ppt",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "application/vnd.ms-excel": "xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.oasis.opendocument.text": "odt",
    "application/vnd.oasis.opendocument.spreadsheet": "ods",
    "application/vnd.oasis.opendocument.presentation": "odp",
    "application/rtf": "rtf",
    "text/rtf": "rtf",
    "application/epub+zip": "epub",
    "text/csv": "csv",
    "text/html": "html",
}


@dataclass(frozen=True)
class DocumentMarkdown:
    markdown: str
    backend: str
    detected_format: str
    parser_version: str
    page_count: int | None = None
    pages: tuple[dict, ...] = ()
    pages_needing_ocr: tuple[int, ...] = ()
    pdf_type: str | None = None
    confidence: float | None = None
    is_complex_layout: bool = False
    has_encoding_issues: bool = False


def max_document_bytes() -> int:
    raw = os.getenv("WORKSPACE_MCP_MAX_PARSE_BYTES", str(DEFAULT_MAX_DOCUMENT_BYTES))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("WORKSPACE_MCP_MAX_PARSE_BYTES must be an integer") from exc
    if value <= 0:
        raise ValueError("WORKSPACE_MCP_MAX_PARSE_BYTES must be positive")
    return value


def _validate_size(data: bytes) -> None:
    limit = max_document_bytes()
    if len(data) > limit:
        raise ValueError(
            f"Document is too large to parse safely ({len(data)} bytes; limit {limit} bytes)."
        )


def _package_version(distribution: str) -> str:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return "unknown"


def _parse_pdf(data: bytes) -> DocumentMarkdown:
    import pdf_inspector

    processed = pdf_inspector.process_pdf_bytes(data)
    extracted = pdf_inspector.extract_pages_markdown_bytes(data)
    extracted_pages = list(getattr(extracted, "pages", ()) or ())
    page_count = int(getattr(processed, "page_count", 0) or 0)
    if not page_count and extracted_pages:
        page_count = max(int(page.page) for page in extracted_pages) + 1

    pages_by_number: dict[int, dict] = {}
    pages_needing_ocr: set[int] = set()
    for page in extracted_pages:
        number = int(page.page) + 1
        markdown = str(getattr(page, "markdown", "") or "")
        needs_ocr = bool(getattr(page, "needs_ocr", False))
        pages_by_number[number] = {
            "page": number,
            "markdown": markdown,
            "char_count": len(markdown.strip()),
            "needs_ocr": needs_ocr,
        }
        if needs_ocr:
            pages_needing_ocr.add(number)

    pages_needing_ocr.update(
        int(number)
        for number in (getattr(extracted, "pages_needing_ocr", ()) or ())
        if 1 <= int(number) <= page_count
    )
    has_encoding_issues = bool(getattr(processed, "has_encoding_issues", False))
    if has_encoding_issues:
        pages_needing_ocr = set(range(1, page_count + 1))

    pages = tuple(
        pages_by_number.get(
            number,
            {"page": number, "markdown": "", "char_count": 0, "needs_ocr": True},
        )
        for number in range(1, page_count + 1)
    )
    if pages_needing_ocr and len(pages_needing_ocr) < page_count:
        pdf_type = "mixed"
    else:
        pdf_type = str(getattr(processed, "pdf_type", "unknown") or "unknown")

    markdown = "\n\n".join(
        f"<!-- Page {page['page']} -->\n{page['markdown']}"
        for page in pages
        if page["markdown"].strip()
    )
    return DocumentMarkdown(
        markdown=markdown,
        backend="pdf_inspector",
        detected_format="pdf",
        parser_version=_package_version("pdf-inspector"),
        page_count=page_count,
        pages=pages,
        pages_needing_ocr=tuple(sorted(pages_needing_ocr)),
        pdf_type=pdf_type,
        confidence=float(getattr(processed, "confidence", 0.0) or 0.0),
        is_complex_layout=bool(
            getattr(processed, "is_complex_layout", False)
            or getattr(extracted, "is_complex", False)
        ),
        has_encoding_issues=has_encoding_issues,
    )


def _format_hint(mime_type: str, file_name: str | None) -> str | None:
    hint = ANYDOC_FORMAT_BY_MIME.get(mime_type)
    if hint:
        return hint
    if file_name:
        suffix = Path(file_name).suffix.lower().lstrip(".")
        if suffix in set(ANYDOC_FORMAT_BY_MIME.values()):
            return suffix
    return None


def parse_document_bytes(
    data: bytes,
    *,
    mime_type: str,
    file_name: str | None = None,
) -> DocumentMarkdown:
    """Convert supported document bytes to Markdown with bounded memory input."""
    _validate_size(data)
    if mime_type == PDF_MIME_TYPE:
        return _parse_pdf(data)

    hint = _format_hint(mime_type, file_name)
    if hint is None:
        raise ValueError(
            f"Unsupported document type: {mime_type or file_name or 'unknown'}"
        )

    import anydoc

    markdown = str(anydoc.to_markdown_bytes(data, hint) or "")
    return DocumentMarkdown(
        markdown=markdown,
        backend="anydoc",
        detected_format=hint,
        parser_version=_package_version("firecrawl-anydoc"),
    )


def is_supported_document(mime_type: str) -> bool:
    return mime_type == PDF_MIME_TYPE or mime_type in ANYDOC_FORMAT_BY_MIME
