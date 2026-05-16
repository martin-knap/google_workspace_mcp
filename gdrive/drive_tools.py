"""
Google Drive MCP Tools

This module provides MCP tools for interacting with Google Drive API.
"""

import asyncio
import logging
import io
import base64
import json
import time

from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Callable, Awaitable, BinaryIO
from tempfile import NamedTemporaryFile, SpooledTemporaryFile
from urllib.parse import urlparse
from urllib.request import url2pathname
from pathlib import Path

import httpx
import fitz
from google.cloud import vision
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload

from mcp.types import ToolAnnotations

from auth.scopes import CLOUD_VISION_SCOPE, DRIVE_READONLY_SCOPE
from auth.service_decorator import require_google_service
from auth.oauth_config import is_stateless_mode
from core.attachment_storage import get_attachment_storage, get_attachment_url
from core.utils import (
    GOOGLE_API_WRITE_RETRIES,
    IMAGE_MIME_TYPES,
    encode_image_content,
    extract_office_xml_text,
    extract_pdf_text,
    handle_http_errors,
    validate_file_path,
)
from core.server import server
from core.config import get_transport_mode
from core.http_utils import (
    redact_url as _redact_url,
    ssrf_safe_stream as _ssrf_safe_stream,
)
from gdrive.drive_helpers import (
    DRIVE_QUERY_PATTERNS,
    FOLDER_MIME_TYPE,
    build_drive_list_params,
    check_public_link_permission,
    format_permission_info,
    get_drive_image_url,
    resolve_drive_item,
    resolve_file_type_mime,
    resolve_folder_id,
    validate_expiration_time,
    validate_share_role,
    validate_share_type,
)

logger = logging.getLogger(__name__)

DOWNLOAD_CHUNK_SIZE_BYTES = 256 * 1024  # 256 KB
UPLOAD_CHUNK_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB (Google recommended minimum)
MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB safety limit for URL downloads
SHARED_DRIVE_ORGANIZER_CONCURRENCY_LIMIT = 10


async def _stream_url_with_validation(
    url: str, write_chunk: Optional[Callable[[bytes], Awaitable[None]]] = None
) -> tuple[int, Optional[str]]:
    """Stream a remote file with shared status and size validation."""
    total_bytes = 0

    redacted_url = _redact_url(url)

    async with _ssrf_safe_stream(url) as resp:
        if resp.status_code != 200:
            request = getattr(resp, "request", None)
            if request is None:
                parsed_url = urlparse(url)
                request = httpx.Request(
                    "GET",
                    f"{parsed_url.scheme}://{redacted_url}",
                )
            raise httpx.HTTPStatusError(
                f"Failed to fetch file from URL: {redacted_url} (status {resp.status_code})",
                request=request,
                response=resp,
            )

        content_type = resp.headers.get("Content-Type")
        async for chunk in resp.aiter_bytes(chunk_size=DOWNLOAD_CHUNK_SIZE_BYTES):
            total_bytes += len(chunk)
            if total_bytes > MAX_DOWNLOAD_BYTES:
                raise ValueError(
                    f"Download from {redacted_url} exceeded {MAX_DOWNLOAD_BYTES} byte limit "
                    f"({total_bytes} bytes)"
                )
            if write_chunk is not None:
                await write_chunk(chunk)

    return total_bytes, content_type


async def _download_url_to_bytes(
    url: str,
) -> tuple[BinaryIO, Optional[str]]:
    """Download a remote file into a spooled temporary file with bounded streaming."""
    spool = SpooledTemporaryFile(max_size=UPLOAD_CHUNK_SIZE_BYTES)

    try:

        async def _collect(chunk: bytes) -> None:
            await asyncio.to_thread(spool.write, chunk)

        _total_bytes, content_type = await _stream_url_with_validation(url, _collect)
        await asyncio.to_thread(spool.seek, 0)
        return spool, content_type
    except Exception:
        spool.close()
        raise


async def _get_file_size(file_obj: BinaryIO) -> int:
    """Measure a possibly spooled file off the event loop and restore position."""

    def _measure_size() -> int:
        file_obj.seek(0, io.SEEK_END)
        size = file_obj.tell()
        file_obj.seek(0)
        return size

    return await asyncio.to_thread(_measure_size)


@server.tool(
    title="Search Drive Files",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors("search_drive_files", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def search_drive_files(
    service,
    user_google_email: str,
    query: str,
    page_size: int = 10,
    page_token: Optional[str] = None,
    drive_id: Optional[str] = None,
    include_items_from_all_drives: bool = True,
    corpora: Optional[str] = None,
    file_type: Optional[str] = None,
    detailed: bool = True,
    order_by: Optional[str] = None,
) -> str:
    """
    Searches for files and folders within a user's Google Drive, including shared drives.

    Args:
        user_google_email (str): The user's Google email address. Required.
        query (str): The search query string. Supports Google Drive search operators.
                     NOTE: Owner-based queries ('user@example.com' in owners) DO NOT WORK in Shared Drives
                     because files are owned by the shared drive itself, not individual users.
                     For recent files by a specific user in Shared Drives, search by modifiedTime
                     and use order_by='modifiedTime desc' instead.
        page_size (int): The maximum number of files to return. Defaults to 10.
        page_token (Optional[str]): Page token from a previous response's nextPageToken to retrieve the next page of results.
        drive_id (Optional[str]): ID of the shared drive to search. If None, behavior depends on `corpora` and `include_items_from_all_drives`.
        include_items_from_all_drives (bool): Whether shared drive items should be included in results. Defaults to True. This is effective when not specifying a `drive_id`.
        corpora (Optional[str]): Bodies of items to query (e.g., 'user', 'domain', 'drive', 'allDrives').
                                 If 'drive_id' is specified and 'corpora' is None, it defaults to 'drive'.
                                 Otherwise, Drive API default behavior applies. Prefer 'user' or 'drive' over 'allDrives' for efficiency.
        file_type (Optional[str]): Restrict results to a specific file type. Accepts a friendly
                                   name ('folder', 'document'/'doc', 'spreadsheet'/'sheet',
                                   'presentation'/'slides', 'form', 'drawing', 'pdf', 'shortcut',
                                   'script', 'site', 'jam'/'jamboard') or any raw MIME type
                                   string (e.g. 'application/pdf'). Defaults to None (all types).
        detailed (bool): Whether to include size, modified time, and link in results. Defaults to True.
        order_by (Optional[str]): Sort order. Comma-separated list of sort keys with optional 'desc' modifier.
                                  Valid keys: 'createdTime', 'folder', 'modifiedByMeTime', 'modifiedTime',
                                  'name', 'name_natural', 'quotaBytesUsed', 'recency', 'sharedWithMeTime',
                                  'starred', 'viewedByMeTime'. Example: 'modifiedTime desc' or 'folder,modifiedTime desc,name'.
                                  Defaults to None (Drive API default ordering).

    Returns:
        str: A formatted list of found files/folders with their details (ID, name, type, and optionally size, modified time, link).
             Includes a nextPageToken line when more results are available.
    """
    logger.info(
        f"[search_drive_files] Invoked. Email: '{user_google_email}', Query: '{query}', file_type: '{file_type}'"
    )

    # Check if the query looks like a structured Drive query or free text
    # Look for Drive API operators and structured query patterns
    is_structured_query = any(pattern.search(query) for pattern in DRIVE_QUERY_PATTERNS)

    if is_structured_query:
        final_query = query
        logger.info(
            f"[search_drive_files] Using structured query as-is: '{final_query}'"
        )
    else:
        # For free text queries, wrap in fullText contains
        escaped_query = query.replace("'", "\\'")
        final_query = f"fullText contains '{escaped_query}'"
        logger.info(
            f"[search_drive_files] Reformatting free text query '{query}' to '{final_query}'"
        )

    if file_type is not None:
        mime = resolve_file_type_mime(file_type)
        final_query = f"({final_query}) and mimeType = '{mime}'"
        logger.info(f"[search_drive_files] Added mimeType filter: '{mime}'")

    list_params = build_drive_list_params(
        query=final_query,
        page_size=page_size,
        drive_id=drive_id,
        include_items_from_all_drives=include_items_from_all_drives,
        corpora=corpora,
        page_token=page_token,
        detailed=detailed,
        order_by=order_by,
    )

    results = await asyncio.to_thread(service.files().list(**list_params).execute)
    files = results.get("files", [])
    if not files:
        return f"No files found for '{query}'."

    next_token = results.get("nextPageToken")
    header = f"Found {len(files)} files for {user_google_email} matching '{query}':"
    formatted_files_text_parts = [header]
    for item in files:
        if detailed:
            size_str = f", Size: {item.get('size', 'N/A')}" if "size" in item else ""
            formatted_files_text_parts.append(
                f'- Name: "{item["name"]}" (ID: {item["id"]}, Type: {item["mimeType"]}{size_str}, Modified: {item.get("modifiedTime", "N/A")}) Link: {item.get("webViewLink", "#")}'
            )
        else:
            formatted_files_text_parts.append(
                f'- Name: "{item["name"]}" (ID: {item["id"]}, Type: {item["mimeType"]})'
            )
    if next_token:
        formatted_files_text_parts.append(f"nextPageToken: {next_token}")
    text_output = "\n".join(formatted_files_text_parts)
    return text_output


@server.tool(
    title="Get Drive File Content",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors("get_drive_file_content", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def get_drive_file_content(
    service,
    user_google_email: str,
    file_id: str,
) -> str:
    """
    Retrieves the content of a specific Google Drive file by ID, supporting files in shared drives.

    • Native Google Docs, Sheets, Slides → exported as text / CSV.
    • Office files (.docx, .xlsx, .pptx) → unzipped & parsed with std-lib to
      extract readable text.
    • PDFs → text extracted with pypdf when possible; scanned/image-only PDFs
      fall back to a download hint.
    • Images → returned as base64 with MIME metadata for multimodal clients.
    • Any other file → downloaded; tries UTF-8 decode, else notes binary.

    Args:
        user_google_email: The user’s Google email address.
        file_id: Drive file ID.

    Returns:
        str: The file content as plain text with metadata header.
    """
    logger.info(f"[get_drive_file_content] Invoked. File ID: '{file_id}'")

    resolved_file_id, file_metadata = await resolve_drive_item(
        service,
        file_id,
        extra_fields="name, webViewLink",
    )
    file_id = resolved_file_id
    mime_type = file_metadata.get("mimeType", "")
    file_name = file_metadata.get("name", "Unknown File")
    export_mime_type = {
        "application/vnd.google-apps.document": "text/plain",
        "application/vnd.google-apps.spreadsheet": "text/csv",
        "application/vnd.google-apps.presentation": "text/plain",
    }.get(mime_type)

    request_obj = (
        service.files().export_media(fileId=file_id, mimeType=export_mime_type)
        if export_mime_type
        else service.files().get_media(fileId=file_id)
    )
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request_obj)
    loop = asyncio.get_event_loop()
    done = False
    while not done:
        status, done = await loop.run_in_executor(None, downloader.next_chunk)

    file_content_bytes = fh.getvalue()

    # Attempt Office XML extraction only for actual Office XML files
    office_mime_types = {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }

    if mime_type in office_mime_types:
        # Offload Office XML extraction to a thread to avoid blocking the event loop
        office_text = await asyncio.to_thread(
            extract_office_xml_text, file_content_bytes, mime_type
        )
        if office_text:
            body_text = office_text
        else:
            # Fallback: try UTF-8; otherwise flag binary
            try:
                body_text = file_content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                body_text = (
                    f"[Binary or unsupported text encoding for mimeType '{mime_type}' - "
                    f"{len(file_content_bytes)} bytes]"
                )
    elif mime_type == "application/pdf":
        # Offload PDF text extraction to a thread to avoid blocking the event loop
        pdf_text = await asyncio.to_thread(extract_pdf_text, file_content_bytes)
        if pdf_text:
            body_text = pdf_text
        else:
            body_text = (
                f"[Could not extract text from PDF ({len(file_content_bytes)} bytes) "
                f"- the file may be scanned/image-only. "
                f"Use get_drive_file_download_url to get a direct download link instead.]"
            )
    elif mime_type in IMAGE_MIME_TYPES:
        body_text = encode_image_content(file_content_bytes, mime_type)
    else:
        # For non-Office files (including Google native files), try UTF-8 decode directly
        try:
            body_text = file_content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            body_text = (
                f"[Binary or unsupported text encoding for mimeType '{mime_type}' - "
                f"{len(file_content_bytes)} bytes]"
            )

    # Assemble response
    header = (
        f'File: "{file_name}" (ID: {file_id}, Type: {mime_type})\n'
        f"Link: {file_metadata.get('webViewLink', '#')}\n\n--- CONTENT ---\n"
    )
    return header + body_text


async def _download_drive_file_bytes(service, file_id: str) -> bytes:
    request_obj = service.files().get_media(fileId=file_id, supportsAllDrives=True)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request_obj)
    loop = asyncio.get_event_loop()
    done = False
    while not done:
        _status, done = await loop.run_in_executor(None, downloader.next_chunk)
    return fh.getvalue()


def _extract_pymupdf_pages(pdf_data: bytes) -> tuple[list[dict[str, Any]], int, int]:
    doc = fitz.open(stream=pdf_data, filetype="pdf")
    try:
        pages: list[dict[str, Any]] = []
        total_chars = 0
        for page_num in range(len(doc)):
            text = doc[page_num].get_text()
            char_count = len(text.strip())
            total_chars += char_count
            pages.append({"page": page_num + 1, "text": text, "char_count": char_count})
        return pages, total_chars, len(doc)
    finally:
        doc.close()


def _render_pdf_pages_for_ocr(
    pdf_data: bytes, max_pages: Optional[int] = None
) -> tuple[list[bytes], int]:
    doc = fitz.open(stream=pdf_data, filetype="pdf")
    try:
        total_pages = len(doc)
        pages_to_process = min(total_pages, max_pages) if max_pages else total_pages
        page_images: list[bytes] = []
        for page_num in range(pages_to_process):
            page = doc[page_num]
            pix = page.get_pixmap(matrix=fitz.Matrix(300 / 72, 300 / 72))
            page_images.append(pix.tobytes("png"))
        return page_images, total_pages
    finally:
        doc.close()


async def _get_pdf_metadata(service, file_id: str) -> tuple[str, dict[str, Any]]:
    resolved_file_id, file_metadata = await resolve_drive_item(
        service,
        file_id,
        extra_fields="name, size, modifiedTime, webViewLink",
    )
    mime_type = file_metadata.get("mimeType", "")
    if mime_type != "application/pdf":
        file_name = file_metadata.get("name", "Unknown File")
        raise ValueError(f"File '{file_name}' is not a PDF (MIME type: {mime_type}).")
    return resolved_file_id, file_metadata


@server.tool(
    title="Extract Drive PDF Text",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors("extract_drive_pdf_text", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def extract_drive_pdf_text(
    service,
    user_google_email: str,
    file_id: str,
    include_metadata: bool = True,
) -> str:
    """
    Extracts embedded text from a PDF in Google Drive using PyMuPDF.

    Use extract_scanned_pdf_text_ocr for image-only or scanned PDFs.
    """
    logger.info(f"[extract_drive_pdf_text] Extracting PDF text for file ID: {file_id}")

    file_id, file_metadata = await _get_pdf_metadata(service, file_id)
    file_name = file_metadata.get("name", "Unknown File")
    pdf_bytes = await _download_drive_file_bytes(service, file_id)

    try:
        pages, total_chars, total_pages = await asyncio.to_thread(
            _extract_pymupdf_pages, pdf_bytes
        )
    except Exception as exc:
        logger.error("[extract_drive_pdf_text] PyMuPDF extraction failed: %s", exc)
        return f"Error extracting text from PDF '{file_name}': {exc}"

    extracted_pages = [
        f"--- Page {page['page']} ---\n{page['text']}"
        for page in pages
        if page["text"].strip()
    ]

    header = ""
    if include_metadata:
        header = "\n".join(
            [
                f'File: "{file_name}" (ID: {file_id})',
                f"Type: {file_metadata.get('mimeType', 'application/pdf')}",
                f"Size: {file_metadata.get('size', 'N/A')} bytes",
                f"Modified: {file_metadata.get('modifiedTime', 'N/A')}",
                f"Link: {file_metadata.get('webViewLink', '#')}",
                f"Pages: {total_pages}",
                f"Total characters extracted: {total_chars}",
                "",
                "--- EXTRACTED TEXT ---",
                "",
            ]
        )

    if total_chars == 0:
        return (
            f"{header}No embedded text found in PDF '{file_name}'. "
            "This is likely a scanned or image-only PDF. Use extract_scanned_pdf_text_ocr."
        )

    return header + "\n\n".join(extracted_pages)


@server.tool(
    title="Extract Scanned PDF Text OCR",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors(
    "extract_scanned_pdf_text_ocr", is_read_only=True, service_type="drive"
)
@require_google_service("drive", [DRIVE_READONLY_SCOPE, CLOUD_VISION_SCOPE])
async def extract_scanned_pdf_text_ocr(
    service,
    user_google_email: str,
    file_id: str,
    include_metadata: bool = True,
    max_pages: Optional[int] = None,
) -> str:
    """
    Extracts text from scanned or image-only PDFs using Google Cloud Vision OCR.

    This may incur Google Cloud Vision API costs. For text-based PDFs, use
    extract_drive_pdf_text instead.
    """
    logger.info("[extract_scanned_pdf_text_ocr] Starting OCR for file ID: %s", file_id)

    file_id, file_metadata = await _get_pdf_metadata(service, file_id)
    file_name = file_metadata.get("name", "Unknown File")
    pdf_bytes = await _download_drive_file_bytes(service, file_id)

    try:
        page_images, total_pages = await asyncio.to_thread(
            _render_pdf_pages_for_ocr, pdf_bytes, max_pages
        )
    except Exception as exc:
        logger.error("[extract_scanned_pdf_text_ocr] Page rendering failed: %s", exc)
        return f"Error extracting pages from PDF '{file_name}': {exc}"

    if not page_images:
        return f"No pages found in PDF '{file_name}'."

    credentials = getattr(getattr(service, "_http", None), "credentials", None)
    if credentials is None:
        return "Error setting up Google Cloud Vision API: Drive service credentials are unavailable."

    async def ocr_page(page_image: bytes, page_number: int) -> tuple[int, str]:
        def sync_ocr() -> str:
            client = vision.ImageAnnotatorClient(credentials=credentials)
            image = vision.Image(content=page_image)
            response = client.text_detection(image=image)
            if response.error.message:
                raise RuntimeError(f"Vision API error: {response.error.message}")
            texts = response.text_annotations
            return texts[0].description if texts else ""

        try:
            text = await asyncio.to_thread(sync_ocr)
            return page_number, text
        except Exception as exc:
            logger.error(
                "[extract_scanned_pdf_text_ocr] OCR failed on page %s: %s",
                page_number + 1,
                exc,
            )
            return page_number, f"[Error processing page {page_number + 1}: {exc}]"

    ocr_results = await asyncio.gather(
        *(ocr_page(image, idx) for idx, image in enumerate(page_images))
    )
    ocr_results.sort(key=lambda item: item[0])

    extracted_text_parts: list[str] = []
    total_chars = 0
    for page_num, text in ocr_results:
        if text and not text.startswith("[Error"):
            total_chars += len(text)
            extracted_text_parts.append(f"--- Page {page_num + 1} ---\n{text}")
        elif text:
            extracted_text_parts.append(text)

    header = ""
    if include_metadata:
        pages_info = (
            f"{len(page_images)} of {total_pages}"
            if max_pages and len(page_images) < total_pages
            else str(total_pages)
        )
        header = "\n".join(
            [
                f'File: "{file_name}" (ID: {file_id})',
                f"Type: {file_metadata.get('mimeType', 'application/pdf')}",
                f"Size: {file_metadata.get('size', 'N/A')} bytes",
                f"Modified: {file_metadata.get('modifiedTime', 'N/A')}",
                f"Link: {file_metadata.get('webViewLink', '#')}",
                f"Pages processed: {pages_info}",
                f"Total characters extracted: {total_chars}",
                "",
                "--- EXTRACTED TEXT (via OCR) ---",
                "",
            ]
        )

    if total_chars == 0:
        return (
            f"{header}No text content extracted via OCR from PDF '{file_name}'. "
            "This may be a blank document or OCR failed to recognize text."
        )

    return header + "\n\n".join(extracted_text_parts)


@server.tool(
    title="Extract PDF Text To File",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors("extract_pdf_text_to_file", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def extract_pdf_text_to_file(
    service,
    user_google_email: str,
    file_id: str,
    output_path: str,
    output_format: str = "text",
) -> str:
    """
    Extracts embedded PDF text with PyMuPDF and writes it to a local file.
    """
    file_id, file_metadata = await _get_pdf_metadata(service, file_id)
    file_name = file_metadata.get("name", "Unknown File")
    pdf_bytes = await _download_drive_file_bytes(service, file_id)
    pages, total_chars, total_pages = await asyncio.to_thread(
        _extract_pymupdf_pages, pdf_bytes
    )
    if total_chars == 0:
        return (
            f"No embedded text found in PDF '{file_name}' ({total_pages} pages). "
            "This is likely a scanned document. Use ocr_pdf_to_file instead."
        )

    output_file = Path(output_path).expanduser()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    extracted_at = datetime.now(timezone.utc).isoformat()

    if output_format == "json":
        output_file.write_text(
            json.dumps(
                {
                    "source_file_id": file_id,
                    "source_file_name": file_name,
                    "mime_type": file_metadata.get("mimeType", "application/pdf"),
                    "file_size_bytes": int(file_metadata.get("size", 0)),
                    "modified_date": file_metadata.get("modifiedTime", ""),
                    "web_link": file_metadata.get("webViewLink", ""),
                    "extraction_date": extracted_at,
                    "extraction_method": "pymupdf_text",
                    "total_pages": total_pages,
                    "total_characters": total_chars,
                    "pages": pages,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    else:
        text_parts = [
            f"# Text: {file_name}",
            f"# Source: {file_id}",
            f"# Pages: {total_pages}",
            f"# Characters: {total_chars}",
            "",
        ]
        for page in pages:
            text_parts.extend([f"--- Page {page['page']} ---", page["text"], ""])
        output_file.write_text("\n".join(text_parts), encoding="utf-8")

    first_text = next((p["text"][:200] for p in pages if p["char_count"] > 0), "")
    return "\n".join(
        [
            f"Text extracted: {file_name}",
            f"  Source file ID: {file_id}",
            f"  Pages: {total_pages}",
            f"  Total characters: {total_chars:,}",
            f"  Output: {output_file} ({output_file.stat().st_size / 1024:.1f} KB, format: {output_format})",
            f"  Preview: {first_text}..."
            if first_text
            else "  Preview: (no text extracted)",
        ]
    )


@server.tool(
    title="OCR PDF To File",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors("ocr_pdf_to_file", is_read_only=True, service_type="drive")
@require_google_service("drive", [DRIVE_READONLY_SCOPE, CLOUD_VISION_SCOPE])
async def ocr_pdf_to_file(
    service,
    user_google_email: str,
    file_id: str,
    output_path: str,
    max_pages: Optional[int] = None,
    output_format: str = "text",
) -> str:
    """
    OCRs a scanned PDF with Cloud Vision and writes the output to a local file.
    """
    ocr_text = await extract_scanned_pdf_text_ocr(
        user_google_email=user_google_email,
        file_id=file_id,
        include_metadata=False,
        max_pages=max_pages,
    )
    if ocr_text.startswith("Error") or ocr_text.startswith("No "):
        return ocr_text

    file_id, file_metadata = await _get_pdf_metadata(service, file_id)
    file_name = file_metadata.get("name", "Unknown File")
    output_file = Path(output_path).expanduser()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    pages = []
    for block in ocr_text.split("\n\n--- Page "):
        page_text = block
        if block.startswith("--- Page "):
            page_text = block.split("---\n", 1)[-1]
        pages.append(page_text)
    total_chars = sum(len(page) for page in pages)

    if output_format == "json":
        output_file.write_text(
            json.dumps(
                {
                    "source_file_id": file_id,
                    "source_file_name": file_name,
                    "mime_type": file_metadata.get("mimeType", "application/pdf"),
                    "file_size_bytes": int(file_metadata.get("size", 0)),
                    "modified_date": file_metadata.get("modifiedTime", ""),
                    "web_link": file_metadata.get("webViewLink", ""),
                    "ocr_date": datetime.now(timezone.utc).isoformat(),
                    "total_characters": total_chars,
                    "text": ocr_text,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    else:
        output_file.write_text(
            "\n".join(
                [
                    f"# OCR: {file_name}",
                    f"# Source: {file_id}",
                    f"# Characters: {total_chars}",
                    "",
                    ocr_text,
                ]
            ),
            encoding="utf-8",
        )

    preview = ocr_text[:200]
    return "\n".join(
        [
            f"OCR completed: {file_name}",
            f"  Source file ID: {file_id}",
            f"  Total characters: {total_chars:,}",
            f"  Output: {output_file} ({output_file.stat().st_size / 1024:.1f} KB, format: {output_format})",
            f"  Preview: {preview}..." if preview else "  Preview: (no text extracted)",
        ]
    )


@server.tool(
    title="Get Drive File Download URL",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors(
    "get_drive_file_download_url", is_read_only=True, service_type="drive"
)
@require_google_service("drive", "drive_read")
async def get_drive_file_download_url(
    service,
    user_google_email: str,
    file_id: str,
    export_format: Optional[str] = None,
) -> str:
    """
    Downloads a Google Drive file and saves it to local disk.

    In stdio mode, returns the local file path for direct access.
    In HTTP mode, returns a temporary download URL (valid for 1 hour).

    For Google native files (Docs, Sheets, Slides), exports to a useful format:
    - Google Docs -> PDF (default) or DOCX if export_format='docx'
    - Google Sheets -> XLSX (default), PDF if export_format='pdf', or CSV if export_format='csv'
    - Google Slides -> PDF (default) or PPTX if export_format='pptx'

    For other files, downloads the original file format.

    Args:
        user_google_email: The user's Google email address. Required.
        file_id: The Google Drive file ID to download.
        export_format: Optional export format for Google native files.
                      Options: 'pdf', 'docx', 'xlsx', 'csv', 'pptx'.
                      If not specified, uses sensible defaults (PDF for Docs/Slides, XLSX for Sheets).
                      For Sheets: supports 'csv', 'pdf', or 'xlsx' (default).

    Returns:
        str: File metadata with either a local file path or download URL.
    """
    logger.info(
        f"[get_drive_file_download_url] Invoked. File ID: '{file_id}', Export format: {export_format}"
    )

    # Resolve shortcuts and get file metadata
    resolved_file_id, file_metadata = await resolve_drive_item(
        service,
        file_id,
        extra_fields="name, webViewLink, mimeType",
    )
    file_id = resolved_file_id
    mime_type = file_metadata.get("mimeType", "")
    file_name = file_metadata.get("name", "Unknown File")

    # Determine export format for Google native files
    export_mime_type = None
    output_filename = file_name
    output_mime_type = mime_type

    if mime_type == "application/vnd.google-apps.document":
        # Google Docs
        if export_format == "docx":
            export_mime_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            output_mime_type = export_mime_type
            if not output_filename.endswith(".docx"):
                output_filename = f"{Path(output_filename).stem}.docx"
        else:
            # Default to PDF
            export_mime_type = "application/pdf"
            output_mime_type = export_mime_type
            if not output_filename.endswith(".pdf"):
                output_filename = f"{Path(output_filename).stem}.pdf"

    elif mime_type == "application/vnd.google-apps.spreadsheet":
        # Google Sheets
        if export_format == "csv":
            export_mime_type = "text/csv"
            output_mime_type = export_mime_type
            if not output_filename.endswith(".csv"):
                output_filename = f"{Path(output_filename).stem}.csv"
        elif export_format == "pdf":
            export_mime_type = "application/pdf"
            output_mime_type = export_mime_type
            if not output_filename.endswith(".pdf"):
                output_filename = f"{Path(output_filename).stem}.pdf"
        else:
            # Default to XLSX
            export_mime_type = (
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
            output_mime_type = export_mime_type
            if not output_filename.endswith(".xlsx"):
                output_filename = f"{Path(output_filename).stem}.xlsx"

    elif mime_type == "application/vnd.google-apps.presentation":
        # Google Slides
        if export_format == "pptx":
            export_mime_type = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            output_mime_type = export_mime_type
            if not output_filename.endswith(".pptx"):
                output_filename = f"{Path(output_filename).stem}.pptx"
        else:
            # Default to PDF
            export_mime_type = "application/pdf"
            output_mime_type = export_mime_type
            if not output_filename.endswith(".pdf"):
                output_filename = f"{Path(output_filename).stem}.pdf"

    # Download the file
    request_obj = (
        service.files().export_media(fileId=file_id, mimeType=export_mime_type)
        if export_mime_type
        else service.files().get_media(fileId=file_id)
    )

    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request_obj)
    loop = asyncio.get_event_loop()
    done = False
    while not done:
        status, done = await loop.run_in_executor(None, downloader.next_chunk)

    file_content_bytes = fh.getvalue()
    size_bytes = len(file_content_bytes)
    size_kb = size_bytes / 1024 if size_bytes else 0

    # Check if we're in stateless mode (can't save files)
    if is_stateless_mode():
        result_lines = [
            "File downloaded successfully!",
            f"File: {file_name}",
            f"File ID: {file_id}",
            f"Size: {size_kb:.1f} KB ({size_bytes} bytes)",
            f"MIME Type: {output_mime_type}",
            "\n⚠️ Stateless mode: File storage disabled.",
            "\nBase64-encoded content (first 100 characters shown):",
            f"{base64.b64encode(file_content_bytes[:100]).decode('utf-8')}...",
        ]
        logger.info(
            f"[get_drive_file_download_url] Successfully downloaded {size_kb:.1f} KB file (stateless mode)"
        )
        return "\n".join(result_lines)

    # Save file to local disk and return file path
    try:
        storage = get_attachment_storage()

        # Encode bytes to base64 (as expected by AttachmentStorage)
        base64_data = base64.urlsafe_b64encode(file_content_bytes).decode("utf-8")

        # Save attachment to local disk
        result = storage.save_attachment(
            base64_data=base64_data,
            filename=output_filename,
            mime_type=output_mime_type,
        )

        result_lines = [
            "File downloaded successfully!",
            f"File: {file_name}",
            f"File ID: {file_id}",
            f"Size: {size_kb:.1f} KB ({size_bytes} bytes)",
            f"MIME Type: {output_mime_type}",
        ]

        if get_transport_mode() == "stdio":
            result_lines.append(f"\n📎 Saved to: {result.path}")
            result_lines.append(
                "\nThe file has been saved to disk and can be accessed directly via the file path."
            )
        else:
            download_url = get_attachment_url(result.file_id)
            result_lines.append(f"\n📎 Download URL: {download_url}")
            result_lines.append("\nThe file will expire after 1 hour.")

        if export_mime_type:
            result_lines.append(
                f"\nNote: Google native file exported to {output_mime_type} format."
            )

        logger.info(
            f"[get_drive_file_download_url] Successfully saved {size_kb:.1f} KB file to {result.path}"
        )
        return "\n".join(result_lines)

    except Exception as e:
        logger.error(f"[get_drive_file_download_url] Failed to save file: {e}")
        return (
            f"Error: Failed to save file for download.\n"
            f"File was downloaded successfully ({size_kb:.1f} KB) but could not be saved.\n\n"
            f"Error details: {str(e)}"
        )


@server.tool(
    title="List Drive Items",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors("list_drive_items", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def list_drive_items(
    service,
    user_google_email: str,
    folder_id: str = "root",
    page_size: int = 100,
    page_token: Optional[str] = None,
    drive_id: Optional[str] = None,
    include_items_from_all_drives: bool = True,
    corpora: Optional[str] = None,
    file_type: Optional[str] = None,
    detailed: bool = True,
    order_by: Optional[str] = None,
    resource_type: str = "items",
    query: Optional[str] = None,
    include_organizers: bool = False,
) -> str:
    """
    Lists files/folders or shared drive containers, supporting shared drives.
    If `drive_id` is specified, lists items within that shared drive. `folder_id` is then relative to that drive (or use drive_id as folder_id for root).
    If `drive_id` is not specified, lists items from user's "My Drive" and accessible shared drives (if `include_items_from_all_drives` is True).
    Set `resource_type` to "shared_drives" to list shared drive containers instead of folder contents.

    Args:
        user_google_email (str): The user's Google email address. Required.
        folder_id (str): The ID of the Google Drive folder. Defaults to 'root'. For a shared drive, this can be the shared drive's ID to list its root, or a folder ID within that shared drive.
        page_size (int): The maximum number of items to return. Defaults to 100.
        page_token (Optional[str]): Page token from a previous response's nextPageToken to retrieve the next page of results.
        drive_id (Optional[str]): ID of the shared drive. If provided, the listing is scoped to this drive.
        include_items_from_all_drives (bool): Whether items from all accessible shared drives should be included if `drive_id` is not set. Defaults to True.
        corpora (Optional[str]): Corpus to query ('user', 'drive', 'allDrives'). If `drive_id` is set and `corpora` is None, 'drive' is used. If None and no `drive_id`, API defaults apply.
        file_type (Optional[str]): Restrict results to a specific file type. Accepts a friendly
                                   name ('folder', 'document'/'doc', 'spreadsheet'/'sheet',
                                   'presentation'/'slides', 'form', 'drawing', 'pdf', 'shortcut',
                                   'script', 'site', 'jam'/'jamboard') or any raw MIME type
                                   string (e.g. 'application/pdf'). Defaults to None (all types).
        detailed (bool): Whether to include size, modified time, and link in results. Defaults to True.
        order_by (Optional[str]): Sort order. Comma-separated list of sort keys with optional 'desc' modifier.
                                  Valid keys: 'createdTime', 'folder', 'modifiedByMeTime', 'modifiedTime',
                                  'name', 'name_natural', 'quotaBytesUsed', 'recency', 'sharedWithMeTime',
                                  'starred', 'viewedByMeTime'. Example: 'modifiedTime desc' or 'folder,modifiedTime desc,name'.
                                  Defaults to None (Drive API default ordering).
        resource_type (str): What to list. Use "items" for folder contents or
                             "shared_drives" for shared drive containers. Defaults to "items".
        query (Optional[str]): Shared drive query used only when resource_type="shared_drives",
                               e.g. "name contains 'Engineering'".
        include_organizers (bool): When resource_type="shared_drives", include principals
                                   with the organizer role. This costs one extra permissions.list
                                   API call per shared drive returned. Defaults to False.

    Returns:
        str: A formatted list of files/folders in the specified folder or shared drives.
             Includes a nextPageToken line when more results are available.
    """
    logger.info(
        f"[list_drive_items] Invoked. Email: '{user_google_email}', Folder ID: '{folder_id}', "
        f"File Type: '{file_type}', Resource Type: '{resource_type}'"
    )

    normalized_resource_type = resource_type.lower().strip()
    if normalized_resource_type == "shared_drives":
        return await _list_shared_drives_impl(
            service=service,
            user_google_email=user_google_email,
            page_size=page_size,
            page_token=page_token,
            query=query,
            include_organizers=include_organizers,
        )
    if normalized_resource_type != "items":
        raise ValueError("resource_type must be either 'items' or 'shared_drives'")

    resolved_folder_id = await resolve_folder_id(service, folder_id)
    final_query = f"'{resolved_folder_id}' in parents and trashed=false"

    if file_type is not None:
        mime = resolve_file_type_mime(file_type)
        final_query = f"({final_query}) and mimeType = '{mime}'"
        logger.info(f"[list_drive_items] Added mimeType filter: '{mime}'")

    list_params = build_drive_list_params(
        query=final_query,
        page_size=page_size,
        drive_id=drive_id,
        include_items_from_all_drives=include_items_from_all_drives,
        corpora=corpora,
        page_token=page_token,
        detailed=detailed,
        order_by=order_by,
    )

    results = await asyncio.to_thread(service.files().list(**list_params).execute)
    files = results.get("files", [])
    if not files:
        return f"No items found in folder '{folder_id}'."

    next_token = results.get("nextPageToken")
    header = (
        f"Found {len(files)} items in folder '{folder_id}' for {user_google_email}:"
    )
    formatted_items_text_parts = [header]
    for item in files:
        if detailed:
            size_str = f", Size: {item.get('size', 'N/A')}" if "size" in item else ""
            drive_id_str = (
                f", Drive ID: {item['driveId']}" if item.get("driveId") else ""
            )
            formatted_items_text_parts.append(
                f'- Name: "{item["name"]}" (ID: {item["id"]}, Type: {item["mimeType"]}{size_str}{drive_id_str}, Modified: {item.get("modifiedTime", "N/A")}) Link: {item.get("webViewLink", "#")}'
            )
        else:
            formatted_items_text_parts.append(
                f'- Name: "{item["name"]}" (ID: {item["id"]}, Type: {item["mimeType"]})'
            )
    if next_token:
        formatted_items_text_parts.append(f"nextPageToken: {next_token}")
    text_output = "\n".join(formatted_items_text_parts)
    return text_output


async def _list_shared_drives_impl(
    service,
    user_google_email: str,
    page_size: int = 100,
    page_token: Optional[str] = None,
    query: Optional[str] = None,
    include_organizers: bool = False,
) -> str:
    """List shared drives available to the authenticated user."""
    logger.info(
        f"[list_shared_drives] Invoked. Email: '{user_google_email}', page_size: {page_size}, "
        f"include_organizers: {include_organizers}"
    )

    list_params: Dict[str, Any] = {
        "pageSize": min(max(page_size, 1), 100),
        "fields": (
            "drives(id, name, createdTime, hidden, "
            "restrictions, capabilities(canManageMembers, canEdit)), "
            "nextPageToken"
        ),
    }
    if page_token:
        list_params["pageToken"] = page_token
    if query:
        list_params["q"] = query

    results = await asyncio.to_thread(service.drives().list(**list_params).execute)
    drives = results.get("drives", [])
    if not drives:
        return f"No shared drives found for {user_google_email}."

    if include_organizers:

        async def _fetch_organizers(d: Dict[str, Any]) -> None:
            try:
                permissions = []
                next_permission_page_token = None

                while True:
                    list_kwargs: Dict[str, Any] = {
                        "fileId": d["id"],
                        "supportsAllDrives": True,
                        "useDomainAdminAccess": False,
                        "fields": (
                            "nextPageToken, "
                            "permissions(emailAddress, displayName, role, type, domain)"
                        ),
                        "pageSize": 100,
                    }
                    if next_permission_page_token:
                        list_kwargs["pageToken"] = next_permission_page_token

                    perms = await asyncio.to_thread(
                        service.permissions().list(**list_kwargs).execute
                    )
                    permissions.extend(perms.get("permissions", []))

                    next_permission_page_token = perms.get("nextPageToken")
                    if not next_permission_page_token:
                        break

                d["_organizers"] = [
                    p for p in permissions if p.get("role") == "organizer"
                ]
            except HttpError as e:
                status = getattr(e, "status_code", None)
                if status is None and getattr(e, "resp", None) is not None:
                    status = getattr(e.resp, "status", None)
                reason = getattr(e, "reason", None) or str(e)
                d["_organizers_error"] = f"{status or 'unknown'}: {reason}"

        organizer_fetch_sem = asyncio.Semaphore(
            SHARED_DRIVE_ORGANIZER_CONCURRENCY_LIMIT
        )

        async def _bounded_fetch_organizers(d: Dict[str, Any]) -> None:
            async with organizer_fetch_sem:
                await _fetch_organizers(d)

        await asyncio.gather(*[_bounded_fetch_organizers(d) for d in drives])

    next_token = results.get("nextPageToken")
    parts = [f"Found {len(drives)} shared drives for {user_google_email}:"]
    for d in drives:
        caps = d.get("capabilities") or {}
        rest = d.get("restrictions") or {}
        cap_flags = ", ".join(k for k, v in caps.items() if v) or "none"
        rest_flags = ", ".join(k for k, v in rest.items() if v) or "none"
        hidden = " [hidden]" if d.get("hidden") else ""
        parts.append(
            f'- Name: "{d["name"]}" (ID: {d["id"]}, Created: {d.get("createdTime", "N/A")}){hidden} '
            f"Capabilities: {cap_flags}; Restrictions: {rest_flags}"
        )
        if include_organizers:
            err = d.get("_organizers_error")
            if err:
                parts.append(f"  Organizers: <error: {err}>")
            else:
                organizers = d.get("_organizers", [])
                if not organizers:
                    parts.append("  Organizers: <none returned>")
                else:
                    for o in organizers:
                        identifier = (
                            o.get("emailAddress")
                            or o.get("domain")
                            or o.get("displayName")
                            or o.get("type", "?")
                        )
                        display = o.get("displayName")
                        kind = o.get("type", "?")
                        suffix = (
                            f' ("{display}")'
                            if display and display != identifier
                            else ""
                        )
                        parts.append(f"  Organizer ({kind}): {identifier}{suffix}")
    if next_token:
        parts.append(f"nextPageToken: {next_token}")
    return "\n".join(parts)


async def _create_drive_folder_impl(
    service,
    user_google_email: str,
    folder_name: str,
    parent_folder_id: str = "root",
) -> str:
    """Internal implementation for create_drive_folder. Used by tests."""
    resolved_folder_id = await resolve_folder_id(service, parent_folder_id)
    file_metadata = {
        "name": folder_name,
        "parents": [resolved_folder_id],
        "mimeType": FOLDER_MIME_TYPE,
    }
    created_file = await asyncio.to_thread(
        service.files()
        .create(
            body=file_metadata,
            fields="id, name, webViewLink",
            supportsAllDrives=True,
        )
        .execute
    )
    link = created_file.get("webViewLink", "")
    return (
        f"Successfully created folder '{created_file.get('name', folder_name)}' (ID: {created_file.get('id', 'N/A')}) "
        f"in folder '{parent_folder_id}' for {user_google_email}. Link: {link}"
    )


@server.tool(
    title="Create Drive Folder",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
@handle_http_errors("create_drive_folder", service_type="drive")
@require_google_service("drive", "drive_file")
async def create_drive_folder(
    service,
    user_google_email: str,
    folder_name: str,
    parent_folder_id: str = "root",
) -> str:
    """
    Creates a new folder in Google Drive, supporting creation within shared drives.

    Args:
        user_google_email (str): The user's Google email address. Required.
        folder_name (str): The name for the new folder.
        parent_folder_id (str): The ID of the parent folder. Defaults to 'root'.
            For shared drives, use a folder ID within that shared drive.

    Returns:
        str: Confirmation message with folder name, ID, and link.
    """
    logger.info(
        f"[create_drive_folder] Invoked. Email: '{user_google_email}', Folder: '{folder_name}', Parent: '{parent_folder_id}'"
    )
    return await _create_drive_folder_impl(
        service, user_google_email, folder_name, parent_folder_id
    )


@server.tool(
    title="Create Drive File",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
@handle_http_errors("create_drive_file", service_type="drive")
@require_google_service("drive", "drive_file")
async def create_drive_file(
    service,
    user_google_email: str,
    file_name: str,
    content: Optional[str] = None,  # Now explicitly Optional
    folder_id: str = "root",
    mime_type: str = "text/plain",
    fileUrl: Optional[str] = None,  # Now explicitly Optional
) -> str:
    """
    Creates a new file in Google Drive, supporting creation within shared drives.
    Accepts either direct content or a fileUrl to fetch the content from.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_name (str): The name for the new file.
        content (Optional[str]): If provided, the content to write to the file.
        folder_id (str): The ID of the parent folder. Defaults to 'root'. For shared drives, this must be a folder ID within the shared drive.
        mime_type (str): The MIME type of the file. Defaults to 'text/plain'.
        fileUrl (Optional[str]): If provided, fetches the file content from this URL. Supports file://, http://, and https:// protocols.

    Returns:
        str: Confirmation message of the successful file creation with file link.
    """
    logger.info(
        f"[create_drive_file] Invoked. Email: '{user_google_email}', File Name: {file_name}, Folder ID: {folder_id}, fileUrl: {fileUrl}"
    )

    if content is None and fileUrl is None and mime_type != FOLDER_MIME_TYPE:
        raise Exception("You must provide either 'content' or 'fileUrl'.")

    # Create folder (no content or media_body). Prefer create_drive_folder for new code.
    if mime_type == FOLDER_MIME_TYPE:
        return await _create_drive_folder_impl(
            service, user_google_email, file_name, folder_id
        )

    file_data = None
    resolved_folder_id = await resolve_folder_id(service, folder_id)

    file_metadata = {
        "name": file_name,
        "parents": [resolved_folder_id],
        "mimeType": mime_type,
    }

    # Prefer fileUrl if both are provided
    if fileUrl:
        logger.info(f"[create_drive_file] Fetching file from URL: {fileUrl}")

        # Check if this is a file:// URL
        parsed_url = urlparse(fileUrl)
        if parsed_url.scheme == "file":
            # Handle file:// URL - read from local filesystem
            logger.info(
                "[create_drive_file] Detected file:// URL, reading from local filesystem"
            )
            transport_mode = get_transport_mode()
            running_streamable = transport_mode == "streamable-http"
            if running_streamable:
                logger.warning(
                    "[create_drive_file] file:// URL requested while server runs in streamable-http mode. Ensure the file path is accessible to the server (e.g., Docker volume) or use an HTTP(S) URL."
                )

            # Convert file:// URL to a cross-platform local path
            raw_path = parsed_url.path or ""
            netloc = parsed_url.netloc
            if netloc and netloc.lower() != "localhost":
                raw_path = f"//{netloc}{raw_path}"
            file_path = url2pathname(raw_path)

            # Validate path safety and verify file exists
            path_obj = validate_file_path(file_path)
            if not path_obj.exists():
                extra = (
                    " The server is running via streamable-http, so file:// URLs must point to files inside the container or remote host."
                    if running_streamable
                    else ""
                )
                raise Exception(f"Local file does not exist: {file_path}.{extra}")
            if not path_obj.is_file():
                extra = (
                    " In streamable-http/Docker deployments, mount the file into the container or provide an HTTP(S) URL."
                    if running_streamable
                    else ""
                )
                raise Exception(f"Path is not a file: {file_path}.{extra}")

            logger.info(f"[create_drive_file] Reading local file: {file_path}")

            # Read file and upload
            file_data = await asyncio.to_thread(path_obj.read_bytes)
            total_bytes = len(file_data)
            logger.info(f"[create_drive_file] Read {total_bytes} bytes from local file")

            media = MediaIoBaseUpload(
                io.BytesIO(file_data),
                mimetype=mime_type,
                resumable=True,
                chunksize=UPLOAD_CHUNK_SIZE_BYTES,
            )

            logger.info("[create_drive_file] Starting upload to Google Drive...")
            created_file = await asyncio.to_thread(
                service.files()
                .create(
                    body=file_metadata,
                    media_body=media,
                    fields="id, name, webViewLink",
                    supportsAllDrives=True,
                )
                .execute,
                num_retries=GOOGLE_API_WRITE_RETRIES,
            )
        # Handle HTTP/HTTPS URLs
        elif parsed_url.scheme in ("http", "https"):
            # when running in stateless mode, deployment may not have access to local file system
            if is_stateless_mode():
                with SpooledTemporaryFile(max_size=UPLOAD_CHUNK_SIZE_BYTES) as spool:

                    async def _write_spool(chunk: bytes) -> None:
                        await asyncio.to_thread(spool.write, chunk)

                    _total, content_type = await _stream_url_with_validation(
                        fileUrl, _write_spool
                    )
                    await asyncio.to_thread(spool.seek, 0)

                    # Try to get MIME type from Content-Type header
                    if content_type and content_type != "application/octet-stream":
                        mime_type = content_type
                        file_metadata["mimeType"] = content_type
                        logger.info(
                            f"[create_drive_file] Using MIME type from Content-Type header: {content_type}"
                        )

                    media = MediaIoBaseUpload(
                        spool,
                        mimetype=mime_type,
                        resumable=True,
                        chunksize=UPLOAD_CHUNK_SIZE_BYTES,
                    )

                    created_file = await asyncio.to_thread(
                        service.files()
                        .create(
                            body=file_metadata,
                            media_body=media,
                            fields="id, name, webViewLink",
                            supportsAllDrives=True,
                        )
                        .execute,
                        num_retries=GOOGLE_API_WRITE_RETRIES,
                    )
            else:
                # Stream download to temp file with SSRF protection, then upload
                with NamedTemporaryFile() as temp_file:

                    async def _write_chunk(chunk: bytes) -> None:
                        await asyncio.to_thread(temp_file.write, chunk)

                    total_bytes, content_type = await _stream_url_with_validation(
                        fileUrl, _write_chunk
                    )

                    logger.info(
                        f"[create_drive_file] Downloaded {total_bytes} bytes "
                        f"from URL before upload."
                    )

                    if content_type and content_type != "application/octet-stream":
                        mime_type = content_type
                        file_metadata["mimeType"] = mime_type
                        logger.info(
                            f"[create_drive_file] Using MIME type from "
                            f"Content-Type header: {mime_type}"
                        )

                    # Reset file pointer to beginning for upload
                    temp_file.seek(0)

                    media = MediaIoBaseUpload(
                        temp_file,
                        mimetype=mime_type,
                        resumable=True,
                        chunksize=UPLOAD_CHUNK_SIZE_BYTES,
                    )

                    logger.info(
                        "[create_drive_file] Starting upload to Google Drive..."
                    )
                    created_file = await asyncio.to_thread(
                        service.files()
                        .create(
                            body=file_metadata,
                            media_body=media,
                            fields="id, name, webViewLink",
                            supportsAllDrives=True,
                        )
                        .execute,
                        num_retries=GOOGLE_API_WRITE_RETRIES,
                    )
        else:
            if not parsed_url.scheme:
                raise Exception(
                    "fileUrl is missing a URL scheme. Use file://, http://, or https://."
                )
            raise Exception(
                f"Unsupported URL scheme '{parsed_url.scheme}'. Only file://, http://, and https:// are supported."
            )
    elif content is not None:
        file_data = content.encode("utf-8")
        media = io.BytesIO(file_data)

        created_file = await asyncio.to_thread(
            service.files()
            .create(
                body=file_metadata,
                media_body=MediaIoBaseUpload(media, mimetype=mime_type, resumable=True),
                fields="id, name, webViewLink",
                supportsAllDrives=True,
            )
            .execute,
            num_retries=GOOGLE_API_WRITE_RETRIES,
        )

    link = created_file.get("webViewLink", "No link available")
    confirmation_message = f"Successfully created file '{created_file.get('name', file_name)}' (ID: {created_file.get('id', 'N/A')}) in folder '{folder_id}' for {user_google_email}. Link: {link}"
    logger.info(f"Successfully created file. Link: {link}")
    return confirmation_message


# Mapping of file extensions to source MIME types for Google Docs conversion
GOOGLE_DOCS_IMPORT_FORMATS = {
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".txt": "text/plain",
    ".text": "text/plain",
    ".html": "text/html",
    ".htm": "text/html",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".doc": "application/msword",
    ".rtf": "application/rtf",
    ".odt": "application/vnd.oasis.opendocument.text",
}

GOOGLE_DOCS_MIME_TYPE = "application/vnd.google-apps.document"


def _detect_source_format(file_name: str, content: Optional[str] = None) -> str:
    """
    Detect the source MIME type based on file extension.
    Falls back to text/plain if unknown.
    """
    ext = Path(file_name).suffix.lower()
    if ext in GOOGLE_DOCS_IMPORT_FORMATS:
        return GOOGLE_DOCS_IMPORT_FORMATS[ext]

    # If content is provided and looks like markdown, use markdown
    if content and (content.startswith("#") or "```" in content or "**" in content):
        return "text/markdown"

    return "text/plain"


@server.tool(
    title="Import to Google Doc",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
@handle_http_errors("import_to_google_doc", service_type="drive")
@require_google_service("drive", "drive_file")
async def import_to_google_doc(
    service,
    user_google_email: str,
    file_name: str,
    content: Optional[str] = None,
    file_path: Optional[str] = None,
    file_url: Optional[str] = None,
    source_format: Optional[str] = None,
    folder_id: str = "root",
) -> str:
    """
    Imports a file (Markdown, DOCX, TXT, HTML, RTF, ODT) into Google Docs format with automatic conversion.

    Google Drive automatically converts the source file to native Google Docs format,
    preserving formatting like headings, lists, bold, italic, etc.
    For batch operations, prefer file_path for files on disk so callers do not need
    to load full file contents into their context.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_name (str): The name for the new Google Doc (extension will be ignored).
        content (Optional[str]): Text content for text-based formats. Use only for short snippets or content already in memory.
        file_path (Optional[str]): Local file path or file:// URL for any supported format (MD, TXT, HTML, DOCX, ODT, RTF). Appropriate for larger files than content, but file_path may still load the file into memory or perform non-streaming reads. Avoid very large files that could exceed memory or time limits; use streaming/chunked uploads or an alternative API for huge files.
        file_url (Optional[str]): Remote URL to fetch the file from (http/https).
        source_format (Optional[str]): Source format hint ('md', 'markdown', 'docx', 'txt', 'html', 'rtf', 'odt').
                                       Auto-detected from file_name extension if not provided.
        folder_id (str): The ID of the parent folder. Defaults to 'root'.

    Returns:
        str: Confirmation message with the new Google Doc link.

    Examples:
        # Import a markdown file from disk (preferred for batch operations)
        import_to_google_doc(file_name="My Doc.md", file_path="/path/to/my-doc.md", source_format="md")

        # Import markdown content directly
        import_to_google_doc(file_name="My Doc.md", content="# Title\\n\\nHello **world**")

        # Import a local DOCX file
        import_to_google_doc(file_name="Report", file_path="/path/to/report.docx")

        # Import from URL
        import_to_google_doc(file_name="Remote Doc", file_url="https://example.com/doc.md")
    """
    logger.info(
        f"[import_to_google_doc] Invoked. Email: '{user_google_email}', "
        f"File Name: '{file_name}', Source Format: '{source_format}', Folder ID: '{folder_id}'"
    )

    # Validate inputs
    source_count = sum(1 for x in [content, file_path, file_url] if x is not None)
    if source_count == 0:
        raise ValueError(
            "You must provide one of: 'content', 'file_path', or 'file_url'."
        )
    if source_count > 1:
        raise ValueError("Provide only one of: 'content', 'file_path', or 'file_url'.")

    # Determine source MIME type
    if source_format:
        # Normalize format hint
        format_key = f".{source_format.lower().lstrip('.')}"
        if format_key in GOOGLE_DOCS_IMPORT_FORMATS:
            source_mime_type = GOOGLE_DOCS_IMPORT_FORMATS[format_key]
        else:
            raise ValueError(
                f"Unsupported source_format: '{source_format}'. "
                f"Supported: {', '.join(ext.lstrip('.') for ext in GOOGLE_DOCS_IMPORT_FORMATS.keys())}"
            )
    else:
        # Auto-detect from file_name, file_path, or file_url
        detection_name = file_path or file_url or file_name
        source_mime_type = _detect_source_format(detection_name, content)

    logger.info(f"[import_to_google_doc] Detected source MIME type: {source_mime_type}")

    # Clean up file name (remove extension since it becomes a Google Doc)
    doc_name = Path(file_name).stem if Path(file_name).suffix else file_name

    # Resolve folder
    resolved_folder_id = await resolve_folder_id(service, folder_id)

    # File metadata - destination is Google Docs format
    file_metadata = {
        "name": doc_name,
        "parents": [resolved_folder_id],
        "mimeType": GOOGLE_DOCS_MIME_TYPE,  # Target format = Google Docs
    }

    file_data: bytes
    remote_file_data: Optional[BinaryIO] = None
    remote_content_type: Optional[str] = None

    # Handle content (string input for text formats)
    if content is not None:
        file_data = content.encode("utf-8")
        logger.info(f"[import_to_google_doc] Using content: {len(file_data)} bytes")

    # Handle file_path (local file)
    elif file_path is not None:
        parsed_url = urlparse(file_path)

        # Handle file:// URL format
        if parsed_url.scheme == "file":
            raw_path = parsed_url.path or ""
            netloc = parsed_url.netloc
            if netloc and netloc.lower() != "localhost":
                raw_path = f"//{netloc}{raw_path}"
            actual_path = url2pathname(raw_path)
        elif parsed_url.scheme == "":
            # Regular path
            actual_path = file_path
        else:
            raise ValueError(
                f"file_path should be a local path or file:// URL, got: {file_path}"
            )

        path_obj = validate_file_path(actual_path)
        if not path_obj.exists():
            raise FileNotFoundError(f"File not found: {actual_path}")
        if not path_obj.is_file():
            raise ValueError(f"Path is not a file: {actual_path}")

        file_data = await asyncio.to_thread(path_obj.read_bytes)
        logger.info(f"[import_to_google_doc] Read local file: {len(file_data)} bytes")

        # Re-detect format from actual file if not specified
        if not source_format:
            source_mime_type = _detect_source_format(actual_path)
            logger.info(
                f"[import_to_google_doc] Re-detected from path: {source_mime_type}"
            )

    # Handle file_url (remote file)
    elif file_url is not None:
        parsed_url = urlparse(file_url)
        if parsed_url.scheme not in ("http", "https"):
            raise ValueError(f"file_url must be http:// or https://, got: {file_url}")

        # SSRF protection: block internal/private network URLs and validate redirects
        remote_file_data, remote_content_type = await _download_url_to_bytes(file_url)

    # Upload with conversion
    if remote_file_data is not None:
        with remote_file_data:
            remote_size = await _get_file_size(remote_file_data)

            logger.info(
                f"[import_to_google_doc] Downloaded from URL: {remote_size} bytes"
            )

            # Prefer the Content-Type from the download; fall back to URL-based detection
            if not source_format:
                ct_base = (remote_content_type or "").split(";", 1)[0].strip()
                if ct_base and ct_base != "application/octet-stream":
                    source_mime_type = ct_base
                    logger.info(
                        f"[import_to_google_doc] Using Content-Type from response: {source_mime_type}"
                    )
                else:
                    source_mime_type = _detect_source_format(file_url)
                    logger.info(
                        f"[import_to_google_doc] Detected from URL path: {source_mime_type}"
                    )

            media = MediaIoBaseUpload(
                remote_file_data,
                mimetype=source_mime_type,  # Source format
                resumable=True,
                chunksize=UPLOAD_CHUNK_SIZE_BYTES,
            )

            logger.info(
                f"[import_to_google_doc] Uploading to Google Drive with conversion: "
                f"{source_mime_type} → {GOOGLE_DOCS_MIME_TYPE}"
            )

            created_file = await asyncio.to_thread(
                service.files()
                .create(
                    body=file_metadata,
                    media_body=media,
                    fields="id, name, webViewLink, mimeType",
                    supportsAllDrives=True,
                )
                .execute,
                num_retries=GOOGLE_API_WRITE_RETRIES,
            )
    else:
        media = MediaIoBaseUpload(
            io.BytesIO(file_data),
            mimetype=source_mime_type,  # Source format
            resumable=True,
            chunksize=UPLOAD_CHUNK_SIZE_BYTES,
        )

        logger.info(
            f"[import_to_google_doc] Uploading to Google Drive with conversion: "
            f"{source_mime_type} → {GOOGLE_DOCS_MIME_TYPE}"
        )

        created_file = await asyncio.to_thread(
            service.files()
            .create(
                body=file_metadata,
                media_body=media,
                fields="id, name, webViewLink, mimeType",
                supportsAllDrives=True,
            )
            .execute,
            num_retries=GOOGLE_API_WRITE_RETRIES,
        )

    result_mime = created_file.get("mimeType", "unknown")
    if result_mime != GOOGLE_DOCS_MIME_TYPE:
        logger.warning(
            f"[import_to_google_doc] Conversion may have failed. "
            f"Expected {GOOGLE_DOCS_MIME_TYPE}, got {result_mime}"
        )

    link = created_file.get("webViewLink", "No link available")
    doc_id = created_file.get("id", "N/A")

    confirmation = (
        f"✅ Successfully imported '{doc_name}' as Google Doc\n"
        f"   Document ID: {doc_id}\n"
        f"   Source format: {source_mime_type}\n"
        f"   Folder: {folder_id}\n"
        f"   Link: {link}"
    )

    logger.info(f"[import_to_google_doc] Success. Link: {link}")
    return confirmation


@server.tool(
    title="Get Drive File Permissions",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors(
    "get_drive_file_permissions", is_read_only=True, service_type="drive"
)
@require_google_service("drive", "drive_read")
async def get_drive_file_permissions(
    service,
    user_google_email: str,
    file_id: str,
) -> str:
    """
    Gets detailed metadata about a Google Drive file including sharing permissions.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the file to check permissions for.

    Returns:
        str: Detailed file metadata including sharing status and URLs.
    """
    logger.info(
        f"[get_drive_file_permissions] Checking file {file_id} for {user_google_email}"
    )

    resolved_file_id, _ = await resolve_drive_item(service, file_id)
    file_id = resolved_file_id

    try:
        # Get comprehensive file metadata including permissions with details
        file_metadata = await asyncio.to_thread(
            service.files()
            .get(
                fileId=file_id,
                fields="id, name, mimeType, size, modifiedTime, owners, "
                "permissions(id, type, role, emailAddress, domain, expirationTime, permissionDetails), "
                "webViewLink, webContentLink, shared, sharingUser, viewersCanCopyContent",
                supportsAllDrives=True,
            )
            .execute
        )

        # Format the response
        output_parts = [
            f"File: {file_metadata.get('name', 'Unknown')}",
            f"ID: {file_id}",
            f"Type: {file_metadata.get('mimeType', 'Unknown')}",
            f"Size: {file_metadata.get('size', 'N/A')} bytes",
            f"Modified: {file_metadata.get('modifiedTime', 'N/A')}",
            "",
            "Sharing Status:",
            f"  Shared: {file_metadata.get('shared', False)}",
        ]

        # Add sharing user if available
        sharing_user = file_metadata.get("sharingUser")
        if sharing_user:
            output_parts.append(
                f"  Shared by: {sharing_user.get('displayName', 'Unknown')} ({sharing_user.get('emailAddress', 'Unknown')})"
            )

        # Process permissions
        permissions = file_metadata.get("permissions", [])
        if permissions:
            output_parts.append(f"  Number of permissions: {len(permissions)}")
            output_parts.append("  Permissions:")
            for perm in permissions:
                output_parts.append(f"    - {format_permission_info(perm)}")
        else:
            output_parts.append("  No additional permissions (private file)")

        # Add URLs
        output_parts.extend(
            [
                "",
                "URLs:",
                f"  View Link: {file_metadata.get('webViewLink', 'N/A')}",
            ]
        )

        # webContentLink is only available for files that can be downloaded
        web_content_link = file_metadata.get("webContentLink")
        if web_content_link:
            output_parts.append(f"  Direct Download Link: {web_content_link}")

        has_public_link = check_public_link_permission(permissions)

        if has_public_link:
            output_parts.extend(
                [
                    "",
                    "✅ This file is shared with 'Anyone with the link' - it can be inserted into Google Docs",
                ]
            )
        else:
            output_parts.extend(
                [
                    "",
                    "❌ This file is NOT shared with 'Anyone with the link' - it cannot be inserted into Google Docs",
                    "   To fix: Right-click the file in Google Drive → Share → Anyone with the link → Viewer",
                ]
            )

        return "\n".join(output_parts)

    except Exception as e:
        logger.error(f"Error getting file permissions: {e}")
        return f"Error getting file permissions: {e}"


@server.tool(
    title="Check Drive File Public Access",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors(
    "check_drive_file_public_access", is_read_only=True, service_type="drive"
)
@require_google_service("drive", "drive_read")
async def check_drive_file_public_access(
    service,
    user_google_email: str,
    file_name: str,
    drive_id: Optional[str] = None,
) -> str:
    """
    Searches for a file by name and checks if it has public link sharing enabled.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_name (str): The name of the file to check.
        drive_id (Optional[str]): ID of the shared drive to scope the search to. When set, the
                                  underlying files.list call uses corpora='drive' and the given
                                  driveId, which is required to reliably find files that live only
                                  in that shared drive. When None, behaviour is unchanged
                                  (default API corpora applies).

    Returns:
        str: Information about the file's sharing status and whether it can be used in Google Docs.
    """
    logger.info(
        f"[check_drive_file_public_access] Searching for {file_name}"
        + (f" within drive_id={drive_id}" if drive_id else "")
    )

    # Search for the file
    escaped_name = file_name.replace("'", "\\'")
    query = f"name = '{escaped_name}'"

    list_params: Dict[str, Any] = {
        "q": query,
        "pageSize": 10,
        "fields": "files(id, name, mimeType, webViewLink)",
        "supportsAllDrives": True,
        "includeItemsFromAllDrives": True,
    }
    if drive_id:
        list_params["corpora"] = "drive"
        list_params["driveId"] = drive_id

    results = await asyncio.to_thread(service.files().list(**list_params).execute)

    files = results.get("files", [])
    if not files:
        return f"No file found with name '{file_name}'"

    if len(files) > 1:
        output_parts = [f"Found {len(files)} files with name '{file_name}':"]
        for f in files:
            output_parts.append(f"  - {f['name']} (ID: {f['id']})")
        output_parts.append("\nChecking the first file...")
        output_parts.append("")
    else:
        output_parts = []

    # Check permissions for the first file
    file_id = files[0]["id"]
    resolved_file_id, _ = await resolve_drive_item(service, file_id)
    file_id = resolved_file_id

    # Get detailed permissions
    file_metadata = await asyncio.to_thread(
        service.files()
        .get(
            fileId=file_id,
            fields="id, name, mimeType, permissions, webViewLink, webContentLink, shared",
            supportsAllDrives=True,
        )
        .execute
    )

    permissions = file_metadata.get("permissions", [])

    has_public_link = check_public_link_permission(permissions)

    output_parts.extend(
        [
            f"File: {file_metadata['name']}",
            f"ID: {file_id}",
            f"Type: {file_metadata['mimeType']}",
            f"Shared: {file_metadata.get('shared', False)}",
            "",
        ]
    )

    if has_public_link:
        output_parts.extend(
            [
                "✅ PUBLIC ACCESS ENABLED - This file can be inserted into Google Docs",
                f"Use with insert_doc_image_url: {get_drive_image_url(file_id)}",
            ]
        )
    else:
        output_parts.extend(
            [
                "❌ NO PUBLIC ACCESS - Cannot insert into Google Docs",
                "Fix: Drive → Share → 'Anyone with the link' → 'Viewer'",
            ]
        )

    return "\n".join(output_parts)


@server.tool(
    title="Update Drive File",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
@handle_http_errors("update_drive_file", is_read_only=False, service_type="drive")
@require_google_service("drive", "drive_file")
async def update_drive_file(
    service,
    user_google_email: str,
    file_id: str,
    # File metadata updates
    name: Optional[str] = None,
    description: Optional[str] = None,
    mime_type: Optional[str] = None,
    # Folder organization
    add_parents: Optional[str] = None,  # Comma-separated folder IDs to add
    remove_parents: Optional[str] = None,  # Comma-separated folder IDs to remove
    # File status
    starred: Optional[bool] = None,
    trashed: Optional[bool] = None,
    # Sharing and permissions
    writers_can_share: Optional[bool] = None,
    copy_requires_writer_permission: Optional[bool] = None,
    # Custom properties
    properties: Optional[dict] = None,  # User-visible custom properties
) -> str:
    """
    Updates metadata and properties of a Google Drive file.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the file to update. Required.
        name (Optional[str]): New name for the file.
        description (Optional[str]): New description for the file.
        mime_type (Optional[str]): New MIME type (note: changing type may require content upload).
        add_parents (Optional[str]): Comma-separated folder IDs to add as parents.
        remove_parents (Optional[str]): Comma-separated folder IDs to remove from parents.
        starred (Optional[bool]): Whether to star/unstar the file.
        trashed (Optional[bool]): Whether to move file to/from trash.
        writers_can_share (Optional[bool]): Whether editors can share the file.
        copy_requires_writer_permission (Optional[bool]): Whether copying requires writer permission.
        properties (Optional[dict]): Custom key-value properties for the file.

    Returns:
        str: Confirmation message with details of the updates applied.
    """
    logger.info(f"[update_drive_file] Updating file {file_id} for {user_google_email}")

    current_file_fields = (
        "name, description, mimeType, parents, starred, trashed, webViewLink, "
        "writersCanShare, copyRequiresWriterPermission, properties"
    )
    resolved_file_id, current_file = await resolve_drive_item(
        service,
        file_id,
        extra_fields=current_file_fields,
    )
    file_id = resolved_file_id

    # Build the update body with only specified fields
    update_body = {}
    if name is not None:
        update_body["name"] = name
    if description is not None:
        update_body["description"] = description
    if mime_type is not None:
        update_body["mimeType"] = mime_type
    if starred is not None:
        update_body["starred"] = starred
    if trashed is not None:
        update_body["trashed"] = trashed
    if writers_can_share is not None:
        update_body["writersCanShare"] = writers_can_share
    if copy_requires_writer_permission is not None:
        update_body["copyRequiresWriterPermission"] = copy_requires_writer_permission
    if properties is not None:
        update_body["properties"] = properties

    async def _resolve_parent_arguments(parent_arg: Optional[str]) -> Optional[str]:
        if not parent_arg:
            return None
        parent_ids = [part.strip() for part in parent_arg.split(",") if part.strip()]
        if not parent_ids:
            return None

        resolved_ids = []
        for parent in parent_ids:
            resolved_parent = await resolve_folder_id(service, parent)
            resolved_ids.append(resolved_parent)
        return ",".join(resolved_ids)

    resolved_add_parents = await _resolve_parent_arguments(add_parents)
    resolved_remove_parents = await _resolve_parent_arguments(remove_parents)

    # Build query parameters for parent changes
    query_params = {
        "fileId": file_id,
        "supportsAllDrives": True,
        "fields": "id, name, description, mimeType, parents, starred, trashed, webViewLink, writersCanShare, copyRequiresWriterPermission, properties",
    }

    if resolved_add_parents:
        query_params["addParents"] = resolved_add_parents
    if resolved_remove_parents:
        query_params["removeParents"] = resolved_remove_parents

    # Only include body if there are updates
    if update_body:
        query_params["body"] = update_body

    # Perform the update
    updated_file = await asyncio.to_thread(
        service.files().update(**query_params).execute
    )

    # Build response message
    output_parts = [
        f"✅ Successfully updated file: {updated_file.get('name', current_file['name'])}"
    ]
    output_parts.append(f"   File ID: {file_id}")

    # Report what changed
    changes = []
    if name is not None and name != current_file.get("name"):
        changes.append(f"   • Name: '{current_file.get('name')}' → '{name}'")
    if description is not None:
        old_desc_value = current_file.get("description")
        new_desc_value = description
        should_report_change = (old_desc_value or "") != (new_desc_value or "")
        if should_report_change:
            old_desc_display = (
                old_desc_value if old_desc_value not in (None, "") else "(empty)"
            )
            new_desc_display = (
                new_desc_value if new_desc_value not in (None, "") else "(empty)"
            )
            changes.append(f"   • Description: {old_desc_display} → {new_desc_display}")
    if add_parents:
        changes.append(f"   • Added to folder(s): {add_parents}")
    if remove_parents:
        changes.append(f"   • Removed from folder(s): {remove_parents}")
    current_starred = current_file.get("starred")
    if starred is not None and starred != current_starred:
        star_status = "starred" if starred else "unstarred"
        changes.append(f"   • File {star_status}")
    current_trashed = current_file.get("trashed")
    if trashed is not None and trashed != current_trashed:
        trash_status = "moved to trash" if trashed else "restored from trash"
        changes.append(f"   • File {trash_status}")
    current_writers_can_share = current_file.get("writersCanShare")
    if writers_can_share is not None and writers_can_share != current_writers_can_share:
        share_status = "can" if writers_can_share else "cannot"
        changes.append(f"   • Writers {share_status} share the file")
    current_copy_requires_writer_permission = current_file.get(
        "copyRequiresWriterPermission"
    )
    if (
        copy_requires_writer_permission is not None
        and copy_requires_writer_permission != current_copy_requires_writer_permission
    ):
        copy_status = (
            "requires" if copy_requires_writer_permission else "doesn't require"
        )
        changes.append(f"   • Copying {copy_status} writer permission")
    if properties:
        changes.append(f"   • Updated custom properties: {properties}")

    if changes:
        output_parts.append("")
        output_parts.append("Changes applied:")
        output_parts.extend(changes)
    else:
        output_parts.append("   (No changes were made)")

    output_parts.append("")
    output_parts.append(f"View file: {updated_file.get('webViewLink', '#')}")

    return "\n".join(output_parts)


@server.tool(
    title="Get Drive Shareable Link",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors("get_drive_shareable_link", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def get_drive_shareable_link(
    service,
    user_google_email: str,
    file_id: str,
) -> str:
    """
    Gets the shareable link for a Google Drive file or folder.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the file or folder to get the shareable link for. Required.

    Returns:
        str: The shareable links and current sharing status.
    """
    logger.info(
        f"[get_drive_shareable_link] Invoked. Email: '{user_google_email}', File ID: '{file_id}'"
    )

    resolved_file_id, _ = await resolve_drive_item(service, file_id)
    file_id = resolved_file_id

    file_metadata = await asyncio.to_thread(
        service.files()
        .get(
            fileId=file_id,
            fields="id, name, mimeType, webViewLink, webContentLink, shared, "
            "permissions(id, type, role, emailAddress, domain, expirationTime)",
            supportsAllDrives=True,
        )
        .execute
    )

    output_parts = [
        f"File: {file_metadata.get('name', 'Unknown')}",
        f"ID: {file_id}",
        f"Type: {file_metadata.get('mimeType', 'Unknown')}",
        f"Shared: {file_metadata.get('shared', False)}",
        "",
        "Links:",
        f"  View: {file_metadata.get('webViewLink', 'N/A')}",
    ]

    web_content_link = file_metadata.get("webContentLink")
    if web_content_link:
        output_parts.append(f"  Download: {web_content_link}")

    permissions = file_metadata.get("permissions", [])
    if permissions:
        output_parts.append("")
        output_parts.append("Current permissions:")
        for perm in permissions:
            output_parts.append(f"  - {format_permission_info(perm)}")

    return "\n".join(output_parts)


@server.tool(
    title="Manage Drive Access",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
@handle_http_errors("manage_drive_access", is_read_only=False, service_type="drive")
@require_google_service("drive", "drive_file")
async def manage_drive_access(
    service,
    user_google_email: str,
    file_id: str,
    action: str,
    share_with: Optional[str] = None,
    role: Optional[str] = None,
    share_type: str = "user",
    permission_id: Optional[str] = None,
    recipients: Optional[List[Dict[str, Any]]] = None,
    send_notification: bool = True,
    email_message: Optional[str] = None,
    expiration_time: Optional[str] = None,
    allow_file_discovery: Optional[bool] = None,
    new_owner_email: Optional[str] = None,
    move_to_new_owners_root: bool = False,
) -> str:
    """
    Consolidated tool for managing Google Drive file and folder access permissions.

    Supports granting, batch-granting, updating, revoking permissions, and
    transferring file ownership -- all through a single entry point.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the file or folder. Required.
        action (str): The access management action to perform. Required. One of:
            - "grant": Share with a single user, group, domain, or anyone.
            - "grant_batch": Share with multiple recipients in one call.
            - "update": Modify an existing permission (role or expiration).
            - "revoke": Remove an existing permission.
            - "transfer_owner": Transfer file ownership to another user.
        share_with (Optional[str]): Email address (user/group), domain name (domain),
            or omit for 'anyone'. Used by "grant".
        role (Optional[str]): Permission role -- 'reader', 'commenter', or 'writer'.
            Used by "grant" (defaults to 'reader') and "update".
        share_type (str): Type of sharing -- 'user', 'group', 'domain', or 'anyone'.
            Used by "grant". Defaults to 'user'.
        permission_id (Optional[str]): The permission ID to modify or remove.
            Required for "update" and "revoke" actions.
        recipients (Optional[List[Dict[str, Any]]]): List of recipient objects for
            "grant_batch". Each should have: email (str), role (str, optional),
            share_type (str, optional), expiration_time (str, optional). For domain
            shares use 'domain' field instead of 'email'.
        send_notification (bool): Whether to send notification emails. Defaults to True.
            Used by "grant" and "grant_batch".
        email_message (Optional[str]): Custom notification email message.
            Used by "grant" and "grant_batch".
        expiration_time (Optional[str]): Expiration in RFC 3339 format
            (e.g., "2025-01-15T00:00:00Z"). Used by "grant" and "update".
        allow_file_discovery (Optional[bool]): For 'domain'/'anyone' shares, whether
            the file appears in search. Used by "grant".
        new_owner_email (Optional[str]): Email of the new owner.
            Required for "transfer_owner".
        move_to_new_owners_root (bool): Move file to the new owner's My Drive root.
            Defaults to False. Used by "transfer_owner".

    Returns:
        str: Confirmation with details of the permission change applied.
    """
    valid_actions = ("grant", "grant_batch", "update", "revoke", "transfer_owner")
    if action not in valid_actions:
        raise ValueError(
            f"Invalid action '{action}'. Must be one of: {', '.join(valid_actions)}"
        )

    logger.info(
        f"[manage_drive_access] Invoked. Email: '{user_google_email}', "
        f"File ID: '{file_id}', Action: '{action}'"
    )

    # --- grant: share with a single recipient ---
    if action == "grant":
        effective_role = role or "reader"
        validate_share_role(effective_role)
        validate_share_type(share_type)

        if share_type in ("user", "group") and not share_with:
            raise ValueError(f"share_with is required for share_type '{share_type}'")
        if share_type == "domain" and not share_with:
            raise ValueError(
                "share_with (domain name) is required for share_type 'domain'"
            )

        resolved_file_id, file_metadata = await resolve_drive_item(
            service, file_id, extra_fields="name, webViewLink"
        )
        file_id = resolved_file_id

        permission_body: Dict[str, Any] = {
            "type": share_type,
            "role": effective_role,
        }
        if share_type in ("user", "group"):
            permission_body["emailAddress"] = share_with
        elif share_type == "domain":
            permission_body["domain"] = share_with

        if expiration_time:
            validate_expiration_time(expiration_time)
            permission_body["expirationTime"] = expiration_time

        if share_type in ("domain", "anyone") and allow_file_discovery is not None:
            permission_body["allowFileDiscovery"] = allow_file_discovery

        create_params: Dict[str, Any] = {
            "fileId": file_id,
            "body": permission_body,
            "supportsAllDrives": True,
            "fields": "id, type, role, emailAddress, domain, expirationTime",
        }
        if share_type in ("user", "group"):
            create_params["sendNotificationEmail"] = send_notification
            if email_message:
                create_params["emailMessage"] = email_message

        created_permission = await asyncio.to_thread(
            service.permissions().create(**create_params).execute
        )

        return "\n".join(
            [
                f"Successfully shared '{file_metadata.get('name', 'Unknown')}'",
                "",
                "Permission created:",
                f"  - {format_permission_info(created_permission)}",
                "",
                f"View link: {file_metadata.get('webViewLink', 'N/A')}",
            ]
        )

    # --- grant_batch: share with multiple recipients ---
    if action == "grant_batch":
        if not recipients:
            raise ValueError("recipients list is required for 'grant_batch' action")

        resolved_file_id, file_metadata = await resolve_drive_item(
            service, file_id, extra_fields="name, webViewLink"
        )
        file_id = resolved_file_id

        results: List[str] = []
        success_count = 0
        failure_count = 0

        for recipient in recipients:
            r_share_type = recipient.get("share_type", "user")

            if r_share_type == "domain":
                domain = recipient.get("domain")
                if not domain:
                    results.append("  - Skipped: missing domain for domain share")
                    failure_count += 1
                    continue
                identifier = domain
            else:
                r_email = recipient.get("email")
                if not r_email:
                    results.append("  - Skipped: missing email address")
                    failure_count += 1
                    continue
                identifier = r_email

            r_role = recipient.get("role", "reader")
            try:
                validate_share_role(r_role)
            except ValueError as e:
                results.append(f"  - {identifier}: Failed - {e}")
                failure_count += 1
                continue

            try:
                validate_share_type(r_share_type)
            except ValueError as e:
                results.append(f"  - {identifier}: Failed - {e}")
                failure_count += 1
                continue

            r_perm_body: Dict[str, Any] = {
                "type": r_share_type,
                "role": r_role,
            }
            if r_share_type == "domain":
                r_perm_body["domain"] = identifier
            else:
                r_perm_body["emailAddress"] = identifier

            if recipient.get("expiration_time"):
                try:
                    validate_expiration_time(recipient["expiration_time"])
                    r_perm_body["expirationTime"] = recipient["expiration_time"]
                except ValueError as e:
                    results.append(f"  - {identifier}: Failed - {e}")
                    failure_count += 1
                    continue

            r_create_params: Dict[str, Any] = {
                "fileId": file_id,
                "body": r_perm_body,
                "supportsAllDrives": True,
                "fields": "id, type, role, emailAddress, domain, expirationTime",
            }
            if r_share_type in ("user", "group"):
                r_create_params["sendNotificationEmail"] = send_notification
                if email_message:
                    r_create_params["emailMessage"] = email_message

            try:
                created_perm = await asyncio.to_thread(
                    service.permissions().create(**r_create_params).execute
                )
                results.append(f"  - {format_permission_info(created_perm)}")
                success_count += 1
            except HttpError as e:
                results.append(f"  - {identifier}: Failed - {str(e)}")
                failure_count += 1

        output_parts = [
            f"Batch share results for '{file_metadata.get('name', 'Unknown')}'",
            "",
            f"Summary: {success_count} succeeded, {failure_count} failed",
            "",
            "Results:",
        ]
        output_parts.extend(results)
        output_parts.extend(
            [
                "",
                f"View link: {file_metadata.get('webViewLink', 'N/A')}",
            ]
        )
        return "\n".join(output_parts)

    # --- update: modify an existing permission ---
    if action == "update":
        if not permission_id:
            raise ValueError("permission_id is required for 'update' action")
        if not role and not expiration_time:
            raise ValueError(
                "Must provide at least one of: role, expiration_time for 'update' action"
            )

        if role:
            validate_share_role(role)
        if expiration_time:
            validate_expiration_time(expiration_time)

        resolved_file_id, file_metadata = await resolve_drive_item(
            service, file_id, extra_fields="name"
        )
        file_id = resolved_file_id

        effective_role = role
        if not effective_role:
            current_permission = await asyncio.to_thread(
                service.permissions()
                .get(
                    fileId=file_id,
                    permissionId=permission_id,
                    supportsAllDrives=True,
                    fields="role",
                )
                .execute
            )
            effective_role = current_permission.get("role")

        update_body: Dict[str, Any] = {"role": effective_role}
        if expiration_time:
            update_body["expirationTime"] = expiration_time

        updated_permission = await asyncio.to_thread(
            service.permissions()
            .update(
                fileId=file_id,
                permissionId=permission_id,
                body=update_body,
                supportsAllDrives=True,
                fields="id, type, role, emailAddress, domain, expirationTime",
            )
            .execute
        )

        return "\n".join(
            [
                f"Successfully updated permission on '{file_metadata.get('name', 'Unknown')}'",
                "",
                "Updated permission:",
                f"  - {format_permission_info(updated_permission)}",
            ]
        )

    # --- revoke: remove an existing permission ---
    if action == "revoke":
        if not permission_id:
            raise ValueError("permission_id is required for 'revoke' action")

        resolved_file_id, file_metadata = await resolve_drive_item(
            service, file_id, extra_fields="name"
        )
        file_id = resolved_file_id

        await asyncio.to_thread(
            service.permissions()
            .delete(
                fileId=file_id,
                permissionId=permission_id,
                supportsAllDrives=True,
            )
            .execute
        )

        return "\n".join(
            [
                f"Successfully removed permission from '{file_metadata.get('name', 'Unknown')}'",
                "",
                f"Permission ID '{permission_id}' has been revoked.",
            ]
        )

    # --- transfer_owner: transfer file ownership ---
    # action == "transfer_owner"
    if not new_owner_email:
        raise ValueError("new_owner_email is required for 'transfer_owner' action")

    resolved_file_id, file_metadata = await resolve_drive_item(
        service, file_id, extra_fields="name, owners"
    )
    file_id = resolved_file_id

    current_owners = file_metadata.get("owners", [])
    current_owner_emails = [o.get("emailAddress", "") for o in current_owners]

    transfer_body: Dict[str, Any] = {
        "type": "user",
        "role": "owner",
        "emailAddress": new_owner_email,
    }

    await asyncio.to_thread(
        service.permissions()
        .create(
            fileId=file_id,
            body=transfer_body,
            transferOwnership=True,
            moveToNewOwnersRoot=move_to_new_owners_root,
            supportsAllDrives=True,
            fields="id, type, role, emailAddress",
        )
        .execute
    )

    output_parts = [
        f"Successfully transferred ownership of '{file_metadata.get('name', 'Unknown')}'",
        "",
        f"New owner: {new_owner_email}",
        f"Previous owner(s): {', '.join(current_owner_emails) or 'Unknown'}",
    ]
    if move_to_new_owners_root:
        output_parts.append(f"File moved to {new_owner_email}'s My Drive root.")
    output_parts.extend(["", "Note: Previous owner now has editor access."])

    return "\n".join(output_parts)


@server.tool(
    title="Copy Drive File",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
@handle_http_errors("copy_drive_file", is_read_only=False, service_type="drive")
@require_google_service("drive", "drive_file")
async def copy_drive_file(
    service,
    user_google_email: str,
    file_id: str,
    new_name: Optional[str] = None,
    parent_folder_id: str = "root",
) -> str:
    """
    Creates a copy of an existing Google Drive file.

    This tool copies the template document to a new location with an optional new name.
    The copy maintains all formatting and content from the original file.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the file to copy. Required.
        new_name (Optional[str]): New name for the copied file. If not provided, uses "Copy of [original name]".
        parent_folder_id (str): The ID of the folder where the copy should be created. Defaults to 'root' (My Drive).

    Returns:
        str: Confirmation message with details of the copied file and its link.
    """
    logger.info(
        f"[copy_drive_file] Invoked. Email: '{user_google_email}', File ID: '{file_id}', New name: '{new_name}', Parent folder: '{parent_folder_id}'"
    )

    resolved_file_id, file_metadata = await resolve_drive_item(
        service, file_id, extra_fields="name, webViewLink, mimeType"
    )
    file_id = resolved_file_id
    original_name = file_metadata.get("name", "Unknown File")

    resolved_folder_id = await resolve_folder_id(service, parent_folder_id)

    copy_body = {}
    if new_name:
        copy_body["name"] = new_name
    else:
        copy_body["name"] = f"Copy of {original_name}"

    if resolved_folder_id != "root":
        copy_body["parents"] = [resolved_folder_id]

    copied_file = await asyncio.to_thread(
        service.files()
        .copy(
            fileId=file_id,
            body=copy_body,
            supportsAllDrives=True,
            fields="id, name, webViewLink, mimeType, parents",
        )
        .execute
    )

    output_parts = [
        f"Successfully copied '{original_name}'",
        "",
        f"Original file ID: {file_id}",
        f"New file ID: {copied_file.get('id', 'N/A')}",
        f"New file name: {copied_file.get('name', 'Unknown')}",
        f"File type: {copied_file.get('mimeType', 'Unknown')}",
        f"Location: {parent_folder_id}",
        "",
        f"View copied file: {copied_file.get('webViewLink', 'N/A')}",
    ]

    return "\n".join(output_parts)


@server.tool(
    title="Set Drive File Permissions",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
@handle_http_errors(
    "set_drive_file_permissions", is_read_only=False, service_type="drive"
)
@require_google_service("drive", "drive_file")
async def set_drive_file_permissions(
    service,
    user_google_email: str,
    file_id: str,
    link_sharing: Optional[str] = None,
    writers_can_share: Optional[bool] = None,
    copy_requires_writer_permission: Optional[bool] = None,
) -> str:
    """
    Sets file-level sharing settings and controls link sharing for a Google Drive file or folder.

    This is a high-level tool for the most common permission changes. Use this to toggle
    "anyone with the link" access or configure file-level sharing behavior. For managing
    individual user/group permissions, use share_drive_file or update_drive_permission instead.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the file or folder. Required.
        link_sharing (Optional[str]): Control "anyone with the link" access for the file.
            - "off": Disable "anyone with the link" access for this file.
            - "reader": Anyone with the link can view.
            - "commenter": Anyone with the link can comment.
            - "writer": Anyone with the link can edit.
        writers_can_share (Optional[bool]): Whether editors can change permissions and share.
            If False, only the owner can share. Defaults to None (no change).
        copy_requires_writer_permission (Optional[bool]): Whether viewers and commenters
            are prevented from copying, printing, or downloading. Defaults to None (no change).

    Returns:
        str: Summary of all permission changes applied to the file.
    """
    logger.info(
        f"[set_drive_file_permissions] Invoked. Email: '{user_google_email}', "
        f"File ID: '{file_id}', Link sharing: '{link_sharing}', "
        f"Writers can share: {writers_can_share}, Copy restriction: {copy_requires_writer_permission}"
    )

    if (
        link_sharing is None
        and writers_can_share is None
        and copy_requires_writer_permission is None
    ):
        raise ValueError(
            "Must provide at least one of: link_sharing, writers_can_share, copy_requires_writer_permission"
        )

    valid_link_sharing = {"off", "reader", "commenter", "writer"}
    if link_sharing is not None and link_sharing not in valid_link_sharing:
        raise ValueError(
            f"Invalid link_sharing '{link_sharing}'. Must be one of: {', '.join(sorted(valid_link_sharing))}"
        )

    resolved_file_id, file_metadata = await resolve_drive_item(
        service, file_id, extra_fields="name, webViewLink"
    )
    file_id = resolved_file_id
    file_name = file_metadata.get("name", "Unknown")

    output_parts = [f"Permission settings updated for '{file_name}'", ""]
    changes_made = []

    # Handle file-level settings via files().update()
    file_update_body = {}
    if writers_can_share is not None:
        file_update_body["writersCanShare"] = writers_can_share
    if copy_requires_writer_permission is not None:
        file_update_body["copyRequiresWriterPermission"] = (
            copy_requires_writer_permission
        )

    if file_update_body:
        await asyncio.to_thread(
            service.files()
            .update(
                fileId=file_id,
                body=file_update_body,
                supportsAllDrives=True,
                fields="id",
            )
            .execute
        )
        if writers_can_share is not None:
            state = "allowed" if writers_can_share else "restricted to owner"
            changes_made.append(f"  - Editors sharing: {state}")
        if copy_requires_writer_permission is not None:
            state = "restricted" if copy_requires_writer_permission else "allowed"
            changes_made.append(f"  - Viewers copy/print/download: {state}")

    # Handle link sharing via permissions API
    if link_sharing is not None:
        current_permissions = await asyncio.to_thread(
            service.permissions()
            .list(
                fileId=file_id,
                supportsAllDrives=True,
                fields="permissions(id, type, role)",
            )
            .execute
        )
        anyone_perms = [
            p
            for p in current_permissions.get("permissions", [])
            if p.get("type") == "anyone"
        ]

        if link_sharing == "off":
            if anyone_perms:
                for perm in anyone_perms:
                    await asyncio.to_thread(
                        service.permissions()
                        .delete(
                            fileId=file_id,
                            permissionId=perm["id"],
                            supportsAllDrives=True,
                        )
                        .execute
                    )
                changes_made.append(
                    "  - Link sharing: disabled (restricted to specific people)"
                )
            else:
                changes_made.append("  - Link sharing: already off (no change)")
        else:
            if anyone_perms:
                await asyncio.to_thread(
                    service.permissions()
                    .update(
                        fileId=file_id,
                        permissionId=anyone_perms[0]["id"],
                        body={
                            "role": link_sharing,
                            "allowFileDiscovery": False,
                        },
                        supportsAllDrives=True,
                        fields="id, type, role",
                    )
                    .execute
                )
                changes_made.append(f"  - Link sharing: updated to '{link_sharing}'")
            else:
                await asyncio.to_thread(
                    service.permissions()
                    .create(
                        fileId=file_id,
                        body={
                            "type": "anyone",
                            "role": link_sharing,
                            "allowFileDiscovery": False,
                        },
                        supportsAllDrives=True,
                        fields="id, type, role",
                    )
                    .execute
                )
                changes_made.append(f"  - Link sharing: enabled as '{link_sharing}'")

    output_parts.append("Changes:")
    if changes_made:
        output_parts.extend(changes_made)
    else:
        output_parts.append("  - No changes (already configured)")
    output_parts.extend(["", f"View link: {file_metadata.get('webViewLink', 'N/A')}"])

    return "\n".join(output_parts)


@server.tool(
    title="Move Drive Files",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
@handle_http_errors("move_drive_files", service_type="drive")
@require_google_service("drive", "drive_file")
async def move_drive_files(
    service,
    user_google_email: str,
    moves: List[Dict[str, str]],
    keep_existing_parents: bool = False,
) -> str:
    """Move one or more files into a different Drive folder.

    Each move entry must include ``file_id`` and ``destination_folder_id``. An
    optional ``remove_parent_ids`` list can specify exactly which parents to
    detach. When ``keep_existing_parents`` is True, the file is simply added to
    the new folder without removing existing parents.
    """

    if not moves:
        raise ValueError("'moves' must contain at least one move request.")

    logger.info(
        "[move_drive_files] Invoked for %s with %d move requests",
        user_google_email,
        len(moves),
    )

    successes: List[str] = []
    failures: List[str] = []

    for move in moves:
        file_id = move.get("file_id")
        destination_folder_id = move.get("destination_folder_id")

        if not file_id or not destination_folder_id:
            failures.append(
                f"Missing file_id or destination_folder_id in move payload: {move}"
            )
            continue

        try:
            file_metadata = await asyncio.to_thread(
                service.files()
                .get(
                    fileId=file_id,
                    fields="id, name, parents",
                    supportsAllDrives=True,
                )
                .execute
            )

            current_parents = file_metadata.get("parents", [])
            remove_parent_ids = move.get("remove_parent_ids")

            if keep_existing_parents:
                remove_parents_arg = None
            elif remove_parent_ids:
                remove_parents_arg = ",".join(remove_parent_ids)
            else:
                remove_parents_arg = (
                    ",".join(current_parents) if current_parents else None
                )

            await asyncio.to_thread(
                service.files()
                .update(
                    fileId=file_id,
                    addParents=destination_folder_id,
                    removeParents=remove_parents_arg,
                    supportsAllDrives=True,
                    fields="id, parents",
                )
                .execute
            )

            successes.append(
                f"Moved '{file_metadata.get('name', file_id)}' ({file_id}) -> {destination_folder_id}"
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "[move_drive_files] Failed to move file %s to %s",
                file_id,
                destination_folder_id,
            )
            failures.append(
                f"Failed to move file {file_id} -> {destination_folder_id}: {exc}"
            )

    response_lines = [
        f"Processed {len(moves)} move request(s).",
        f"Successful: {len(successes)}",
        f"Failed: {len(failures)}",
    ]

    if successes:
        response_lines.append("\nSuccesses:")
        response_lines.extend(f"- {msg}" for msg in successes)

    if failures:
        response_lines.append("\nFailures:")
        response_lines.extend(f"- {msg}" for msg in failures)

    return "\n".join(response_lines)


@server.tool(
    title="Update Drive File Content",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
@handle_http_errors("update_drive_file_content", service_type="drive")
@require_google_service("drive", "drive_file")
async def update_drive_file_content(
    service,
    user_google_email: str,
    file_id: str,
    content: str,
    mime_type: str = "application/json",
    new_name: Optional[str] = None,
) -> str:
    """Replace the contents of an existing Drive file.

    Args:
        user_google_email: Google Workspace account email.
        file_id: ID of the Drive file to update.
        content: New file content.
        mime_type: MIME type (defaults to application/json).
        new_name: Optional new name for the file.

    Returns:
        Confirmation message including file link.
    """

    file_metadata: dict[str, str] = {}
    if new_name:
        file_metadata["name"] = new_name

    media = MediaIoBaseUpload(
        io.BytesIO(content.encode("utf-8")), mimetype=mime_type, resumable=True
    )

    updated = await asyncio.to_thread(
        service.files()
        .update(
            fileId=file_id,
            body=file_metadata or None,
            media_body=media,
            fields="id, name, webViewLink",
            supportsAllDrives=True,
        )
        .execute
    )

    link = updated.get("webViewLink", "No link available")
    return (
        f"Successfully updated file '{updated.get('name', file_id)}' (ID: {updated.get('id', file_id)}) "
        f"for {user_google_email}. Link: {link}"
    )


@server.tool(
    title="Recursive Folder Scan",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors("recursive_folder_scan", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def recursive_folder_scan(
    service,
    user_google_email: str,
    folder_id: str,
    include_metadata: bool = True,
    include_stats: bool = True,
    include_tree: bool = True,
    include_all_files: bool = True,
    max_depth: Optional[int] = None,
    file_types: Optional[List[str]] = None,
    exclude_folders: Optional[List[str]] = None,
    output_format: str = "full",
    max_files: Optional[int] = None,
    page_size: Optional[int] = None,
    page_number: Optional[int] = None,
    output_file: Optional[str] = None,
):
    """
    Recursively scans an entire Google Drive folder structure and returns comprehensive file inventory
    with metadata, aggregated statistics, and hierarchical structure.

    This tool is designed for complete Drive inventory, storage analysis, and coverage reporting.
    It returns both a flat list (for database insertion) and a tree structure (for visualization).

    Args:
        user_google_email (str): The user's Google email address. Required.
        folder_id (str): Root folder ID to scan (required).
        include_metadata (bool): Include full file metadata (default: True).
        include_stats (bool): Include aggregated statistics (default: True).
        include_tree (bool): Include folder tree structure in output (default: True).
        include_all_files (bool): Include flat list of all files in output (default: True).
        max_depth (Optional[int]): Maximum folder depth to scan (default: unlimited).
        file_types (Optional[List[str]]): Filter by file extensions like ["pdf", "xlsx"] (default: all types).
        exclude_folders (Optional[List[str]]): Folder names to skip like ["FOTKY", "images"] (default: none).
        output_format (str): Output format - "full", "summary", or "tree" (default: "full").
        max_files (Optional[int]): Maximum number of files to return (default: all files).
        page_size (Optional[int]): Number of files per page for pagination (default: None).
        page_number (Optional[int]): Page number to return (0-indexed, default: None).
        output_file (Optional[str]): Path to write results to file instead of returning (default: None).

    Returns:
        dict or str: If output_file is specified, returns confirmation message. Otherwise returns
                     comprehensive scan results with summary, stats, folder tree, and file list.

    Note:
        - Pagination: Use either max_files OR (page_size + page_number), not both.
        - If output_file is specified, results are written to that file as JSON.
        - Pagination only affects the 'all_files' list, not the folder tree or stats.
    """
    logger.info(f"[recursive_folder_scan] Starting scan of folder {folder_id}")

    scan_start_time = time.time()
    all_files = []
    stats_by_type = {}
    total_size_bytes = 0
    max_depth_reached = 0

    mime_to_ext_map = {
        "application/pdf": "pdf",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
        "application/vnd.google-apps.spreadsheet": "xlsx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
        "application/vnd.google-apps.document": "docx",
        "image/jpeg": "jpg",
        "image/png": "png",
        "application/vnd.google-apps.presentation": "pptx",
    }

    async def scan_folder_recursive(
        folder_id: str, folder_path: str = "", current_depth: int = 0
    ):
        """Recursively scan a folder and its subfolders."""
        nonlocal max_depth_reached, total_size_bytes

        if max_depth is not None and current_depth >= max_depth:
            return {
                "path": folder_path,
                "file_count": 0,
                "folder_count": 0,
                "files": [],
                "subfolders": [],
            }

        max_depth_reached = max(max_depth_reached, current_depth)

        query = f"'{folder_id}' in parents and trashed=false"
        page_token = None
        folder_files = []
        subfolders = []

        while True:
            list_params = {
                "q": query,
                "pageSize": 1000,
                "fields": "nextPageToken, files(id, name, mimeType, size, modifiedTime, webViewLink, parents)",
                "supportsAllDrives": True,
                "includeItemsFromAllDrives": True,
                "pageToken": page_token,
            }

            results = await asyncio.to_thread(
                service.files().list(**list_params).execute
            )

            items = results.get("files", [])

            for item in items:
                mime_type = item.get("mimeType", "")
                file_name = item.get("name", "")

                if mime_type == "application/vnd.google-apps.folder":
                    if exclude_folders and file_name in exclude_folders:
                        logger.info(
                            f"[recursive_folder_scan] Skipping excluded folder: {file_name}"
                        )
                        continue

                    subfolder_path = f"{folder_path}{file_name}/"
                    subfolder_data = await scan_folder_recursive(
                        item["id"], subfolder_path, current_depth + 1
                    )
                    subfolders.append(subfolder_data)
                else:
                    file_ext = mime_to_ext_map.get(
                        mime_type,
                        file_name.split(".")[-1] if "." in file_name else "unknown",
                    )

                    if file_types and file_ext.lower() not in [
                        ft.lower() for ft in file_types
                    ]:
                        continue

                    file_size = int(item.get("size", 0)) if item.get("size") else 0
                    total_size_bytes += file_size

                    if file_ext not in stats_by_type:
                        stats_by_type[file_ext] = {"count": 0, "total_size": 0}
                    stats_by_type[file_ext]["count"] += 1
                    stats_by_type[file_ext]["total_size"] += file_size

                    file_entry = {
                        "file_id": item["id"],
                        "file_name": file_name,
                        "folder_path": folder_path,
                        "file_type": file_ext,
                        "file_size": file_size,
                        "modified_date": item.get("modifiedTime", ""),
                        "web_link": item.get("webViewLink", ""),
                        "mime_type": mime_type,
                    }

                    folder_files.append(file_entry)
                    all_files.append(file_entry)

            page_token = results.get("nextPageToken")
            if not page_token:
                break

        return {
            "path": folder_path,
            "folder_id": folder_id,
            "file_count": len(folder_files),
            "folder_count": len(subfolders),
            "total_size": sum(f["file_size"] for f in folder_files),
            "files": folder_files if include_metadata else [],
            "subfolders": subfolders,
        }

    root_folder_metadata = await asyncio.to_thread(
        service.files()
        .get(fileId=folder_id, fields="name", supportsAllDrives=True)
        .execute
    )
    root_folder_name = root_folder_metadata.get("name", folder_id)

    folder_tree = await scan_folder_recursive(folder_id, root_folder_name + "/")

    scan_time = time.time() - scan_start_time

    total_files_scanned = len(all_files)
    paginated_files = all_files
    pagination_info = None

    if max_files is not None and page_size is not None:
        logger.warning(
            "[recursive_folder_scan] Both max_files and page_size specified. Using max_files only."
        )

    if max_files is not None:
        paginated_files = all_files[:max_files]
        pagination_info = {
            "total_files": total_files_scanned,
            "returned_files": len(paginated_files),
            "max_files": max_files,
        }
        logger.info(
            f"[recursive_folder_scan] Pagination: returning {len(paginated_files)} of {total_files_scanned} files (max_files={max_files})"
        )
    elif page_size is not None and page_number is not None:
        start_idx = page_number * page_size
        end_idx = start_idx + page_size
        paginated_files = all_files[start_idx:end_idx]
        total_pages = (total_files_scanned + page_size - 1) // page_size

        pagination_info = {
            "total_files": total_files_scanned,
            "returned_files": len(paginated_files),
            "page_size": page_size,
            "page_number": page_number,
            "total_pages": total_pages,
            "has_next_page": page_number < total_pages - 1,
            "has_previous_page": page_number > 0,
        }
        logger.info(
            f"[recursive_folder_scan] Pagination: returning page {page_number} ({len(paginated_files)} files) of {total_pages} total pages"
        )

    summary = {
        "total_files": total_files_scanned,
        "total_folders": sum(1 for _ in _count_folders(folder_tree)),
        "total_size_bytes": total_size_bytes,
        "scan_depth": max_depth_reached + 1,
        "scan_time_seconds": round(scan_time, 2),
    }

    if pagination_info:
        summary["pagination"] = pagination_info

    if output_format == "summary":
        result = {"summary": summary, "stats_by_type": stats_by_type}
    elif output_format == "tree":
        result = {"summary": summary, "folder_tree": _format_tree_text(folder_tree)}
    else:  # full
        result = {
            "summary": summary,
            "stats_by_type": stats_by_type if include_stats else {},
            "folder_tree": [folder_tree] if (include_metadata and include_tree) else [],
            "all_files": paginated_files
            if (include_metadata and include_all_files)
            else [],
        }

    if output_file:
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

            file_size_kb = output_path.stat().st_size / 1024
            confirmation = {
                "status": "success",
                "message": f"Scan results written to file: {output_file}",
                "output_file": str(output_path.absolute()),
                "file_size_kb": round(file_size_kb, 2),
                "summary": summary,
            }
            logger.info(
                f"[recursive_folder_scan] Results written to {output_file} ({file_size_kb:.2f} KB)"
            )
            return confirmation

        except Exception as e:
            logger.error(
                f"[recursive_folder_scan] Error writing to file {output_file}: {e}"
            )
            return {
                "status": "error",
                "message": f"Failed to write to file: {str(e)}",
                "output_file": output_file,
            }

    return result


def _count_folders(tree_node):
    """Generator yielding every folder node in a recursive_folder_scan tree."""
    yield tree_node
    for subfolder in tree_node.get("subfolders", []):
        yield from _count_folders(subfolder)


def _format_tree_text(tree_node, indent=""):
    """Format folder tree as text for visualization."""
    lines = []
    path = tree_node["path"]
    file_count = tree_node["file_count"]
    folder_count = tree_node["folder_count"]

    lines.append(f"{indent}{path} ({file_count} files, {folder_count} folders)")

    for i, subfolder in enumerate(tree_node.get("subfolders", [])):
        is_last = i == len(tree_node["subfolders"]) - 1
        sub_indent = indent + ("    " if is_last else "│   ")
        lines.extend(_format_tree_text(subfolder, sub_indent))

    return "\n".join(lines)


@server.tool(
    title="Get Folder Statistics",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors("get_folder_statistics", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def get_folder_statistics(
    service,
    user_google_email: str,
    folder_id: str,
    recursive: bool = True,
    group_by: str = "type",
) -> dict:
    """
    Quick statistical overview of a folder without returning all file details.

    This tool provides file counts, sizes, and breakdowns by type or folder without
    loading full file metadata, making it ideal for quick metrics.

    Args:
        user_google_email (str): The user's Google email address. Required.
        folder_id (str): The ID of the folder to analyze.
        recursive (bool): Include subfolders (default: True).
        group_by (str): Group statistics by "type", "category", or "folder" (default: "type").

    Returns:
        dict: Statistical summary including file counts, sizes, and breakdowns.
    """
    logger.info(f"[get_folder_statistics] Getting statistics for folder {folder_id}")

    total_files = 0
    total_folders = 0
    total_size = 0
    breakdown: Dict[str, int] = {}
    largest_files: List[Dict[str, Any]] = []

    mime_to_ext_map = {
        "application/pdf": "pdf",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
        "application/vnd.google-apps.spreadsheet": "xlsx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
        "application/vnd.google-apps.document": "docx",
        "image/jpeg": "jpg",
        "image/png": "png",
    }

    async def scan_folder(folder_id: str):
        """Scan a single folder for statistics."""
        nonlocal total_files, total_folders, total_size

        query = f"'{folder_id}' in parents and trashed=false"
        page_token = None

        while True:
            list_params = {
                "q": query,
                "pageSize": 1000,
                "fields": "nextPageToken, files(id, name, mimeType, size)",
                "supportsAllDrives": True,
                "includeItemsFromAllDrives": True,
                "pageToken": page_token,
            }

            results = await asyncio.to_thread(
                service.files().list(**list_params).execute
            )

            items = results.get("files", [])

            for item in items:
                mime_type = item.get("mimeType", "")

                if mime_type == "application/vnd.google-apps.folder":
                    total_folders += 1
                    if recursive:
                        await scan_folder(item["id"])
                else:
                    total_files += 1
                    file_size = int(item.get("size", 0)) if item.get("size") else 0
                    total_size += file_size

                    if group_by == "type":
                        file_ext = mime_to_ext_map.get(mime_type, "other")
                        breakdown[file_ext] = breakdown.get(file_ext, 0) + 1

                    if file_size > 0:
                        largest_files.append(
                            {
                                "name": item.get("name", "Unknown"),
                                "size_mb": round(file_size / (1024 * 1024), 2),
                            }
                        )

            page_token = results.get("nextPageToken")
            if not page_token:
                break

    folder_metadata = await asyncio.to_thread(
        service.files()
        .get(fileId=folder_id, fields="name", supportsAllDrives=True)
        .execute
    )
    folder_name = folder_metadata.get("name", folder_id)

    await scan_folder(folder_id)

    largest_files.sort(key=lambda x: x["size_mb"], reverse=True)
    largest_files = largest_files[:10]

    return {
        "folder_name": folder_name,
        "total_files": total_files,
        "total_folders": total_folders,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "breakdown": breakdown,
        "largest_files": largest_files,
    }


@server.tool(
    title="Get Recent Drive Activity",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors(
    "get_recent_drive_activity", is_read_only=True, service_type="driveactivity"
)
@require_google_service("driveactivity", "drive_activity_read")
async def get_recent_drive_activity(
    service,
    user_google_email: str,
    folder_id: Optional[str] = None,
    days_back: int = 7,
    activity_types: Optional[List[str]] = None,
    include_subfolders: bool = True,
) -> dict:
    """
    Gets recent file activity (uploads, edits, deletions, moves, renames) in a folder to track
    all changes since last sync using the Google Drive Activity API.

    This is the primary change tracking mechanism for Drive synchronization. It provides detailed
    activity information including moves and renames with full context.

    Args:
        user_google_email (str): The user's Google email address. Required.
        folder_id (Optional[str]): Specific folder ID to filter activities (default: all files).
        days_back (int): How many days of history to retrieve (default: 7).
        activity_types (Optional[List[str]]): Filter by activity types: ["create", "edit", "delete", "move", "rename"] (default: all).
        include_subfolders (bool): Include nested folders (default: True).

    Returns:
        dict: Activity history with detailed actions, timestamps, and summary statistics.
    """
    logger.info(
        f"[get_recent_drive_activity] Getting activity for last {days_back} days"
    )

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days_back)

    request_body: Dict[str, Any] = {
        "pageSize": 100,
        "filter": f'time >= "{start_time.strftime("%Y-%m-%dT%H:%M:%S")}Z"',
    }

    if folder_id:
        request_body["ancestorName"] = f"items/{folder_id}"

    activities: List[Dict[str, Any]] = []
    page_token = None

    while True:
        if page_token:
            request_body["pageToken"] = page_token

        response = await asyncio.to_thread(
            service.activity().query(body=request_body).execute
        )

        for activity in response.get("activities", []):
            timestamp = activity.get("timestamp", "")
            primary_action_detail = activity.get("primaryActionDetail", {})
            targets = activity.get("targets", [])
            actors = activity.get("actors", [])

            actor_email = "unknown"
            if actors:
                actor = actors[0]
                if "user" in actor:
                    actor_email = (
                        actor["user"].get("knownUser", {}).get("personName", "unknown")
                    )

            for target in targets:
                if "driveItem" not in target:
                    continue

                drive_item = target["driveItem"]
                file_id = drive_item.get("name", "").replace("items/", "")
                file_name = drive_item.get("title", "Unknown")

                activity_type = None
                old_path = None
                new_path = None
                old_name = None
                new_name = None

                if "create" in primary_action_detail:
                    activity_type = "create"
                elif "edit" in primary_action_detail:
                    activity_type = "edit"
                elif "delete" in primary_action_detail:
                    activity_type = "delete"
                elif "move" in primary_action_detail:
                    activity_type = "move"
                    move_detail = primary_action_detail["move"]
                    old_path = (
                        move_detail.get("addedParents", [{}])[0]
                        .get("driveItem", {})
                        .get("title", "")
                    )
                    new_path = (
                        move_detail.get("removedParents", [{}])[0]
                        .get("driveItem", {})
                        .get("title", "")
                    )
                elif "rename" in primary_action_detail:
                    activity_type = "rename"
                    rename_detail = primary_action_detail["rename"]
                    old_name = rename_detail.get("oldTitle", "")
                    new_name = rename_detail.get("newTitle", "")

                if activity_types and activity_type not in activity_types:
                    continue

                activity_entry: Dict[str, Any] = {
                    "file_id": file_id,
                    "file_name": file_name,
                    "activity_type": activity_type,
                    "user": actor_email,
                    "timestamp": timestamp,
                }

                if old_path:
                    activity_entry["old_path"] = old_path
                if new_path:
                    activity_entry["new_path"] = new_path
                if old_name:
                    activity_entry["old_name"] = old_name
                if new_name:
                    activity_entry["new_name"] = new_name

                activities.append(activity_entry)

        page_token = response.get("nextPageToken")
        if not page_token:
            break

    summary = {
        "creates": sum(1 for a in activities if a["activity_type"] == "create"),
        "edits": sum(1 for a in activities if a["activity_type"] == "edit"),
        "deletes": sum(1 for a in activities if a["activity_type"] == "delete"),
        "moves": sum(1 for a in activities if a["activity_type"] == "move"),
        "renames": sum(1 for a in activities if a["activity_type"] == "rename"),
    }

    return {
        "period": f"Last {days_back} days",
        "activities": activities,
        "summary": summary,
    }


@server.tool(
    title="Get Drive Folder Tree",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors("get_drive_folder_tree", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def get_drive_folder_tree(
    service,
    user_google_email: str,
    folder_id: str,
    max_depth: Optional[int] = None,
    show_file_counts: bool = True,
    show_sizes: bool = False,
) -> str:
    """
    Gets visual tree structure of folders (no file details) for navigation and understanding hierarchy.

    This tool provides a quick visualization of the Drive folder structure without loading
    all file details, making it ideal for exploring large folder hierarchies.

    Args:
        user_google_email (str): The user's Google email address. Required.
        folder_id (str): Root folder ID to visualize.
        max_depth (Optional[int]): Limit depth of tree (default: unlimited).
        show_file_counts (bool): Show file count per folder (default: True).
        show_sizes (bool): Show total size per folder (default: False).

    Returns:
        str: ASCII tree visualization of folder structure.
    """
    logger.info(f"[get_drive_folder_tree] Building tree for folder {folder_id}")

    async def build_tree(folder_id: str, folder_name: str = "", current_depth: int = 0):
        """Recursively build folder tree."""
        if max_depth is not None and current_depth >= max_depth:
            return None

        query = f"'{folder_id}' in parents and trashed=false"

        list_params = {
            "q": query,
            "pageSize": 1000,
            "fields": "files(id, name, mimeType, size)",
            "supportsAllDrives": True,
            "includeItemsFromAllDrives": True,
        }

        results = await asyncio.to_thread(service.files().list(**list_params).execute)

        items = results.get("files", [])
        file_count = sum(
            1
            for item in items
            if item.get("mimeType") != "application/vnd.google-apps.folder"
        )
        folder_count = sum(
            1
            for item in items
            if item.get("mimeType") == "application/vnd.google-apps.folder"
        )
        total_size = sum(int(item.get("size", 0)) for item in items if item.get("size"))

        children = []
        for item in items:
            if item.get("mimeType") == "application/vnd.google-apps.folder":
                child_tree = await build_tree(
                    item["id"], item["name"], current_depth + 1
                )
                if child_tree:
                    children.append(child_tree)

        return {
            "name": folder_name or folder_id,
            "file_count": file_count,
            "folder_count": folder_count,
            "total_size": total_size,
            "children": children,
        }

    folder_metadata = await asyncio.to_thread(
        service.files()
        .get(fileId=folder_id, fields="name", supportsAllDrives=True)
        .execute
    )
    folder_name = folder_metadata.get("name", folder_id)

    tree = await build_tree(folder_id, folder_name)

    def format_tree(node, indent="", is_last=True):
        """Format tree node as ASCII."""
        prefix = "└── " if is_last else "├── "
        line = f"{indent}{prefix}{node['name']}/"

        if show_file_counts:
            line += f" ({node['file_count']} files"
            if node["folder_count"] > 0:
                line += f", {node['folder_count']} folders"
            line += ")"

        if show_sizes and node["total_size"] > 0:
            size_mb = round(node["total_size"] / (1024 * 1024), 2)
            line += f" [{size_mb} MB]"

        lines = [line]

        children = node.get("children", [])
        for i, child in enumerate(children):
            is_last_child = i == len(children) - 1
            child_indent = indent + ("    " if is_last else "│   ")
            lines.extend(format_tree(child, child_indent, is_last_child))

        return lines

    tree_lines = format_tree(tree)
    return "\n".join(tree_lines)


@server.tool(
    title="Batch Get File Metadata",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
@handle_http_errors("batch_get_file_metadata", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def batch_get_file_metadata(
    service,
    user_google_email: str,
    file_ids: List[str],
    fields: Optional[List[str]] = None,
) -> dict:
    """
    Gets detailed metadata for multiple files by their IDs in a single batch operation.

    This tool efficiently fetches metadata for known file IDs without iterating through folders,
    making it ideal for targeted queries when you already know which files you need.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_ids (List[str]): List of file IDs to fetch metadata for.
        fields (Optional[List[str]]): Specific fields to return (default: all common fields).

    Returns:
        dict: Dictionary containing file metadata and list of file IDs that were not found.
    """
    logger.info(
        f"[batch_get_file_metadata] Fetching metadata for {len(file_ids)} files"
    )

    if not fields:
        fields = [
            "id",
            "name",
            "mimeType",
            "size",
            "modifiedTime",
            "createdTime",
            "webViewLink",
            "parents",
            "owners",
            "modifiedByMe",
        ]

    fields_str = ", ".join(fields)

    files: List[Dict[str, Any]] = []
    not_found: List[str] = []

    for file_id in file_ids:
        try:
            file_metadata = await asyncio.to_thread(
                service.files()
                .get(fileId=file_id, fields=fields_str, supportsAllDrives=True)
                .execute
            )
            files.append(file_metadata)
        except Exception as e:
            logger.warning(f"[batch_get_file_metadata] File {file_id} not found: {e}")
            not_found.append(file_id)

    return {
        "files": files,
        "not_found": not_found,
    }
