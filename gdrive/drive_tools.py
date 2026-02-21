"""
Google Drive MCP Tools

This module provides MCP tools for interacting with Google Drive API.
"""

import asyncio
import logging
import io
import httpx
import base64
import ipaddress
import socket
import json
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import AsyncIterator, Optional, List, Dict, Any
from tempfile import NamedTemporaryFile
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import url2pathname
from pathlib import Path

from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import fitz  # PyMuPDF
from google.cloud import vision
from google.oauth2.credentials import Credentials as GoogleCredentials

from auth.service_decorator import require_google_service
from auth.google_auth import get_credentials, start_auth_flow
from auth.oauth_config import get_oauth_config, is_stateless_mode
from auth.scopes import CLOUD_VISION_SCOPE
from core.config import get_transport_mode, get_oauth_redirect_uri
from core.context import get_fastmcp_session_id
from core.attachment_storage import get_attachment_storage, get_attachment_url
from core.utils import extract_office_xml_text, handle_http_errors, validate_file_path
from core.server import server
from gdrive.drive_helpers import (
    DRIVE_QUERY_PATTERNS,
    FOLDER_MIME_TYPE,
    build_drive_list_params,
    check_public_link_permission,
    format_permission_info,
    get_drive_image_url,
    resolve_drive_item,
    resolve_folder_id,
    validate_expiration_time,
    validate_share_role,
    validate_share_type,
)

logger = logging.getLogger(__name__)

DOWNLOAD_CHUNK_SIZE_BYTES = 256 * 1024  # 256 KB
UPLOAD_CHUNK_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB (Google recommended minimum)
MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB safety limit for URL downloads


@server.tool()
@handle_http_errors("search_drive_files", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def search_drive_files(
    service,
    user_google_email: str,
    query: str,
    page_size: int = 10,
    drive_id: Optional[str] = None,
    include_items_from_all_drives: bool = True,
    corpora: Optional[str] = None,
) -> str:
    """
    Searches for files and folders within a user's Google Drive, including shared drives.

    Args:
        user_google_email (str): The user's Google email address. Required.
        query (str): The search query string. Supports Google Drive search operators.
        page_size (int): The maximum number of files to return. Defaults to 10.
        drive_id (Optional[str]): ID of the shared drive to search. If None, behavior depends on `corpora` and `include_items_from_all_drives`.
        include_items_from_all_drives (bool): Whether shared drive items should be included in results. Defaults to True. This is effective when not specifying a `drive_id`.
        corpora (Optional[str]): Bodies of items to query (e.g., 'user', 'domain', 'drive', 'allDrives').
                                 If 'drive_id' is specified and 'corpora' is None, it defaults to 'drive'.
                                 Otherwise, Drive API default behavior applies. Prefer 'user' or 'drive' over 'allDrives' for efficiency.

    Returns:
        str: A formatted list of found files/folders with their details (ID, name, type, size, modified time, link).
    """
    logger.info(
        f"[search_drive_files] Invoked. Email: '{user_google_email}', Query: '{query}'"
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

    list_params = build_drive_list_params(
        query=final_query,
        page_size=page_size,
        drive_id=drive_id,
        include_items_from_all_drives=include_items_from_all_drives,
        corpora=corpora,
    )

    results = await asyncio.to_thread(service.files().list(**list_params).execute)
    files = results.get("files", [])
    if not files:
        return f"No files found for '{query}'."

    formatted_files_text_parts = [
        f"Found {len(files)} files for {user_google_email} matching '{query}':"
    ]
    for item in files:
        size_str = f", Size: {item.get('size', 'N/A')}" if "size" in item else ""
        formatted_files_text_parts.append(
            f'- Name: "{item["name"]}" (ID: {item["id"]}, Type: {item["mimeType"]}{size_str}, Modified: {item.get("modifiedTime", "N/A")}) Link: {item.get("webViewLink", "#")}'
        )
    text_output = "\n".join(formatted_files_text_parts)
    return text_output


@server.tool()
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
        office_text = extract_office_xml_text(file_content_bytes, mime_type)
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


@server.tool()
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


@server.tool()
@handle_http_errors("list_drive_items", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def list_drive_items(
    service,
    user_google_email: str,
    folder_id: str = "root",
    page_size: int = 100,
    drive_id: Optional[str] = None,
    include_items_from_all_drives: bool = True,
    corpora: Optional[str] = None,
) -> str:
    """
    Lists files and folders, supporting shared drives.
    If `drive_id` is specified, lists items within that shared drive. `folder_id` is then relative to that drive (or use drive_id as folder_id for root).
    If `drive_id` is not specified, lists items from user's "My Drive" and accessible shared drives (if `include_items_from_all_drives` is True).

    Args:
        user_google_email (str): The user's Google email address. Required.
        folder_id (str): The ID of the Google Drive folder. Defaults to 'root'. For a shared drive, this can be the shared drive's ID to list its root, or a folder ID within that shared drive.
        page_size (int): The maximum number of items to return. Defaults to 100.
        drive_id (Optional[str]): ID of the shared drive. If provided, the listing is scoped to this drive.
        include_items_from_all_drives (bool): Whether items from all accessible shared drives should be included if `drive_id` is not set. Defaults to True.
        corpora (Optional[str]): Corpus to query ('user', 'drive', 'allDrives'). If `drive_id` is set and `corpora` is None, 'drive' is used. If None and no `drive_id`, API defaults apply.

    Returns:
        str: A formatted list of files/folders in the specified folder.
    """
    logger.info(
        f"[list_drive_items] Invoked. Email: '{user_google_email}', Folder ID: '{folder_id}'"
    )

    resolved_folder_id = await resolve_folder_id(service, folder_id)
    final_query = f"'{resolved_folder_id}' in parents and trashed=false"

    list_params = build_drive_list_params(
        query=final_query,
        page_size=page_size,
        drive_id=drive_id,
        include_items_from_all_drives=include_items_from_all_drives,
        corpora=corpora,
    )

    results = await asyncio.to_thread(service.files().list(**list_params).execute)
    files = results.get("files", [])
    if not files:
        return f"No items found in folder '{folder_id}'."

    formatted_items_text_parts = [
        f"Found {len(files)} items in folder '{folder_id}' for {user_google_email}:"
    ]
    for item in files:
        size_str = f", Size: {item.get('size', 'N/A')}" if "size" in item else ""
        formatted_items_text_parts.append(
            f'- Name: "{item["name"]}" (ID: {item["id"]}, Type: {item["mimeType"]}{size_str}, Modified: {item.get("modifiedTime", "N/A")}) Link: {item.get("webViewLink", "#")}'
        )
    text_output = "\n".join(formatted_items_text_parts)
    return text_output


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


@server.tool()
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


@server.tool()
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

    if not content and not fileUrl and mime_type != FOLDER_MIME_TYPE:
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
                .execute
            )
        # Handle HTTP/HTTPS URLs
        elif parsed_url.scheme in ("http", "https"):
            # when running in stateless mode, deployment may not have access to local file system
            if is_stateless_mode():
                resp = await _ssrf_safe_fetch(fileUrl)
                if resp.status_code != 200:
                    raise Exception(
                        f"Failed to fetch file from URL: {fileUrl} (status {resp.status_code})"
                    )
                file_data = resp.content
                # Try to get MIME type from Content-Type header
                content_type = resp.headers.get("Content-Type")
                if content_type and content_type != "application/octet-stream":
                    mime_type = content_type
                    file_metadata["mimeType"] = content_type
                    logger.info(
                        f"[create_drive_file] Using MIME type from Content-Type header: {content_type}"
                    )

                media = MediaIoBaseUpload(
                    io.BytesIO(file_data),
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
                    .execute
                )
            else:
                # Stream download to temp file with SSRF protection, then upload
                with NamedTemporaryFile() as temp_file:
                    total_bytes = 0
                    content_type = None

                    async with _ssrf_safe_stream(fileUrl) as resp:
                        if resp.status_code != 200:
                            raise Exception(
                                f"Failed to fetch file from URL: {fileUrl} "
                                f"(status {resp.status_code})"
                            )

                        content_type = resp.headers.get("Content-Type")

                        async for chunk in resp.aiter_bytes(
                            chunk_size=DOWNLOAD_CHUNK_SIZE_BYTES
                        ):
                            total_bytes += len(chunk)
                            if total_bytes > MAX_DOWNLOAD_BYTES:
                                raise Exception(
                                    f"Download exceeded {MAX_DOWNLOAD_BYTES} byte limit"
                                )
                            await asyncio.to_thread(temp_file.write, chunk)

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
                        .execute
                    )
        else:
            if not parsed_url.scheme:
                raise Exception(
                    "fileUrl is missing a URL scheme. Use file://, http://, or https://."
                )
            raise Exception(
                f"Unsupported URL scheme '{parsed_url.scheme}'. Only file://, http://, and https:// are supported."
            )
    elif content:
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
            .execute
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


def _resolve_and_validate_host(hostname: str) -> list[str]:
    """
    Resolve a hostname to IP addresses and validate none are private/internal.

    Uses getaddrinfo to handle both IPv4 and IPv6. Fails closed on DNS errors.

    Returns:
        list[str]: Validated resolved IP address strings.

    Raises:
        ValueError: If hostname resolves to private/internal IPs or DNS fails.
    """
    if not hostname:
        raise ValueError("Invalid URL: no hostname")

    # Block localhost variants
    if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise ValueError("URLs pointing to localhost are not allowed")

    # Resolve hostname using getaddrinfo (handles both IPv4 and IPv6)
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(
            f"Cannot resolve hostname '{hostname}': {e}. "
            "Refusing request (fail-closed)."
        )

    if not addr_infos:
        raise ValueError(f"No addresses found for hostname: {hostname}")

    resolved_ips: list[str] = []
    seen_ips: set[str] = set()
    for _family, _type, _proto, _canonname, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        ip = ipaddress.ip_address(ip_str)
        if not ip.is_global:
            raise ValueError(
                f"URLs pointing to private/internal networks are not allowed: "
                f"{hostname} resolves to {ip_str}"
            )
        if ip_str not in seen_ips:
            seen_ips.add(ip_str)
            resolved_ips.append(ip_str)

    return resolved_ips


def _validate_url_not_internal(url: str) -> list[str]:
    """
    Validate that a URL doesn't point to internal/private networks (SSRF protection).

    Returns:
        list[str]: Validated resolved IP addresses for the hostname.

    Raises:
        ValueError: If URL points to localhost or private IP ranges.
    """
    parsed = urlparse(url)
    return _resolve_and_validate_host(parsed.hostname)


def _format_host_header(hostname: str, scheme: str, port: Optional[int]) -> str:
    """Format the Host header value for IPv4/IPv6 hostnames."""
    host_value = hostname
    if ":" in host_value and not host_value.startswith("["):
        host_value = f"[{host_value}]"

    is_default_port = (scheme == "http" and (port is None or port == 80)) or (
        scheme == "https" and (port is None or port == 443)
    )
    if not is_default_port and port is not None:
        host_value = f"{host_value}:{port}"
    return host_value


def _build_pinned_url(parsed_url, ip_address_str: str) -> str:
    """Build a URL that targets a resolved IP while preserving path/query."""
    pinned_host = ip_address_str
    if ":" in pinned_host and not pinned_host.startswith("["):
        pinned_host = f"[{pinned_host}]"

    userinfo = ""
    if parsed_url.username is not None:
        userinfo = parsed_url.username
        if parsed_url.password is not None:
            userinfo += f":{parsed_url.password}"
        userinfo += "@"

    port_part = f":{parsed_url.port}" if parsed_url.port is not None else ""
    netloc = f"{userinfo}{pinned_host}{port_part}"

    path = parsed_url.path or "/"
    return urlunparse(
        (
            parsed_url.scheme,
            netloc,
            path,
            parsed_url.params,
            parsed_url.query,
            parsed_url.fragment,
        )
    )


async def _fetch_url_with_pinned_ip(url: str) -> httpx.Response:
    """
    Fetch URL content by connecting to a validated, pre-resolved IP address.

    This prevents DNS rebinding between validation and the outbound connection.
    """
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
        raise ValueError(f"Only http:// and https:// are supported: {url}")
    if not parsed_url.hostname:
        raise ValueError(f"Invalid URL: missing hostname ({url})")

    resolved_ips = _validate_url_not_internal(url)
    host_header = _format_host_header(
        parsed_url.hostname, parsed_url.scheme, parsed_url.port
    )

    last_error: Optional[Exception] = None
    for resolved_ip in resolved_ips:
        pinned_url = _build_pinned_url(parsed_url, resolved_ip)
        try:
            async with httpx.AsyncClient(
                follow_redirects=False, trust_env=False
            ) as client:
                request = client.build_request(
                    "GET",
                    pinned_url,
                    headers={"Host": host_header},
                    extensions={"sni_hostname": parsed_url.hostname},
                )
                return await client.send(request)
        except httpx.HTTPError as exc:
            last_error = exc
            logger.warning(
                f"[ssrf_safe_fetch] Failed request via resolved IP {resolved_ip} for host "
                f"{parsed_url.hostname}: {exc}"
            )

    raise Exception(
        f"Failed to fetch URL after trying {len(resolved_ips)} validated IP(s): {url}"
    ) from last_error


async def _ssrf_safe_fetch(url: str, *, stream: bool = False) -> httpx.Response:
    """
    Fetch a URL with SSRF protection that covers redirects and DNS rebinding.

    Validates the initial URL and every redirect target against private/internal
    networks. Disables automatic redirect following and handles redirects manually.

    Args:
        url: The URL to fetch.
        stream: If True, returns a streaming response (caller must manage context).

    Returns:
        httpx.Response with the final response content.

    Raises:
        ValueError: If any URL in the redirect chain points to a private network.
        Exception: If the HTTP request fails.
    """
    if stream:
        raise ValueError("Streaming mode is not supported by _ssrf_safe_fetch.")

    max_redirects = 10
    current_url = url

    for _ in range(max_redirects):
        resp = await _fetch_url_with_pinned_ip(current_url)

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location")
            if not location:
                raise Exception(f"Redirect with no Location header from {current_url}")

            # Resolve relative redirects against the current URL
            location = urljoin(current_url, location)

            redirect_parsed = urlparse(location)
            if redirect_parsed.scheme not in ("http", "https"):
                raise ValueError(
                    f"Redirect to disallowed scheme: {redirect_parsed.scheme}"
                )

            current_url = location
            continue

        return resp

    raise Exception(f"Too many redirects (max {max_redirects}) fetching {url}")


@asynccontextmanager
async def _ssrf_safe_stream(url: str) -> AsyncIterator[httpx.Response]:
    """
    SSRF-safe streaming fetch: validates each redirect target against private
    networks, then streams the final response body without buffering it all
    in memory.

    Usage::

        async with _ssrf_safe_stream(file_url) as resp:
            async for chunk in resp.aiter_bytes(chunk_size=DOWNLOAD_CHUNK_SIZE_BYTES):
                ...
    """
    max_redirects = 10
    current_url = url

    # Resolve redirects manually so every hop is SSRF-validated
    for _ in range(max_redirects):
        parsed = urlparse(current_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Only http:// and https:// are supported: {current_url}")
        if not parsed.hostname:
            raise ValueError(f"Invalid URL: missing hostname ({current_url})")

        resolved_ips = _validate_url_not_internal(current_url)
        host_header = _format_host_header(parsed.hostname, parsed.scheme, parsed.port)

        last_error: Optional[Exception] = None
        resp: Optional[httpx.Response] = None
        for resolved_ip in resolved_ips:
            pinned_url = _build_pinned_url(parsed, resolved_ip)
            client = httpx.AsyncClient(follow_redirects=False, trust_env=False)
            try:
                request = client.build_request(
                    "GET",
                    pinned_url,
                    headers={"Host": host_header},
                    extensions={"sni_hostname": parsed.hostname},
                )
                resp = await client.send(request, stream=True)
                break
            except httpx.HTTPError as exc:
                last_error = exc
                await client.aclose()
                logger.warning(
                    f"[ssrf_safe_stream] Failed via IP {resolved_ip} for "
                    f"{parsed.hostname}: {exc}"
                )
            except Exception:
                await client.aclose()
                raise

        if resp is None:
            raise Exception(
                f"Failed to fetch URL after trying {len(resolved_ips)} validated IP(s): "
                f"{current_url}"
            ) from last_error

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location")
            await resp.aclose()
            await client.aclose()
            if not location:
                raise Exception(f"Redirect with no Location header from {current_url}")
            location = urljoin(current_url, location)
            redirect_parsed = urlparse(location)
            if redirect_parsed.scheme not in ("http", "https"):
                raise ValueError(
                    f"Redirect to disallowed scheme: {redirect_parsed.scheme}"
                )
            current_url = location
            continue

        # Non-redirect — yield the streaming response
        try:
            yield resp
        finally:
            await resp.aclose()
            await client.aclose()
        return

    raise Exception(f"Too many redirects (max {max_redirects}) fetching {url}")


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


@server.tool()
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


@server.tool()
@handle_http_errors("update_drive_file_content", service_type="drive")
@require_google_service("drive", "drive_file")
async def update_drive_file_content(
    service,
    user_google_email: str,
    file_id: str,
    content: str,
    mime_type: str = "application/json",
    new_name: str | None = None,
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


@server.tool()
@handle_http_errors("minify_drive_json_files", service_type="drive")
@require_google_service("drive", "drive_file")
async def minify_drive_json_files(
    service,
    user_google_email: str,
    file_ids: List[str],
) -> str:
    """Compact JSON files so each record sits on a single line.

    This is useful for Airbyte JSONL ingestion, which requires every file to be a
    single-line JSON object. The tool downloads each Drive file, parses it as JSON,
    rewrites it without whitespace, and uploads the result in-place.

    Args:
        user_google_email: Google Workspace account email.
        file_ids: List of Drive file IDs to minify.

    Returns:
        Human-readable summary of successes and failures.
    """

    if not file_ids:
        return "No file IDs provided."

    successes: list[str] = []
    failures: list[str] = []

    for file_id in file_ids:
        try:
            # Basic metadata for logging / name lookup
            metadata = await asyncio.to_thread(
                service.files()
                .get(
                    fileId=file_id, fields="id, name, mimeType", supportsAllDrives=True
                )
                .execute
            )

            name = metadata.get("name", file_id)
            mime_type = metadata.get("mimeType", "application/json")

            if not mime_type.endswith("json"):
                raise ValueError(f"Unsupported mime type '{mime_type}' for {name}")

            download_request = service.files().get_media(
                fileId=file_id, supportsAllDrives=True
            )
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, download_request)

            done = False
            while not done:
                _, done = await asyncio.to_thread(downloader.next_chunk)

            fh.seek(0)
            try:
                content_str = fh.read().decode("utf-8")
            except UnicodeDecodeError as exc:  # pragma: no cover - rare encoding issue
                raise ValueError("File is not valid UTF-8 JSON") from exc

            try:
                parsed = json.loads(content_str)
            except json.JSONDecodeError as exc:
                raise ValueError(f"File content is not valid JSON: {exc}") from exc

            minified = json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))

            media = MediaIoBaseUpload(
                io.BytesIO(minified.encode("utf-8")),
                mimetype="application/json",
                resumable=True,
            )

            await asyncio.to_thread(
                service.files()
                .update(
                    fileId=file_id,
                    media_body=media,
                    supportsAllDrives=True,
                    fields="id, name, webViewLink",
                )
                .execute
            )

            successes.append(f"Minified '{name}' ({file_id})")
        except Exception as exc:  # noqa: BLE001
            logger.exception("[minify_drive_json_files] Failed for %s", file_id)
            failures.append(f"{file_id}: {exc}")

    summary = [
        f"Processed {len(file_ids)} file(s).",
        f"Successful: {len(successes)}",
        f"Failed: {len(failures)}",
    ]

    if successes:
        summary.append("\nSuccesses:")
        summary.extend(f"- {msg}" for msg in successes)

    if failures:
        summary.append("\nFailures:")
        summary.extend(f"- {msg}" for msg in failures)

    return "\n".join(summary)


@server.tool()
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

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_name (str): The name for the new Google Doc (extension will be ignored).
        content (Optional[str]): Text content for text-based formats (MD, TXT, HTML).
        file_path (Optional[str]): Local file path for binary formats (DOCX, ODT). Supports file:// URLs.
        file_url (Optional[str]): Remote URL to fetch the file from (http/https).
        source_format (Optional[str]): Source format hint ('md', 'markdown', 'docx', 'txt', 'html', 'rtf', 'odt').
                                       Auto-detected from file_name extension if not provided.
        folder_id (str): The ID of the parent folder. Defaults to 'root'.

    Returns:
        str: Confirmation message with the new Google Doc link.

    Examples:
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
        resp = await _ssrf_safe_fetch(file_url)
        if resp.status_code != 200:
            raise Exception(
                f"Failed to fetch file from URL: {file_url} (status {resp.status_code})"
            )
        file_data = resp.content

        logger.info(
            f"[import_to_google_doc] Downloaded from URL: {len(file_data)} bytes"
        )

        # Re-detect format from URL if not specified
        if not source_format:
            source_mime_type = _detect_source_format(file_url)
            logger.info(
                f"[import_to_google_doc] Re-detected from URL: {source_mime_type}"
            )

    # Upload with conversion
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
        .execute
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
        f"Successfully imported '{doc_name}' as Google Doc\n"
        f"   Document ID: {doc_id}\n"
        f"   Source format: {source_mime_type}\n"
        f"   Folder: {folder_id}\n"
        f"   Link: {link}"
    )

    logger.info(f"[import_to_google_doc] Success. Link: {link}")
    return confirmation


@server.tool()
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


@server.tool()
@handle_http_errors(
    "check_drive_file_public_access", is_read_only=True, service_type="drive"
)
@require_google_service("drive", "drive_read")
async def check_drive_file_public_access(
    service,
    user_google_email: str,
    file_name: str,
) -> str:
    """
    Searches for a file by name and checks if it has public link sharing enabled.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_name (str): The name of the file to check.

    Returns:
        str: Information about the file's sharing status and whether it can be used in Google Docs.
    """
    logger.info(f"[check_drive_file_public_access] Searching for {file_name}")

    # Search for the file
    escaped_name = file_name.replace("'", "\\'")
    query = f"name = '{escaped_name}'"

    list_params = {
        "q": query,
        "pageSize": 10,
        "fields": "files(id, name, mimeType, webViewLink)",
        "supportsAllDrives": True,
        "includeItemsFromAllDrives": True,
    }

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


@server.tool()
@handle_http_errors("extract_drive_pdf_text", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def extract_drive_pdf_text(
    service,
    user_google_email: str,
    file_id: str,
    include_metadata: bool = True,
) -> str:
    """
    Extracts readable text content from a PDF file stored in Google Drive.

    This tool uses PyMuPDF (fitz) to parse PDF files and extract text content,
    including both text-based PDFs and scanned documents with embedded text.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the PDF file in Google Drive.
        include_metadata (bool): Whether to include file metadata in the output. Defaults to True.

    Returns:
        str: The extracted text content with optional metadata header.
    """
    logger.info(
        f"[extract_drive_pdf_text] Extracting PDF text for file ID: '{file_id}'"
    )

    # Get file metadata
    file_metadata = await asyncio.to_thread(
        service.files()
        .get(
            fileId=file_id,
            fields="id, name, mimeType, size, modifiedTime, webViewLink",
            supportsAllDrives=True,
        )
        .execute
    )

    file_name = file_metadata.get("name", "Unknown File")
    mime_type = file_metadata.get("mimeType", "")

    # Verify it's a PDF
    if mime_type != "application/pdf":
        return f"Error: File '{file_name}' is not a PDF (MIME type: {mime_type}). Use get_drive_file_content for other file types."

    # Download the PDF binary
    request_obj = service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request_obj)
    loop = asyncio.get_event_loop()
    done = False

    while not done:
        status, done = await loop.run_in_executor(None, downloader.next_chunk)

    pdf_bytes = fh.getvalue()

    # Extract text using PyMuPDF in a thread to avoid blocking
    def extract_text_from_pdf(pdf_data: bytes) -> tuple[str, dict]:
        """Extract text from PDF bytes using PyMuPDF."""
        doc = fitz.open(stream=pdf_data, filetype="pdf")

        extracted_text_parts = []
        pdf_info = {
            "page_count": len(doc),
            "has_text": False,
            "total_chars": 0,
        }

        for page_num in range(len(doc)):
            page = doc[page_num]
            page_text = page.get_text()

            if page_text.strip():
                pdf_info["has_text"] = True
                pdf_info["total_chars"] += len(page_text)
                extracted_text_parts.append(f"--- Page {page_num + 1} ---\n{page_text}")

        doc.close()

        full_text = "\n\n".join(extracted_text_parts)
        return full_text, pdf_info

    # Run extraction in thread
    try:
        extracted_text, pdf_info = await loop.run_in_executor(
            None, extract_text_from_pdf, pdf_bytes
        )
    except Exception as e:
        logger.error(f"[extract_drive_pdf_text] Error extracting PDF text: {e}")
        return f"Error extracting text from PDF '{file_name}': {str(e)}"

    # Build response
    if include_metadata:
        header_parts = [
            f'File: "{file_name}" (ID: {file_id})',
            f"Type: {mime_type}",
            f"Size: {file_metadata.get('size', 'N/A')} bytes",
            f"Modified: {file_metadata.get('modifiedTime', 'N/A')}",
            f"Link: {file_metadata.get('webViewLink', '#')}",
            f"Pages: {pdf_info['page_count']}",
            f"Total characters extracted: {pdf_info['total_chars']}",
            "",
            "--- EXTRACTED TEXT ---",
            "",
        ]
        header = "\n".join(header_parts)
    else:
        header = ""

    if not pdf_info["has_text"] or pdf_info["total_chars"] == 0:
        return (
            f"{header}No text content found in PDF '{file_name}'. "
            f"This may be a scanned document without OCR, an image-based PDF, or an empty PDF. "
            f"Consider using Google Drive's OCR feature by converting the PDF to Google Docs format."
        )

    return header + extracted_text


@server.tool()
@handle_http_errors(
    "extract_scanned_pdf_text_ocr", is_read_only=True, service_type="drive"
)
@require_google_service("drive", "drive_read")
async def extract_scanned_pdf_text_ocr(
    service,
    user_google_email: str,
    file_id: str,
    include_metadata: bool = True,
    max_pages: Optional[int] = None,
) -> str:
    """
    Extracts text from scanned PDF files using Google Cloud Vision API OCR.

    This tool is designed for scanned documents or image-based PDFs without embedded text.
    It uses Google Cloud Vision API to perform OCR on each page of the PDF.
    For text-based PDFs, use extract_drive_pdf_text instead (faster and free).

    Note: Requires Google Cloud Vision API to be enabled in your Google Cloud project.
    This may incur costs based on Google Cloud Vision API pricing.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the PDF file in Google Drive.
        include_metadata (bool): Whether to include file metadata in the output. Defaults to True.
        max_pages (Optional[int]): Maximum number of pages to process. If None, processes all pages.

    Returns:
        str: The extracted text content from OCR with optional metadata header.
    """
    logger.info(f"[extract_scanned_pdf_text_ocr] Starting OCR for file ID: '{file_id}'")

    # Get file metadata
    file_metadata = await asyncio.to_thread(
        service.files()
        .get(
            fileId=file_id,
            fields="id, name, mimeType, size, modifiedTime, webViewLink",
            supportsAllDrives=True,
        )
        .execute
    )

    file_name = file_metadata.get("name", "Unknown File")
    mime_type = file_metadata.get("mimeType", "")

    # Verify it's a PDF
    if mime_type != "application/pdf":
        return f"Error: File '{file_name}' is not a PDF (MIME type: {mime_type})."

    # Download the PDF binary
    request_obj = service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request_obj)
    loop = asyncio.get_event_loop()
    done = False

    while not done:
        status, done = await loop.run_in_executor(None, downloader.next_chunk)

    pdf_bytes = fh.getvalue()

    # Extract images from PDF pages using PyMuPDF
    def extract_page_images(
        pdf_data: bytes, max_pages_limit: Optional[int] = None
    ) -> tuple[list[bytes], int]:
        """Extract each page as an image from PDF."""
        doc = fitz.open(stream=pdf_data, filetype="pdf")
        page_images = []
        total_pages = len(doc)

        # Limit pages if specified
        pages_to_process = (
            min(total_pages, max_pages_limit) if max_pages_limit else total_pages
        )

        for page_num in range(pages_to_process):
            page = doc[page_num]
            # Render page as image at 300 DPI for good OCR quality
            pix = page.get_pixmap(matrix=fitz.Matrix(300 / 72, 300 / 72))
            img_bytes = pix.tobytes("png")
            page_images.append(img_bytes)

        doc.close()
        return page_images, total_pages

    try:
        page_images, total_pages = await loop.run_in_executor(
            None, extract_page_images, pdf_bytes, max_pages
        )
    except Exception as e:
        logger.error(
            f"[extract_scanned_pdf_text_ocr] Error extracting page images: {e}"
        )
        return f"Error extracting pages from PDF '{file_name}': {str(e)}"

    if not page_images:
        return f"No pages found in PDF '{file_name}'."

    # Get OAuth credentials for Vision API
    session_id = None
    try:
        session_id = get_fastmcp_session_id()
    except Exception as e:
        logger.debug(
            f"[extract_scanned_pdf_text_ocr] Unable to get FastMCP session ID: {e}"
        )

    try:
        creds = get_credentials(
            user_google_email,
            [CLOUD_VISION_SCOPE],
            session_id=session_id,
        )
        if not creds:
            logger.warning(
                "[extract_scanned_pdf_text_ocr] Missing Cloud Vision credentials; initiating re-auth flow."
            )
            from auth.oauth_callback_server import ensure_oauth_callback_available

            config = get_oauth_config()
            success, error_msg = ensure_oauth_callback_available(
                get_transport_mode(),
                config.port,
                config.base_uri,
            )
            if not success:
                detail = f" ({error_msg})" if error_msg else ""
                return (
                    "Error: Unable to initiate Google authorization required for Cloud Vision OCR."
                    f" OAuth callback server unavailable{detail}."
                )

            auth_message = await start_auth_flow(
                user_google_email=user_google_email,
                service_name="Google Drive (Vision OCR)",
                redirect_uri=get_oauth_redirect_uri(),
            )
            return (
                "Additional Google authorization is required to use Cloud Vision OCR.\n\n"
                f"{auth_message}\n\n"
                "After completing the authorization flow, rerun this tool."
            )

        # Create Vision API client with OAuth credentials
        vision_creds = GoogleCredentials(
            token=creds.token,
            refresh_token=creds.refresh_token,
            token_uri=creds.token_uri,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            scopes=creds.scopes,
        )

    except Exception as e:
        logger.error(
            f"[extract_scanned_pdf_text_ocr] Error setting up Vision API credentials: {e}"
        )
        return f"Error setting up Google Cloud Vision API: {str(e)}"

    # Perform OCR on each page
    async def ocr_page(page_image: bytes, page_number: int) -> tuple[int, str]:
        """Perform OCR on a single page image."""

        def sync_ocr():
            client = vision.ImageAnnotatorClient(credentials=vision_creds)
            image = vision.Image(content=page_image)
            response = client.text_detection(image=image)

            if response.error.message:
                raise Exception(f"Vision API error: {response.error.message}")

            texts = response.text_annotations
            if texts:
                # First annotation contains the full text
                return texts[0].description
            return ""

        try:
            text = await loop.run_in_executor(None, sync_ocr)
            return page_number, text
        except Exception as e:
            logger.error(
                f"[extract_scanned_pdf_text_ocr] Error OCR page {page_number + 1}: {e}"
            )
            return page_number, f"[Error processing page {page_number + 1}: {str(e)}]"

    # Process all pages
    logger.info(
        f"[extract_scanned_pdf_text_ocr] Processing {len(page_images)} pages with Vision API OCR"
    )

    ocr_tasks = [ocr_page(img, idx) for idx, img in enumerate(page_images)]
    ocr_results = await asyncio.gather(*ocr_tasks)

    # Sort by page number and format output
    ocr_results.sort(key=lambda x: x[0])

    extracted_text_parts = []
    total_chars = 0

    for page_num, text in ocr_results:
        if text and not text.startswith("[Error"):
            total_chars += len(text)
            extracted_text_parts.append(f"--- Page {page_num + 1} ---\n{text}")
        elif text.startswith("[Error"):
            extracted_text_parts.append(text)

    # Build response
    if include_metadata:
        pages_info = (
            f"{len(page_images)} of {total_pages}"
            if max_pages and len(page_images) < total_pages
            else str(total_pages)
        )
        header_parts = [
            f'File: "{file_name}" (ID: {file_id})',
            f"Type: {mime_type}",
            f"Size: {file_metadata.get('size', 'N/A')} bytes",
            f"Modified: {file_metadata.get('modifiedTime', 'N/A')}",
            f"Link: {file_metadata.get('webViewLink', '#')}",
            f"Pages processed: {pages_info}",
            f"Total characters extracted: {total_chars}",
            "",
            "--- EXTRACTED TEXT (via OCR) ---",
            "",
        ]
        header = "\n".join(header_parts)
    else:
        header = ""

    if total_chars == 0:
        return (
            f"{header}No text content extracted via OCR from PDF '{file_name}'. "
            f"This may be a blank document or the OCR failed to recognize any text."
        )

    full_text = "\n\n".join(extracted_text_parts)
    return header + full_text


@server.tool()
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
    Extracts text from a text-based PDF and writes the full text to a local file.

    Unlike extract_drive_pdf_text which returns the full text in the response,
    this tool writes output to a local file and returns only a summary.
    Uses PyMuPDF (embedded text extraction) — fast and free, no OCR/API costs.
    For scanned/image PDFs, use ocr_pdf_to_file instead.

    Supports two output formats:
    - "text": Plain text with page markers (default)
    - "json": JSON with per-page text, metadata, and file info

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the PDF file in Google Drive.
        output_path (str): Local filesystem path to write the extracted text.
            Parent directories will be created if they don't exist.
        output_format (str): Output format - "text" for plain text, "json" for structured JSON.
            Defaults to "text".

    Returns:
        str: Summary with file path, page count, character count, and text preview.
            If no text is found, suggests using ocr_pdf_to_file for scanned documents.
    """
    logger.info(
        f"[extract_pdf_text_to_file] Extracting PDF text for file ID: '{file_id}' -> '{output_path}'"
    )

    # Get file metadata
    file_metadata = await asyncio.to_thread(
        service.files()
        .get(
            fileId=file_id,
            fields="id, name, mimeType, size, modifiedTime, webViewLink",
            supportsAllDrives=True,
        )
        .execute
    )

    file_name = file_metadata.get("name", "Unknown File")
    mime_type = file_metadata.get("mimeType", "")

    if mime_type != "application/pdf":
        return f"Error: File '{file_name}' is not a PDF (MIME type: {mime_type})."

    # Download the PDF binary
    request_obj = service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request_obj)
    loop = asyncio.get_event_loop()
    done = False

    while not done:
        status, done = await loop.run_in_executor(None, downloader.next_chunk)

    pdf_bytes = fh.getvalue()

    # Extract text using PyMuPDF
    def extract_text(pdf_data: bytes) -> tuple[list[dict], int, int]:
        doc = fitz.open(stream=pdf_data, filetype="pdf")
        pages_data = []
        total_chars = 0
        total_pages = len(doc)

        for page_num in range(total_pages):
            page = doc[page_num]
            page_text = page.get_text()
            char_count = len(page_text.strip())
            total_chars += char_count
            pages_data.append(
                {
                    "page": page_num + 1,
                    "text": page_text,
                    "char_count": char_count,
                }
            )

        doc.close()
        return pages_data, total_chars, total_pages

    try:
        pages_data, total_chars, total_pages = await loop.run_in_executor(
            None, extract_text, pdf_bytes
        )
    except Exception as e:
        logger.error(f"[extract_pdf_text_to_file] Error extracting PDF text: {e}")
        return f"Error extracting text from PDF '{file_name}': {str(e)}"

    if total_chars == 0:
        return (
            f"No embedded text found in PDF '{file_name}' ({total_pages} pages). "
            f"This is likely a scanned document. Use ocr_pdf_to_file instead."
        )

    # Ensure output directory exists
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Write to file
    if output_format == "json":
        json_output = {
            "source_file_id": file_id,
            "source_file_name": file_name,
            "mime_type": mime_type,
            "file_size_bytes": int(file_metadata.get("size", 0)),
            "modified_date": file_metadata.get("modifiedTime", ""),
            "web_link": file_metadata.get("webViewLink", ""),
            "extraction_date": datetime.utcnow().isoformat() + "Z",
            "extraction_method": "pymupdf_text",
            "total_pages": total_pages,
            "total_characters": total_chars,
            "pages": [
                {"page": p["page"], "text": p["text"], "char_count": p["char_count"]}
                for p in pages_data
            ],
        }
        output_file.write_text(
            json.dumps(json_output, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    else:
        text_parts = []
        text_parts.append(f"# Text: {file_name}")
        text_parts.append(f"# Source: {file_id}")
        text_parts.append(f"# Pages: {total_pages}")
        text_parts.append(f"# Characters: {total_chars}")
        text_parts.append("")
        for p in pages_data:
            text_parts.append(f"--- Page {p['page']} ---")
            text_parts.append(p["text"])
            text_parts.append("")
        output_file.write_text("\n".join(text_parts), encoding="utf-8")

    file_size_kb = output_file.stat().st_size / 1024

    # Build summary
    first_text = next((p["text"][:200] for p in pages_data if p["char_count"] > 0), "")

    summary_parts = [
        f"Text extracted: {file_name}",
        f"  Source file ID: {file_id}",
        f"  Pages: {total_pages}",
        f"  Total characters: {total_chars:,}",
        f"  Output: {output_path} ({file_size_kb:.1f} KB, format: {output_format})",
        f"  Preview: {first_text}..."
        if first_text
        else "  Preview: (no text extracted)",
    ]

    return "\n".join(summary_parts)


@server.tool()
@handle_http_errors("ocr_pdf_to_file", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def ocr_pdf_to_file(
    service,
    user_google_email: str,
    file_id: str,
    output_path: str,
    max_pages: Optional[int] = None,
    output_format: str = "text",
) -> str:
    """
    Extracts text from a scanned PDF using OCR and writes the full text to a local file.

    Unlike extract_scanned_pdf_text_ocr which returns the full text in the response,
    this tool writes OCR output to a local file and returns only a summary.
    Ideal for batch processing or when the full text would be too large for the context window.

    Supports two output formats:
    - "text": Plain text with page markers (default)
    - "json": JSON with per-page text, metadata, and file info

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the PDF file in Google Drive.
        output_path (str): Local filesystem path to write the extracted text.
            Parent directories will be created if they don't exist.
        max_pages (Optional[int]): Maximum number of pages to process. If None, processes all pages.
        output_format (str): Output format - "text" for plain text, "json" for structured JSON.
            Defaults to "text".

    Returns:
        str: Summary with file path, page count, character count, and text preview.
    """
    logger.info(
        f"[ocr_pdf_to_file] Starting OCR for file ID: '{file_id}' -> '{output_path}'"
    )

    # Get file metadata
    file_metadata = await asyncio.to_thread(
        service.files()
        .get(
            fileId=file_id,
            fields="id, name, mimeType, size, modifiedTime, webViewLink",
            supportsAllDrives=True,
        )
        .execute
    )

    file_name = file_metadata.get("name", "Unknown File")
    mime_type = file_metadata.get("mimeType", "")

    if mime_type != "application/pdf":
        return f"Error: File '{file_name}' is not a PDF (MIME type: {mime_type})."

    # Download the PDF binary
    request_obj = service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request_obj)
    loop = asyncio.get_event_loop()
    done = False

    while not done:
        status, done = await loop.run_in_executor(None, downloader.next_chunk)

    pdf_bytes = fh.getvalue()

    # Extract images from PDF pages using PyMuPDF
    def extract_page_images(
        pdf_data: bytes, max_pages_limit: Optional[int] = None
    ) -> tuple[list[bytes], int]:
        doc = fitz.open(stream=pdf_data, filetype="pdf")
        page_images = []
        total_pages = len(doc)
        pages_to_process = (
            min(total_pages, max_pages_limit) if max_pages_limit else total_pages
        )

        for page_num in range(pages_to_process):
            page = doc[page_num]
            pix = page.get_pixmap(matrix=fitz.Matrix(300 / 72, 300 / 72))
            img_bytes = pix.tobytes("png")
            page_images.append(img_bytes)

        doc.close()
        return page_images, total_pages

    try:
        page_images, total_pages = await loop.run_in_executor(
            None, extract_page_images, pdf_bytes, max_pages
        )
    except Exception as e:
        logger.error(f"[ocr_pdf_to_file] Error extracting page images: {e}")
        return f"Error extracting pages from PDF '{file_name}': {str(e)}"

    if not page_images:
        return f"No pages found in PDF '{file_name}'."

    # Get OAuth credentials for Vision API
    session_id = None
    try:
        session_id = get_fastmcp_session_id()
    except Exception:
        pass

    try:
        creds = get_credentials(
            user_google_email,
            [CLOUD_VISION_SCOPE],
            session_id=session_id,
        )
        if not creds:
            from auth.oauth_callback_server import ensure_oauth_callback_available

            config = get_oauth_config()
            success, error_msg = ensure_oauth_callback_available(
                get_transport_mode(),
                config.port,
                config.base_uri,
            )
            if not success:
                detail = f" ({error_msg})" if error_msg else ""
                return f"Error: Unable to initiate Google authorization for Cloud Vision OCR. OAuth callback unavailable{detail}."

            auth_message = await start_auth_flow(
                user_google_email=user_google_email,
                service_name="Google Drive (Vision OCR)",
                redirect_uri=get_oauth_redirect_uri(),
            )
            return f"Additional Google authorization required for Cloud Vision OCR.\n\n{auth_message}\n\nAfter completing authorization, rerun this tool."

        vision_creds = GoogleCredentials(
            token=creds.token,
            refresh_token=creds.refresh_token,
            token_uri=creds.token_uri,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            scopes=creds.scopes,
        )

    except Exception as e:
        logger.error(f"[ocr_pdf_to_file] Error setting up Vision API credentials: {e}")
        return f"Error setting up Google Cloud Vision API: {str(e)}"

    # Perform OCR on each page
    async def ocr_page(page_image: bytes, page_number: int) -> tuple[int, str]:
        def sync_ocr():
            client = vision.ImageAnnotatorClient(credentials=vision_creds)
            image = vision.Image(content=page_image)
            response = client.text_detection(image=image)
            if response.error.message:
                raise Exception(f"Vision API error: {response.error.message}")
            texts = response.text_annotations
            return texts[0].description if texts else ""

        try:
            text = await loop.run_in_executor(None, sync_ocr)
            return page_number, text
        except Exception as e:
            logger.error(f"[ocr_pdf_to_file] Error OCR page {page_number + 1}: {e}")
            return page_number, f"[Error processing page {page_number + 1}: {str(e)}]"

    logger.info(
        f"[ocr_pdf_to_file] Processing {len(page_images)} pages with Vision API OCR"
    )
    ocr_tasks = [ocr_page(img, idx) for idx, img in enumerate(page_images)]
    ocr_results = await asyncio.gather(*ocr_tasks)
    ocr_results.sort(key=lambda x: x[0])

    # Collect results
    pages_data = []
    total_chars = 0
    for page_num, text in ocr_results:
        is_error = text.startswith("[Error") if text else False
        char_count = len(text) if not is_error else 0
        total_chars += char_count
        pages_data.append(
            {
                "page": page_num + 1,
                "text": text,
                "char_count": char_count,
                "error": is_error,
            }
        )

    # Ensure output directory exists
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Write to file
    pages_processed = len(page_images)
    if output_format == "json":
        json_output = {
            "source_file_id": file_id,
            "source_file_name": file_name,
            "mime_type": mime_type,
            "file_size_bytes": int(file_metadata.get("size", 0)),
            "modified_date": file_metadata.get("modifiedTime", ""),
            "web_link": file_metadata.get("webViewLink", ""),
            "ocr_date": datetime.utcnow().isoformat() + "Z",
            "pages_processed": pages_processed,
            "total_pages": total_pages,
            "total_characters": total_chars,
            "pages": [
                {"page": p["page"], "text": p["text"], "char_count": p["char_count"]}
                for p in pages_data
                if not p["error"]
            ],
            "errors": [
                {"page": p["page"], "error": p["text"]}
                for p in pages_data
                if p["error"]
            ],
        }
        output_file.write_text(
            json.dumps(json_output, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    else:
        text_parts = []
        text_parts.append(f"# OCR: {file_name}")
        text_parts.append(f"# Source: {file_id}")
        text_parts.append(f"# Pages: {pages_processed} of {total_pages}")
        text_parts.append(f"# Characters: {total_chars}")
        text_parts.append("")
        for p in pages_data:
            text_parts.append(f"--- Page {p['page']} ---")
            text_parts.append(p["text"])
            text_parts.append("")
        output_file.write_text("\n".join(text_parts), encoding="utf-8")

    file_size_kb = output_file.stat().st_size / 1024

    # Build summary (no full text)
    first_text = next(
        (p["text"][:200] for p in pages_data if p["text"] and not p["error"]), ""
    )
    errors = [p for p in pages_data if p["error"]]

    summary_parts = [
        f"OCR completed: {file_name}",
        f"  Source file ID: {file_id}",
        f"  Pages processed: {pages_processed} of {total_pages}",
        f"  Total characters: {total_chars:,}",
        f"  Output: {output_path} ({file_size_kb:.1f} KB, format: {output_format})",
        f"  Preview: {first_text}..."
        if first_text
        else "  Preview: (no text extracted)",
    ]
    if errors:
        summary_parts.append(f"  Errors: {len(errors)} page(s) failed OCR")

    return "\n".join(summary_parts)


# ===== NEW ADVANCED DRIVE TOOLS =====


@server.tool()
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

    # File type extension mapping
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

        # Query for all items in this folder
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

                # Check if it's a folder
                if mime_type == "application/vnd.google-apps.folder":
                    # Check if folder should be excluded
                    if exclude_folders and file_name in exclude_folders:
                        logger.info(
                            f"[recursive_folder_scan] Skipping excluded folder: {file_name}"
                        )
                        continue

                    # Recursively scan subfolder
                    subfolder_path = f"{folder_path}{file_name}/"
                    subfolder_data = await scan_folder_recursive(
                        item["id"], subfolder_path, current_depth + 1
                    )
                    subfolders.append(subfolder_data)
                else:
                    # It's a file
                    file_ext = mime_to_ext_map.get(
                        mime_type,
                        file_name.split(".")[-1] if "." in file_name else "unknown",
                    )

                    # Filter by file types if specified
                    if file_types and file_ext.lower() not in [
                        ft.lower() for ft in file_types
                    ]:
                        continue

                    file_size = int(item.get("size", 0)) if item.get("size") else 0
                    total_size_bytes += file_size

                    # Update stats by type
                    if file_ext not in stats_by_type:
                        stats_by_type[file_ext] = {"count": 0, "total_size": 0}
                    stats_by_type[file_ext]["count"] += 1
                    stats_by_type[file_ext]["total_size"] += file_size

                    # Build file entry
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

    # Get root folder name first
    root_folder_metadata = await asyncio.to_thread(
        service.files()
        .get(fileId=folder_id, fields="name", supportsAllDrives=True)
        .execute
    )
    root_folder_name = root_folder_metadata.get("name", folder_id)

    # Start recursive scan with root folder name as the initial path
    folder_tree = await scan_folder_recursive(folder_id, root_folder_name + "/")

    scan_time = time.time() - scan_start_time

    # Apply pagination to all_files
    total_files_scanned = len(all_files)
    paginated_files = all_files
    pagination_info = None

    if max_files is not None and page_size is not None:
        logger.warning(
            "[recursive_folder_scan] Both max_files and page_size specified. Using max_files only."
        )

    if max_files is not None:
        # Simple limit on total files
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
        # Page-based pagination
        start_idx = page_number * page_size
        end_idx = start_idx + page_size
        paginated_files = all_files[start_idx:end_idx]
        total_pages = (
            total_files_scanned + page_size - 1
        ) // page_size  # Ceiling division

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

    # Build summary
    summary = {
        "total_files": total_files_scanned,
        "total_folders": sum(1 for _ in _count_folders(folder_tree)),
        "total_size_bytes": total_size_bytes,
        "scan_depth": max_depth_reached + 1,
        "scan_time_seconds": round(scan_time, 2),
    }

    # Add pagination info to summary if applicable
    if pagination_info:
        summary["pagination"] = pagination_info

    # Build result based on output format
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

    # If output_file is specified, write to file instead of returning
    if output_file:
        try:
            output_path = Path(output_file)
            # Create parent directories if they don't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Write JSON to file
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

    # Otherwise, return the result normally
    return result


def _count_folders(tree_node):
    """Generator to count all folders in the tree."""
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


@server.tool()
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
    breakdown = {}
    largest_files = []

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

                    # Group by type
                    if group_by == "type":
                        file_ext = mime_to_ext_map.get(mime_type, "other")
                        breakdown[file_ext] = breakdown.get(file_ext, 0) + 1

                    # Track largest files
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

    # Get folder name
    folder_metadata = await asyncio.to_thread(
        service.files()
        .get(fileId=folder_id, fields="name", supportsAllDrives=True)
        .execute
    )
    folder_name = folder_metadata.get("name", folder_id)

    # Start scan
    await scan_folder(folder_id)

    # Sort largest files
    largest_files.sort(key=lambda x: x["size_mb"], reverse=True)
    largest_files = largest_files[:10]  # Top 10

    return {
        "folder_name": folder_name,
        "total_files": total_files,
        "total_folders": total_folders,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "breakdown": breakdown,
        "largest_files": largest_files,
    }


@server.tool()
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

    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days_back)

    # Build request body
    request_body = {"pageSize": 100, "filter": f'time >= "{start_time.isoformat()}Z"'}

    if folder_id:
        request_body["ancestorName"] = f"items/{folder_id}"

    activities = []
    page_token = None

    while True:
        if page_token:
            request_body["pageToken"] = page_token

        # Query Drive Activity API
        response = await asyncio.to_thread(
            service.activity().query(body=request_body).execute
        )

        for activity in response.get("activities", []):
            # Parse activity
            timestamp = activity.get("timestamp", "")
            primary_action_detail = activity.get("primaryActionDetail", {})
            targets = activity.get("targets", [])
            actors = activity.get("actors", [])

            # Get actor (user who performed the action)
            actor_email = "unknown"
            if actors:
                actor = actors[0]
                if "user" in actor:
                    actor_email = (
                        actor["user"].get("knownUser", {}).get("personName", "unknown")
                    )

            # Process different action types
            for target in targets:
                if "driveItem" not in target:
                    continue

                drive_item = target["driveItem"]
                file_id = drive_item.get("name", "").replace("items/", "")
                file_name = drive_item.get("title", "Unknown")

                # Determine activity type
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

                # Filter by activity types if specified
                if activity_types and activity_type not in activity_types:
                    continue

                activity_entry = {
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

    # Generate summary
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


@server.tool()
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

        # Count files and subfolders
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

        # Build children
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

    # Get folder name
    folder_metadata = await asyncio.to_thread(
        service.files()
        .get(fileId=folder_id, fields="name", supportsAllDrives=True)
        .execute
    )
    folder_name = folder_metadata.get("name", folder_id)

    # Build tree
    tree = await build_tree(folder_id, folder_name)

    # Format as ASCII tree
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


@server.tool()
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

    # Default fields if not specified
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

    files = []
    not_found = []

    # Fetch metadata for each file
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


@server.tool()
@handle_http_errors(
    "get_extraction_manifest_status", is_read_only=True, service_type="drive"
)
@require_google_service("drive", "drive_read")
async def get_extraction_manifest_status(
    service,
    user_google_email: str,
    project_id: str = "03_H83",
    manifest_folder_id: str = "1ANYWlH575tOYyrCv3UwA6tOGQPi9yK0Z",
) -> str:
    """
    Get current extraction manifest status showing progress and files needing extraction.

    This tool automatically locates the manifest file, reads it, and provides:
    - Last sync date and total file count
    - Extraction progress statistics
    - Files that need extraction (new or modified since last extraction)

    Args:
        user_google_email (str): The user's Google email address. Required.
        project_id (str): Project identifier (default: "03_H83")
        manifest_folder_id (str): Folder ID where manifest is stored

    Returns:
        str: Formatted status report with statistics and file lists
    """

    # Step 1: Search for manifest file
    manifest_filename = f"{project_id}_drive_scan.json"
    query = f"name='{manifest_filename}' and '{manifest_folder_id}' in parents and trashed=false"

    results = await asyncio.to_thread(
        service.files()
        .list(
            q=query,
            fields="files(id, name, modifiedTime)",
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
        )
        .execute
    )

    files = results.get("files", [])

    if not files:
        return f"❌ No manifest found for project {project_id}\n\nRun 'update_extraction_manifest' to create initial manifest."

    manifest_file = files[0]

    # Step 2: Read manifest content
    request = service.files().get_media(fileId=manifest_file["id"])
    file_content = io.BytesIO()
    downloader = MediaIoBaseDownload(file_content, request)

    done = False
    while not done:
        status, done = await asyncio.to_thread(downloader.next_chunk)

    file_content.seek(0)
    manifest = json.loads(file_content.read().decode("utf-8"))

    # Step 3: Calculate statistics
    files_list = manifest.get("files", [])
    stats = manifest.get("stats", {})

    pending_files = [f for f in files_list if f.get("extraction_status") == "pending"]
    extracted_files = [
        f for f in files_list if f.get("extraction_status") == "extracted"
    ]

    # Step 4: Format output
    output = []
    output.append(
        f"📊 Extraction Status for {manifest.get('project_name', project_id)}"
    )
    output.append("=" * 60)
    output.append(f"\n📅 Last Sync: {manifest.get('last_scan_date', 'Unknown')}")
    output.append(f"📁 Total Files: {manifest.get('total_files', 0)}")
    output.append(f"   Active: {manifest.get('active_files', 0)}")
    output.append(f"   Archived: {manifest.get('archived_files', 0)}")

    output.append("\n📈 Extraction Progress:")
    output.append(f"   ✅ Extracted: {stats.get('extracted', 0)}")
    output.append(f"   ⏳ Pending: {stats.get('pending', 0)}")
    output.append(f"   ❌ Failed: {stats.get('failed', 0)}")
    output.append(f"   ⏭️  Skipped: {stats.get('skipped', 0)}")

    progress = manifest.get("extraction_progress", {})
    completion = progress.get("completion_percentage", 0)
    output.append(f"   📊 Completion: {completion}%")

    # Show sample of pending files
    if pending_files:
        output.append(
            f"\n⏳ Files Needing Extraction (showing first 10 of {len(pending_files)}):"
        )
        for i, file in enumerate(pending_files[:10], 1):
            doc_type = file.get("document_type") or "unclassified"
            file_name = file.get("file_name", "unnamed")
            folder = file.get("folder_path", "")
            output.append(f"   {i}. [{doc_type}] {file_name}")
            output.append(f"      📁 {folder}")

    # Show sample of recently extracted files
    if extracted_files:
        recent_extracted = sorted(
            extracted_files, key=lambda x: x.get("extraction_date", ""), reverse=True
        )[:5]
        output.append("\n✅ Recently Extracted (last 5):")
        for i, file in enumerate(recent_extracted, 1):
            doc_type = file.get("document_type") or "unclassified"
            file_name = file.get("file_name", "unnamed")
            extraction_date = file.get("extraction_date", "unknown")
            output.append(f"   {i}. [{doc_type}] {file_name}")
            output.append(f"      🕒 {extraction_date}")

    return "\n".join(output)


@server.tool()
@handle_http_errors("update_extraction_manifest", service_type="drive")
@require_google_service("drive", "drive_file")
async def update_extraction_manifest(
    service,
    user_google_email: str,
    project_id: str,
    source_folder_id: str,
    manifest_folder_id: str,
    project_name: str,
) -> str:
    """
    Update extraction manifest by scanning Drive for new and modified files.

    This tool:
    1. Scans the entire Drive folder structure recursively
    2. Identifies new files (not in manifest)
    3. Detects modified files (modified_date > extraction_date)
    4. Preserves extraction status for unchanged files
    5. Marks deleted files as archived
    6. Updates manifest with statistics

    NOTE: Does NOT classify documents - document_type is set by extraction skill.

    Args:
        user_google_email (str): The user's Google email address. Required.
        project_id (str): Project identifier
        source_folder_id (str): Drive folder ID to scan
        manifest_folder_id (str): Where to store updated manifest
        project_name (str): Human-readable project name

    Returns:
        str: Summary of changes (new files, modified files, archived files)
    """

    # Step 1: Recursively scan for all PDF files in folder tree
    logger.info(
        f"[update_extraction_manifest] Scanning for PDFs in project {project_id}"
    )

    all_files = []
    folders_to_scan = [source_folder_id]
    scanned_folders = set()

    while folders_to_scan:
        current_folder = folders_to_scan.pop(0)
        if current_folder in scanned_folders:
            continue
        scanned_folders.add(current_folder)

        # Get all items in current folder
        page_token = None
        while True:
            try:
                results = await asyncio.to_thread(
                    service.files()
                    .list(
                        q=f"'{current_folder}' in parents and trashed=false",
                        fields="files(id, name, size, modifiedTime, webViewLink, mimeType)",
                        pageSize=100,
                        pageToken=page_token,
                        supportsAllDrives=True,
                        includeItemsFromAllDrives=True,
                    )
                    .execute
                )

                for item in results.get("files", []):
                    if item["mimeType"] == "application/vnd.google-apps.folder":
                        # Add subfolder to scan queue
                        folders_to_scan.append(item["id"])
                    elif item["mimeType"] == "application/pdf":
                        # Add PDF file
                        all_files.append(
                            {
                                "file_id": item["id"],
                                "file_name": item["name"],
                                "file_size": int(item.get("size", 0)),
                                "folder_path": f"/{current_folder}",
                                "mime_type": item["mimeType"],
                                "modified_date": item.get("modifiedTime", ""),
                                "web_link": item.get("webViewLink", ""),
                            }
                        )

                page_token = results.get("nextPageToken")
                if not page_token:
                    break
            except Exception as e:
                logger.warning(
                    f"[update_extraction_manifest] Error scanning folder {current_folder}: {e}"
                )
                break  # Skip this folder and continue with others

    logger.info(f"[update_extraction_manifest] Scan found {len(all_files)} PDF files")

    # Step 2: Deduplicate by file_id (same file in multiple folders)
    files_by_id = {}
    for file in all_files:
        file_id = file["file_id"]
        if file_id not in files_by_id:
            files_by_id[file_id] = {
                "file_id": file_id,
                "file_name": file["file_name"],
                "file_size_bytes": file.get("file_size", 0),
                "folder_path": file["folder_path"],
                "mime_type": file["mime_type"],
                "modified_date": file["modified_date"],
                "web_link": file["web_link"],
                "extraction_status": "pending",  # Default for new files
                "document_type": None,  # Set by extraction skill
                "first_seen": datetime.utcnow().isoformat() + "Z",
            }

    logger.info(
        f"[update_extraction_manifest] After deduplication: {len(files_by_id)} unique files"
    )

    # Step 3: Load existing manifest (if exists)
    existing_manifest = None
    manifest_filename = f"{project_id}_drive_scan.json"

    try:
        query = f"name='{manifest_filename}' and '{manifest_folder_id}' in parents and trashed=false"
        results = await asyncio.to_thread(
            service.files()
            .list(
                q=query,
                fields="files(id)",
                supportsAllDrives=True,
                includeItemsFromAllDrives=True,
            )
            .execute
        )

        if results.get("files"):
            manifest_file_id = results["files"][0]["id"]
            request = service.files().get_media(fileId=manifest_file_id)
            file_content = io.BytesIO()
            downloader = MediaIoBaseDownload(file_content, request)
            done = False
            while not done:
                status, done = await asyncio.to_thread(downloader.next_chunk)
            file_content.seek(0)
            existing_manifest = json.loads(file_content.read().decode("utf-8"))
            logger.info(
                f"[update_extraction_manifest] Loaded existing manifest with {len(existing_manifest.get('files', []))} files"
            )
    except Exception as e:
        logger.info(f"[update_extraction_manifest] No existing manifest found: {e}")

    # Step 4: Merge with existing manifest (SMART LOGIC)
    new_files_count = 0
    modified_files_count = 0
    unchanged_extracted_count = 0

    if existing_manifest and "files" in existing_manifest:
        existing_by_id = {f["file_id"]: f for f in existing_manifest["files"]}

        for file_id, file_data in files_by_id.items():
            if file_id in existing_by_id:
                existing_file = existing_by_id[file_id]

                # KEY LOGIC: Check if file was modified AFTER extraction
                file_modified = file_data["modified_date"]
                extraction_date = existing_file.get("extraction_date")

                if (
                    existing_file.get("extraction_status") == "extracted"
                    and extraction_date
                ):
                    if file_modified > extraction_date:
                        # File changed after extraction - mark as pending
                        file_data["extraction_status"] = "pending"
                        file_data["document_type"] = existing_file.get(
                            "document_type"
                        )  # Preserve classification
                        file_data["previous_extraction_date"] = extraction_date
                        modified_files_count += 1
                        logger.info(
                            f"[update_extraction_manifest] File modified after extraction: {file_data['file_name']}"
                        )
                    else:
                        # File unchanged - preserve extraction status and ALL metadata
                        file_data["extraction_status"] = "extracted"
                        file_data["extraction_date"] = extraction_date
                        file_data["document_type"] = existing_file.get("document_type")
                        file_data["extracted_to"] = existing_file.get("extracted_to")
                        file_data["extracted_file_id"] = existing_file.get(
                            "extracted_file_id"
                        )
                        file_data["extraction_quality"] = existing_file.get(
                            "extraction_quality"
                        )
                        file_data["pages_extracted"] = existing_file.get(
                            "pages_extracted"
                        )
                        file_data["value_czk"] = existing_file.get("value_czk")
                        unchanged_extracted_count += 1
                else:
                    # Preserve whatever status it had (pending, failed, skipped)
                    file_data["extraction_status"] = existing_file.get(
                        "extraction_status", "pending"
                    )
                    file_data["document_type"] = existing_file.get("document_type")
                    if existing_file.get("extraction_date"):
                        file_data["extraction_date"] = existing_file["extraction_date"]
                    if existing_file.get("failure_reason"):
                        file_data["failure_reason"] = existing_file["failure_reason"]

                file_data["first_seen"] = existing_file.get(
                    "first_seen", file_data["first_seen"]
                )

                # Check for moved files
                if file_data["folder_path"] != existing_file.get("folder_path"):
                    logger.info(
                        f"[update_extraction_manifest] File moved: {file_data['file_name']}"
                    )
                    file_data["previous_folder_path"] = existing_file.get("folder_path")
            else:
                # New file
                new_files_count += 1
                logger.info(
                    f"[update_extraction_manifest] New file: {file_data['file_name']}"
                )
    else:
        # No existing manifest - all files are new
        new_files_count = len(files_by_id)
        logger.info(
            f"[update_extraction_manifest] Creating new manifest with {new_files_count} files"
        )

    # Step 5: Mark archived files
    archived_files = []
    if existing_manifest and "files" in existing_manifest:
        existing_by_id = {f["file_id"]: f for f in existing_manifest["files"]}
        existing_ids = set(f["file_id"] for f in existing_manifest["files"])
        current_ids = set(files_by_id.keys())
        deleted_ids = existing_ids - current_ids

        for file_id in deleted_ids:
            old_file = existing_by_id[file_id]
            if old_file.get("extraction_status") != "archived":
                old_file["extraction_status"] = "archived"
                old_file["archived_date"] = datetime.utcnow().isoformat() + "Z"
                archived_files.append(old_file)
                logger.info(
                    f"[update_extraction_manifest] File archived: {old_file.get('file_name')}"
                )

    # Step 6: Build updated manifest
    all_files_list = list(files_by_id.values()) + archived_files

    stats = {
        "pending": sum(
            1 for f in all_files_list if f["extraction_status"] == "pending"
        ),
        "extracted": sum(
            1 for f in all_files_list if f["extraction_status"] == "extracted"
        ),
        "failed": sum(1 for f in all_files_list if f["extraction_status"] == "failed"),
        "skipped": sum(
            1 for f in all_files_list if f["extraction_status"] == "skipped"
        ),
        "archived": sum(
            1 for f in all_files_list if f["extraction_status"] == "archived"
        ),
    }

    total_pending_and_extracted = stats["pending"] + stats["extracted"]
    completion_percentage = 0
    if total_pending_and_extracted > 0:
        completion_percentage = round(
            (stats["extracted"] / total_pending_and_extracted) * 100, 2
        )

    updated_manifest = {
        "project_id": project_id,
        "project_name": project_name,
        "source_drive_folder_id": source_folder_id,
        "last_scan_date": datetime.utcnow().isoformat() + "Z",
        "last_update_date": datetime.utcnow().isoformat() + "Z",
        "total_files": len(all_files_list),
        "active_files": len(files_by_id),
        "archived_files": len(archived_files),
        "manifest_version": "2.0",
        "files": all_files_list,
        "stats": stats,
        "extraction_progress": {
            "total_documents": total_pending_and_extracted,
            "extracted_documents": stats["extracted"],
            "completion_percentage": completion_percentage,
        },
        "scan_metadata": {
            "scan_type": "full",
            "files_added": new_files_count,
            "files_modified": modified_files_count,
            "files_unchanged_extracted": unchanged_extracted_count,
            "files_archived": len(archived_files),
        },
    }

    # Step 7: Write manifest to Drive
    manifest_json = json.dumps(updated_manifest, indent=2, ensure_ascii=False)
    media = MediaIoBaseUpload(
        io.BytesIO(manifest_json.encode("utf-8")),
        mimetype="application/json",
        resumable=True,
    )

    # Check if manifest already exists
    try:
        query = f"name='{manifest_filename}' and '{manifest_folder_id}' in parents and trashed=false"
        results = await asyncio.to_thread(
            service.files()
            .list(
                q=query,
                fields="files(id)",
                supportsAllDrives=True,
                includeItemsFromAllDrives=True,
            )
            .execute
        )

        if results.get("files"):
            # Update existing
            manifest_file_id = results["files"][0]["id"]
            await asyncio.to_thread(
                service.files()
                .update(
                    fileId=manifest_file_id, media_body=media, supportsAllDrives=True
                )
                .execute
            )
            logger.info(
                f"[update_extraction_manifest] Updated existing manifest file: {manifest_file_id}"
            )
        else:
            # Create new
            file_metadata = {
                "name": manifest_filename,
                "parents": [manifest_folder_id],
                "mimeType": "application/json",
            }
            result = await asyncio.to_thread(
                service.files()
                .create(
                    body=file_metadata,
                    media_body=media,
                    fields="id",
                    supportsAllDrives=True,
                )
                .execute
            )
            logger.info(
                f"[update_extraction_manifest] Created new manifest file: {result.get('id')}"
            )
    except Exception as e:
        logger.error(f"[update_extraction_manifest] Error writing manifest: {e}")
        return f"❌ Error writing manifest: {e}"

    # Step 8: Format summary
    output = []
    output.append(f"✅ Manifest updated for {project_name}")
    output.append("=" * 60)
    output.append("\n📊 Scan Results:")
    output.append(f"   Total files: {updated_manifest['total_files']}")
    output.append(f"   Active: {updated_manifest['active_files']}")
    output.append(f"   Archived: {updated_manifest['archived_files']}")

    output.append("\n📈 Changes:")
    output.append(f"   🆕 New files: {new_files_count}")
    output.append(f"   📝 Modified files: {modified_files_count}")
    output.append(f"   ✅ Unchanged (extracted): {unchanged_extracted_count}")
    output.append(f"   🗑️  Archived files: {len(archived_files)}")

    output.append("\n📊 Extraction Status:")
    output.append(f"   ✅ Extracted: {stats['extracted']}")
    output.append(f"   ⏳ Pending: {stats['pending']}")
    output.append(f"   ❌ Failed: {stats['failed']}")
    output.append(f"   ⏭️  Skipped: {stats['skipped']}")
    output.append(f"   Completion: {completion_percentage}%")

    return "\n".join(output)


# ============================================================================
# MANIFEST TRACKING TOOLS (New - for incremental extraction tracking)
# ============================================================================


@server.tool()
async def mark_file_as_extracted(
    user_google_email: str,
    project_id: str,
    source_file_id: str,
    document_type: str,
    output_file_path: str,
    extraction_quality: str = "high",
    extraction_date: Optional[str] = None,
    manifest_folder_id: str = "1ANYWlH575tOYyrCv3UwA6tOGQPi9yK0Z",
    pages_extracted: Optional[int] = None,
    total_pages: Optional[int] = None,
    extraction_notes: Optional[str] = None,
) -> str:
    """
    Mark a single file as extracted in the manifest.

    This performs an atomic update without requiring a full Drive rescan:
    1. Reads the manifest
    2. Updates specific file status
    3. Recalculates statistics
    4. Writes manifest back

    Args:
        user_google_email: Google account email
        project_id: Project ID (e.g., "03_H83")
        source_file_id: Drive file ID of source PDF
        document_type: Document type (invoice, lease, purchase_contract, etc.)
        output_file_path: Relative path to output JSON
        extraction_quality: "high", "medium", or "low"
        extraction_date: ISO timestamp (defaults to now)
        manifest_folder_id: Folder containing manifest
        pages_extracted: Number of pages extracted
        total_pages: Total pages in document
        extraction_notes: Extraction notes

    Returns:
        JSON string with update result and statistics
    """
    from .manifest_tools import mark_file_as_extracted as _mark_file

    result = await asyncio.to_thread(
        _mark_file,
        user_google_email=user_google_email,
        project_id=project_id,
        source_file_id=source_file_id,
        document_type=document_type,
        output_file_path=output_file_path,
        extraction_quality=extraction_quality,
        extraction_date=extraction_date,
        manifest_folder_id=manifest_folder_id,
        pages_extracted=pages_extracted,
        total_pages=total_pages,
        extraction_notes=extraction_notes,
    )

    # Format result for display
    stats = result["manifest_stats"]
    output = f"""✅ Marked as extracted: {result["file_name"]}

Previous status: {result["previous_status"]}
New status: {result["new_status"]}
Document type: {document_type}
Output: {output_file_path}

📊 Manifest Statistics:
   Total files: {stats["total_files"]}
   Extracted: {stats["extracted"]}
   Pending: {stats["pending"]}
   Failed: {stats["failed"]}
   Progress: {stats["completion_pct"]}%
"""
    return output


@server.tool()
async def mark_files_as_extracted_batch(
    user_google_email: str,
    project_id: str,
    extracted_files: List[dict],
    manifest_folder_id: str = "1ANYWlH575tOYyrCv3UwA6tOGQPi9yK0Z",
) -> str:
    """
    Mark multiple files as extracted in a single batch operation.

    More efficient than individual updates - reads/writes manifest only once.

    Args:
        user_google_email: Google account email
        project_id: Project ID
        extracted_files: List of dicts with:
            - source_file_id (required)
            - document_type (required)
            - output_file_path (required)
            - extraction_quality (optional)
            - extraction_date (optional)
            - pages_extracted (optional)
            - total_pages (optional)
            - extraction_notes (optional)
        manifest_folder_id: Folder containing manifest

    Returns:
        JSON string with batch update results
    """
    from .manifest_tools import mark_files_as_extracted_batch as _mark_batch

    result = await asyncio.to_thread(
        _mark_batch,
        user_google_email=user_google_email,
        project_id=project_id,
        extracted_files=extracted_files,
        manifest_folder_id=manifest_folder_id,
    )

    stats = result["manifest_stats"]
    output = f"""✅ Batch update complete

Files updated: {result["files_updated"]}
Files not found: {len(result["files_not_found"])}

📊 Manifest Statistics:
   Total files: {stats["total_files"]}
   Extracted: {stats["extracted"]}
   Pending: {stats["pending"]}
   Failed: {stats["failed"]}
   Progress: {stats["completion_pct"]}%
"""

    if result["files_not_found"]:
        output += "\n⚠️ Files not found in manifest:\n"
        for file_id in result["files_not_found"][:5]:
            output += f"   - {file_id}\n"
        if len(result["files_not_found"]) > 5:
            output += f"   ... and {len(result['files_not_found']) - 5} more\n"

    return output


@server.tool()
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


@server.tool()
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


@server.tool()
@handle_http_errors("share_drive_file", is_read_only=False, service_type="drive")
@require_google_service("drive", "drive_file")
async def share_drive_file(
    service,
    user_google_email: str,
    file_id: str,
    share_with: Optional[str] = None,
    role: str = "reader",
    share_type: str = "user",
    send_notification: bool = True,
    email_message: Optional[str] = None,
    expiration_time: Optional[str] = None,
    allow_file_discovery: Optional[bool] = None,
) -> str:
    """
    Shares a Google Drive file or folder with a user, group, domain, or anyone with the link.

    When sharing a folder, all files inside inherit the permission.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the file or folder to share. Required.
        share_with (Optional[str]): Email address (for user/group), domain name (for domain), or omit for 'anyone'.
        role (str): Permission role - 'reader', 'commenter', or 'writer'. Defaults to 'reader'.
        share_type (str): Type of sharing - 'user', 'group', 'domain', or 'anyone'. Defaults to 'user'.
        send_notification (bool): Whether to send a notification email. Defaults to True.
        email_message (Optional[str]): Custom message for the notification email.
        expiration_time (Optional[str]): Expiration time in RFC 3339 format (e.g., "2025-01-15T00:00:00Z"). Permission auto-revokes after this time.
        allow_file_discovery (Optional[bool]): For 'domain' or 'anyone' shares - whether the file can be found via search. Defaults to None (API default).

    Returns:
        str: Confirmation with permission details and shareable link.
    """
    logger.info(
        f"[share_drive_file] Invoked. Email: '{user_google_email}', File ID: '{file_id}', Share with: '{share_with}', Role: '{role}', Type: '{share_type}'"
    )

    validate_share_role(role)
    validate_share_type(share_type)

    if share_type in ("user", "group") and not share_with:
        raise ValueError(f"share_with is required for share_type '{share_type}'")
    if share_type == "domain" and not share_with:
        raise ValueError("share_with (domain name) is required for share_type 'domain'")

    resolved_file_id, file_metadata = await resolve_drive_item(
        service, file_id, extra_fields="name, webViewLink"
    )
    file_id = resolved_file_id

    permission_body = {
        "type": share_type,
        "role": role,
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

    create_params = {
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

    output_parts = [
        f"Successfully shared '{file_metadata.get('name', 'Unknown')}'",
        "",
        "Permission created:",
        f"  - {format_permission_info(created_permission)}",
        "",
        f"View link: {file_metadata.get('webViewLink', 'N/A')}",
    ]

    return "\n".join(output_parts)


@server.tool()
@handle_http_errors("batch_share_drive_file", is_read_only=False, service_type="drive")
@require_google_service("drive", "drive_file")
async def batch_share_drive_file(
    service,
    user_google_email: str,
    file_id: str,
    recipients: List[Dict[str, Any]],
    send_notification: bool = True,
    email_message: Optional[str] = None,
) -> str:
    """
    Shares a Google Drive file or folder with multiple users or groups in a single operation.

    Each recipient can have a different role and optional expiration time.

    Note: Each recipient is processed sequentially. For very large recipient lists,
    consider splitting into multiple calls.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the file or folder to share. Required.
        recipients (List[Dict]): List of recipient objects. Each should have:
            - email (str): Recipient email address. Required for 'user' or 'group' share_type.
            - role (str): Permission role - 'reader', 'commenter', or 'writer'. Defaults to 'reader'.
            - share_type (str, optional): 'user', 'group', or 'domain'. Defaults to 'user'.
            - expiration_time (str, optional): Expiration in RFC 3339 format (e.g., "2025-01-15T00:00:00Z").
            For domain shares, use 'domain' field instead of 'email':
            - domain (str): Domain name. Required when share_type is 'domain'.
        send_notification (bool): Whether to send notification emails. Defaults to True.
        email_message (Optional[str]): Custom message for notification emails.

    Returns:
        str: Summary of created permissions with success/failure for each recipient.
    """
    logger.info(
        f"[batch_share_drive_file] Invoked. Email: '{user_google_email}', File ID: '{file_id}', Recipients: {len(recipients)}"
    )

    resolved_file_id, file_metadata = await resolve_drive_item(
        service, file_id, extra_fields="name, webViewLink"
    )
    file_id = resolved_file_id

    if not recipients:
        raise ValueError("recipients list cannot be empty")

    results = []
    success_count = 0
    failure_count = 0

    for recipient in recipients:
        share_type = recipient.get("share_type", "user")

        if share_type == "domain":
            domain = recipient.get("domain")
            if not domain:
                results.append("  - Skipped: missing domain for domain share")
                failure_count += 1
                continue
            identifier = domain
        else:
            email = recipient.get("email")
            if not email:
                results.append("  - Skipped: missing email address")
                failure_count += 1
                continue
            identifier = email

        role = recipient.get("role", "reader")
        try:
            validate_share_role(role)
        except ValueError as e:
            results.append(f"  - {identifier}: Failed - {e}")
            failure_count += 1
            continue

        try:
            validate_share_type(share_type)
        except ValueError as e:
            results.append(f"  - {identifier}: Failed - {e}")
            failure_count += 1
            continue

        permission_body = {
            "type": share_type,
            "role": role,
        }

        if share_type == "domain":
            permission_body["domain"] = identifier
        else:
            permission_body["emailAddress"] = identifier

        if recipient.get("expiration_time"):
            try:
                validate_expiration_time(recipient["expiration_time"])
                permission_body["expirationTime"] = recipient["expiration_time"]
            except ValueError as e:
                results.append(f"  - {identifier}: Failed - {e}")
                failure_count += 1
                continue

        create_params = {
            "fileId": file_id,
            "body": permission_body,
            "supportsAllDrives": True,
            "fields": "id, type, role, emailAddress, domain, expirationTime",
        }

        if share_type in ("user", "group"):
            create_params["sendNotificationEmail"] = send_notification
            if email_message:
                create_params["emailMessage"] = email_message

        try:
            created_permission = await asyncio.to_thread(
                service.permissions().create(**create_params).execute
            )
            results.append(f"  - {format_permission_info(created_permission)}")
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


@server.tool()
@handle_http_errors("update_drive_permission", is_read_only=False, service_type="drive")
@require_google_service("drive", "drive_file")
async def update_drive_permission(
    service,
    user_google_email: str,
    file_id: str,
    permission_id: str,
    role: Optional[str] = None,
    expiration_time: Optional[str] = None,
) -> str:
    """
    Updates an existing permission on a Google Drive file or folder.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the file or folder. Required.
        permission_id (str): The ID of the permission to update (from get_drive_file_permissions). Required.
        role (Optional[str]): New role - 'reader', 'commenter', or 'writer'. If not provided, role unchanged.
        expiration_time (Optional[str]): Expiration time in RFC 3339 format (e.g., "2025-01-15T00:00:00Z"). Set or update when permission expires.

    Returns:
        str: Confirmation with updated permission details.
    """
    logger.info(
        f"[update_drive_permission] Invoked. Email: '{user_google_email}', File ID: '{file_id}', Permission ID: '{permission_id}', Role: '{role}'"
    )

    if not role and not expiration_time:
        raise ValueError("Must provide at least one of: role, expiration_time")

    if role:
        validate_share_role(role)
    if expiration_time:
        validate_expiration_time(expiration_time)

    resolved_file_id, file_metadata = await resolve_drive_item(
        service, file_id, extra_fields="name"
    )
    file_id = resolved_file_id

    # Google API requires role in update body, so fetch current if not provided
    if not role:
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
        role = current_permission.get("role")

    update_body = {"role": role}
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

    output_parts = [
        f"Successfully updated permission on '{file_metadata.get('name', 'Unknown')}'",
        "",
        "Updated permission:",
        f"  - {format_permission_info(updated_permission)}",
    ]

    return "\n".join(output_parts)


@server.tool()
@handle_http_errors("remove_drive_permission", is_read_only=False, service_type="drive")
@require_google_service("drive", "drive_file")
async def remove_drive_permission(
    service,
    user_google_email: str,
    file_id: str,
    permission_id: str,
) -> str:
    """
    Removes a permission from a Google Drive file or folder, revoking access.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the file or folder. Required.
        permission_id (str): The ID of the permission to remove (from get_drive_file_permissions). Required.

    Returns:
        str: Confirmation of the removed permission.
    """
    logger.info(
        f"[remove_drive_permission] Invoked. Email: '{user_google_email}', File ID: '{file_id}', Permission ID: '{permission_id}'"
    )

    resolved_file_id, file_metadata = await resolve_drive_item(
        service, file_id, extra_fields="name"
    )
    file_id = resolved_file_id

    await asyncio.to_thread(
        service.permissions()
        .delete(fileId=file_id, permissionId=permission_id, supportsAllDrives=True)
        .execute
    )

    output_parts = [
        f"Successfully removed permission from '{file_metadata.get('name', 'Unknown')}'",
        "",
        f"Permission ID '{permission_id}' has been revoked.",
    ]

    return "\n".join(output_parts)


@server.tool()
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


@server.tool()
@handle_http_errors(
    "transfer_drive_ownership", is_read_only=False, service_type="drive"
)
@require_google_service("drive", "drive_file")
async def transfer_drive_ownership(
    service,
    user_google_email: str,
    file_id: str,
    new_owner_email: str,
    move_to_new_owners_root: bool = False,
) -> str:
    """
    Transfers ownership of a Google Drive file or folder to another user.

    This is an irreversible operation. The current owner will become an editor.
    Only works within the same Google Workspace domain or for personal accounts.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the file or folder to transfer. Required.
        new_owner_email (str): Email address of the new owner. Required.
        move_to_new_owners_root (bool): If True, moves the file to the new owner's My Drive root. Defaults to False.

    Returns:
        str: Confirmation of the ownership transfer.
    """
    logger.info(
        f"[transfer_drive_ownership] Invoked. Email: '{user_google_email}', File ID: '{file_id}', New owner: '{new_owner_email}'"
    )

    resolved_file_id, file_metadata = await resolve_drive_item(
        service, file_id, extra_fields="name, owners"
    )
    file_id = resolved_file_id

    current_owners = file_metadata.get("owners", [])
    current_owner_emails = [o.get("emailAddress", "") for o in current_owners]

    permission_body = {
        "type": "user",
        "role": "owner",
        "emailAddress": new_owner_email,
    }

    await asyncio.to_thread(
        service.permissions()
        .create(
            fileId=file_id,
            body=permission_body,
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


@server.tool()
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
