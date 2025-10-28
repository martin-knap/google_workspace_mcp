"""
Google Drive MCP Tools

This module provides MCP tools for interacting with Google Drive API.
"""
import logging
import asyncio
from typing import Optional, List, Dict
from datetime import datetime, timedelta
import time
import json
from pathlib import Path

from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import io
import httpx
import fitz  # PyMuPDF
from google.cloud import vision
from google.oauth2.credentials import Credentials as GoogleCredentials

from auth.service_decorator import require_google_service
from auth.google_auth import get_credentials
from auth.scopes import CLOUD_VISION_SCOPE
from core.utils import extract_office_xml_text, handle_http_errors
from core.server import server
from gdrive.drive_helpers import DRIVE_QUERY_PATTERNS, build_drive_list_params

logger = logging.getLogger(__name__)

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
    logger.info(f"[search_drive_files] Invoked. Email: '{user_google_email}', Query: '{query}'")

    # Check if the query looks like a structured Drive query or free text
    # Look for Drive API operators and structured query patterns
    is_structured_query = any(pattern.search(query) for pattern in DRIVE_QUERY_PATTERNS)

    if is_structured_query:
        final_query = query
        logger.info(f"[search_drive_files] Using structured query as-is: '{final_query}'")
    else:
        # For free text queries, wrap in fullText contains
        escaped_query = query.replace("'", "\\'")
        final_query = f"fullText contains '{escaped_query}'"
        logger.info(f"[search_drive_files] Reformatting free text query '{query}' to '{final_query}'")

    list_params = build_drive_list_params(
        query=final_query,
        page_size=page_size,
        drive_id=drive_id,
        include_items_from_all_drives=include_items_from_all_drives,
        corpora=corpora,
    )

    results = await asyncio.to_thread(
        service.files().list(**list_params).execute
    )
    files = results.get('files', [])
    if not files:
        return f"No files found for '{query}'."

    formatted_files_text_parts = [f"Found {len(files)} files for {user_google_email} matching '{query}':"]
    for item in files:
        size_str = f", Size: {item.get('size', 'N/A')}" if 'size' in item else ""
        formatted_files_text_parts.append(
            f"- Name: \"{item['name']}\" (ID: {item['id']}, Type: {item['mimeType']}{size_str}, Modified: {item.get('modifiedTime', 'N/A')}) Link: {item.get('webViewLink', '#')}"
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

    file_metadata = await asyncio.to_thread(
        service.files().get(
            fileId=file_id, fields="id, name, mimeType, webViewLink", supportsAllDrives=True
        ).execute
    )
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
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
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
        f'Link: {file_metadata.get("webViewLink", "#")}\n\n--- CONTENT ---\n'
    )
    return header + body_text


@server.tool()
@handle_http_errors("list_drive_items", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def list_drive_items(
    service,
    user_google_email: str,
    folder_id: str = 'root',
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
    logger.info(f"[list_drive_items] Invoked. Email: '{user_google_email}', Folder ID: '{folder_id}'")

    final_query = f"'{folder_id}' in parents and trashed=false"

    list_params = build_drive_list_params(
        query=final_query,
        page_size=page_size,
        drive_id=drive_id,
        include_items_from_all_drives=include_items_from_all_drives,
        corpora=corpora,
    )

    results = await asyncio.to_thread(
        service.files().list(**list_params).execute
    )
    files = results.get('files', [])
    if not files:
        return f"No items found in folder '{folder_id}'."

    formatted_items_text_parts = [f"Found {len(files)} items in folder '{folder_id}' for {user_google_email}:"]
    for item in files:
        size_str = f", Size: {item.get('size', 'N/A')}" if 'size' in item else ""
        formatted_items_text_parts.append(
            f"- Name: \"{item['name']}\" (ID: {item['id']}, Type: {item['mimeType']}{size_str}, Modified: {item.get('modifiedTime', 'N/A')}) Link: {item.get('webViewLink', '#')}"
        )
    text_output = "\n".join(formatted_items_text_parts)
    return text_output

@server.tool()
@handle_http_errors("create_drive_file", service_type="drive")
@require_google_service("drive", "drive_file")
async def create_drive_file(
    service,
    user_google_email: str,
    file_name: str,
    content: Optional[str] = None,  # Now explicitly Optional
    folder_id: str = 'root',
    mime_type: str = 'text/plain',
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
        fileUrl (Optional[str]): If provided, fetches the file content from this URL.

    Returns:
        str: Confirmation message of the successful file creation with file link.
    """
    logger.info(f"[create_drive_file] Invoked. Email: '{user_google_email}', File Name: {file_name}, Folder ID: {folder_id}, fileUrl: {fileUrl}")

    if not content and not fileUrl:
        raise Exception("You must provide either 'content' or 'fileUrl'.")

    file_data = None
    # Prefer fileUrl if both are provided
    if fileUrl:
        logger.info(f"[create_drive_file] Fetching file from URL: {fileUrl}")
        async with httpx.AsyncClient() as client:
            resp = await client.get(fileUrl)
            if resp.status_code != 200:
                raise Exception(f"Failed to fetch file from URL: {fileUrl} (status {resp.status_code})")
            file_data = await resp.aread()
            # Try to get MIME type from Content-Type header
            content_type = resp.headers.get("Content-Type")
            if content_type and content_type != "application/octet-stream":
                mime_type = content_type
                logger.info(f"[create_drive_file] Using MIME type from Content-Type header: {mime_type}")
    elif content:
        file_data = content.encode('utf-8')

    file_metadata = {
        'name': file_name,
        'parents': [folder_id],
        'mimeType': mime_type
    }
    media = io.BytesIO(file_data)

    created_file = await asyncio.to_thread(
        service.files().create(
            body=file_metadata,
            media_body=MediaIoBaseUpload(media, mimetype=mime_type, resumable=True),
            fields='id, name, webViewLink',
            supportsAllDrives=True
        ).execute
    )

    link = created_file.get('webViewLink', 'No link available')
    confirmation_message = f"Successfully created file '{created_file.get('name', file_name)}' (ID: {created_file.get('id', 'N/A')}) in folder '{folder_id}' for {user_google_email}. Link: {link}"
    logger.info(f"Successfully created file. Link: {link}")
    return confirmation_message

@server.tool()
@handle_http_errors("create_drive_folder", service_type="drive")
@require_google_service("drive", "drive_file")
async def create_drive_folder(
    service,
    user_google_email: str,
    folder_name: str,
    parent_folder_id: str = 'root',
) -> str:
    """
    Creates a new folder in Google Drive, supporting creation within shared drives.

    Args:
        user_google_email (str): The user's Google email address. Required.
        folder_name (str): The name for the new folder.
        parent_folder_id (str): The ID of the parent folder. Defaults to 'root'. For shared drives, this must be a folder ID within the shared drive.

    Returns:
        str: Confirmation message of the successful folder creation with folder link.
    """
    logger.info(f"[create_drive_folder] Invoked. Email: '{user_google_email}', Folder Name: {folder_name}, Parent Folder ID: {parent_folder_id}")

    file_metadata = {
        'name': folder_name,
        'parents': [parent_folder_id],
        'mimeType': 'application/vnd.google-apps.folder'
    }

    created_folder = await asyncio.to_thread(
        service.files().create(
            body=file_metadata,
            fields='id, name, webViewLink',
            supportsAllDrives=True
        ).execute
    )

    link = created_folder.get('webViewLink', 'No link available')
    confirmation_message = f"Successfully created folder '{created_folder.get('name', folder_name)}' (ID: {created_folder.get('id', 'N/A')}) in parent folder '{parent_folder_id}' for {user_google_email}. Link: {link}"
    logger.info(f"Successfully created folder. Link: {link}")
    return confirmation_message


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
                remove_parents_arg = ",".join(current_parents) if current_parents else None

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
                "[move_drive_files] Failed to move file %s to %s", file_id, destination_folder_id
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
@handle_http_errors("update_drive_file", service_type="drive")
@require_google_service("drive", "drive_file")
async def update_drive_file(
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

    media = MediaIoBaseUpload(io.BytesIO(content.encode("utf-8")), mimetype=mime_type, resumable=True)

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
                .get(fileId=file_id, fields="id, name, mimeType", supportsAllDrives=True)
                .execute
            )

            name = metadata.get("name", file_id)
            mime_type = metadata.get("mimeType", "application/json")

            if not mime_type.endswith("json"):
                raise ValueError(f"Unsupported mime type '{mime_type}' for {name}")

            download_request = service.files().get_media(fileId=file_id, supportsAllDrives=True)
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

            media = MediaIoBaseUpload(io.BytesIO(minified.encode("utf-8")), mimetype="application/json", resumable=True)

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

    summary = [f"Processed {len(file_ids)} file(s).", f"Successful: {len(successes)}", f"Failed: {len(failures)}"]

    if successes:
        summary.append("\nSuccesses:")
        summary.extend(f"- {msg}" for msg in successes)

    if failures:
        summary.append("\nFailures:")
        summary.extend(f"- {msg}" for msg in failures)

    return "\n".join(summary)

@server.tool()
@handle_http_errors("get_drive_file_permissions", is_read_only=True, service_type="drive")
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
    logger.info(f"[get_drive_file_permissions] Checking file {file_id} for {user_google_email}")
    
    try:
        # Get comprehensive file metadata including permissions
        file_metadata = await asyncio.to_thread(
            service.files().get(
                fileId=file_id,
                fields="id, name, mimeType, size, modifiedTime, owners, permissions, "
                       "webViewLink, webContentLink, shared, sharingUser, viewersCanCopyContent",
                supportsAllDrives=True
            ).execute
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
        sharing_user = file_metadata.get('sharingUser')
        if sharing_user:
            output_parts.append(f"  Shared by: {sharing_user.get('displayName', 'Unknown')} ({sharing_user.get('emailAddress', 'Unknown')})")
        
        # Process permissions
        permissions = file_metadata.get('permissions', [])
        if permissions:
            output_parts.append(f"  Number of permissions: {len(permissions)}")
            output_parts.append("  Permissions:")
            for perm in permissions:
                perm_type = perm.get('type', 'unknown')
                role = perm.get('role', 'unknown')
                
                if perm_type == 'anyone':
                    output_parts.append(f"    - Anyone with the link ({role})")
                elif perm_type == 'user':
                    email = perm.get('emailAddress', 'unknown')
                    output_parts.append(f"    - User: {email} ({role})")
                elif perm_type == 'domain':
                    domain = perm.get('domain', 'unknown')
                    output_parts.append(f"    - Domain: {domain} ({role})")
                elif perm_type == 'group':
                    email = perm.get('emailAddress', 'unknown')
                    output_parts.append(f"    - Group: {email} ({role})")
                else:
                    output_parts.append(f"    - {perm_type} ({role})")
        else:
            output_parts.append("  No additional permissions (private file)")
        
        # Add URLs
        output_parts.extend([
            "",
            "URLs:",
            f"  View Link: {file_metadata.get('webViewLink', 'N/A')}",
        ])
        
        # webContentLink is only available for files that can be downloaded
        web_content_link = file_metadata.get('webContentLink')
        if web_content_link:
            output_parts.append(f"  Direct Download Link: {web_content_link}")
        
        # Check if file has "anyone with link" permission
        from gdrive.drive_helpers import check_public_link_permission
        has_public_link = check_public_link_permission(permissions)
        
        if has_public_link:
            output_parts.extend([
                "",
                "✅ This file is shared with 'Anyone with the link' - it can be inserted into Google Docs"
            ])
        else:
            output_parts.extend([
                "",
                "❌ This file is NOT shared with 'Anyone with the link' - it cannot be inserted into Google Docs",
                "   To fix: Right-click the file in Google Drive → Share → Anyone with the link → Viewer"
            ])
        
        return "\n".join(output_parts)
        
    except Exception as e:
        logger.error(f"Error getting file permissions: {e}")
        return f"Error getting file permissions: {e}"


@server.tool()
@handle_http_errors("check_drive_file_public_access", is_read_only=True, service_type="drive")
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
    
    results = await asyncio.to_thread(
        service.files().list(**list_params).execute
    )
    
    files = results.get('files', [])
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
    file_id = files[0]['id']
    
    # Get detailed permissions
    file_metadata = await asyncio.to_thread(
        service.files().get(
            fileId=file_id,
            fields="id, name, mimeType, permissions, webViewLink, webContentLink, shared",
            supportsAllDrives=True
        ).execute
    )
    
    permissions = file_metadata.get('permissions', [])
    from gdrive.drive_helpers import check_public_link_permission, get_drive_image_url
    has_public_link = check_public_link_permission(permissions)
    
    output_parts.extend([
        f"File: {file_metadata['name']}",
        f"ID: {file_id}",
        f"Type: {file_metadata['mimeType']}",
        f"Shared: {file_metadata.get('shared', False)}",
        ""
    ])
    
    if has_public_link:
        output_parts.extend([
            "✅ PUBLIC ACCESS ENABLED - This file can be inserted into Google Docs",
            f"Use with insert_doc_image_url: {get_drive_image_url(file_id)}"
        ])
    else:
        output_parts.extend([
            "❌ NO PUBLIC ACCESS - Cannot insert into Google Docs",
            "Fix: Drive → Share → 'Anyone with the link' → 'Viewer'"
        ])

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
    logger.info(f"[extract_drive_pdf_text] Extracting PDF text for file ID: '{file_id}'")

    # Get file metadata
    file_metadata = await asyncio.to_thread(
        service.files().get(
            fileId=file_id,
            fields="id, name, mimeType, size, modifiedTime, webViewLink",
            supportsAllDrives=True
        ).execute
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
        extracted_text, pdf_info = await loop.run_in_executor(None, extract_text_from_pdf, pdf_bytes)
    except Exception as e:
        logger.error(f"[extract_drive_pdf_text] Error extracting PDF text: {e}")
        return f"Error extracting text from PDF '{file_name}': {str(e)}"

    # Build response
    if include_metadata:
        header_parts = [
            f"File: \"{file_name}\" (ID: {file_id})",
            f"Type: {mime_type}",
            f"Size: {file_metadata.get('size', 'N/A')} bytes",
            f"Modified: {file_metadata.get('modifiedTime', 'N/A')}",
            f"Link: {file_metadata.get('webViewLink', '#')}",
            f"Pages: {pdf_info['page_count']}",
            f"Total characters extracted: {pdf_info['total_chars']}",
            "",
            "--- EXTRACTED TEXT ---",
            ""
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
@handle_http_errors("extract_scanned_pdf_text_ocr", is_read_only=True, service_type="drive")
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
        service.files().get(
            fileId=file_id,
            fields="id, name, mimeType, size, modifiedTime, webViewLink",
            supportsAllDrives=True
        ).execute
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
    def extract_page_images(pdf_data: bytes, max_pages_limit: Optional[int] = None) -> tuple[list[bytes], int]:
        """Extract each page as an image from PDF."""
        doc = fitz.open(stream=pdf_data, filetype="pdf")
        page_images = []
        total_pages = len(doc)

        # Limit pages if specified
        pages_to_process = min(total_pages, max_pages_limit) if max_pages_limit else total_pages

        for page_num in range(pages_to_process):
            page = doc[page_num]
            # Render page as image at 300 DPI for good OCR quality
            pix = page.get_pixmap(matrix=fitz.Matrix(300/72, 300/72))
            img_bytes = pix.tobytes("png")
            page_images.append(img_bytes)

        doc.close()
        return page_images, total_pages

    try:
        page_images, total_pages = await loop.run_in_executor(
            None, extract_page_images, pdf_bytes, max_pages
        )
    except Exception as e:
        logger.error(f"[extract_scanned_pdf_text_ocr] Error extracting page images: {e}")
        return f"Error extracting pages from PDF '{file_name}': {str(e)}"

    if not page_images:
        return f"No pages found in PDF '{file_name}'."

    # Get OAuth credentials for Vision API
    try:
        creds = get_credentials(user_google_email, [CLOUD_VISION_SCOPE])
        if not creds:
            return "Error: Could not retrieve credentials for Google Cloud Vision API. Please authenticate first."

        # Create Vision API client with OAuth credentials
        vision_creds = GoogleCredentials(
            token=creds.token,
            refresh_token=creds.refresh_token,
            token_uri=creds.token_uri,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            scopes=creds.scopes
        )

    except Exception as e:
        logger.error(f"[extract_scanned_pdf_text_ocr] Error setting up Vision API credentials: {e}")
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
            logger.error(f"[extract_scanned_pdf_text_ocr] Error OCR page {page_number + 1}: {e}")
            return page_number, f"[Error processing page {page_number + 1}: {str(e)}]"

    # Process all pages
    logger.info(f"[extract_scanned_pdf_text_ocr] Processing {len(page_images)} pages with Vision API OCR")

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
        pages_info = f"{len(page_images)} of {total_pages}" if max_pages and len(page_images) < total_pages else str(total_pages)
        header_parts = [
            f"File: \"{file_name}\" (ID: {file_id})",
            f"Type: {mime_type}",
            f"Size: {file_metadata.get('size', 'N/A')} bytes",
            f"Modified: {file_metadata.get('modifiedTime', 'N/A')}",
            f"Link: {file_metadata.get('webViewLink', '#')}",
            f"Pages processed: {pages_info}",
            f"Total characters extracted: {total_chars}",
            "",
            "--- EXTRACTED TEXT (via OCR) ---",
            ""
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

    async def scan_folder_recursive(folder_id: str, folder_path: str = "", current_depth: int = 0):
        """Recursively scan a folder and its subfolders."""
        nonlocal max_depth_reached, total_size_bytes

        if max_depth is not None and current_depth >= max_depth:
            return {"path": folder_path, "file_count": 0, "folder_count": 0, "files": [], "subfolders": []}

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

            items = results.get('files', [])

            for item in items:
                mime_type = item.get('mimeType', '')
                file_name = item.get('name', '')

                # Check if it's a folder
                if mime_type == 'application/vnd.google-apps.folder':
                    # Check if folder should be excluded
                    if exclude_folders and file_name in exclude_folders:
                        logger.info(f"[recursive_folder_scan] Skipping excluded folder: {file_name}")
                        continue

                    # Recursively scan subfolder
                    subfolder_path = f"{folder_path}{file_name}/"
                    subfolder_data = await scan_folder_recursive(
                        item['id'],
                        subfolder_path,
                        current_depth + 1
                    )
                    subfolders.append(subfolder_data)
                else:
                    # It's a file
                    file_ext = mime_to_ext_map.get(mime_type, file_name.split('.')[-1] if '.' in file_name else 'unknown')

                    # Filter by file types if specified
                    if file_types and file_ext.lower() not in [ft.lower() for ft in file_types]:
                        continue

                    file_size = int(item.get('size', 0)) if item.get('size') else 0
                    total_size_bytes += file_size

                    # Update stats by type
                    if file_ext not in stats_by_type:
                        stats_by_type[file_ext] = {"count": 0, "total_size": 0}
                    stats_by_type[file_ext]["count"] += 1
                    stats_by_type[file_ext]["total_size"] += file_size

                    # Build file entry
                    file_entry = {
                        "file_id": item['id'],
                        "file_name": file_name,
                        "folder_path": folder_path,
                        "file_type": file_ext,
                        "file_size": file_size,
                        "modified_date": item.get('modifiedTime', ''),
                        "web_link": item.get('webViewLink', ''),
                        "mime_type": mime_type,
                    }

                    folder_files.append(file_entry)
                    all_files.append(file_entry)

            page_token = results.get('nextPageToken')
            if not page_token:
                break

        return {
            "path": folder_path,
            "folder_id": folder_id,
            "file_count": len(folder_files),
            "folder_count": len(subfolders),
            "total_size": sum(f['file_size'] for f in folder_files),
            "files": folder_files if include_metadata else [],
            "subfolders": subfolders,
        }

    # Get root folder name first
    root_folder_metadata = await asyncio.to_thread(
        service.files().get(
            fileId=folder_id,
            fields="name",
            supportsAllDrives=True
        ).execute
    )
    root_folder_name = root_folder_metadata.get('name', folder_id)

    # Start recursive scan with root folder name as the initial path
    folder_tree = await scan_folder_recursive(folder_id, root_folder_name + "/")

    scan_time = time.time() - scan_start_time

    # Apply pagination to all_files
    total_files_scanned = len(all_files)
    paginated_files = all_files
    pagination_info = None

    if max_files is not None and page_size is not None:
        logger.warning("[recursive_folder_scan] Both max_files and page_size specified. Using max_files only.")

    if max_files is not None:
        # Simple limit on total files
        paginated_files = all_files[:max_files]
        pagination_info = {
            "total_files": total_files_scanned,
            "returned_files": len(paginated_files),
            "max_files": max_files,
        }
        logger.info(f"[recursive_folder_scan] Pagination: returning {len(paginated_files)} of {total_files_scanned} files (max_files={max_files})")
    elif page_size is not None and page_number is not None:
        # Page-based pagination
        start_idx = page_number * page_size
        end_idx = start_idx + page_size
        paginated_files = all_files[start_idx:end_idx]
        total_pages = (total_files_scanned + page_size - 1) // page_size  # Ceiling division

        pagination_info = {
            "total_files": total_files_scanned,
            "returned_files": len(paginated_files),
            "page_size": page_size,
            "page_number": page_number,
            "total_pages": total_pages,
            "has_next_page": page_number < total_pages - 1,
            "has_previous_page": page_number > 0,
        }
        logger.info(f"[recursive_folder_scan] Pagination: returning page {page_number} ({len(paginated_files)} files) of {total_pages} total pages")

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
            "all_files": paginated_files if (include_metadata and include_all_files) else [],
        }

    # If output_file is specified, write to file instead of returning
    if output_file:
        try:
            output_path = Path(output_file)
            # Create parent directories if they don't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Write JSON to file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

            file_size_kb = output_path.stat().st_size / 1024
            confirmation = {
                "status": "success",
                "message": f"Scan results written to file: {output_file}",
                "output_file": str(output_path.absolute()),
                "file_size_kb": round(file_size_kb, 2),
                "summary": summary,
            }
            logger.info(f"[recursive_folder_scan] Results written to {output_file} ({file_size_kb:.2f} KB)")
            return confirmation

        except Exception as e:
            logger.error(f"[recursive_folder_scan] Error writing to file {output_file}: {e}")
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
    for subfolder in tree_node.get('subfolders', []):
        yield from _count_folders(subfolder)


def _format_tree_text(tree_node, indent=""):
    """Format folder tree as text for visualization."""
    lines = []
    path = tree_node['path']
    file_count = tree_node['file_count']
    folder_count = tree_node['folder_count']

    lines.append(f"{indent}{path} ({file_count} files, {folder_count} folders)")

    for i, subfolder in enumerate(tree_node.get('subfolders', [])):
        is_last = i == len(tree_node['subfolders']) - 1
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

            items = results.get('files', [])

            for item in items:
                mime_type = item.get('mimeType', '')

                if mime_type == 'application/vnd.google-apps.folder':
                    total_folders += 1
                    if recursive:
                        await scan_folder(item['id'])
                else:
                    total_files += 1
                    file_size = int(item.get('size', 0)) if item.get('size') else 0
                    total_size += file_size

                    # Group by type
                    if group_by == "type":
                        file_ext = mime_to_ext_map.get(mime_type, "other")
                        breakdown[file_ext] = breakdown.get(file_ext, 0) + 1

                    # Track largest files
                    if file_size > 0:
                        largest_files.append({
                            "name": item.get('name', 'Unknown'),
                            "size_mb": round(file_size / (1024 * 1024), 2)
                        })

            page_token = results.get('nextPageToken')
            if not page_token:
                break

    # Get folder name
    folder_metadata = await asyncio.to_thread(
        service.files().get(fileId=folder_id, fields="name", supportsAllDrives=True).execute
    )
    folder_name = folder_metadata.get('name', folder_id)

    # Start scan
    await scan_folder(folder_id)

    # Sort largest files
    largest_files.sort(key=lambda x: x['size_mb'], reverse=True)
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
@handle_http_errors("get_recent_drive_activity", is_read_only=True, service_type="driveactivity")
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
    logger.info(f"[get_recent_drive_activity] Getting activity for last {days_back} days")

    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days_back)

    # Build request body
    request_body = {
        "pageSize": 100,
        "filter": f'time >= "{start_time.isoformat()}Z"'
    }

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

        for activity in response.get('activities', []):
            # Parse activity
            timestamp = activity.get('timestamp', '')
            primary_action_detail = activity.get('primaryActionDetail', {})
            targets = activity.get('targets', [])
            actors = activity.get('actors', [])

            # Get actor (user who performed the action)
            actor_email = "unknown"
            if actors:
                actor = actors[0]
                if 'user' in actor:
                    actor_email = actor['user'].get('knownUser', {}).get('personName', 'unknown')

            # Process different action types
            for target in targets:
                if 'driveItem' not in target:
                    continue

                drive_item = target['driveItem']
                file_id = drive_item.get('name', '').replace('items/', '')
                file_name = drive_item.get('title', 'Unknown')

                # Determine activity type
                activity_type = None
                old_path = None
                new_path = None
                old_name = None
                new_name = None

                if 'create' in primary_action_detail:
                    activity_type = "create"
                elif 'edit' in primary_action_detail:
                    activity_type = "edit"
                elif 'delete' in primary_action_detail:
                    activity_type = "delete"
                elif 'move' in primary_action_detail:
                    activity_type = "move"
                    move_detail = primary_action_detail['move']
                    old_path = move_detail.get('addedParents', [{}])[0].get('driveItem', {}).get('title', '')
                    new_path = move_detail.get('removedParents', [{}])[0].get('driveItem', {}).get('title', '')
                elif 'rename' in primary_action_detail:
                    activity_type = "rename"
                    rename_detail = primary_action_detail['rename']
                    old_name = rename_detail.get('oldTitle', '')
                    new_name = rename_detail.get('newTitle', '')

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

        page_token = response.get('nextPageToken')
        if not page_token:
            break

    # Generate summary
    summary = {
        "creates": sum(1 for a in activities if a['activity_type'] == 'create'),
        "edits": sum(1 for a in activities if a['activity_type'] == 'edit'),
        "deletes": sum(1 for a in activities if a['activity_type'] == 'delete'),
        "moves": sum(1 for a in activities if a['activity_type'] == 'move'),
        "renames": sum(1 for a in activities if a['activity_type'] == 'rename'),
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

        results = await asyncio.to_thread(
            service.files().list(**list_params).execute
        )

        items = results.get('files', [])
        file_count = sum(1 for item in items if item.get('mimeType') != 'application/vnd.google-apps.folder')
        folder_count = sum(1 for item in items if item.get('mimeType') == 'application/vnd.google-apps.folder')
        total_size = sum(int(item.get('size', 0)) for item in items if item.get('size'))

        # Build children
        children = []
        for item in items:
            if item.get('mimeType') == 'application/vnd.google-apps.folder':
                child_tree = await build_tree(item['id'], item['name'], current_depth + 1)
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
        service.files().get(fileId=folder_id, fields="name", supportsAllDrives=True).execute
    )
    folder_name = folder_metadata.get('name', folder_id)

    # Build tree
    tree = await build_tree(folder_id, folder_name)

    # Format as ASCII tree
    def format_tree(node, indent="", is_last=True):
        """Format tree node as ASCII."""
        prefix = "└── " if is_last else "├── "
        line = f"{indent}{prefix}{node['name']}/"

        if show_file_counts:
            line += f" ({node['file_count']} files"
            if node['folder_count'] > 0:
                line += f", {node['folder_count']} folders"
            line += ")"

        if show_sizes and node['total_size'] > 0:
            size_mb = round(node['total_size'] / (1024 * 1024), 2)
            line += f" [{size_mb} MB]"

        lines = [line]

        children = node.get('children', [])
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
    logger.info(f"[batch_get_file_metadata] Fetching metadata for {len(file_ids)} files")

    # Default fields if not specified
    if not fields:
        fields = ["id", "name", "mimeType", "size", "modifiedTime", "createdTime",
                  "webViewLink", "parents", "owners", "modifiedByMe"]

    fields_str = ", ".join(fields)

    files = []
    not_found = []

    # Fetch metadata for each file
    for file_id in file_ids:
        try:
            file_metadata = await asyncio.to_thread(
                service.files().get(
                    fileId=file_id,
                    fields=fields_str,
                    supportsAllDrives=True
                ).execute
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
@handle_http_errors("get_extraction_manifest_status", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def get_extraction_manifest_status(
    service,
    user_google_email: str,
    project_id: str = "03_H83",
    manifest_folder_id: str = "1ANYWlH575tOYyrCv3UwA6tOGQPi9yK0Z"
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
        service.files().list(
            q=query,
            fields="files(id, name, modifiedTime)",
            supportsAllDrives=True,
            includeItemsFromAllDrives=True
        ).execute
    )

    files = results.get('files', [])

    if not files:
        return f"❌ No manifest found for project {project_id}\n\nRun 'update_extraction_manifest' to create initial manifest."

    manifest_file = files[0]

    # Step 2: Read manifest content
    request = service.files().get_media(fileId=manifest_file['id'])
    file_content = io.BytesIO()
    downloader = MediaIoBaseDownload(file_content, request)

    done = False
    while not done:
        status, done = await asyncio.to_thread(downloader.next_chunk)

    file_content.seek(0)
    manifest = json.loads(file_content.read().decode('utf-8'))

    # Step 3: Calculate statistics
    files_list = manifest.get('files', [])
    stats = manifest.get('stats', {})

    pending_files = [f for f in files_list if f.get('extraction_status') == 'pending']
    extracted_files = [f for f in files_list if f.get('extraction_status') == 'extracted']

    # Step 4: Format output
    output = []
    output.append(f"📊 Extraction Status for {manifest.get('project_name', project_id)}")
    output.append("=" * 60)
    output.append(f"\n📅 Last Sync: {manifest.get('last_scan_date', 'Unknown')}")
    output.append(f"📁 Total Files: {manifest.get('total_files', 0)}")
    output.append(f"   Active: {manifest.get('active_files', 0)}")
    output.append(f"   Archived: {manifest.get('archived_files', 0)}")

    output.append(f"\n📈 Extraction Progress:")
    output.append(f"   ✅ Extracted: {stats.get('extracted', 0)}")
    output.append(f"   ⏳ Pending: {stats.get('pending', 0)}")
    output.append(f"   ❌ Failed: {stats.get('failed', 0)}")
    output.append(f"   ⏭️  Skipped: {stats.get('skipped', 0)}")

    progress = manifest.get('extraction_progress', {})
    completion = progress.get('completion_percentage', 0)
    output.append(f"   📊 Completion: {completion}%")

    # Show sample of pending files
    if pending_files:
        output.append(f"\n⏳ Files Needing Extraction (showing first 10 of {len(pending_files)}):")
        for i, file in enumerate(pending_files[:10], 1):
            doc_type = file.get('document_type') or 'unclassified'
            file_name = file.get('file_name', 'unnamed')
            folder = file.get('folder_path', '')
            output.append(f"   {i}. [{doc_type}] {file_name}")
            output.append(f"      📁 {folder}")

    # Show sample of recently extracted files
    if extracted_files:
        recent_extracted = sorted(
            extracted_files,
            key=lambda x: x.get('extraction_date', ''),
            reverse=True
        )[:5]
        output.append(f"\n✅ Recently Extracted (last 5):")
        for i, file in enumerate(recent_extracted, 1):
            doc_type = file.get('document_type') or 'unclassified'
            file_name = file.get('file_name', 'unnamed')
            extraction_date = file.get('extraction_date', 'unknown')
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
    project_name: str
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
    logger.info(f"[update_extraction_manifest] Scanning for PDFs in project {project_id}")

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
                    service.files().list(
                        q=f"'{current_folder}' in parents and trashed=false",
                        fields="files(id, name, size, modifiedTime, webViewLink, mimeType)",
                        pageSize=100,
                        pageToken=page_token,
                        supportsAllDrives=True,
                        includeItemsFromAllDrives=True
                    ).execute
                )

                for item in results.get('files', []):
                    if item['mimeType'] == 'application/vnd.google-apps.folder':
                        # Add subfolder to scan queue
                        folders_to_scan.append(item['id'])
                    elif item['mimeType'] == 'application/pdf':
                        # Add PDF file
                        all_files.append({
                            "file_id": item['id'],
                            "file_name": item['name'],
                            "file_size": int(item.get('size', 0)),
                            "folder_path": f"/{current_folder}",
                            "mime_type": item['mimeType'],
                            "modified_date": item.get('modifiedTime', ''),
                            "web_link": item.get('webViewLink', '')
                        })

                page_token = results.get('nextPageToken')
                if not page_token:
                    break
            except Exception as e:
                logger.warning(f"[update_extraction_manifest] Error scanning folder {current_folder}: {e}")
                break  # Skip this folder and continue with others

    logger.info(f"[update_extraction_manifest] Scan found {len(all_files)} PDF files")

    # Step 2: Deduplicate by file_id (same file in multiple folders)
    files_by_id = {}
    for file in all_files:
        file_id = file['file_id']
        if file_id not in files_by_id:
            files_by_id[file_id] = {
                "file_id": file_id,
                "file_name": file['file_name'],
                "file_size_bytes": file.get('file_size', 0),
                "folder_path": file['folder_path'],
                "mime_type": file['mime_type'],
                "modified_date": file['modified_date'],
                "web_link": file['web_link'],
                "extraction_status": "pending",  # Default for new files
                "document_type": None,  # Set by extraction skill
                "first_seen": datetime.utcnow().isoformat() + "Z"
            }

    logger.info(f"[update_extraction_manifest] After deduplication: {len(files_by_id)} unique files")

    # Step 3: Load existing manifest (if exists)
    existing_manifest = None
    manifest_filename = f"{project_id}_drive_scan.json"

    try:
        query = f"name='{manifest_filename}' and '{manifest_folder_id}' in parents and trashed=false"
        results = await asyncio.to_thread(
            service.files().list(
                q=query,
                fields="files(id)",
                supportsAllDrives=True,
                includeItemsFromAllDrives=True
            ).execute
        )

        if results.get('files'):
            manifest_file_id = results['files'][0]['id']
            request = service.files().get_media(fileId=manifest_file_id)
            file_content = io.BytesIO()
            downloader = MediaIoBaseDownload(file_content, request)
            done = False
            while not done:
                status, done = await asyncio.to_thread(downloader.next_chunk)
            file_content.seek(0)
            existing_manifest = json.loads(file_content.read().decode('utf-8'))
            logger.info(f"[update_extraction_manifest] Loaded existing manifest with {len(existing_manifest.get('files', []))} files")
    except Exception as e:
        logger.info(f"[update_extraction_manifest] No existing manifest found: {e}")

    # Step 4: Merge with existing manifest (SMART LOGIC)
    new_files_count = 0
    modified_files_count = 0
    unchanged_extracted_count = 0

    if existing_manifest and 'files' in existing_manifest:
        existing_by_id = {f['file_id']: f for f in existing_manifest['files']}

        for file_id, file_data in files_by_id.items():
            if file_id in existing_by_id:
                existing_file = existing_by_id[file_id]

                # KEY LOGIC: Check if file was modified AFTER extraction
                file_modified = file_data['modified_date']
                extraction_date = existing_file.get('extraction_date')

                if existing_file.get('extraction_status') == 'extracted' and extraction_date:
                    if file_modified > extraction_date:
                        # File changed after extraction - mark as pending
                        file_data['extraction_status'] = 'pending'
                        file_data['document_type'] = existing_file.get('document_type')  # Preserve classification
                        file_data['previous_extraction_date'] = extraction_date
                        modified_files_count += 1
                        logger.info(f"[update_extraction_manifest] File modified after extraction: {file_data['file_name']}")
                    else:
                        # File unchanged - preserve extraction status and ALL metadata
                        file_data['extraction_status'] = 'extracted'
                        file_data['extraction_date'] = extraction_date
                        file_data['document_type'] = existing_file.get('document_type')
                        file_data['extracted_to'] = existing_file.get('extracted_to')
                        file_data['extracted_file_id'] = existing_file.get('extracted_file_id')
                        file_data['extraction_quality'] = existing_file.get('extraction_quality')
                        file_data['pages_extracted'] = existing_file.get('pages_extracted')
                        file_data['value_czk'] = existing_file.get('value_czk')
                        unchanged_extracted_count += 1
                else:
                    # Preserve whatever status it had (pending, failed, skipped)
                    file_data['extraction_status'] = existing_file.get('extraction_status', 'pending')
                    file_data['document_type'] = existing_file.get('document_type')
                    if existing_file.get('extraction_date'):
                        file_data['extraction_date'] = existing_file['extraction_date']
                    if existing_file.get('failure_reason'):
                        file_data['failure_reason'] = existing_file['failure_reason']

                file_data['first_seen'] = existing_file.get('first_seen', file_data['first_seen'])

                # Check for moved files
                if file_data['folder_path'] != existing_file.get('folder_path'):
                    logger.info(f"[update_extraction_manifest] File moved: {file_data['file_name']}")
                    file_data['previous_folder_path'] = existing_file.get('folder_path')
            else:
                # New file
                new_files_count += 1
                logger.info(f"[update_extraction_manifest] New file: {file_data['file_name']}")
    else:
        # No existing manifest - all files are new
        new_files_count = len(files_by_id)
        logger.info(f"[update_extraction_manifest] Creating new manifest with {new_files_count} files")

    # Step 5: Mark archived files
    archived_files = []
    if existing_manifest and 'files' in existing_manifest:
        existing_by_id = {f['file_id']: f for f in existing_manifest['files']}
        existing_ids = set(f['file_id'] for f in existing_manifest['files'])
        current_ids = set(files_by_id.keys())
        deleted_ids = existing_ids - current_ids

        for file_id in deleted_ids:
            old_file = existing_by_id[file_id]
            if old_file.get('extraction_status') != 'archived':
                old_file['extraction_status'] = 'archived'
                old_file['archived_date'] = datetime.utcnow().isoformat() + "Z"
                archived_files.append(old_file)
                logger.info(f"[update_extraction_manifest] File archived: {old_file.get('file_name')}")

    # Step 6: Build updated manifest
    all_files_list = list(files_by_id.values()) + archived_files

    stats = {
        "pending": sum(1 for f in all_files_list if f['extraction_status'] == 'pending'),
        "extracted": sum(1 for f in all_files_list if f['extraction_status'] == 'extracted'),
        "failed": sum(1 for f in all_files_list if f['extraction_status'] == 'failed'),
        "skipped": sum(1 for f in all_files_list if f['extraction_status'] == 'skipped'),
        "archived": sum(1 for f in all_files_list if f['extraction_status'] == 'archived')
    }

    total_pending_and_extracted = stats['pending'] + stats['extracted']
    completion_percentage = 0
    if total_pending_and_extracted > 0:
        completion_percentage = round((stats['extracted'] / total_pending_and_extracted) * 100, 2)

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
            "extracted_documents": stats['extracted'],
            "completion_percentage": completion_percentage
        },
        "scan_metadata": {
            "scan_type": "full",
            "files_added": new_files_count,
            "files_modified": modified_files_count,
            "files_unchanged_extracted": unchanged_extracted_count,
            "files_archived": len(archived_files)
        }
    }

    # Step 7: Write manifest to Drive
    manifest_json = json.dumps(updated_manifest, indent=2, ensure_ascii=False)
    media = MediaIoBaseUpload(
        io.BytesIO(manifest_json.encode('utf-8')),
        mimetype='application/json',
        resumable=True
    )

    # Check if manifest already exists
    try:
        query = f"name='{manifest_filename}' and '{manifest_folder_id}' in parents and trashed=false"
        results = await asyncio.to_thread(
            service.files().list(
                q=query,
                fields="files(id)",
                supportsAllDrives=True,
                includeItemsFromAllDrives=True
            ).execute
        )

        if results.get('files'):
            # Update existing
            manifest_file_id = results['files'][0]['id']
            await asyncio.to_thread(
                service.files().update(
                    fileId=manifest_file_id,
                    media_body=media,
                    supportsAllDrives=True
                ).execute
            )
            logger.info(f"[update_extraction_manifest] Updated existing manifest file: {manifest_file_id}")
        else:
            # Create new
            file_metadata = {
                'name': manifest_filename,
                'parents': [manifest_folder_id],
                'mimeType': 'application/json'
            }
            result = await asyncio.to_thread(
                service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields='id',
                    supportsAllDrives=True
                ).execute
            )
            logger.info(f"[update_extraction_manifest] Created new manifest file: {result.get('id')}")
    except Exception as e:
        logger.error(f"[update_extraction_manifest] Error writing manifest: {e}")
        return f"❌ Error writing manifest: {e}"

    # Step 8: Format summary
    output = []
    output.append(f"✅ Manifest updated for {project_name}")
    output.append("=" * 60)
    output.append(f"\n📊 Scan Results:")
    output.append(f"   Total files: {updated_manifest['total_files']}")
    output.append(f"   Active: {updated_manifest['active_files']}")
    output.append(f"   Archived: {updated_manifest['archived_files']}")

    output.append(f"\n📈 Changes:")
    output.append(f"   🆕 New files: {new_files_count}")
    output.append(f"   📝 Modified files: {modified_files_count}")
    output.append(f"   ✅ Unchanged (extracted): {unchanged_extracted_count}")
    output.append(f"   🗑️  Archived files: {len(archived_files)}")

    output.append(f"\n📊 Extraction Status:")
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
    extraction_notes: Optional[str] = None
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
        extraction_notes=extraction_notes
    )

    # Format result for display
    stats = result['manifest_stats']
    output = f"""✅ Marked as extracted: {result['file_name']}

Previous status: {result['previous_status']}
New status: {result['new_status']}
Document type: {document_type}
Output: {output_file_path}

📊 Manifest Statistics:
   Total files: {stats['total_files']}
   Extracted: {stats['extracted']}
   Pending: {stats['pending']}
   Failed: {stats['failed']}
   Progress: {stats['completion_pct']}%
"""
    return output


@server.tool()
async def mark_files_as_extracted_batch(
    user_google_email: str,
    project_id: str,
    extracted_files: List[dict],
    manifest_folder_id: str = "1ANYWlH575tOYyrCv3UwA6tOGQPi9yK0Z"
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
        manifest_folder_id=manifest_folder_id
    )

    stats = result['manifest_stats']
    output = f"""✅ Batch update complete

Files updated: {result['files_updated']}
Files not found: {len(result['files_not_found'])}

📊 Manifest Statistics:
   Total files: {stats['total_files']}
   Extracted: {stats['extracted']}
   Pending: {stats['pending']}
   Failed: {stats['failed']}
   Progress: {stats['completion_pct']}%
"""

    if result['files_not_found']:
        output += f"\n⚠️ Files not found in manifest:\n"
        for file_id in result['files_not_found'][:5]:
            output += f"   - {file_id}\n"
        if len(result['files_not_found']) > 5:
            output += f"   ... and {len(result['files_not_found']) - 5} more\n"

    return output
