"""
Google Word MCP Tools

This module provides MCP tools for interacting with Word documents stored in Google Drive.
Uses server-side conversion to Google Docs format to avoid downloading files.
"""

import logging
import asyncio
from datetime import datetime

from auth.service_decorator import require_google_service, require_multiple_services
from core.server import server
from core.utils import handle_http_errors

# Configure module logger
logger = logging.getLogger(__name__)

# Word MIME type constant
WORD_MIME_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
DOCS_MIME_TYPE = "application/vnd.google-apps.document"


@server.tool()
@handle_http_errors("list_word_files", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def list_word_files(
    service,
    user_google_email: str,
    max_results: int = 25,
) -> str:
    """
    Lists Word (.docx) documents from Google Drive that the user has access to.

    Args:
        user_google_email (str): The user's Google email address. Required.
        max_results (int): Maximum number of Word documents to return. Defaults to 25.

    Returns:
        str: A formatted list of Word documents (name, ID, modified time, link).
    """
    logger.info(f"[list_word_files] Invoked. Email: '{user_google_email}'")

    files_response = await asyncio.to_thread(
        service.files()
        .list(
            q=f"mimeType='{WORD_MIME_TYPE}'",
            pageSize=max_results,
            fields="files(id,name,modifiedTime,webViewLink)",
            orderBy="modifiedTime desc",
        )
        .execute
    )

    files = files_response.get("files", [])
    if not files:
        return f"No Word documents found for {user_google_email}."

    files_list = [
        f"- \"{file['name']}\" (ID: {file['id']}) | Modified: {file.get('modifiedTime', 'Unknown')} | Link: {file.get('webViewLink', 'No link')}"
        for file in files
    ]

    text_output = (
        f"Successfully listed {len(files)} Word documents for {user_google_email}:\n"
        + "\n".join(files_list)
    )

    logger.info(f"Successfully listed {len(files)} Word documents for {user_google_email}.")
    return text_output


@server.tool()
@handle_http_errors("get_word_info", is_read_only=True, service_type="word")
@require_multiple_services([
    {"service_type": "drive", "scopes": "drive_file", "param_name": "drive_service"},
    {"service_type": "docs", "scopes": "docs_read", "param_name": "docs_service"}
])
async def get_word_info(
    drive_service,
    docs_service,
    user_google_email: str,
    file_id: str,
) -> str:
    """
    Gets information about a Word document including title and content statistics.

    This tool temporarily converts the Word document to Google Docs format to read
    metadata, then automatically deletes the temporary file.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the Word document to get info for. Required.

    Returns:
        str: Formatted Word document information including title and statistics.
    """
    logger.info(f"[get_word_info] Invoked. Email: '{user_google_email}', File ID: {file_id}")

    # First, verify this is a Word document and get its name
    file_metadata = await asyncio.to_thread(
        drive_service.files().get(
            fileId=file_id,
            fields="id, name, mimeType, size, modifiedTime"
        ).execute
    )

    file_name = file_metadata.get("name", "Unknown")
    mime_type = file_metadata.get("mimeType", "")

    if mime_type != WORD_MIME_TYPE:
        return f"Error: File '{file_name}' is not a Word document (MIME type: {mime_type}). Expected {WORD_MIME_TYPE}."

    # Create temporary Google Docs copy for inspection
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_name = f"_temp_word_info_{file_id}_{timestamp}"

    logger.info(f"[get_word_info] Creating temporary Docs copy: {temp_name}")

    temp_file = await asyncio.to_thread(
        drive_service.files().copy(
            fileId=file_id,
            body={
                'name': temp_name,
                'mimeType': DOCS_MIME_TYPE
            }
        ).execute
    )

    temp_file_id = temp_file['id']
    logger.info(f"[get_word_info] Temporary file created with ID: {temp_file_id}")

    try:
        # Get document metadata and content
        document = await asyncio.to_thread(
            docs_service.documents().get(documentId=temp_file_id).execute
        )

        title = document.get("title", "Unknown")

        # Extract content statistics
        content = document.get("body", {}).get("content", [])

        # Count paragraphs and estimate word count
        paragraph_count = 0
        total_text = ""

        for element in content:
            if "paragraph" in element:
                paragraph_count += 1
                paragraph = element["paragraph"]
                for elem in paragraph.get("elements", []):
                    if "textRun" in elem:
                        text_content = elem["textRun"].get("content", "")
                        total_text += text_content

        # Estimate word count (split by whitespace)
        word_count = len(total_text.split())
        char_count = len(total_text)

        text_output = (
            f"Word Document: \"{file_name}\" (ID: {file_id})\n"
            f"Title: {title}\n"
            f"Size: {file_metadata.get('size', 'Unknown')} bytes\n"
            f"Modified: {file_metadata.get('modifiedTime', 'Unknown')}\n"
            f"Statistics:\n"
            f"  - Paragraphs: {paragraph_count}\n"
            f"  - Words (estimated): {word_count}\n"
            f"  - Characters: {char_count}"
        )

        logger.info(f"Successfully retrieved info for Word document {file_id} for {user_google_email}.")
        return text_output

    finally:
        # ALWAYS delete the temporary file
        logger.info(f"[get_word_info] Cleaning up temporary file: {temp_file_id}")
        try:
            await asyncio.to_thread(
                drive_service.files().delete(fileId=temp_file_id).execute
            )
            logger.info("[get_word_info] Temporary file deleted successfully")
        except Exception as cleanup_error:
            logger.error(f"[get_word_info] Failed to delete temporary file {temp_file_id}: {cleanup_error}")
            # Don't raise - cleanup failure shouldn't fail the operation


@server.tool()
@handle_http_errors("read_word_content", is_read_only=True, service_type="word")
@require_multiple_services([
    {"service_type": "drive", "scopes": "drive_file", "param_name": "drive_service"},
    {"service_type": "docs", "scopes": "docs_read", "param_name": "docs_service"}
])
async def read_word_content(
    drive_service,
    docs_service,
    user_google_email: str,
    file_id: str,
) -> str:
    """
    Reads the full text content from a Word document.

    This tool temporarily converts the Word document to Google Docs format to read
    the content, then automatically deletes the temporary file.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the Word document. Required.

    Returns:
        str: The formatted text content from the Word document.
    """
    logger.info(f"[read_word_content] Invoked. Email: '{user_google_email}', File ID: {file_id}")

    # First, verify this is a Word document and get its name
    file_metadata = await asyncio.to_thread(
        drive_service.files().get(
            fileId=file_id,
            fields="id, name, mimeType"
        ).execute
    )

    file_name = file_metadata.get("name", "Unknown")
    mime_type = file_metadata.get("mimeType", "")

    if mime_type != WORD_MIME_TYPE:
        return f"Error: File '{file_name}' is not a Word document (MIME type: {mime_type}). Expected {WORD_MIME_TYPE}."

    # Create temporary Google Docs copy for reading
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_name = f"_temp_word_read_{file_id}_{timestamp}"

    logger.info(f"[read_word_content] Creating temporary Docs copy: {temp_name}")

    temp_file = await asyncio.to_thread(
        drive_service.files().copy(
            fileId=file_id,
            body={
                'name': temp_name,
                'mimeType': DOCS_MIME_TYPE
            }
        ).execute
    )

    temp_file_id = temp_file['id']
    logger.info(f"[read_word_content] Temporary file created with ID: {temp_file_id}")

    try:
        # Get document content
        document = await asyncio.to_thread(
            docs_service.documents().get(documentId=temp_file_id).execute
        )

        title = document.get("title", "Unknown")
        content = document.get("body", {}).get("content", [])

        # Extract all text content
        text_parts = []

        for element in content:
            if "paragraph" in element:
                paragraph = element["paragraph"]
                paragraph_text = ""

                for elem in paragraph.get("elements", []):
                    if "textRun" in elem:
                        text_content = elem["textRun"].get("content", "")
                        paragraph_text += text_content

                if paragraph_text.strip():
                    text_parts.append(paragraph_text.rstrip())
            elif "table" in element:
                # Note presence of tables
                text_parts.append("[Table content - structure preserved in original document]")

        full_text = "\n".join(text_parts)

        if not full_text.strip():
            return f"No text content found in Word document '{file_name}'."

        # Format output with header
        text_output = (
            f"Word Document: \"{file_name}\" (ID: {file_id})\n"
            f"Title: {title}\n"
            f"\n--- CONTENT ---\n\n"
            f"{full_text}"
        )

        logger.info(f"Successfully read content from Word document {file_id} for {user_google_email}.")
        return text_output

    finally:
        # ALWAYS delete the temporary file
        logger.info(f"[read_word_content] Cleaning up temporary file: {temp_file_id}")
        try:
            await asyncio.to_thread(
                drive_service.files().delete(fileId=temp_file_id).execute
            )
            logger.info("[read_word_content] Temporary file deleted successfully")
        except Exception as cleanup_error:
            logger.error(f"[read_word_content] Failed to delete temporary file {temp_file_id}: {cleanup_error}")
            # Don't raise - cleanup failure shouldn't fail the operation
