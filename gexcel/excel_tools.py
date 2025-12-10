"""
Google Excel MCP Tools

This module provides MCP tools for interacting with Excel files stored in Google Drive.
Uses server-side conversion to Google Sheets format to avoid downloading files.
"""

import logging
import asyncio
from datetime import datetime

from auth.service_decorator import require_google_service
from core.server import server
from core.utils import handle_http_errors
from googleapiclient.discovery import build

# Configure module logger
logger = logging.getLogger(__name__)

# Excel MIME type constant
EXCEL_MIME_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
SHEETS_MIME_TYPE = "application/vnd.google-apps.spreadsheet"


@server.tool()
@handle_http_errors("list_excel_files", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def list_excel_files(
    service,
    user_google_email: str,
    max_results: int = 25,
) -> str:
    """
    Lists Excel (.xlsx) files from Google Drive that the user has access to.

    Args:
        max_results (int): Maximum number of Excel files to return. Defaults to 25.

    Returns:
        str: A formatted list of Excel files (name, ID, modified time, link).
    """
    logger.info(f"[list_excel_files] Invoked. Email: '{user_google_email}'")

    files_response = await asyncio.to_thread(
        service.files()
        .list(
            q=f"mimeType='{EXCEL_MIME_TYPE}'",
            pageSize=max_results,
            fields="files(id,name,modifiedTime,webViewLink)",
            orderBy="modifiedTime desc",
        )
        .execute
    )

    files = files_response.get("files", [])
    if not files:
        return f"No Excel files found for {user_google_email}."

    files_list = [
        f"- \"{file['name']}\" (ID: {file['id']}) | Modified: {file.get('modifiedTime', 'Unknown')} | Link: {file.get('webViewLink', 'No link')}"
        for file in files
    ]

    text_output = (
        f"Successfully listed {len(files)} Excel files for {user_google_email}:\n"
        + "\n".join(files_list)
    )

    logger.info(f"Successfully listed {len(files)} Excel files for {user_google_email}.")
    return text_output


@server.tool()
@handle_http_errors("get_excel_info", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_file")
async def get_excel_info(
    service,
    user_google_email: str,
    file_id: str,
) -> str:
    """
    Gets information about an Excel file including its worksheets and dimensions.

    This tool temporarily converts the Excel file to Google Sheets format to read
    metadata, then automatically deletes the temporary file.

    Args:
        file_id (str): The ID of the Excel file to get info for. Required.

    Returns:
        str: Formatted Excel file information including title and worksheet details.
    """
    logger.info(f"[get_excel_info] Invoked. Email: '{user_google_email}', File ID: {file_id}")

    drive_service = service
    
    # Build sheets service using the same credentials
    sheets_service = build("sheets", "v4", credentials=service._http.credentials)

    # First, verify this is an Excel file and get its name
    file_metadata = await asyncio.to_thread(
        drive_service.files().get(
            fileId=file_id,
            fields="id, name, mimeType"
        ).execute
    )

    file_name = file_metadata.get("name", "Unknown")
    mime_type = file_metadata.get("mimeType", "")

    if mime_type != EXCEL_MIME_TYPE:
        return f"Error: File '{file_name}' is not an Excel file (MIME type: {mime_type}). Expected {EXCEL_MIME_TYPE}."

    # Create temporary Google Sheets copy for inspection
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_name = f"_temp_excel_info_{file_id}_{timestamp}"

    logger.info(f"[get_excel_info] Creating temporary Sheets copy: {temp_name}")

    temp_file = await asyncio.to_thread(
        drive_service.files().copy(
            fileId=file_id,
            body={
                'name': temp_name,
                'mimeType': SHEETS_MIME_TYPE
            }
        ).execute
    )

    temp_file_id = temp_file['id']
    logger.info(f"[get_excel_info] Temporary file created with ID: {temp_file_id}")

    try:
        # Get spreadsheet metadata
        spreadsheet = await asyncio.to_thread(
            sheets_service.spreadsheets().get(spreadsheetId=temp_file_id).execute
        )

        sheets = spreadsheet.get("sheets", [])

        sheets_info = []
        for sheet in sheets:
            sheet_props = sheet.get("properties", {})
            sheet_name = sheet_props.get("title", "Unknown")
            sheet_id = sheet_props.get("sheetId", "Unknown")
            grid_props = sheet_props.get("gridProperties", {})
            rows = grid_props.get("rowCount", "Unknown")
            cols = grid_props.get("columnCount", "Unknown")

            sheets_info.append(
                f"  - \"{sheet_name}\" (ID: {sheet_id}) | Size: {rows}x{cols}"
            )

        text_output = (
            f"Excel File: \"{file_name}\" (ID: {file_id})\n"
            f"Worksheets ({len(sheets)}):\n"
            + "\n".join(sheets_info) if sheets_info else "  No worksheets found"
        )

        logger.info(f"Successfully retrieved info for Excel file {file_id} for {user_google_email}.")
        return text_output

    finally:
        # ALWAYS delete the temporary file
        logger.info(f"[get_excel_info] Cleaning up temporary file: {temp_file_id}")
        try:
            await asyncio.to_thread(
                drive_service.files().delete(fileId=temp_file_id).execute
            )
            logger.info("[get_excel_info] Temporary file deleted successfully")
        except Exception as cleanup_error:
            logger.error(f"[get_excel_info] Failed to delete temporary file {temp_file_id}: {cleanup_error}")


@server.tool()
@handle_http_errors("read_excel_values", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_file")
async def read_excel_values(
    service,
    user_google_email: str,
    file_id: str,
    range_name: str = "A1:Z1000",
) -> str:
    """
    Reads values from a specific range in an Excel file.

    This tool temporarily converts the Excel file to Google Sheets format to read
    the data, then automatically deletes the temporary file.

    Args:
        file_id (str): The ID of the Excel file. Required.
        range_name (str): The range to read (e.g., "Sheet1!A1:D10", "A1:D10"). Defaults to "A1:Z1000".

    Returns:
        str: The formatted values from the specified range.
    """
    logger.info(f"[read_excel_values] Invoked. Email: '{user_google_email}', File ID: {file_id}, Range: {range_name}")

    drive_service = service
    
    # Build sheets service using the same credentials
    sheets_service = build("sheets", "v4", credentials=service._http.credentials)

    # First, verify this is an Excel file and get its name
    file_metadata = await asyncio.to_thread(
        drive_service.files().get(
            fileId=file_id,
            fields="id, name, mimeType"
        ).execute
    )

    file_name = file_metadata.get("name", "Unknown")
    mime_type = file_metadata.get("mimeType", "")

    if mime_type != EXCEL_MIME_TYPE:
        return f"Error: File '{file_name}' is not an Excel file (MIME type: {mime_type}). Expected {EXCEL_MIME_TYPE}."

    # Create temporary Google Sheets copy for reading
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_name = f"_temp_excel_read_{file_id}_{timestamp}"

    logger.info(f"[read_excel_values] Creating temporary Sheets copy: {temp_name}")

    temp_file = await asyncio.to_thread(
        drive_service.files().copy(
            fileId=file_id,
            body={
                'name': temp_name,
                'mimeType': SHEETS_MIME_TYPE
            }
        ).execute
    )

    temp_file_id = temp_file['id']
    logger.info(f"[read_excel_values] Temporary file created with ID: {temp_file_id}")

    try:
        # Read values from the temporary Sheets file
        result = await asyncio.to_thread(
            sheets_service.spreadsheets()
            .values()
            .get(spreadsheetId=temp_file_id, range=range_name)
            .execute
        )

        values = result.get("values", [])
        if not values:
            return f"No data found in range '{range_name}' for Excel file '{file_name}'."

        # Format the output as a readable table
        formatted_rows = []
        for i, row in enumerate(values, 1):
            # Pad row with empty strings to show structure
            padded_row = row + [""] * max(0, len(values[0]) - len(row)) if values else row
            formatted_rows.append(f"Row {i:2d}: {padded_row}")

        text_output = (
            f"Successfully read {len(values)} rows from range '{range_name}' in Excel file '{file_name}' (ID: {file_id}) for {user_google_email}:\n"
            + "\n".join(formatted_rows[:50])  # Limit to first 50 rows for readability
            + (f"\n... and {len(values) - 50} more rows" if len(values) > 50 else "")
        )

        logger.info(f"Successfully read {len(values)} rows from Excel file for {user_google_email}.")
        return text_output

    finally:
        # ALWAYS delete the temporary file
        logger.info(f"[read_excel_values] Cleaning up temporary file: {temp_file_id}")
        try:
            await asyncio.to_thread(
                drive_service.files().delete(fileId=temp_file_id).execute
            )
            logger.info("[read_excel_values] Temporary file deleted successfully")
        except Exception as cleanup_error:
            logger.error(f"[read_excel_values] Failed to delete temporary file {temp_file_id}: {cleanup_error}")
