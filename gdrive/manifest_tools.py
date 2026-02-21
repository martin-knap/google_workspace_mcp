"""
Manifest tracking tools for document extraction workflow.

These tools provide efficient, incremental updates to extraction manifests
without requiring full Drive rescans.
"""

import json
import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Any
from auth.google_auth import get_authenticated_google_service
from auth.scopes import DRIVE_SCOPES


def mark_file_as_extracted(
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
) -> Dict[str, Any]:
    """
    Mark a single file as extracted in the manifest.

    This function performs an atomic update operation:
    1. Finds the manifest file
    2. Reads current manifest
    3. Updates specific file status
    4. Recalculates statistics
    5. Writes manifest back to Drive

    Args:
        user_google_email: Google account email (e.g., "ai@flatbee.cz")
        project_id: Project identifier (e.g., "03_H83")
        source_file_id: Google Drive file ID of the source PDF
        document_type: Type of document ("invoice", "lease", "purchase_contract", etc.)
        output_file_path: Relative path to output JSON file
        extraction_quality: Quality rating ("high", "medium", "low")
        extraction_date: ISO 8601 timestamp (defaults to now if None)
        manifest_folder_id: Drive folder ID containing manifest
        pages_extracted: Number of pages extracted
        total_pages: Total pages in source document
        extraction_notes: Notes about the extraction

    Returns:
        dict: {
            "success": bool,
            "file_id": str,
            "file_name": str,
            "previous_status": str,
            "new_status": "extracted",
            "manifest_stats": {
                "total_files": int,
                "extracted": int,
                "pending": int,
                "failed": int,
                "completion_pct": float
            }
        }

    Raises:
        FileNotFoundError: If manifest or source file not found
        ValueError: If invalid parameters
    """
    # Get Drive service synchronously
    service, _ = asyncio.run(
        get_authenticated_google_service(
            service_name="drive",
            version="v3",
            tool_name="mark_file_as_extracted",
            user_google_email=user_google_email,
            required_scopes=DRIVE_SCOPES,
        )
    )

    # 1. Find manifest file
    manifest_filename = f"{project_id}_drive_scan.json"
    query = f"name = '{manifest_filename}' and '{manifest_folder_id}' in parents and trashed = false"

    results = (
        service.files().list(q=query, fields="files(id, name)", pageSize=1).execute()
    )

    manifest_files = results.get("files", [])
    if not manifest_files:
        raise FileNotFoundError(
            f"Manifest file '{manifest_filename}' not found in folder {manifest_folder_id}"
        )

    manifest_file_id = manifest_files[0]["id"]

    # 2. Read manifest content
    request = service.files().get_media(fileId=manifest_file_id)
    manifest_content = request.execute().decode("utf-8")
    manifest = json.loads(manifest_content)

    # 3. Find and update specific file
    file_found = False
    previous_status = None
    file_name = None

    for file_record in manifest.get("files", []):
        if file_record.get("file_id") == source_file_id:
            file_found = True
            previous_status = file_record.get("extraction_status", "pending")
            file_name = file_record.get("file_name", "unknown")

            # Update file record
            file_record["extraction_status"] = "extracted"
            file_record["document_type"] = document_type
            file_record["extracted_to"] = output_file_path
            file_record["extraction_date"] = (
                extraction_date or datetime.utcnow().isoformat() + "Z"
            )
            file_record["extraction_quality"] = extraction_quality

            if pages_extracted is not None:
                file_record["pages_extracted"] = pages_extracted
            if total_pages is not None:
                file_record["total_pages"] = total_pages
            if extraction_notes:
                file_record["extraction_notes"] = extraction_notes

            break

    if not file_found:
        raise FileNotFoundError(
            f"File {source_file_id} not found in manifest for project {project_id}"
        )

    # 4. Recalculate statistics
    stats = {"pending": 0, "extracted": 0, "failed": 0, "skipped": 0}

    for file_record in manifest.get("files", []):
        status = file_record.get("extraction_status", "pending")
        if status in stats:
            stats[status] += 1

    manifest["stats"] = stats
    manifest["last_updated"] = datetime.utcnow().isoformat() + "Z"

    # 5. Write manifest back to Drive
    from io import BytesIO
    from googleapiclient.http import MediaIoBaseUpload

    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)
    media = MediaIoBaseUpload(
        BytesIO(manifest_json.encode("utf-8")),
        mimetype="application/json",
        resumable=True,
    )

    service.files().update(fileId=manifest_file_id, media_body=media).execute()

    # 6. Return result
    total_files = len(manifest.get("files", []))
    completion_pct = (
        round(100.0 * stats["extracted"] / total_files, 2) if total_files > 0 else 0.0
    )

    return {
        "success": True,
        "file_id": source_file_id,
        "file_name": file_name,
        "previous_status": previous_status,
        "new_status": "extracted",
        "manifest_stats": {
            "total_files": total_files,
            "extracted": stats["extracted"],
            "pending": stats["pending"],
            "failed": stats["failed"],
            "skipped": stats["skipped"],
            "completion_pct": completion_pct,
        },
    }


def mark_files_as_extracted_batch(
    user_google_email: str,
    project_id: str,
    extracted_files: List[Dict[str, Any]],
    manifest_folder_id: str = "1ANYWlH575tOYyrCv3UwA6tOGQPi9yK0Z",
) -> Dict[str, Any]:
    """
    Mark multiple files as extracted in a single batch operation.

    More efficient than calling mark_file_as_extracted multiple times
    because it only reads/writes the manifest once.

    Args:
        user_google_email: Google account email
        project_id: Project identifier
        extracted_files: List of file records, each containing:
            {
                "source_file_id": str,
                "document_type": str,
                "output_file_path": str,
                "extraction_quality": str (optional),
                "extraction_date": str (optional),
                "pages_extracted": int (optional),
                "total_pages": int (optional),
                "extraction_notes": str (optional)
            }
        manifest_folder_id: Drive folder ID containing manifest

    Returns:
        dict: {
            "success": bool,
            "files_updated": int,
            "files_not_found": List[str],
            "manifest_stats": {...}
        }
    """
    # Get Drive service synchronously
    service, _ = asyncio.run(
        get_authenticated_google_service(
            service_name="drive",
            version="v3",
            tool_name="mark_files_as_extracted_batch",
            user_google_email=user_google_email,
            required_scopes=DRIVE_SCOPES,
        )
    )

    # 1. Find and read manifest
    manifest_filename = f"{project_id}_drive_scan.json"
    query = f"name = '{manifest_filename}' and '{manifest_folder_id}' in parents and trashed = false"

    results = (
        service.files().list(q=query, fields="files(id, name)", pageSize=1).execute()
    )

    manifest_files = results.get("files", [])
    if not manifest_files:
        raise FileNotFoundError(f"Manifest file '{manifest_filename}' not found")

    manifest_file_id = manifest_files[0]["id"]

    request = service.files().get_media(fileId=manifest_file_id)
    manifest_content = request.execute().decode("utf-8")
    manifest = json.loads(manifest_content)

    # 2. Build lookup for fast updates
    file_lookup = {
        f.get("file_id"): f for f in manifest.get("files", []) if "file_id" in f
    }

    # 3. Update all files
    files_updated = 0
    files_not_found = []

    for extracted_file in extracted_files:
        source_file_id = extracted_file.get("source_file_id")
        if not source_file_id:
            continue

        file_record = file_lookup.get(source_file_id)
        if not file_record:
            files_not_found.append(source_file_id)
            continue

        # Update record
        file_record["extraction_status"] = "extracted"
        file_record["document_type"] = extracted_file.get("document_type", "unknown")
        file_record["extracted_to"] = extracted_file.get("output_file_path", "")
        file_record["extraction_date"] = extracted_file.get(
            "extraction_date", datetime.utcnow().isoformat() + "Z"
        )
        file_record["extraction_quality"] = extracted_file.get(
            "extraction_quality", "high"
        )

        if "pages_extracted" in extracted_file:
            file_record["pages_extracted"] = extracted_file["pages_extracted"]
        if "total_pages" in extracted_file:
            file_record["total_pages"] = extracted_file["total_pages"]
        if "extraction_notes" in extracted_file:
            file_record["extraction_notes"] = extracted_file["extraction_notes"]

        files_updated += 1

    # 4. Recalculate statistics
    stats = {"pending": 0, "extracted": 0, "failed": 0, "skipped": 0}

    for file_record in manifest.get("files", []):
        status = file_record.get("extraction_status", "pending")
        if status in stats:
            stats[status] += 1

    manifest["stats"] = stats
    manifest["last_updated"] = datetime.utcnow().isoformat() + "Z"

    # 5. Write back
    from io import BytesIO
    from googleapiclient.http import MediaIoBaseUpload

    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)
    media = MediaIoBaseUpload(
        BytesIO(manifest_json.encode("utf-8")),
        mimetype="application/json",
        resumable=True,
    )

    service.files().update(fileId=manifest_file_id, media_body=media).execute()

    # 6. Return result
    total_files = len(manifest.get("files", []))
    completion_pct = (
        round(100.0 * stats["extracted"] / total_files, 2) if total_files > 0 else 0.0
    )

    return {
        "success": True,
        "files_updated": files_updated,
        "files_not_found": files_not_found,
        "manifest_stats": {
            "total_files": total_files,
            "extracted": stats["extracted"],
            "pending": stats["pending"],
            "failed": stats["failed"],
            "skipped": stats["skipped"],
            "completion_pct": completion_pct,
        },
    }
