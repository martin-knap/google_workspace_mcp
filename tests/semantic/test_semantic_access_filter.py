from types import SimpleNamespace

import pytest
from googleapiclient.errors import HttpError

from semantic.semantic_tools import (
    _enrich_rows_with_drive_metadata,
    _filter_rows_by_drive_access,
    _should_bypass_drive_acl,
)


class _FakeExecute:
    def __init__(self, status: int | None):
        self.status = status

    def execute(self):
        if self.status is None:
            return {
                "id": "allowed-file",
                "createdTime": "2026-01-02T03:04:05Z",
                "modifiedTime": "2026-08-11T12:34:56Z",
            }
        raise HttpError(
            resp=SimpleNamespace(status=self.status, reason="forbidden"),
            content=b"{}",
        )


class _FakeFiles:
    def __init__(self, statuses: dict[str, int | None]):
        self.statuses = statuses

    def get(self, *, fileId: str, fields: str, supportsAllDrives: bool):
        assert fields == "id,createdTime,modifiedTime"
        assert supportsAllDrives is True
        return _FakeExecute(self.statuses[fileId])


class _FakeService:
    def __init__(self, statuses: dict[str, int | None]):
        self.statuses = statuses

    def files(self):
        return _FakeFiles(self.statuses)


@pytest.mark.asyncio
async def test_filter_rows_by_drive_access_hides_forbidden_and_missing_file_ids():
    rows = [
        {"drive_file_id": "allowed-file", "chunk_id": 1},
        {"drive_file_id": "forbidden-file", "chunk_id": 2},
        {"drive_file_id": "", "chunk_id": 3},
    ]

    accessible, filtered_count = await _filter_rows_by_drive_access(
        _FakeService({"allowed-file": None, "forbidden-file": 403}),
        rows,
        limit=10,
    )

    assert accessible == [
        {
            "drive_file_id": "allowed-file",
            "chunk_id": 1,
            "drive_created_time": "2026-01-02T03:04:05Z",
            "drive_modified_time": "2026-08-11T12:34:56Z",
        }
    ]
    assert filtered_count == 2


@pytest.mark.asyncio
async def test_trusted_rows_are_enriched_without_filtering_missing_metadata():
    rows = [
        {"drive_file_id": "allowed-file", "chunk_id": 1},
        {"drive_file_id": "missing-file", "chunk_id": 2},
    ]

    await _enrich_rows_with_drive_metadata(
        _FakeService({"allowed-file": None, "missing-file": 404}),
        rows,
    )

    assert rows[0]["drive_modified_time"] == "2026-08-11T12:34:56Z"
    assert rows[1] == {"drive_file_id": "missing-file", "chunk_id": 2}


def test_should_bypass_drive_acl_for_trusted_flatbee_accounts(monkeypatch):
    monkeypatch.delenv("SEMANTIC_SEARCH_ACL_BYPASS_EMAILS", raising=False)

    assert _should_bypass_drive_acl("ai@flatbee.cz")
    assert _should_bypass_drive_acl("jakub.chodura@flatbee.cz")
    assert _should_bypass_drive_acl("michal.kniha@flatbee.cz")
    assert _should_bypass_drive_acl("dusan.kniha@flatbee.cz")
    assert _should_bypass_drive_acl(" Michal.Kniha@flatbee.cz ")
    assert not _should_bypass_drive_acl("someone.else@flatbee.cz")


def test_should_bypass_drive_acl_can_be_overridden_by_env(monkeypatch):
    monkeypatch.setenv("SEMANTIC_SEARCH_ACL_BYPASS_EMAILS", "security@example.com")

    assert _should_bypass_drive_acl("security@example.com")
    assert not _should_bypass_drive_acl("ai@flatbee.cz")
