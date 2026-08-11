from __future__ import annotations

import pytest

from flatbee_ops.clients import _unwrap_records, twenty_query


def test_unwraps_twenty_rest_envelope():
    records, page_info = _unwrap_records(
        {
            "data": {
                "projects": [{"id": "p1", "projectCode": "P22"}],
                "pageInfo": {"totalCount": 1},
            }
        },
        "projects",
    )
    assert records == [{"id": "p1", "projectCode": "P22"}]
    assert page_info == {"totalCount": 1}


def test_unwraps_top_level_twenty_total_count():
    records, page_info = _unwrap_records(
        {
            "data": {"documents": [{"id": "d1"}]},
            "pageInfo": {"hasNextPage": True},
            "totalCount": 57,
        },
        "documents",
    )
    assert records == [{"id": "d1"}]
    assert page_info == {"hasNextPage": True, "totalCount": 57}


@pytest.mark.asyncio
async def test_twenty_query_rejects_unknown_object_before_network():
    with pytest.raises(ValueError, match="Unsupported Twenty object"):
        await twenty_query("people")


@pytest.mark.asyncio
async def test_twenty_query_rejects_unknown_filter_before_network(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://example.invalid")
    monkeypatch.setenv("TWENTY_API_KEY", "test")
    with pytest.raises(ValueError, match="Unsupported filters"):
        await twenty_query("projects", {"name": "anything"})
