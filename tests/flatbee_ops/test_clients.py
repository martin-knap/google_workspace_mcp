from __future__ import annotations

import pytest

from flatbee_ops.clients import (
    _mcp_payload,
    _scope_graphiti_payload,
    _unwrap_records,
    twenty_query,
)


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


def test_unwraps_legacy_mcp_structured_result():
    result = type(
        "Result", (), {"structured_content": {"result": '{"entities":[{"uuid":"n1"}]}'}}
    )()
    assert _mcp_payload(result) == {"entities": [{"uuid": "n1"}]}


def test_graphiti_project_scope_drops_cross_project_hits():
    payload = {
        "entities": [
            {"name": "P22 Pobrezni"},
            {"name": "PERN22 Pernerova"},
            {"name": "unscoped bank"},
        ],
        "relationships": [
            {"fact": "Material for project P22 was delivered."},
            {"fact": "H83 lease ended."},
        ],
        "message": "hybrid results",
    }

    scoped, dropped = _scope_graphiti_payload(payload, "P22")

    assert scoped == {
        "entities": [{"name": "P22 Pobrezni"}],
        "relationships": [
            {"fact": "Material for project P22 was delivered."}
        ],
        "message": "hybrid results",
    }
    assert dropped == {"entities": 2, "relationships": 1}


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
