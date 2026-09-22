from __future__ import annotations

import asyncio

from flatbee_ops.ops_tools import OPS_CAPABILITIES, ops_twenty_query, ops_project_brief
from flatbee_ops.project_brief import compose_project_brief
from flatbee_ops.clients import TWENTY_OBJECT_FILTERS


def _fake_twenty(data: dict[str, list[dict]], fail: set[str] = frozenset()):
    calls: list[tuple[str, dict | None, int]] = []

    async def query(object_name, filters=None, limit=50):
        calls.append((object_name, dict(filters or {}), limit))
        if object_name in fail:
            raise RuntimeError("twenty down")
        records = data.get(object_name, [])
        if filters and filters.get("status"):
            records = [r for r in records if r.get("status") == filters["status"]]
        return {
            "object": object_name,
            "count": len(records),
            "total_count": len(records),
            "truncated": False,
            "records": records,
        }

    return query, calls


def test_brief_composes_project_card(monkeypatch):
    monkeypatch.setenv("TWENTY_BASE_URL", "https://twenty.example")
    query, calls = _fake_twenty(
        {
            "projects": [
                {
                    "id": "p1",
                    "name": "PERN22",
                    "projectCode": "PERN22",
                    "lifecyclePhase": "03_ACQUISITION",
                    "driveRootPath": "01_CZ/05_PERN22",
                }
            ],
            "financings": [
                {
                    "id": "f1",
                    "financingType": "INVESTOR_LOAN",
                    "counterpartyName": "PJF Invest s.r.o.",
                    "principalCzk": 62252000,
                    "sourceFileId": "file-1",
                },
                {"id": "f2", "financingType": "BANK_LOAN", "principalCzk": 80000000},
            ],
            "leases": [
                {"id": "l1", "tenantName": "A", "monthlyRentCzk": 10000},
                {"id": "l2", "tenantName": "B", "monthlyRentCzk": 5000},
            ],
            "units": [
                {"id": "u1", "status": "OCCUPIED"},
                {"id": "u2", "status": "UNKNOWN"},
            ],
            "documents": [
                {"id": "d1", "docType": "lease"},
                {"id": "d2", "docType": "lease"},
            ],
            "dataQualityIssues": [
                {
                    "id": "q1",
                    "status": "open",
                    "title": "Missing tenant",
                    "severity": "high",
                },
                {"id": "q2", "status": "APPLIED", "title": "Done"},
            ],
            "lifecycleMilestones": [
                {
                    "id": "m1",
                    "activity": "Doplatek KC",
                    "statusCandidate": "current_candidate",
                },
                {
                    "id": "m2",
                    "activity": "DSP",
                    "statusCandidate": "planned",
                    "startDate": "2026-11-01",
                },
                {
                    "id": "m3",
                    "activity": "Geodet",
                    "statusCandidate": "planned",
                    "startDate": "2026-10-01",
                },
            ],
        }
    )
    brief = asyncio.run(compose_project_brief("PERN22", query))

    assert brief["found"] is True
    assert brief["project"]["twenty_url"] == "https://twenty.example/object/project/p1"
    assert brief["financings"]["principal_total_czk"] == 142252000
    assert brief["financings"]["by_type"] == {"INVESTOR_LOAN": 1, "BANK_LOAN": 1}
    assert brief["financings"]["items"][0]["sourceFileId"] == "file-1"
    assert brief["leases"]["monthly_rent_total_czk"] == 15000
    assert brief["units"]["by_status"] == {"OCCUPIED": 1, "UNKNOWN": 1}
    assert brief["documents"]["by_doc_type_sample"] == {"lease": 2}
    assert brief["data_quality_open"]["total_count"] == 1
    assert brief["data_quality_open"]["items"][0]["title"] == "Missing tenant"
    assert [m["activity"] for m in brief["lifecycle"]["upcoming"]] == ["Geodet", "DSP"]
    assert brief["lifecycle"]["current"][0]["activity"] == "Doplatek KC"
    assert "ops_semantic_search" in brief["authority"]
    # every read is bounded to the project and uses approved filters only
    for object_name, filters, _limit in calls:
        assert filters["projectCode"] == "PERN22"
        assert set(filters) <= TWENTY_OBJECT_FILTERS[object_name]


def test_brief_reports_missing_project():
    query, _ = _fake_twenty({})
    brief = asyncio.run(compose_project_brief("XX99", query))
    assert brief["found"] is False
    assert "ops_twenty_query" in brief["hint"]


def test_brief_survives_partial_backend_failure():
    query, _ = _fake_twenty(
        {"projects": [{"id": "p1", "projectCode": "H83"}]},
        fail={"financings", "leases"},
    )
    brief = asyncio.run(compose_project_brief("H83", query))
    assert brief["found"] is True
    assert brief["financings"]["error"].startswith("RuntimeError")
    assert brief["leases"]["error"].startswith("RuntimeError")
    assert brief["units"]["total_count"] == 0


def test_brief_is_listed_and_tool_docs_route_the_model():
    names = {item["tool"] for item in OPS_CAPABILITIES}
    assert "ops_project_brief" in names
    brief_doc = (
        ops_project_brief.fn.__doc__
        if hasattr(ops_project_brief, "fn")
        else ops_project_brief.__doc__
    )
    assert "PERN22" in brief_doc and "FIRST" in brief_doc
    twenty_doc = (
        ops_twenty_query.fn.__doc__
        if hasattr(ops_twenty_query, "fn")
        else ops_twenty_query.__doc__
    )
    for object_name in TWENTY_OBJECT_FILTERS:
        assert object_name in twenty_doc, object_name
