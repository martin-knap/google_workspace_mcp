"""One-call project card composed from bounded Twenty reads.

The brief exists so that a chat model that sees a project code (PERN22, H83,
P22 …) can load the current structured truth in one round trip instead of
asking the human to dictate prices, counterparties and dates from memory.
Everything here is `exact` authority (Twenty current state). Contract wording,
legal conditions and amounts that must be quoted still come from the source
document via semantic search; the brief points at the source files so the
model can follow up.
"""

from __future__ import annotations

import asyncio
import os
from collections import Counter
from collections.abc import Awaitable, Callable
from typing import Any

QueryFn = Callable[[str, dict[str, str] | None, int], Awaitable[dict[str, Any]]]

_SINGULAR = {
    "projects": "project",
    "financings": "financing",
    "leases": "lease",
    "unitSales": "unitSale",
    "units": "unit",
    "documents": "document",
    "dataQualityIssues": "dataQualityIssue",
    "lifecycleMilestones": "lifecycleMilestone",
}

_FINANCING_FIELDS = (
    "financingType",
    "facilityForm",
    "counterpartyName",
    "borrowerName",
    "principalCzk",
    "fundedCzk",
    "outstandingCzk",
    "currencyCode",
    "interestRatePa",
    "returnType",
    "contractDate",
    "maturityDate",
    "termMonths",
    "isSubordinated",
    "hasSecurity",
    "sourceFileName",
    "sourceFileId",
)
_LEASE_FIELDS = (
    "tenantName",
    "unitNumber",
    "leaseType",
    "monthlyRentCzk",
    "monthlyServicesCzk",
    "monthlyTotalCzk",
    "depositCzk",
    "areaSqm",
    "startDate",
    "endDate",
    "durationType",
    "sourceFileName",
    "sourceFileId",
)
_SALE_FIELDS = (
    "stage",
    "unitNumberInContract",
    "buyerName",
    "buyerType",
    "priceTotalCzk",
    "reservationDepositCzk",
    "signedDate",
    "areaSqm",
    "sourceFileName",
    "sourceFileId",
)
_DQ_FIELDS = ("title", "severity", "issueType", "recommendedAction", "sourceEvidence")
_MILESTONE_FIELDS = (
    "activity",
    "phase",
    "lifecyclePhaseCode",
    "statusCandidate",
    "startDate",
    "endDate",
    "ownerRole",
)
_PROJECT_FIELDS = (
    "name",
    "projectCode",
    "siteAddress",
    "city",
    "country",
    "businessStatus",
    "lifecyclePhase",
    "lifecyclePhases",
    "currentPhaseStart",
    "currentPhaseEnd",
    "phaseEvidence",
    "phaseSource",
    "documentControlState",
    "driveRootPath",
    "docFamilyBreakdown",
    "missingExpected",
    "cockpitNote",
    "financeNote",
)


def _twenty_url(object_name: str, record_id: Any) -> str | None:
    base = os.getenv("TWENTY_BASE_URL", "").strip().rstrip("/")
    if not base or not record_id:
        return None
    return f"{base}/object/{_SINGULAR.get(object_name, object_name)}/{record_id}"


def _pick(
    record: dict[str, Any], fields: tuple[str, ...], object_name: str
) -> dict[str, Any]:
    item = {
        key: record.get(key)
        for key in fields
        if record.get(key) not in (None, "", [], {})
    }
    item["twenty_url"] = _twenty_url(object_name, record.get("id"))
    return item


def _sum(records: list[dict[str, Any]], key: str) -> float | None:
    values = [r.get(key) for r in records if isinstance(r.get(key), (int, float))]
    return float(sum(values)) if values else None


async def _safe(coro: Awaitable[dict[str, Any]]) -> dict[str, Any]:
    try:
        return await coro
    except Exception as exc:  # backend outage must not hide the rest of the card
        return {
            "error": f"{type(exc).__name__}: {exc}",
            "records": [],
            "total_count": None,
        }


async def compose_project_brief(project_code: str, query: QueryFn) -> dict[str, Any]:
    """Compose the card. `query(object_name, filters, limit)` is the bounded Twenty read."""
    code_filter = {"projectCode": project_code}
    (
        projects,
        financings,
        leases,
        sales,
        units,
        documents,
        dq_open,
        milestones,
    ) = await asyncio.gather(
        _safe(query("projects", code_filter, 2)),
        _safe(query("financings", code_filter, 50)),
        _safe(query("leases", code_filter, 100)),
        _safe(query("unitSales", code_filter, 100)),
        _safe(query("units", code_filter, 100)),
        _safe(query("documents", code_filter, 100)),
        _safe(query("dataQualityIssues", {**code_filter, "status": "open"}, 50)),
        _safe(query("lifecycleMilestones", code_filter, 100)),
    )

    project_records = projects.get("records") or []
    if not project_records and not projects.get("error"):
        return {
            "project_code": project_code,
            "found": False,
            "hint": (
                "No Twenty project has this projectCode. Check the code with "
                "ops_twenty_query('projects') or search documents with ops_semantic_search."
            ),
        }
    project = project_records[0] if project_records else {}

    financing_records = financings.get("records") or []
    lease_records = leases.get("records") or []
    sale_records = sales.get("records") or []
    unit_records = units.get("records") or []
    document_records = documents.get("records") or []
    dq_records = dq_open.get("records") or []
    milestone_records = milestones.get("records") or []

    current = [
        m for m in milestone_records if m.get("statusCandidate") == "current_candidate"
    ]
    planned = sorted(
        (m for m in milestone_records if m.get("statusCandidate") == "planned"),
        key=lambda m: str(m.get("startDate") or "9999"),
    )

    brief: dict[str, Any] = {
        "project_code": project_code,
        "found": True,
        "authority": (
            "exact: Twenty current operational state. For contract wording, legal "
            "conditions, penalties or any amount you will quote to a counterparty, "
            "cite the source document via ops_semantic_search(project_code=...) or "
            "ops_document_read(sourceFileId)."
        ),
        "project": _pick(project, _PROJECT_FIELDS, "projects")
        if project
        else {"error": projects.get("error")},
        "financings": {
            "total_count": financings.get("total_count"),
            "principal_total_czk": _sum(financing_records, "principalCzk"),
            "by_type": dict(
                Counter(str(r.get("financingType")) for r in financing_records)
            ),
            "items": [
                _pick(r, _FINANCING_FIELDS, "financings")
                for r in financing_records[:30]
            ],
            **({"error": financings["error"]} if financings.get("error") else {}),
        },
        "leases": {
            "total_count": leases.get("total_count"),
            "monthly_rent_total_czk": _sum(lease_records, "monthlyRentCzk"),
            "monthly_total_czk": _sum(lease_records, "monthlyTotalCzk"),
            "items": [_pick(r, _LEASE_FIELDS, "leases") for r in lease_records[:25]],
            "truncated": leases.get("truncated", False) or len(lease_records) > 25,
            **({"error": leases["error"]} if leases.get("error") else {}),
        },
        "unit_sales": {
            "total_count": sales.get("total_count"),
            "price_total_czk": _sum(sale_records, "priceTotalCzk"),
            "by_stage": dict(Counter(str(r.get("stage")) for r in sale_records)),
            "items": [_pick(r, _SALE_FIELDS, "unitSales") for r in sale_records[:40]],
            **({"error": sales["error"]} if sales.get("error") else {}),
        },
        "units": {
            "total_count": units.get("total_count"),
            "by_status": dict(Counter(str(r.get("status")) for r in unit_records)),
            "by_type": dict(Counter(str(r.get("unitType")) for r in unit_records)),
            **({"error": units["error"]} if units.get("error") else {}),
        },
        "documents": {
            "total_count": documents.get("total_count"),
            "by_doc_type_sample": dict(
                Counter(str(r.get("docType")) for r in document_records).most_common(15)
            ),
            "sample_truncated": bool(documents.get("truncated")),
            "drive_root_path": project.get("driveRootPath"),
            **({"error": documents["error"]} if documents.get("error") else {}),
        },
        "data_quality_open": {
            "total_count": dq_open.get("total_count"),
            "items": [
                _pick(r, _DQ_FIELDS, "dataQualityIssues") for r in dq_records[:15]
            ],
            **({"error": dq_open["error"]} if dq_open.get("error") else {}),
        },
        "lifecycle": {
            "current": [
                _pick(m, _MILESTONE_FIELDS, "lifecycleMilestones") for m in current
            ],
            "upcoming": [
                _pick(m, _MILESTONE_FIELDS, "lifecycleMilestones") for m in planned[:8]
            ],
            "total_milestones": milestones.get("total_count"),
            **({"error": milestones["error"]} if milestones.get("error") else {}),
        },
        "follow_up": [
            "ops_semantic_search(query=..., project_code=code) for contract clauses, "
            "penalties, deadlines, escrow terms and bank offer conditions (cite the document).",
            "ops_twenty_query(object_name, filters) for exact counts and full lists "
            "beyond the samples in this card.",
            "ops_graph_search for who-is-who, aliases and relationships between "
            "people, companies and units.",
        ],
    }
    return brief
