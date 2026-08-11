from __future__ import annotations

import pytest

from flatbee_ops.store import OpsStore


def workflow_payload(name: str = "project_review") -> dict:
    return {
        "name": name,
        "description": "Review one project",
        "definition": {
            "steps": [
                {
                    "type": "twenty_query",
                    "arguments": {
                        "object_name": "projects",
                        "filters": {"projectCode": "${input.project_code}"},
                    },
                }
            ]
        },
    }


def test_plan_is_actor_bound_single_use_and_versions_workflow(tmp_path):
    store = OpsStore(str(tmp_path / "ops.sqlite"))
    plan = store.prepare(
        "ai@flatbee.cz",
        "workflow.upsert",
        "Activate project_review",
        workflow_payload(),
    )

    with pytest.raises(ValueError, match="this actor"):
        store.get_plan(plan["id"], "other@flatbee.cz")
    with pytest.raises(ValueError, match="exactly match"):
        store.execute_workflow_upsert(plan["id"], "ai@flatbee.cz", "yes")

    result = store.execute_workflow_upsert(plan["id"], "ai@flatbee.cz", plan["id"])
    assert result == {
        "ok": True,
        "plan_id": plan["id"],
        "workflow": "project_review",
        "version": 1,
        "active": True,
    }
    assert store.get_workflow("project_review")["version"] == 1
    with pytest.raises(ValueError, match="completed"):
        store.execute_workflow_upsert(plan["id"], "ai@flatbee.cz", plan["id"])

    next_plan = store.prepare(
        "ai@flatbee.cz",
        "workflow.upsert",
        "Update project_review",
        workflow_payload(),
    )
    store.execute_workflow_upsert(next_plan["id"], "ai@flatbee.cz", next_plan["id"])
    assert store.get_workflow("project_review")["version"] == 2
