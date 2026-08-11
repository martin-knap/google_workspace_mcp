from __future__ import annotations

import pytest

from flatbee_ops.ops_tools import (
    _template,
    _validate_project_code,
    _validate_workflow_definition,
)


def test_project_code_is_canonicalized_and_bounded():
    assert _validate_project_code(" pern22 ") == "PERN22"
    with pytest.raises(ValueError, match="canonical code"):
        _validate_project_code("../P22")


def test_workflow_rejects_arbitrary_tool_execution():
    with pytest.raises(ValueError, match="unsupported type"):
        _validate_workflow_definition(
            [{"type": "execute_any_tool", "arguments": {"name": "delete"}}]
        )


def test_workflow_templates_only_exact_input_placeholders():
    value = {
        "project_code": "${input.project_code}",
        "query": "Review ${input.project_code}",
    }
    assert _template(value, {"project_code": "P22"}) == {
        "project_code": "P22",
        "query": "Review ${input.project_code}",
    }

