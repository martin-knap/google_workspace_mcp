"""Production runs `--tools flatbee_ops --tool-tier core`: an ops tool missing from the
core tier is silently not served, even though ops_capabilities and the server
instructions tell the model to call it (ops_project_brief, ops_playbook until 2026-10-08)."""

from pathlib import Path

import yaml

from flatbee_ops.ops_tools import OPS_CAPABILITIES


def test_every_advertised_ops_tool_is_in_the_core_tier():
    tiers = yaml.safe_load(
        (Path(__file__).parents[2] / "core" / "tool_tiers.yaml").read_text()
    )
    core = set(tiers["flatbee_ops"]["core"])
    advertised = {entry["tool"] for entry in OPS_CAPABILITIES}
    assert advertised - core == set()
