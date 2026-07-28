"""
Unit tests for get_events detailed output field parity.

The single-event branch (event_id + detailed) and the ranged branch
(time_min/time_max + detailed) format their output separately, so they can
drift apart. Historically colorId was emitted only for single-event lookups,
and recurringEventId, eventType and status by neither. A ranged query could
not be used to audit event colours or resolve a recurring series parent.

Both branches now emit all four. The parity tests below assert that directly,
so a field added to one branch and not the other fails here.
"""

import os
import sys
from unittest.mock import Mock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from gcalendar.calendar_tools import get_events


def _unwrap(tool):
    """Unwrap FunctionTool + decorators to the original async function."""
    fn = tool.fn if hasattr(tool, "fn") else tool
    while hasattr(fn, "__wrapped__"):
        fn = fn.__wrapped__
    return fn


RECURRING_INSTANCE = {
    "id": "evt123_20260406T090000Z",
    "summary": "Standup",
    "start": {"dateTime": "2026-04-06T09:00:00Z"},
    "end": {"dateTime": "2026-04-06T09:15:00Z"},
    "htmlLink": "https://calendar.google.com/event?eid=evt123",
    "colorId": "8",
    "recurringEventId": "evt123",
    "status": "confirmed",
}


def _mock_service(items):
    mock_service = Mock()
    mock_service.events().list().execute = Mock(return_value={"items": items})
    mock_service.events().get().execute = Mock(return_value=items[0])
    return mock_service


async def _ranged_detail(item):
    """Detailed output via the time_min/time_max branch."""
    return await _unwrap(get_events)(
        service=_mock_service([item]),
        user_google_email="user@example.com",
        time_min="2026-04-06T00:00:00Z",
        time_max="2026-04-07T00:00:00Z",
        detailed=True,
    )


async def _single_detail(item):
    """Detailed output via the event_id branch."""
    return await _unwrap(get_events)(
        service=_mock_service([item]),
        user_google_email="user@example.com",
        event_id=item["id"],
        detailed=True,
    )


@pytest.mark.asyncio
async def test_ranged_detailed_output_includes_color_id():
    """A ranged detailed query must expose colorId, not just single-event lookups."""
    service = _mock_service([RECURRING_INSTANCE])

    result = await _unwrap(get_events)(
        service=service,
        user_google_email="user@example.com",
        time_min="2026-04-06T00:00:00Z",
        time_max="2026-04-07T00:00:00Z",
        detailed=True,
    )

    assert "Color ID: 8" in result


@pytest.mark.asyncio
async def test_ranged_detailed_output_includes_recurring_event_id():
    """recurringEventId is needed to update a series rather than one instance."""
    service = _mock_service([RECURRING_INSTANCE])

    result = await _unwrap(get_events)(
        service=service,
        user_google_email="user@example.com",
        time_min="2026-04-06T00:00:00Z",
        time_max="2026-04-07T00:00:00Z",
        detailed=True,
    )

    assert "Recurring Event ID: evt123" in result


@pytest.mark.asyncio
async def test_non_default_event_type_is_surfaced():
    """workingLocation/outOfOffice events are indistinguishable without eventType."""
    service = _mock_service(
        [
            {
                "id": "wl1",
                "summary": "Home",
                "start": {"date": "2026-04-06"},
                "end": {"date": "2026-04-07"},
                "htmlLink": "https://calendar.google.com/event?eid=wl1",
                "eventType": "workingLocation",
            }
        ]
    )

    result = await _unwrap(get_events)(
        service=service,
        user_google_email="user@example.com",
        time_min="2026-04-06T00:00:00Z",
        time_max="2026-04-07T00:00:00Z",
        detailed=True,
    )

    assert "Event Type: workingLocation" in result


@pytest.mark.asyncio
async def test_default_event_type_and_confirmed_status_are_omitted():
    """Only non-default values are emitted, to keep output compact."""
    service = _mock_service(
        [
            {
                "id": "evt1",
                "summary": "One-off",
                "start": {"dateTime": "2026-04-06T09:00:00Z"},
                "end": {"dateTime": "2026-04-06T09:15:00Z"},
                "htmlLink": "https://calendar.google.com/event?eid=evt1",
                "eventType": "default",
                "status": "confirmed",
            }
        ]
    )

    result = await _unwrap(get_events)(
        service=service,
        user_google_email="user@example.com",
        time_min="2026-04-06T00:00:00Z",
        time_max="2026-04-07T00:00:00Z",
        detailed=True,
    )

    assert "Event Type:" not in result
    assert "Status:" not in result
    assert "Recurring Event ID:" not in result


@pytest.mark.asyncio
async def test_missing_color_id_renders_as_none():
    """Matches the single-event branch, which defaults colorId to the string 'None'."""
    service = _mock_service(
        [
            {
                "id": "evt1",
                "summary": "No colour",
                "start": {"dateTime": "2026-04-06T09:00:00Z"},
                "end": {"dateTime": "2026-04-06T09:15:00Z"},
                "htmlLink": "https://calendar.google.com/event?eid=evt1",
            }
        ]
    )

    result = await _unwrap(get_events)(
        service=service,
        user_google_email="user@example.com",
        time_min="2026-04-06T00:00:00Z",
        time_max="2026-04-07T00:00:00Z",
        detailed=True,
    )

    assert "Color ID: None" in result


@pytest.mark.asyncio
async def test_basic_ranged_output_is_unchanged():
    """detailed=False output must stay compact — no new fields leak into it."""
    service = _mock_service([RECURRING_INSTANCE])

    result = await _unwrap(get_events)(
        service=service,
        user_google_email="user@example.com",
        time_min="2026-04-06T00:00:00Z",
        time_max="2026-04-07T00:00:00Z",
        detailed=False,
    )

    assert "Color ID" not in result
    assert "Recurring Event ID" not in result


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["cancelled", "tentative"])
async def test_non_confirmed_status_is_surfaced(status):
    """Only 'confirmed' is suppressed — other statuses must remain visible.

    Guards the omission test above: a regression that dropped every status,
    rather than just the default one, would otherwise go unnoticed.
    """
    service = _mock_service(
        [
            {
                "id": "evt123_20260406T090000Z",
                "summary": "Standup",
                "start": {"dateTime": "2026-04-06T09:00:00Z"},
                "end": {"dateTime": "2026-04-06T09:15:00Z"},
                "htmlLink": "https://calendar.google.com/event?eid=evt123",
                "recurringEventId": "evt123",
                "status": status,
            }
        ]
    )

    result = await _unwrap(get_events)(
        service=service,
        user_google_email="user@example.com",
        time_min="2026-04-06T00:00:00Z",
        time_max="2026-04-07T00:00:00Z",
        detailed=True,
    )

    assert f"Status: {status}" in result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "line",
    ["Color ID: 8", "Recurring Event ID: evt123"],
)
async def test_both_branches_emit_the_same_metadata(line):
    """The two formatters must agree — that disagreement is the bug being fixed."""
    assert line in await _ranged_detail(RECURRING_INSTANCE)
    assert line in await _single_detail(RECURRING_INSTANCE)


@pytest.mark.asyncio
async def test_single_event_branch_surfaces_non_default_event_type():
    """An event_id lookup of an outOfOffice entry must say so."""
    item = {
        "id": "ooo1",
        "summary": "Out of office",
        "start": {"date": "2026-04-06"},
        "end": {"date": "2026-04-07"},
        "htmlLink": "https://calendar.google.com/event?eid=ooo1",
        "eventType": "outOfOffice",
        "status": "tentative",
    }

    result = await _single_detail(item)

    assert "Event Type: outOfOffice" in result
    assert "Status: tentative" in result


@pytest.mark.asyncio
async def test_single_event_branch_omits_default_event_type_and_confirmed_status():
    """Compact-output rules apply to both branches, not just the ranged one."""
    item = {
        "id": "evt1",
        "summary": "One-off",
        "start": {"dateTime": "2026-04-06T09:00:00Z"},
        "end": {"dateTime": "2026-04-06T09:15:00Z"},
        "htmlLink": "https://calendar.google.com/event?eid=evt1",
        "eventType": "default",
        "status": "confirmed",
    }

    result = await _single_detail(item)

    assert "Event Type:" not in result
    assert "Status:" not in result
    assert "Recurring Event ID:" not in result
