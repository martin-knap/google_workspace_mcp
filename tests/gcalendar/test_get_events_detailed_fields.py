"""
Unit tests for get_events detailed output field parity.

The single-event branch (event_id + detailed) and the ranged branch
(time_min/time_max + detailed) should surface the same event metadata.
Historically colorId, recurringEventId, eventType and status were emitted
only for single-event lookups, so a ranged query could not be used to audit
event colours or resolve a recurring series parent.
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
