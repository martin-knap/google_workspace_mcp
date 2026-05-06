from unittest.mock import Mock

import pytest

from core.utils import UserInputError
from gslides.slides_tools import batch_update_presentation


def _unwrap(tool):
    """Unwrap FunctionTool + decorators to the original async function."""
    fn = tool.fn if hasattr(tool, "fn") else tool
    while hasattr(fn, "__wrapped__"):
        fn = fn.__wrapped__
    return fn


def _build_slides_service(presentation=None, batch_update_response=None):
    service = Mock()
    presentations = service.presentations.return_value
    presentations.get.return_value.execute.return_value = presentation or {
        "slides": [{"objectId": "p"}]
    }
    presentations.batchUpdate.return_value.execute.return_value = (
        batch_update_response or {"replies": []}
    )
    return service, presentations


@pytest.mark.asyncio
async def test_batch_update_rejects_insert_text_targeting_slide_id():
    service, presentations = _build_slides_service()

    with pytest.raises(UserInputError) as exc_info:
        await _unwrap(batch_update_presentation)(
            service=service,
            user_google_email="user@example.com",
            presentation_id="presentation-1",
            requests=[
                {
                    "insertText": {
                        "objectId": "p",
                        "insertionIndex": 0,
                        "text": "Title",
                    }
                }
            ],
        )

    assert "requests[0].insertText.objectId='p'" in str(exc_info.value)
    assert "createShape" in str(exc_info.value)
    presentations.batchUpdate.assert_not_called()


@pytest.mark.asyncio
async def test_batch_update_rejects_insert_text_targeting_other_page_ids():
    service, presentations = _build_slides_service(
        presentation={
            "slides": [{"objectId": "slide_1"}],
            "masters": [{"objectId": "master_1"}],
            "layouts": [{"objectId": "layout_1"}],
            "notesMaster": {"objectId": "notes_master_1"},
        }
    )

    with pytest.raises(UserInputError) as exc_info:
        await _unwrap(batch_update_presentation)(
            service=service,
            user_google_email="user@example.com",
            presentation_id="presentation-1",
            requests=[
                {
                    "insertText": {
                        "objectId": "master_1",
                        "insertionIndex": 0,
                        "text": "Title",
                    }
                },
                {
                    "insertText": {
                        "objectId": "layout_1",
                        "insertionIndex": 0,
                        "text": "Title",
                    }
                },
                {
                    "insertText": {
                        "objectId": "notes_master_1",
                        "insertionIndex": 0,
                        "text": "Title",
                    }
                },
            ],
        )

    message = str(exc_info.value)
    assert "requests[0].insertText.objectId='master_1'" in message
    assert "requests[1].insertText.objectId='layout_1'" in message
    assert "requests[2].insertText.objectId='notes_master_1'" in message
    presentations.get.assert_called_once_with(
        presentationId="presentation-1",
        fields=(
            "slides(objectId),masters(objectId),layouts(objectId),notesMaster(objectId)"
        ),
    )
    presentations.batchUpdate.assert_not_called()


@pytest.mark.asyncio
async def test_batch_update_allows_insert_text_targeting_created_shape():
    service, presentations = _build_slides_service(
        batch_update_response={
            "replies": [
                {},
                {"createShape": {"objectId": "title_box"}},
                {},
            ]
        }
    )
    requests = [
        {"createSlide": {"objectId": "slide_2"}},
        {
            "createShape": {
                "objectId": "title_box",
                "shapeType": "TEXT_BOX",
                "elementProperties": {"pageObjectId": "slide_2"},
            }
        },
        {
            "insertText": {
                "objectId": "title_box",
                "insertionIndex": 0,
                "text": "Title",
            }
        },
    ]

    result = await _unwrap(batch_update_presentation)(
        service=service,
        user_google_email="user@example.com",
        presentation_id="presentation-1",
        requests=requests,
    )

    call_kwargs = presentations.batchUpdate.call_args.kwargs
    assert call_kwargs["body"] == {"requests": requests}
    assert "Batch Update Completed" in result
    assert "Created shape with ID title_box" in result


@pytest.mark.asyncio
async def test_batch_update_rejects_insert_text_targeting_new_slide_id():
    service, presentations = _build_slides_service(presentation={"slides": []})

    with pytest.raises(UserInputError) as exc_info:
        await _unwrap(batch_update_presentation)(
            service=service,
            user_google_email="user@example.com",
            presentation_id="presentation-1",
            requests=[
                {"createSlide": {"objectId": "slide_2"}},
                {
                    "insertText": {
                        "objectId": "slide_2",
                        "insertionIndex": 0,
                        "text": "Title",
                    }
                },
            ],
        )

    assert "requests[1].insertText.objectId='slide_2'" in str(exc_info.value)
    presentations.batchUpdate.assert_not_called()
