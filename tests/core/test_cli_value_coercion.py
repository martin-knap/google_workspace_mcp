"""Tests for workspace-cli key=value argument coercion (core.cli._coerce_cli_value).

Regression coverage for a parser that ran json.loads on every value: a quoted
string such as '"grow therapy"' is valid JSON, so the quotes were silently
stripped and Gmail phrase queries broke. Values should only be JSON-decoded when
they actually look like JSON; everything else must survive verbatim.
"""

import pytest

from core.cli import _coerce_cli_value


@pytest.mark.parametrize(
    "raw, expected",
    [
        # Plain strings survive unchanged...
        ("is:unread", "is:unread"),
        ("gmail drive calendar", "gmail drive calendar"),
        # ...including strings that merely contain quotes (Gmail phrase queries).
        ('"grow therapy"', '"grow therapy"'),
        ('"grow therapy" newer_than:15mo', '"grow therapy" newer_than:15mo'),
        # Date-like strings are not numbers and must not be coerced.
        ("2026/04/16", "2026/04/16"),
        # Empty string stays an empty string.
        ("", ""),
    ],
)
def test_strings_are_preserved_verbatim(raw, expected):
    assert _coerce_cli_value(raw) == expected


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("3", 3),
        ("-2", -2),
        ("3.5", 3.5),
        ("true", True),
        ("false", False),
        ("null", None),
        ('["a", "b"]', ["a", "b"]),
        ('[["a", "b"]]', [["a", "b"]]),
        ('{"k": 1}', {"k": 1}),
    ],
)
def test_json_like_values_are_coerced(raw, expected):
    assert _coerce_cli_value(raw) == expected
