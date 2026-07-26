"""
Unit tests for Google Sheets helper utilities.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import pytest

from core.utils import UserInputError
from gsheets.sheets_helpers import (
    _column_to_index,
    _parse_a1_part,
    _quote_sheet_title_for_a1,
)


def test_column_to_index_valid_letters():
    assert _column_to_index("A") == 0
    assert _column_to_index("B") == 1
    assert _column_to_index("Z") == 25
    assert _column_to_index("AA") == 26
    assert _column_to_index("AL") == 37


def test_column_to_index_rejects_empty_and_non_letters():
    assert _column_to_index("") is None
    assert _column_to_index("A1") is None
    assert _column_to_index("B2") is None
    assert _column_to_index("A:B") is None
    assert _column_to_index("Sheet1") is None
    assert _column_to_index("5") is None
    assert _column_to_index("A$B") is None


def test_column_to_index_rejects_trailing_whitespace():
    """Regex anchors alone allow a trailing newline; fullmatch must reject it."""
    assert _column_to_index("A\n") is None
    assert _column_to_index("AA\n") is None
    assert _column_to_index("A ") is None
    assert _column_to_index("\nA") is None


def test_parse_a1_part_rejects_trailing_newline():
    assert _parse_a1_part("B2") == (1, 1)
    with pytest.raises(UserInputError, match="Invalid A1 range part"):
        _parse_a1_part("B2\n")


def test_quote_sheet_title_quotes_titles_with_trailing_newline():
    assert _quote_sheet_title_for_a1("Sheet1") == "Sheet1"
    assert _quote_sheet_title_for_a1("Sheet1\n") == "'Sheet1\n'"
