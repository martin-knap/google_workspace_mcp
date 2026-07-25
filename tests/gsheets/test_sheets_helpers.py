"""
Unit tests for Google Sheets helper utilities.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from gsheets.sheets_helpers import _column_to_index


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
