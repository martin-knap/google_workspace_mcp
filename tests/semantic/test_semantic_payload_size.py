"""Regression tests for the semantic_search_drive_docs payload size.

The original payload for queries like "kolko bytov ma Pobrezni 22" exceeded 29k
characters because every result carried verbose scoring debug, internal IDs,
folder paths, full-length snippets and near-duplicate verification blocks. The
trimmed format keeps only the title, URL, project/canonical flags, page and a
<=400 char snippet, which must stay well under 5000 chars even for the default
limit of 3 results.
"""

from __future__ import annotations

from semantic.semantic_tools import (
    SNIPPET_MAX_CHARS,
    VERIFICATION_MAX_CHARS,
    _format_result,
    _trim_snippet,
    _verification_overlap,
)


_LONG_SNIPPET = (
    "[[page 4]] Nájemce se zavazuje hradit nájemné ve výši stanovené v článku III. "
    "této smlouvy a uhradí jej vždy nejpozději do pátého dne kalendářního měsíce. "
    "Pronajímatel přenechává nájemci do užívání bytovou jednotku číslo 412 o "
    "dispozici 2+kk a o výměře 48,3 m2 nacházející se v budově Pobřežní 22, "
    "Praha 8, včetně sklepní kóje, parkovacího stání a vybavení uvedeného v "
    "příloze č. 1. Předmět nájmu je předáván ve stavu způsobilém k řádnému "
    "užívání. Veškeré opravy nad rámec běžné údržby zajišťuje pronajímatel. "
) * 6  # ~1500+ chars


def _mock_row(idx: int) -> dict:
    return {
        "file_name": f"Pobrezni 22 - Najemni smlouva byt 41{idx}.pdf",
        "drive_web_url": (
            f"https://drive.google.com/file/d/1abcDEF{idx}xyz0123456789ABCDEF/view"
        ),
        "drive_file_id": f"1abcDEF{idx}xyz0123456789ABCDEF",
        "chunk_id": 10000 + idx,
        "document_id": 5000 + idx,
        "canonical_document_id": 5000 + idx,
        "version_group_key": f"P22-byt-41{idx}-najem",
        "current_winner_document_id": 5000 + idx,
        "project_code": "P22",
        "folder_path": (
            "Flatbee/01_PROJEKTY_AKTUAL/P22_POBREZNI/Smlouvy/Najemni/2024/"
            f"Pobrezni 22 - byt 41{idx}/podepsane/finalni-verze"
        ),
        "page_number": 4,
        "page_start": 4,
        "page_end": 4,
        "combined_score": 0.8765,
        "retrieval_score": 0.8021,
        "authority_score": 0.0734,
        "vector_score": 0.6543,
        "text_score": 0.4210,
        "is_canonical": True,
        "document_metadata": {
            "current_version": True,
            "canonical_document": True,
            "project_code": "P22",
        },
        "chunk_text": _LONG_SNIPPET,
        "verification_pages": [
            {
                "page_number": 4,
                # Heavily overlapping with chunk_text -> should be dropped.
                "snippet": _LONG_SNIPPET,
            }
        ],
    }


def _build_payload(rows, *, require_hard_verify: bool = False) -> str:
    header = f"Found {len(rows)} results for 'kolko bytov ma Pobrezni 22'."
    body = [
        _format_result(row, index, require_hard_verify)
        for index, row in enumerate(rows, start=1)
    ]
    return "\n\n".join([header] + body)


def test_default_limit_payload_stays_under_5000_chars():
    rows = [_mock_row(i) for i in range(1, 4)]  # default limit = 3
    payload = _build_payload(rows)
    assert len(payload) < 5000, (
        f"Expected trimmed semantic payload <5000 chars, got {len(payload)}"
    )


def test_formatted_result_drops_verbose_debug_fields():
    payload = _format_result(_mock_row(1), 1, require_hard_verify=False)

    # Scoring debug must be gone.
    for forbidden in ("score=", "retrieval=", "authority=", "vector=", "text="):
        assert forbidden not in payload, f"{forbidden!r} should be trimmed"

    # Internal IDs must not leak into the text payload.
    for forbidden in (
        "chunk_id=",
        "document_id=",
        "canonical_document_id=",
        "version_group=",
        "current_winner_document_id=",
        "folder=",
    ):
        assert forbidden not in payload, f"{forbidden!r} should be trimmed"

    # Canonical/current flags and URL/page must remain – the model needs them
    # to cite the right (current) version.
    assert "canonical=True" in payload
    assert "current=True" in payload
    assert "url=" in payload
    assert "page=4" in payload
    assert "snippet:" in payload


def test_snippet_is_trimmed_with_page_anchor_preserved():
    payload = _format_result(_mock_row(1), 1, require_hard_verify=False)
    snippet_line = next(line for line in payload.splitlines() if "snippet:" in line)
    snippet_body = snippet_line.split("snippet:", 1)[1].strip()
    assert snippet_body.startswith("[[page 4]]")
    assert snippet_body.endswith("...")
    assert len(snippet_body) <= SNIPPET_MAX_CHARS + 1  # +1 for leading space after anchor


def test_duplicate_verification_block_is_dropped():
    payload = _format_result(_mock_row(1), 1, require_hard_verify=True)
    assert "verification:" not in payload, (
        "Verification block fully overlapping with snippet must be dropped"
    )


def test_distinct_verification_block_is_kept_and_trimmed():
    row = _mock_row(1)
    row["verification_pages"] = [
        {
            "page_number": 4,
            "snippet": (
                "Příloha č. 2 – předávací protokol uvádí, že byt 412 byl předán "
                "dne 15. 5. 2024 ve stavu plně vybaveném včetně kuchyňské linky, "
                "spotřebičů a vestavěného nábytku v ložnici. " * 4
            ),
        }
    ]
    payload = _format_result(row, 1, require_hard_verify=True)
    verification_lines = [
        line for line in payload.splitlines() if line.strip().startswith("verification:")
    ]
    assert verification_lines, "Distinct verification snippet should remain"
    verification_body = verification_lines[0].split("verification:", 1)[1].strip()
    # Strip the leading "p.4: " marker before length-checking the snippet body.
    snippet_part = verification_body.split(":", 1)[1].strip()
    assert len(snippet_part) <= VERIFICATION_MAX_CHARS + 1


def test_trim_snippet_preserves_short_text():
    assert _trim_snippet("short text", 400) == "short text"


def test_verification_overlap_full_duplicate_is_one():
    assert _verification_overlap("alpha beta gamma", "alpha beta gamma") == 1.0


def test_verification_overlap_disjoint_is_zero():
    assert _verification_overlap("alpha beta", "delta epsilon") == 0.0
