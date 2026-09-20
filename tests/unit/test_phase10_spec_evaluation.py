from __future__ import annotations

from src.specification.evaluation import _matches, _node_location


def test_program_and_evidence_locations_are_normalized() -> None:
    program = {
        "layer": "program",
        "properties": {"location": {"file": "./src/Main.java", "start_line": 12}},
    }
    evidence = {
        "layer": "evidence",
        "properties": {"file": "src/Main.java", "line": 13},
    }
    security = {"layer": "security", "properties": {"file": "src/Main.java", "line": 13}}

    assert _node_location(program) == ("src/Main.java", 12)
    assert _node_location(evidence) == ("src/Main.java", 13)
    assert _node_location(security) is None


def test_fix_scope_matching_supports_line_and_file_annotations() -> None:
    assert _matches(("src/Main.java", 12), [("src/Main.java", 10, 20)])
    assert not _matches(("src/Main.java", 21), [("src/Main.java", 10, 20)])
    assert _matches(("src/Main.java", 999), [("src/Main.java", None, None)])
    assert not _matches(None, [("src/Main.java", None, None)])

