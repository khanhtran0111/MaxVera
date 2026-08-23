from __future__ import annotations


def test_runtime_manifest_has_no_cwe_label(separated_views) -> None:
    runtime_text = separated_views.runtime_manifest.read_text(encoding="utf-8")
    truth_text = separated_views.ground_truth.read_text(encoding="utf-8")

    assert "cwe" not in runtime_text.casefold()
    assert "Cross-site scripting" not in runtime_text
    assert "CWE-79" in truth_text
