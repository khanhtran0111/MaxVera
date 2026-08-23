from __future__ import annotations

import json


def test_runtime_manifest_has_no_cve(separated_views) -> None:
    runtime_text = separated_views.runtime_manifest.read_text(encoding="utf-8")
    truth_text = separated_views.ground_truth.read_text(encoding="utf-8")

    assert "cve" not in runtime_text.casefold()
    assert "CVE-2025-1234" in truth_text
    record = json.loads(runtime_text)
    assert record["instance_id"].startswith("oi_")
    assert "project_slug" not in record
