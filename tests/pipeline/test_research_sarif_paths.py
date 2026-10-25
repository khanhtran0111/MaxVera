"""Shared SARIF decoding must preserve repository path identity and traversal."""

import json

import pytest


@pytest.mark.parametrize("uri", [".maven-runtime/X.java", "./.hidden/X.java", "../escape.java"])
def test_research_sarif_paths_do_not_strip_meaningful_dots(tmp_path, uri):
    from maxvera.reproduction import normalize_sarif

    path = tmp_path / "static.sarif"
    path.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": uri},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        )
    )
    normalized = normalize_sarif(path, "opaque", "static_alerts")
    assert normalized[0]["locations"][0]["file"] == uri.removeprefix("./")
