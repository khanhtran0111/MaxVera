from __future__ import annotations

from pathlib import Path

import yaml

from src.graphs.knowledge.builder import FactStore, _add_codeql_models
from src.graphs.knowledge.model import EDGE_KINDS, NODE_KINDS, edge_id, node_id
from src.graphs.knowledge.prepare import model_tree_digest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _source_config() -> dict[str, object]:
    return {
        "codeql_java_models": {
            "source_id": "codeql-test",
            "publisher": "GitHub",
            "version": "codeql/java-all@test",
            "repository": "https://github.com/github/codeql",
            "commit": "a" * 40,
            "qlpack_filename": "codeql/java-all-test/qlpack.yml",
            "license_name": "MIT",
            "license_url": "https://opensource.org/license/mit",
        }
    }


def _experiment() -> dict[str, object]:
    return {
        "api_semantics": {
            "include_experimental_models": False,
            "allowed_model_provenance": ["manual", "ai-manual"],
            "source_kind_to_cwes": {"remote": ["CWE-22", "CWE-78"]},
            "sink_kind_to_cwe": {
                "path-injection": "CWE-22",
                "command-injection": "CWE-78",
            },
            "sanitizer_kind_to_cwes": {"html-injection": ["CWE-79"]},
        },
        "confidence": {
            "codeql_model_provenance": {"manual": 1.0, "ai-manual": 0.9},
            "unknown_codeql_model": 0.75,
        },
    }


def test_phase8_config_locks_sources_scope_schema_and_dependencies() -> None:
    config = yaml.safe_load(
        (REPO_ROOT / "configs/experiments/phase8_security_kg.yaml").read_text(
            encoding="utf-8"
        )
    )
    sources = yaml.safe_load(
        (REPO_ROOT / "configs/knowledge/phase8_sources.yaml").read_text(encoding="utf-8")
    )
    assert config["protocol_version"] == "1.5.0"
    assert config["scope"]["graph_scope"] == "global"
    assert config["scope"]["root_cwes"] == ["CWE-22", "CWE-78", "CWE-79", "CWE-94"]
    assert set(config["schema"]["node_kinds"]) == NODE_KINDS
    assert set(config["schema"]["edge_kinds"]) == EDGE_KINDS
    assert config["development_dependencies"]["phase6"]["run_id"] == (
        "p6_static_v2_dev_full_001"
    )
    assert config["development_dependencies"]["phase7"]["run_id"] == "p7_pg_dev_full_004"
    assert sources["mitre_cwe"]["version"] == "4.20"
    assert len(sources["mitre_cwe"]["xml_sha256"]) == 64
    assert len(sources["owasp_top10"]["commit"]) == 40
    assert sources["codeql_java_models"]["version"] == "codeql/java-all@9.2.2"
    assert sources["codeql_java_models"]["model_file_count"] == 613


def test_phase8_canonical_selection_is_locked_to_clean_full_002() -> None:
    main = yaml.safe_load(
        (REPO_ROOT / "configs/experiments/main.yaml").read_text(encoding="utf-8")
    )
    lock = main["development_locks"]["phase8_security_knowledge_graph"]
    assert lock["status"] == "locked_for_downstream_development"
    assert lock["canonical_run_id"] == "p8_skg_global_full_002"
    assert lock["run_commit"] == "50ed53ee5b99ce3adeae81fbbf9c41c33e4fe70a"
    assert lock["run_git_dirty"] is False
    assert lock["graph_sha256"] == (
        "8685f50d8e5f3727aa8cba9361f739c58fc57fb3ba444d59a9577dc413fbc805"
    )
    assert lock["llm_inferred_facts"] == 0


def test_phase8_codeql_semantics_are_role_separated_and_provenance_complete(
    tmp_path: Path,
) -> None:
    pack = tmp_path / "codeql/java-all-test"
    model = pack / "ext/example.model.yml"
    model.parent.mkdir(parents=True)
    model.write_text(
        """extensions:
  - addsTo: {pack: codeql/java-all, extensible: sourceModel}
    data:
      - [example, Request, false, get, '()', '', ReturnValue, remote, manual]
  - addsTo: {pack: codeql/java-all, extensible: sinkModel}
    data:
      - [java.io, File, false, File, '(String)', '', 'Argument[0]', path-injection, ai-manual]
  - addsTo: {pack: codeql/java-all, extensible: barrierModel}
    data:
      - [example, Html, false, escape, '(String)', '', ReturnValue, html-injection, manual]
  - addsTo: {pack: codeql/java-all, extensible: summaryModel}
    data:
      - [java.lang, String, false, trim, '()', '', 'Argument[this]', ReturnValue, taint, manual]
""",
        encoding="utf-8",
    )
    (pack / "qlpack.yml").write_text("name: codeql/java-all\n", encoding="utf-8")
    store = FactStore()
    _add_codeql_models(
        store,
        raw_root=tmp_path,
        source_config=_source_config(),
        experiment=_experiment(),
    )
    assert {node["kind"] for node in store.nodes.values()} == {
        "SOURCE",
        "SINK",
        "SANITIZER",
        "PROPAGATOR",
    }
    assert {edge["kind"] for edge in store.edges.values()} == {
        "HAS_SOURCE",
        "HAS_SINK",
        "HAS_SANITIZER",
        "HAS_PROPAGATOR",
    }
    assert all(node["layer"] == "deterministic" for node in store.nodes.values())
    assert all(node["provenance"] for node in store.nodes.values())
    sink = next(node for node in store.nodes.values() if node["kind"] == "SINK")
    assert sink["confidence"] == 0.9
    assert sink["properties"]["semantic_kind"] == "path-injection"


def test_phase8_model_tree_digest_is_path_stable(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    for root in (first, second):
        path = root / "ext/nested/example.model.yml"
        path.parent.mkdir(parents=True)
        path.write_text("extensions: []\n", encoding="utf-8")
    assert model_tree_digest(first) == model_tree_digest(second)


def test_phase8_ids_change_only_with_canonical_identity_or_edge_properties() -> None:
    cwe = node_id("CWE", "CWE-22")
    assert cwe == node_id("CWE", "CWE-22")
    assert cwe != node_id("CWE", "CWE-78")
    first = edge_id("RELATED_CWE", cwe, node_id("CWE", "CWE-73"), {"nature": "ChildOf"})
    second = edge_id("RELATED_CWE", cwe, node_id("CWE", "CWE-73"), {"nature": "PeerOf"})
    assert first != second
