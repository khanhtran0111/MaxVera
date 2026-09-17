"""Build the deterministic Phase 8 Security KG from pinned offline sources."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import yaml

from src.common.provenance import sha256_file
from src.graphs.knowledge.model import (
    edge_record,
    graph_digest,
    node_id,
    node_record,
    sort_edges,
    sort_nodes,
)

CWE_ID_PATTERN = re.compile(r"^CWE-([1-9][0-9]{0,4})$")
OWASP_CWE_PATTERN = re.compile(r"\bCWE-([1-9][0-9]{0,4})\b")


def _text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return " ".join(" ".join(element.itertext()).split())


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _cwe_number(cwe_id: str) -> str:
    match = CWE_ID_PATTERN.fullmatch(cwe_id)
    if match is None:
        raise ValueError(f"non-canonical root CWE: {cwe_id}")
    return match.group(1)


def _merge_provenance(
    left: Sequence[Mapping[str, Any]], right: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    by_json = {
        json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")): dict(item)
        for item in [*left, *right]
    }
    return [by_json[key] for key in sorted(by_json)]


class FactStore:
    """Deduplicate canonical facts while retaining every independent provenance."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}

    def add_node(self, record: Mapping[str, Any]) -> str:
        identifier = str(record["node_id"])
        candidate = dict(record)
        existing = self.nodes.get(identifier)
        if existing is None:
            self.nodes[identifier] = candidate
            return identifier
        comparable = ("kind", "identity", "label", "properties", "layer")
        if any(existing[key] != candidate[key] for key in comparable):
            raise ValueError(f"conflicting Phase 8 node identity: {identifier}")
        existing["confidence"] = max(float(existing["confidence"]), float(candidate["confidence"]))
        existing["provenance"] = _merge_provenance(
            cast(Sequence[Mapping[str, Any]], existing["provenance"]),
            cast(Sequence[Mapping[str, Any]], candidate["provenance"]),
        )
        return identifier

    def add_edge(self, record: Mapping[str, Any]) -> str:
        identifier = str(record["edge_id"])
        candidate = dict(record)
        existing = self.edges.get(identifier)
        if existing is None:
            self.edges[identifier] = candidate
            return identifier
        comparable = ("kind", "source_id", "target_id", "properties", "layer")
        if any(existing[key] != candidate[key] for key in comparable):
            raise ValueError(f"conflicting Phase 8 edge identity: {identifier}")
        existing["confidence"] = max(float(existing["confidence"]), float(candidate["confidence"]))
        existing["provenance"] = _merge_provenance(
            cast(Sequence[Mapping[str, Any]], existing["provenance"]),
            cast(Sequence[Mapping[str, Any]], candidate["provenance"]),
        )
        return identifier


def _provenance(
    *,
    source_id: str,
    publisher: str,
    url: str,
    version: str,
    license_name: str,
    license_url: str,
    artifact_sha256: str,
    locator: str,
    extraction: str,
) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "publisher": publisher,
        "url": url,
        "version": version,
        "license": license_name,
        "license_url": license_url,
        "artifact_sha256": artifact_sha256,
        "locator": locator,
        "extraction": extraction,
    }


def _add_cwe_catalog(
    store: FactStore,
    *,
    raw_root: Path,
    source_config: Mapping[str, Any],
    experiment: Mapping[str, Any],
) -> None:
    mitre = cast(Mapping[str, Any], source_config["mitre_cwe"])
    xml_path = raw_root / str(mitre["xml_filename"])
    catalog = ET.parse(xml_path).getroot()
    namespace = catalog.tag.split("}", 1)[0].lstrip("{")
    ns = {"cwe": namespace}
    weaknesses = {
        str(item.attrib["ID"]): item
        for item in catalog.findall("cwe:Weaknesses/cwe:Weakness", ns)
    }
    roots = {
        _cwe_number(str(cwe))
        for cwe in cast(Mapping[str, Any], experiment["scope"])["root_cwes"]
    }
    view_id = str(cast(Mapping[str, Any], experiment["scope"])["related_cwe_view_id"])
    relations: list[tuple[str, str, dict[str, str]]] = []
    closure = set(roots)
    for source, weakness in weaknesses.items():
        related = weakness.find("cwe:Related_Weaknesses", ns)
        if related is None:
            continue
        for item in related.findall("cwe:Related_Weakness", ns):
            target = str(item.attrib.get("CWE_ID", ""))
            if item.attrib.get("View_ID") != view_id or target not in weaknesses:
                continue
            if source in roots or target in roots:
                relation_properties = {
                    key.lower(): str(value)
                    for key, value in sorted(item.attrib.items())
                    if key != "CWE_ID"
                }
                relations.append((source, target, relation_properties))
                closure.update((source, target))

    xml_sha = str(mitre["xml_sha256"])
    for number in sorted(closure, key=int):
        weakness = weaknesses[number]
        cwe_id = f"CWE-{number}"
        provenance = _provenance(
            source_id=str(mitre["source_id"]),
            publisher=str(mitre["publisher"]),
            url=str(mitre["definition_url_template"]).format(cwe_number=number),
            version=str(mitre["version"]),
            license_name=str(mitre["license_name"]),
            license_url=str(mitre["license_url"]),
            artifact_sha256=xml_sha,
            locator=f"Weakness[@ID='{number}']",
            extraction="MITRE CWE XML deterministic field projection",
        )
        store.add_node(
            node_record(
                kind="CWE",
                identity=cwe_id,
                label=f"{cwe_id}: {weakness.attrib['Name']}",
                properties={
                    "cwe_id": cwe_id,
                    "name": str(weakness.attrib["Name"]),
                    "abstraction": str(weakness.attrib.get("Abstraction", "")),
                    "status": str(weakness.attrib.get("Status", "")),
                    "description": _text(weakness.find("cwe:Description", ns)),
                    "scope": "root" if number in roots else "one_hop_related",
                },
                confidence=float(
                    cast(Mapping[str, Any], experiment["confidence"])[
                        "authoritative_catalog"
                    ]
                ),
                provenance=[provenance],
            )
        )

    for source, target, properties in relations:
        source_cwe = f"CWE-{source}"
        target_cwe = f"CWE-{target}"
        provenance = _provenance(
            source_id=str(mitre["source_id"]),
            publisher=str(mitre["publisher"]),
            url=str(mitre["definition_url_template"]).format(cwe_number=source),
            version=str(mitre["version"]),
            license_name=str(mitre["license_name"]),
            license_url=str(mitre["license_url"]),
            artifact_sha256=xml_sha,
            locator=f"Weakness[@ID='{source}']/Related_Weaknesses",
            extraction="MITRE CWE one-hop relation projection",
        )
        store.add_edge(
            edge_record(
                kind="RELATED_CWE",
                source_id=node_id("CWE", source_cwe),
                target_id=node_id("CWE", target_cwe),
                properties=properties,
                confidence=1.0,
                provenance=[provenance],
            )
        )

    for number in sorted(roots, key=int):
        weakness = weaknesses[number]
        cwe_id = f"CWE-{number}"
        cwe_node = node_id("CWE", cwe_id)
        base_provenance = {
            "source_id": str(mitre["source_id"]),
            "publisher": str(mitre["publisher"]),
            "url": str(mitre["definition_url_template"]).format(cwe_number=number),
            "version": str(mitre["version"]),
            "license_name": str(mitre["license_name"]),
            "license_url": str(mitre["license_url"]),
            "artifact_sha256": xml_sha,
        }
        platforms = weakness.find("cwe:Applicable_Platforms", ns)
        if platforms is not None:
            for index, platform in enumerate(platforms, start=1):
                platform_properties: dict[str, Any] = {
                    "precondition_type": "applicable_platform",
                    "platform_kind": _local_name(platform.tag),
                    "attributes": dict(
                        sorted((str(key), str(value)) for key, value in platform.attrib.items())
                    ),
                }
                if _text(platform):
                    platform_properties["text"] = _text(platform)
                identity = (
                    f"{cwe_id}:platform:{json.dumps(platform_properties, sort_keys=True)}"
                )
                provenance = _provenance(
                    **base_provenance,
                    locator=f"Weakness[@ID='{number}']/Applicable_Platforms/*[{index}]",
                    extraction="MITRE CWE platform-to-precondition projection",
                )
                precondition = store.add_node(
                    node_record(
                        kind="PRECONDITION",
                        identity=identity,
                        label=f"{cwe_id} applicable {_local_name(platform.tag)}",
                        properties=platform_properties,
                        confidence=1.0,
                        provenance=[provenance],
                    )
                )
                store.add_edge(
                    edge_record(
                        kind="HAS_PRECONDITION",
                        source_id=cwe_node,
                        target_id=precondition,
                        properties={"origin": "applicable_platform"},
                        confidence=1.0,
                        provenance=[provenance],
                    )
                )
        introductions = weakness.find("cwe:Modes_Of_Introduction", ns)
        if introductions is not None:
            for index, introduction in enumerate(introductions, start=1):
                phases = sorted(
                    {_text(item) for item in introduction.findall("cwe:Phase", ns) if _text(item)}
                )
                if not phases:
                    continue
                introduction_properties: dict[str, Any] = {
                    "precondition_type": "mode_of_introduction",
                    "phases": phases,
                }
                identity = (
                    f"{cwe_id}:introduction:"
                    f"{json.dumps(introduction_properties, sort_keys=True)}"
                )
                provenance = _provenance(
                    **base_provenance,
                    locator=f"Weakness[@ID='{number}']/Modes_Of_Introduction/Introduction[{index}]",
                    extraction="MITRE CWE introduction-phase projection",
                )
                precondition = store.add_node(
                    node_record(
                        kind="PRECONDITION",
                        identity=identity,
                        label=f"{cwe_id} introduced during {', '.join(phases)}",
                        properties=introduction_properties,
                        confidence=1.0,
                        provenance=[provenance],
                    )
                )
                store.add_edge(
                    edge_record(
                        kind="HAS_PRECONDITION",
                        source_id=cwe_node,
                        target_id=precondition,
                        properties={"origin": "mode_of_introduction"},
                        confidence=1.0,
                        provenance=[provenance],
                    )
                )
        mitigations = weakness.find("cwe:Potential_Mitigations", ns)
        if mitigations is not None:
            for index, mitigation in enumerate(mitigations, start=1):
                description = _text(mitigation.find("cwe:Description", ns))
                if not description:
                    continue
                mitigation_properties: dict[str, Any] = {
                    "phases": sorted(
                        {_text(item) for item in mitigation.findall("cwe:Phase", ns) if _text(item)}
                    ),
                    "strategy": _text(mitigation.find("cwe:Strategy", ns)),
                    "effectiveness": _text(mitigation.find("cwe:Effectiveness", ns)),
                    "description": description,
                }
                identity = (
                    f"{cwe_id}:mitigation:{json.dumps(mitigation_properties, sort_keys=True)}"
                )
                provenance = _provenance(
                    **base_provenance,
                    locator=f"Weakness[@ID='{number}']/Potential_Mitigations/Mitigation[{index}]",
                    extraction="MITRE CWE mitigation projection",
                )
                mitigation_node = store.add_node(
                    node_record(
                        kind="MITIGATION",
                        identity=identity,
                        label=f"{cwe_id} mitigation {index}",
                        properties=mitigation_properties,
                        confidence=1.0,
                        provenance=[provenance],
                    )
                )
                store.add_edge(
                    edge_record(
                        kind="MITIGATED_BY",
                        source_id=cwe_node,
                        target_id=mitigation_node,
                        properties={},
                        confidence=1.0,
                        provenance=[provenance],
                    )
                )


def _add_owasp_mapping(
    store: FactStore,
    *,
    raw_root: Path,
    source_config: Mapping[str, Any],
    experiment: Mapping[str, Any],
) -> None:
    owasp = cast(Mapping[str, Any], source_config["owasp_top10"])
    roots = set(cast(Mapping[str, Any], experiment["scope"])["root_cwes"])
    confidence = float(cast(Mapping[str, Any], experiment["confidence"])["authoritative_mapping"])
    artifacts = cast(Mapping[str, Any], owasp["artifacts"])
    for category_id in sorted(key for key in artifacts if key != "license"):
        artifact = cast(Mapping[str, Any], artifacts[category_id])
        path = raw_root / str(artifact["filename"])
        mapped = {f"CWE-{number}" for number in OWASP_CWE_PATTERN.findall(path.read_text())}
        relevant = roots & mapped
        if not relevant:
            continue
        url = (
            f"{owasp['repository']}/blob/{owasp['commit']}/{artifact['repository_path']}"
        )
        provenance = _provenance(
            source_id=str(owasp["source_id"]),
            publisher=str(owasp["publisher"]),
            url=url,
            version=str(owasp["version"]),
            license_name=str(owasp["license_name"]),
            license_url=str(owasp["license_url"]),
            artifact_sha256=str(artifact["sha256"]),
            locator="List of Mapped CWEs",
            extraction="OWASP mapped-CWE link extraction",
        )
        category_node = store.add_node(
            node_record(
                kind="OWASP_CATEGORY",
                identity=str(category_id),
                label=f"{category_id} {artifact['title']}",
                properties={"category_id": str(category_id), "title": str(artifact["title"])},
                confidence=confidence,
                provenance=[provenance],
            )
        )
        for cwe_id in sorted(relevant):
            store.add_edge(
                edge_record(
                    kind="MAPS_TO_OWASP",
                    source_id=node_id("CWE", cwe_id),
                    target_id=category_node,
                    properties={},
                    confidence=confidence,
                    provenance=[provenance],
                )
            )


def _model_kind(row: Sequence[Any], extension: str) -> str:
    index = 8 if extension == "barrierGuardModel" else 7
    return str(row[index]) if len(row) > index else ""


def _model_targets(
    row: Sequence[Any], extension: str, api_config: Mapping[str, Any]
) -> set[str]:
    kind = _model_kind(row, extension)
    if extension == "sourceModel":
        mapping = cast(Mapping[str, Any], api_config["source_kind_to_cwes"])
        return {str(value) for value in cast(Sequence[Any], mapping.get(kind, []))}
    if extension == "sinkModel":
        base_kind = kind.split("[", 1)[0]
        target = cast(Mapping[str, Any], api_config["sink_kind_to_cwe"]).get(base_kind)
        return {str(target)} if target else set()
    if extension in {"barrierModel", "barrierGuardModel"}:
        mapping = cast(Mapping[str, Any], api_config["sanitizer_kind_to_cwes"])
        return {str(value) for value in cast(Sequence[Any], mapping.get(kind, []))}
    return set()


def _api_properties(row: Sequence[Any], extension: str, relative: str) -> dict[str, Any]:
    if len(row) < 6:
        raise ValueError(f"malformed CodeQL {extension} row in {relative}")
    properties: dict[str, Any] = {
        "package": str(row[0]),
        "type": str(row[1]),
        "subtypes": bool(row[2]),
        "callable": str(row[3]),
        "signature": str(row[4]),
        "extension": str(row[5]),
        "model_file": relative,
        "model_extension": extension,
    }
    if extension in {"sourceModel", "sinkModel", "barrierModel"}:
        properties.update({"access": str(row[6]), "semantic_kind": str(row[7])})
    elif extension == "barrierGuardModel":
        properties.update(
            {"access": str(row[6]), "outcome": str(row[7]), "semantic_kind": str(row[8])}
        )
    elif extension == "summaryModel":
        properties.update(
            {"input": str(row[6]), "output": str(row[7]), "flow_kind": str(row[8])}
        )
    return properties


def _api_label(properties: Mapping[str, Any]) -> str:
    callable_name = str(properties["callable"])
    return (
        f"{properties['package']}.{properties['type']}#{callable_name}"
        f"{properties['signature']} ({properties['model_extension']})"
    )


def _add_codeql_models(
    store: FactStore,
    *,
    raw_root: Path,
    source_config: Mapping[str, Any],
    experiment: Mapping[str, Any],
) -> None:
    codeql = cast(Mapping[str, Any], source_config["codeql_java_models"])
    api_config = cast(Mapping[str, Any], experiment["api_semantics"])
    allowed_origins = {
        str(value) for value in cast(Sequence[Any], api_config["allowed_model_provenance"])
    }
    confidence_config = cast(
        Mapping[str, Any],
        cast(Mapping[str, Any], experiment["confidence"])["codeql_model_provenance"],
    )
    default_confidence = float(
        cast(Mapping[str, Any], experiment["confidence"])["unknown_codeql_model"]
    )
    pack_root = (raw_root / str(codeql["qlpack_filename"])).parent
    for path in sorted(pack_root.glob("ext/**/*.model.yml")):
        relative = path.relative_to(pack_root).as_posix()
        if not bool(api_config["include_experimental_models"]) and "experimental" in path.parts:
            continue
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, Mapping):
            raise ValueError(f"invalid CodeQL model YAML: {relative}")
        groups: list[tuple[str, int, list[Any]]] = []
        file_targets: set[str] = set()
        for extension_index, extension_item in enumerate(loaded.get("extensions", [])):
            if not isinstance(extension_item, Mapping):
                continue
            adds_to = extension_item.get("addsTo", {})
            if not isinstance(adds_to, Mapping):
                continue
            extension = str(adds_to.get("extensible", ""))
            if extension.startswith("experimental"):
                continue
            for row_index, row in enumerate(extension_item.get("data", [])):
                if not isinstance(row, list):
                    raise ValueError(f"non-list CodeQL model row in {relative}")
                if not row or str(row[-1]) not in allowed_origins:
                    continue
                groups.append((extension, row_index + extension_index * 100000, row))
                file_targets.update(_model_targets(row, extension, api_config))
        if not file_targets:
            continue
        file_sha = sha256_file(path)
        for extension, locator_index, row in groups:
            direct_targets = _model_targets(row, extension, api_config)
            if extension == "summaryModel":
                targets = set(file_targets)
                node_kind = "PROPAGATOR"
                edge_kind = "HAS_PROPAGATOR"
                derivation = "same-model-file relevant semantic closure"
            elif extension == "sourceModel" and direct_targets:
                targets = direct_targets
                node_kind = "SOURCE"
                edge_kind = "HAS_SOURCE"
                derivation = "CodeQL source-kind mapping"
            elif extension == "sinkModel" and direct_targets:
                targets = direct_targets
                node_kind = "SINK"
                edge_kind = "HAS_SINK"
                derivation = "CodeQL sink-kind mapping"
            elif extension in {"barrierModel", "barrierGuardModel"} and direct_targets:
                targets = direct_targets
                node_kind = "SANITIZER"
                edge_kind = "HAS_SANITIZER"
                derivation = "CodeQL barrier-kind mapping"
            else:
                continue
            properties = _api_properties(row, extension, relative)
            model_origin = str(row[-1]) if row else "unknown"
            properties["model_origin"] = model_origin
            confidence = float(confidence_config.get(model_origin, default_confidence))
            repository_path = f"java/ql/lib/{relative}"
            provenance = _provenance(
                source_id=str(codeql["source_id"]),
                publisher=str(codeql["publisher"]),
                url=f"{codeql['repository']}/blob/{codeql['commit']}/{repository_path}",
                version=str(codeql["version"]),
                license_name=str(codeql["license_name"]),
                license_url=str(codeql["license_url"]),
                artifact_sha256=file_sha,
                locator=f"{relative}#model-row-{locator_index}",
                extraction=f"{derivation}; provenance={model_origin}",
            )
            identity = f"{extension}:{json.dumps(row, ensure_ascii=False, separators=(',', ':'))}"
            api_node = store.add_node(
                node_record(
                    kind=node_kind,
                    identity=identity,
                    label=_api_label(properties),
                    properties=properties,
                    confidence=confidence,
                    provenance=[provenance],
                )
            )
            for cwe_id in sorted(targets):
                store.add_edge(
                    edge_record(
                        kind=edge_kind,
                        source_id=node_id("CWE", cwe_id),
                        target_id=api_node,
                        properties={"derivation": derivation},
                        confidence=confidence,
                        provenance=[provenance],
                    )
                )


def build_audit(
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    experiment: Mapping[str, Any],
) -> dict[str, Any]:
    validation = cast(Mapping[str, Any], experiment["validation"])
    required = [str(value) for value in cast(Sequence[Any], validation["required_root_relations"])]
    roots = [str(value) for value in cast(Mapping[str, Any], experiment["scope"])["root_cwes"]]
    node_by_id = {str(node["node_id"]): node for node in nodes}
    audits: list[dict[str, Any]] = []
    for cwe_id in roots:
        root_id = node_id("CWE", cwe_id)
        incident: dict[str, list[Mapping[str, Any]]] = {kind: [] for kind in required}
        for edge in edges:
            kind = str(edge["kind"])
            if kind not in incident:
                continue
            if kind == "RELATED_CWE":
                matches = root_id in {str(edge["source_id"]), str(edge["target_id"])}
            else:
                matches = str(edge["source_id"]) == root_id
            if matches:
                incident[kind].append(edge)
        samples: dict[str, Any] = {}
        for kind in required:
            choices = sorted(incident[kind], key=lambda item: str(item["edge_id"]))
            if not choices:
                continue
            sample = choices[0]
            other_id = (
                str(sample["target_id"])
                if str(sample["source_id"]) == root_id
                else str(sample["source_id"])
            )
            samples[kind] = {
                "edge_id": str(sample["edge_id"]),
                "related_node_id": other_id,
                "related_node_label": str(node_by_id[other_id]["label"]),
                "provenance_source_ids": sorted(
                    {str(item["source_id"]) for item in sample["provenance"]}
                ),
            }
        missing = [kind for kind in required if not incident[kind]]
        audits.append(
            {
                "cwe_id": cwe_id,
                "root_node_id": root_id,
                "relation_counts": {kind: len(incident[kind]) for kind in required},
                "samples": samples,
                "missing_required_relations": missing,
                "status": "PASS" if not missing else "FAIL",
            }
        )
    return {
        "schema_version": 1,
        "method": "deterministic one-fact-per-required-relation sample for each root CWE",
        "root_cwes": audits,
        "status": "PASS" if all(item["status"] == "PASS" for item in audits) else "FAIL",
    }


def build_security_kg(
    *,
    raw_root: Path,
    source_config: Mapping[str, Any],
    experiment: Mapping[str, Any],
) -> dict[str, Any]:
    store = FactStore()
    _add_cwe_catalog(
        store, raw_root=raw_root, source_config=source_config, experiment=experiment
    )
    _add_owasp_mapping(
        store, raw_root=raw_root, source_config=source_config, experiment=experiment
    )
    _add_codeql_models(
        store, raw_root=raw_root, source_config=source_config, experiment=experiment
    )
    nodes = sort_nodes(list(store.nodes.values()))
    edges = sort_edges(list(store.edges.values()))
    audit = build_audit(nodes, edges, experiment)
    return {
        "nodes": nodes,
        "edges": edges,
        "audit": audit,
        "summary": {
            "schema_version": 1,
            "nodes": len(nodes),
            "edges": len(edges),
            "node_kinds": dict(sorted(Counter(str(item["kind"]) for item in nodes).items())),
            "edge_kinds": dict(sorted(Counter(str(item["kind"]) for item in edges).items())),
            "deterministic_facts": len(nodes) + len(edges),
            "llm_inferred_facts": 0,
            "llm_calls": 0,
            "graph_sha256": graph_digest(nodes, edges),
            "audit_status": audit["status"],
        },
    }
