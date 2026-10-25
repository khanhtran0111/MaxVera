"""Exact source-backed endpoint verification against the private research database."""

from __future__ import annotations

import csv
import json
import shutil

from maxvera.contracts import digest, redact, safe_id
from maxvera.graph import relative_file
from maxvera.orchestration import Context, StageFailure
from maxvera.process import command
from maxvera.research_database import validate_database
from src.common.provenance import sha256_file
from src.reproduction.common import atomic_jsonl, read_jsonl

FLOW_COLUMNS = [
    f"{role}_{field}"
    for role in ("source", "sink")
    for field in ("file", "line", "start_column", "end_line", "end_column")
]


def classify_verification(source_count: int, sink_count: int, flow_count: int) -> str:
    if source_count != 1 or sink_count != 1:
        return "UNSUPPORTED_SPEC"
    return "FLOW_FOUND" if flow_count > 0 else "NO_FLOW_FOUND"


def _binding(name: str, node: dict) -> str:
    file = json.dumps(relative_file(node["file"]), ensure_ascii=True)
    positions = {
        key: int(node[key]) for key in ("start_line", "start_column", "end_line", "end_column")
    }
    if any(value < 1 for value in positions.values()):
        raise ValueError("targeted endpoint requires positive exact source span")
    return f"""predicate {name}(DataFlow::Node node) {{
  (node = DataFlow::exprNode(node.asExpr()) or
   node = DataFlow::parameterNode(node.asParameter())) and
  node.getLocation().getFile().getRelativePath() = {file} and
  node.getLocation().getStartLine() = {positions["start_line"]} and
  node.getLocation().getStartColumn() = {positions["start_column"]} and
  node.getLocation().getEndLine() = {positions["end_line"]} and
  node.getLocation().getEndColumn() = {positions["end_column"]}
}}"""


def render_queries(candidate_id: str, source: dict, sink: dict) -> tuple[str, str]:
    safe_id(candidate_id)
    common = f"""import java
import semmle.code.java.dataflow.TaintTracking

{_binding("researchSource", source)}

{_binding("researchSink", sink)}
"""
    endpoints = f"""/**
 * @name MaxVera exact endpoint inventory
 * @kind table
 * @id java/maxvera/research/{candidate_id}/endpoints
 */
{common}
from int sourceCount, int sinkCount
where
  sourceCount = count(DataFlow::Node node | researchSource(node)) and
  sinkCount = count(DataFlow::Node node | researchSink(node))
select sourceCount as source_count, sinkCount as sink_count
"""
    flow = f"""/**
 * @name MaxVera targeted modeled taint reachability
 * @kind table
 * @id java/maxvera/research/{candidate_id}/flow
 */
{common}
module ResearchConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node node) {{ researchSource(node) }}
  predicate isSink(DataFlow::Node node) {{ researchSink(node) }}
}}
module ResearchFlow = TaintTracking::Global<ResearchConfig>;

from DataFlow::Node source, DataFlow::Node sink
where ResearchFlow::flow(source, sink)
select source.getLocation().getFile().getRelativePath() as source_file,
  source.getLocation().getStartLine() as source_line,
  source.getLocation().getStartColumn() as source_start_column,
  source.getLocation().getEndLine() as source_end_line,
  source.getLocation().getEndColumn() as source_end_column,
  sink.getLocation().getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line,
  sink.getLocation().getStartColumn() as sink_start_column,
  sink.getLocation().getEndLine() as sink_end_line,
  sink.getLocation().getEndColumn() as sink_end_column
"""
    return endpoints, flow


def _csv(path, expected_columns):
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != expected_columns:
            raise StageFailure("QUERY_INVALID", "unexpected targeted query result columns")
        rows = list(reader)
        if any(
            set(row) != set(expected_columns) or any(value is None for value in row.values())
            for row in rows
        ):
            raise StageFailure("QUERY_INVALID", "malformed targeted query result row")
        return rows


def _endpoints(ctx: Context, candidate: dict, graph: dict) -> tuple[dict, dict]:
    extraction = ctx.output("static_extract")
    snapshot = extraction.get("semantic_snapshot_id", extraction["analyzed_snapshot_id"])
    if candidate["snapshot_id"] != snapshot or graph["snapshot_id"] != snapshot:
        raise ValueError("verification snapshot mismatch")
    full_snapshot = extraction["analyzed_snapshot_id"]
    if (
        graph.get("analyzed_snapshot_id", full_snapshot) != full_snapshot
        or candidate.get("provenance", {}).get("analyzed_snapshot_id", full_snapshot)
        != full_snapshot
    ):
        raise ValueError("verification mixes different analyzed build snapshots")
    by_id = {n["node_id"]: n for n in graph["nodes"]}
    source, sink = (
        by_id.get(candidate.get("source_node_id")),
        by_id.get(candidate.get("sink_node_id")),
    )
    if source is None or sink is None:
        if candidate.get("source_node_id") or candidate.get("sink_node_id"):
            raise ValueError("candidate lacks frozen explicit graph source/sink endpoints")
        from maxvera.sarif_endpoints import resolve_endpoints

        extraction_dir = ctx.run_dir / "stages" / ctx.case["case_id"] / "static_extract"
        return resolve_endpoints(
            candidate,
            extraction_dir / "static.sarif",
            extraction_dir / "workspace",
            extraction["analyzed_files"],
        )
    if "source" not in source.get("roles", []) or "sink" not in sink.get("roles", []):
        raise ValueError("graph endpoint semantic roles do not match source/sink")
    workspace = (
        ctx.run_dir / "stages" / ctx.case["case_id"] / "static_extract/workspace"
    ).resolve()
    for node in (source, sink):
        file = relative_file(node["file"])
        target = workspace / file
        expected = ctx.output("static_extract")["analyzed_files"].get(file)
        if (
            target.is_symlink()
            or not target.resolve().is_relative_to(workspace)
            or not expected
            or node.get("content_hash") != expected
            or sha256_file(target) != expected
        ):
            raise ValueError("verification source changed from analyzed snapshot")
    return source, sink


def targeted_verify(ctx: Context) -> dict:
    if not ctx.config["selected_variant"]["targeted_verification"]:
        return {"status": "SKIPPED_BY_VARIANT", "artifacts": []}
    database_identity = validate_database(ctx)
    base = ctx.run_dir / "stages" / ctx.case["case_id"]
    candidates = read_jsonl(base / "candidate_rank/candidates_ranked.jsonl")
    graph_path = base / "build_graph/graph.json"
    graph = (
        json.loads(graph_path.read_text())
        if graph_path.is_file()
        else {"nodes": [], "snapshot_id": None}
    )
    database = ctx.run_dir / "databases" / ctx.case["case_id"]
    binary = (ctx.root / ctx.config["codeql"]["research_binary"]).resolve()
    maximum = ctx.config.get("research", {}).get("max_verification_queries_per_case", 40)
    used = 0
    results = []

    def run_query(query, prefix):
        nonlocal used
        if used >= maximum:
            raise StageFailure("UNSUPPORTED_SPEC", "targeted query invocation budget exhausted")
        validate_database(ctx)
        used += 1
        bqrs, csv_path = prefix.with_suffix(".bqrs"), prefix.with_suffix(".csv")
        command(
            [
                str(binary),
                "query",
                "run",
                str(query),
                f"--database={database}",
                f"--output={bqrs}",
                f"--ram={ctx.config['codeql']['ram_mb']}",
                f"--threads={ctx.config['codeql']['threads']}",
            ],
            cwd=ctx.root,
            log=prefix.with_suffix(".log"),
            timeout=ctx.remaining_seconds(ctx.config["codeql"]["per_query_timeout_s"]),
            failure="QUERY_INVALID",
        )
        command(
            [str(binary), "bqrs", "decode", str(bqrs), "--format=csv", f"--output={csv_path}"],
            cwd=ctx.root,
            log=prefix.parent / (prefix.name + "-decode.log"),
            timeout=ctx.remaining_seconds(60),
            failure="QUERY_INVALID",
        )
        columns = ["source_count", "sink_count"] if prefix.name == "endpoints" else FLOW_COLUMNS
        return _csv(csv_path, columns)

    for candidate in candidates:
        ctx.remaining_seconds(7200)
        start_used = used
        record = {
            "candidate_id": candidate["candidate_id"],
            "status": "UNSUPPORTED_SPEC",
            "decision": "REVIEW",
            "query_invocations": 0,
            "scope": "TARGETED_STATIC_TAINT_MODEL",
            "coverage": "EXTRACTOR_MODEL_ONLY",
            "is_safety_verdict": False,
            "exploitation_verified": False,
            "database_identity_id": database_identity["database_identity_id"],
        }
        try:
            source, sink = _endpoints(ctx, candidate, graph)
            if not binary.is_file() or not (database / "codeql-database.yml").is_file():
                raise ValueError("private research database or pinned research binary missing")
            endpoint_query, flow_query = render_queries(candidate["candidate_id"], source, sink)
            folder = ctx.stage_dir / safe_id(candidate["candidate_id"])
            folder.mkdir(exist_ok=True)
            pack = ctx.root / "src/static_analysis/queries/v2"
            for name in ("qlpack.yml", "codeql-pack.lock.yml"):
                if (pack / name).is_file():
                    shutil.copyfile(pack / name, folder / name)
            endpoint_path, flow_path = folder / "endpoints.ql", folder / "flow.ql"
            endpoint_path.write_text(endpoint_query)
            flow_path.write_text(flow_query)
            record.update(
                {
                    "snapshot_id": candidate["snapshot_id"],
                    "source_node_id": source["node_id"],
                    "sink_node_id": sink["node_id"],
                    "endpoint_binding_policy": source.get("binding_policy", "GRAPH_EXACT_SPAN_V1"),
                    "static_endpoint_provenance": candidate.get("static_endpoint_spec"),
                    "query_hash": digest([endpoint_query, flow_query]),
                }
            )
            inventory = run_query(endpoint_path, folder / "endpoints")
            if len(inventory) != 1 or set(inventory[0]) != {"source_count", "sink_count"}:
                raise StageFailure("QUERY_INVALID", "invalid targeted endpoint inventory output")
            try:
                source_count, sink_count = (
                    int(inventory[0]["source_count"]),
                    int(inventory[0]["sink_count"]),
                )
                if source_count < 0 or sink_count < 0:
                    raise ValueError("negative count")
            except ValueError as error:
                raise StageFailure(
                    "QUERY_INVALID", "invalid targeted endpoint inventory count"
                ) from error
            record.update({"source_count": source_count, "sink_count": sink_count})
            if source_count != 1 or sink_count != 1:
                record["reason"] = "targeted endpoints absent or ambiguous in current database"
            else:
                flows = run_query(flow_path, folder / "flow")
                for flow in flows:
                    matches = True
                    for role, endpoint in (("source", source), ("sink", sink)):
                        matches &= flow[f"{role}_file"] == endpoint["file"]
                        for field in ("start_line", "start_column", "end_line", "end_column"):
                            column = "line" if field == "start_line" else field
                            try:
                                matches &= int(flow[f"{role}_{column}"]) == endpoint[field]
                            except ValueError as error:
                                raise StageFailure(
                                    "QUERY_INVALID", "invalid targeted flow endpoint coordinate"
                                ) from error
                    if not matches:
                        raise StageFailure(
                            "QUERY_INVALID", "flow output does not match frozen endpoints"
                        )
                record.update(
                    {
                        "status": classify_verification(source_count, sink_count, len(flows)),
                        "flow_count": len(flows),
                        "matched_endpoints": flows,
                    }
                )
        except StageFailure as error:
            if error.status == "DATABASE_INTEGRITY_FAILED":
                raise
            record.update(
                {
                    "status": error.status
                    if error.status in {"TIMEOUT", "QUERY_INVALID", "UNSUPPORTED_SPEC"}
                    else "QUERY_INVALID",
                    "reason": str(redact(str(error))),
                }
            )
        except (ValueError, KeyError, OSError) as error:
            record["reason"] = str(redact(str(error)))
        record["query_invocations"] = used - start_used
        results.append(record)
        atomic_jsonl(ctx.stage_dir / "verification.jsonl", results)
    atomic_jsonl(ctx.stage_dir / "verification.jsonl", results)
    return {
        "artifacts": [
            p.relative_to(ctx.stage_dir).as_posix()
            for p in ctx.stage_dir.rglob("*")
            if p.is_file() and p.name != "stage.json"
        ],
        "flow_found": sum(r["status"] == "FLOW_FOUND" for r in results),
        "query_invocations": used,
        "candidates": len(results),
    }
