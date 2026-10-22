"""LLM-independent research DAG, executed only inside the filesystem firewall."""

from __future__ import annotations

import csv
import json
import os
import shlex
import shutil
from pathlib import Path

from maxvera.candidates import generate, rank
from maxvera.contracts import ORACLE_PATTERN, digest
from maxvera.graph import normalize_graph
from maxvera.orchestration import Context, Stage, StageFailure
from maxvera.process import command
from src.common.provenance import sha256_file
from src.reproduction.common import atomic_json, atomic_jsonl, read_jsonl


def _source(ctx):
    view = (ctx.root / "data/processed/analysis_input").resolve()
    source = (view / ctx.case["source_dir"]).resolve()
    if not source.is_relative_to(view) or not source.is_dir():
        raise StageFailure(
            "FETCH_FAILED", "prepared opaque snapshot missing; dataset prepare --sources required"
        )
    return source


def ingest(ctx: Context) -> dict:
    source = _source(ctx)
    from maxvera.snapshots import source_inventory

    files = source_inventory(source)
    if ctx.case.get("snapshot_content_hash") and digest(files) != ctx.case["snapshot_content_hash"]:
        raise ValueError("source changed after parent input fingerprint")
    snapshot = {
        "schema_version": "2.0",
        "case_id": ctx.case["case_id"],
        "snapshot_id": digest(files),
        "source": str(source),
        "files": files,
    }
    atomic_json(ctx.stage_dir / "snapshot.json", snapshot)
    return {**snapshot, "artifacts": ["snapshot.json"]}


def _codeql(ctx):
    return (ctx.root / ctx.config["codeql"]["research_binary"]).resolve()


def _database(ctx):
    return ctx.run_dir / "databases" / ctx.case["case_id"]


def static_extract(ctx: Context) -> dict:
    original, binary = _source(ctx), _codeql(ctx)
    source = ctx.stage_dir / "workspace"
    if source.exists():
        shutil.rmtree(source)
    shutil.copytree(
        original,
        source,
        symlinks=False,
        ignore=shutil.ignore_patterns(".git", ".gradle", "target", "build", "classes"),
    )
    from maxvera.snapshots import source_inventory

    if source_inventory(source) != ctx.output("ingest")["files"]:
        raise ValueError("frozen snapshot changed before private build copy")
    database = _database(ctx)
    # Source-only DBs live in this run and can be resumed only after validated extraction.
    if database.exists():
        shutil.rmtree(database)
    database.parent.mkdir(parents=True, exist_ok=True)
    if not binary.is_file():
        raise StageFailure("CODEQL_DB_FAILED", "research CodeQL binary missing")
    # Build command originates in trusted dataset materialization, never labels or LLM.
    metadata = source / "build.runtime.json"
    if not metadata.is_file():
        raise StageFailure(
            "BUILD_FAILED", "snapshot lacks trusted build.runtime.json; prepare sources first"
        )
    build = json.loads(metadata.read_text())
    selected = None
    for i, saved_option in enumerate(build["attempts"]):

        def remap(value):
            return value.replace(str(original), str(source))

        option = {
            "command": [remap(a) for a in saved_option["command"]],
            "environment": {k: remap(v) for k, v in saved_option["environment"].items()},
        }
        env = {**os.environ, **option["environment"]}
        try:
            command(
                option["command"],
                cwd=source,
                env=env,
                log=ctx.stage_dir / f"build-{i}.log",
                timeout=ctx.remaining_seconds(ctx.config["budgets"]["timeout_case_s"]),
                failure="BUILD_FAILED",
            )
            selected = option
            break
        except StageFailure:
            continue
    if selected is None:
        raise StageFailure("BUILD_FAILED", "all prepared build options failed")
    command(
        [
            str(binary),
            "database",
            "create",
            str(database),
            "--language=java",
            f"--source-root={source}",
            "--command=" + shlex.join(selected["command"]),
            f"--ram={ctx.config['codeql']['ram_mb']}",
            f"--threads={ctx.config['codeql']['threads']}",
        ],
        cwd=source,
        env={**os.environ, **selected["environment"]},
        log=ctx.stage_dir / "database.log",
        timeout=ctx.remaining_seconds(ctx.config["budgets"]["timeout_case_s"]),
        failure="CODEQL_DB_FAILED",
    )
    # Record official generic suite alerts independently from custom extraction.
    suite = ctx.root / ctx.config["codeql"]["generic_suite"]
    sarif = ctx.stage_dir / "static.sarif"
    command(
        [
            str(binary),
            "database",
            "analyze",
            str(database),
            str(suite),
            "--format=sarif-latest",
            f"--output={sarif}",
            f"--ram={ctx.config['codeql']['ram_mb']}",
            f"--threads={ctx.config['codeql']['threads']}",
        ],
        cwd=ctx.root,
        log=ctx.stage_dir / "static.log",
        timeout=ctx.remaining_seconds(ctx.config["codeql"]["per_query_timeout_s"]),
    )
    from maxvera.reproduction import normalize_sarif

    alerts = normalize_sarif(sarif, ctx.case["case_id"], "static_alerts")
    atomic_jsonl(ctx.stage_dir / "static_signals.jsonl", alerts)
    artifacts = ["static.sarif", "static_signals.jsonl", "database.log", "static.log"]
    graph_enabled = ctx.config["selected_variant"]["graph_enabled"]
    if graph_enabled:
        queries = ctx.root / "src/static_analysis/queries/v2"
        for name in ("program_nodes", "program_edges"):
            bqrs, csv_path = ctx.stage_dir / f"{name}.bqrs", ctx.stage_dir / f"{name}.csv"
            command(
                [
                    str(binary),
                    "query",
                    "run",
                    str(queries / f"{name}.ql"),
                    f"--database={database}",
                    f"--output={bqrs}",
                    f"--ram={ctx.config['codeql']['ram_mb']}",
                ],
                cwd=ctx.root,
                log=ctx.stage_dir / f"{name}.log",
                timeout=ctx.remaining_seconds(ctx.config["codeql"]["per_query_timeout_s"]),
            )
            command(
                [str(binary), "bqrs", "decode", str(bqrs), "--format=csv", f"--output={csv_path}"],
                cwd=ctx.root,
                log=ctx.stage_dir / f"{name}_decode.log",
                timeout=ctx.remaining_seconds(60),
            )
            artifacts += [csv_path.name, bqrs.name, f"{name}.log", f"{name}_decode.log"]
    analyzed = source_inventory(source, include_generated=True)
    baseline = ctx.output("ingest")["files"]
    changed = sorted(rel for rel, content in baseline.items() if analyzed.get(rel) != content)
    generated = sorted(set(analyzed) - set(baseline))
    provenance = {
        "input_snapshot_id": ctx.output("ingest")["snapshot_id"],
        "analyzed_snapshot_id": digest(analyzed),
        "analyzed_files": analyzed,
        "modified_input_files": changed,
        "generated_files": generated,
    }
    atomic_json(ctx.stage_dir / "analyzed_snapshot.json", provenance)
    artifacts += ["analyzed_snapshot.json", *["workspace/" + rel for rel in analyzed]]
    return {**provenance, "artifacts": artifacts, "graph_enabled": graph_enabled}


def build_graph(ctx: Context) -> dict:
    if not ctx.output("static_extract")["graph_enabled"]:
        return {"status": "SKIPPED_BY_VARIANT", "artifacts": []}
    folder = ctx.run_dir / "stages" / ctx.case["case_id"] / "static_extract"

    def load(name):
        with (folder / name).open(newline="") as handle:
            return list(csv.DictReader(handle))

    nodes, edges = load("program_nodes.csv"), load("program_edges.csv")
    if (
        len(nodes) > ctx.config["research"]["max_nodes"]
        or len(edges) > ctx.config["research"]["max_edges"]
    ):
        raise StageFailure("GRAPH_LIMIT", "graph exceeds configured bound; no silent truncation")
    queries = ctx.root / "src/static_analysis/queries/v2"
    query_hash = digest(
        {p.name: sha256_file(p) for p in queries.iterdir() if p.suffix in {".ql", ".qll", ".yml"}}
    )
    graph = normalize_graph(
        ctx.case["case_id"],
        ctx.output("static_extract")["analyzed_snapshot_id"],
        nodes,
        edges,
        query_hash,
    )
    for n in graph["nodes"]:
        n["content_hash"] = ctx.output("static_extract")["analyzed_files"].get(n["file"])
        if n["content_hash"] is None:
            raise ValueError("extracted node is not backed by input snapshot")
    graph["graph_hash"] = digest([graph["nodes"], graph["edges"]])
    graph["quality"]["extraction_seconds"] = ctx.results["static_extract"]["seconds"]
    atomic_jsonl(ctx.stage_dir / "nodes.jsonl", graph["nodes"])
    atomic_jsonl(ctx.stage_dir / "edges.jsonl", graph["edges"])
    atomic_json(ctx.stage_dir / "graph_quality.json", graph["quality"])
    atomic_json(ctx.stage_dir / "graph.json", graph)
    return {
        "graph_hash": graph["graph_hash"],
        "artifacts": ["nodes.jsonl", "edges.jsonl", "graph_quality.json", "graph.json"],
    }


def candidate_generate(ctx: Context) -> dict:
    base = ctx.run_dir / "stages" / ctx.case["case_id"]
    alerts = read_jsonl(base / "static_extract/static_signals.jsonl")
    if ctx.config["selected_variant"]["graph_enabled"]:
        graph = json.loads((base / "build_graph/graph.json").read_text())
    else:
        graph = {
            "case_id": ctx.case["case_id"],
            "snapshot_id": ctx.output("static_extract")["analyzed_snapshot_id"],
            "nodes": [],
            "edges": [],
            "graph_hash": digest([]),
        }
    candidates = generate(
        graph,
        alerts,
        max_hops=ctx.config["evidence"]["max_graph_hops"],
        check_budget=lambda: ctx.remaining_seconds(7200),
    )
    allowed = ctx.config["selected_variant"]["candidate_sources"]
    for c in candidates:
        c["origin_generators"] = [g for g in c["origin_generators"] if g in allowed]
    candidates = [c for c in candidates if c["origin_generators"]]
    atomic_jsonl(ctx.stage_dir / "candidates_raw.jsonl", candidates)
    return {"pool_hash": digest(candidates), "artifacts": ["candidates_raw.jsonl"]}


def candidate_rank(ctx: Context) -> dict:
    base = ctx.run_dir / "stages" / ctx.case["case_id"]
    raw = read_jsonl(base / "candidate_generate/candidates_raw.jsonl")
    from maxvera.schemas import Candidate

    ranked = [
        Candidate({**c, "run_id": ctx.run_dir.name}).to_dict()
        for c in rank(raw, top_k=max(ctx.config["evidence"]["top_k"]))
    ]
    atomic_jsonl(ctx.stage_dir / "candidates_ranked.jsonl", ranked)
    atomic_json(
        ctx.stage_dir / "topk_snapshot.json",
        {
            "candidate_pool_hash": ctx.output("candidate_generate")["pool_hash"],
            "ranked_hash": digest(ranked),
            "top_k": ctx.config["evidence"]["top_k"],
            "candidate_ids": [c["candidate_id"] for c in ranked],
        },
    )
    return {"artifacts": ["candidates_ranked.jsonl", "topk_snapshot.json"]}


def skipped(ctx):
    return {"status": "SKIPPED_BY_VARIANT", "artifacts": []}


def final_rank(ctx):
    path = ctx.run_dir / "stages" / ctx.case["case_id"] / "candidate_rank/candidates_ranked.jsonl"
    findings = [
        {
            **c,
            "finding_id": "finding-" + digest(c["candidate_id"])[:24],
            "decision": "REVIEW",
            "stage": "final",
        }
        for c in read_jsonl(path)
    ]
    atomic_jsonl(ctx.stage_dir / "findings.jsonl", findings)
    return {"findings": findings, "artifacts": ["findings.jsonl"]}


def stages() -> list[Stage]:
    # build_graph may be skipped in static_only; candidate stage checks variant directly.
    return [
        Stage("ingest", ingest),
        Stage("static_extract", static_extract, ("ingest",)),
        Stage("build_graph", build_graph, ("static_extract",)),
        Stage("candidate_generate", candidate_generate, ("static_extract", "build_graph")),
        Stage("candidate_rank", candidate_rank, ("candidate_generate",)),
        Stage("evidence_retrieve", skipped, ("candidate_rank",)),
        Stage("llm_reason", skipped, ("candidate_rank",)),
        Stage("targeted_verify", skipped, ("candidate_rank",)),
        Stage("final_rank", final_rank, ("candidate_rank",)),
    ]


def finalize(path: Path, cases: list[dict]) -> None:
    candidates, findings, raw_pool = [], [], []
    for case in cases:
        base = path / "stages" / case["case_id"]
        for stage, name, dest in [
            ("candidate_generate", "candidates_raw.jsonl", raw_pool),
            ("candidate_rank", "candidates_ranked.jsonl", candidates),
            ("final_rank", "findings.jsonl", findings),
        ]:
            checkpoint = base / stage / "stage.json"
            if checkpoint.is_file() and json.loads(checkpoint.read_text())["status"] == "SUCCESS":
                dest.extend(read_jsonl(base / stage / name))
    # Defense in depth; the OS firewall remains the access boundary.
    if ORACLE_PATTERN.search(json.dumps([candidates, findings])):
        raise ValueError("oracle identifier detected in analyzer output")
    atomic_jsonl(path / "candidates_raw.jsonl", raw_pool)
    atomic_jsonl(path / "candidates_pre_llm.jsonl", candidates)
    atomic_jsonl(path / "findings.jsonl", findings)
