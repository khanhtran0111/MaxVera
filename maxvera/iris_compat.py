"""Explicit run-local repairs around the clean pinned IRIS artifact.

Prompts, positive-only label semantics, heuristics, and endpoint pruning remain
upstream behavior. These repairs prevent JSON corruption and unprocessed tails.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from maxvera.llm import _validate_output


def _parse_labels(self, raw):
    return _validate_output(raw, "array")


def _parse_context(self, raw):
    return _validate_output(raw, "iris_context")


def _run_context(self):
    output = Path(self.posthoc_filtering_output_result_sarif_path)
    if (
        output.exists()
        and not self.overwrite
        and not self.overwrite_posthoc_filter
        and (
            not self.rerun_skipped_fp
            or list(self.iter_code_flows_for_query(json.loads(output.read_text())))
        )
    ):
        self.project_logger.info("  ==> Found existing posthoc filter results; skipping...")
        return
    if not Path(self.query_output_result_sarif_path).exists() and self.test_run:
        return
    classes_csv = pd.read_csv(self.class_locs_path)
    methods_csv = pd.read_csv(self.func_locs_path)
    classes = self.extract_enclosing_decl_locs_map(classes_csv)
    methods = self.extract_enclosing_decl_locs_map(methods_csv)
    fixed_methods = self.extract_fixed_methods()
    original = json.loads(Path(self.query_output_result_sarif_path).read_text())
    grouped, false_sources, false_sinks = {}, {}, {}
    results, retained, pending = [], [], []
    stats = {"num_gpt_calls": 0, "num_cached": 0, "num_failure": 0, "num_vulnerable_paths": 0}

    def record(result_id, flow_id, entry):
        results.append({"result_id": result_id, "code_flow_id": flow_id, "entry": entry})
        if entry.get("ignored_by_filter"):
            return
        stats["num_cached" if entry.get("using_cache") else "num_gpt_calls"] += 1
        verdict = entry["result"]
        if "is_vulnerable" not in verdict:
            stats["num_failure"] += 1
        elif verdict["is_vulnerable"]:
            stats["num_vulnerable_paths"] += 1
            retained.append((result_id, flow_id))

    def flush():
        entries = self.batched_query_gpt_on_code_flow(
            pending, classes, methods, grouped, false_sources, false_sinks
        )
        if [(rid, fid) for rid, fid, _ in entries] != [(rid, fid) for rid, fid, _ in pending]:
            raise RuntimeError("IRIS context batch returned an incomplete path assessment set")
        for result_id, flow_id, entry in entries:
            record(result_id, flow_id, entry)
        pending.clear()

    for result_id, flow_id, path in self.iter_code_flows_for_query(original):
        cached = self.use_cache_on_code_flow(
            result_id, flow_id, path, methods, grouped, false_sources, false_sinks
        )
        if cached is not None:
            record(
                result_id,
                flow_id,
                {"path": path, "prompt": "", "using_cache": True, "result": cached},
            )
        elif self.posthoc_filtering_skip_fp and not self.code_flow_passes_fix_method(
            path, fixed_methods, classes_csv, methods_csv
        ):
            continue
        elif self.ignore_code_flow(path):
            record(
                result_id,
                flow_id,
                {
                    "path": path,
                    "prompt": "",
                    "using_cache": False,
                    "ignored_by_filter": True,
                    "result": False,
                },
            )
        else:
            pending.append((result_id, flow_id, path))
            if len(pending) == self.batch_size:
                flush()
    # Flush even when the final input used a cache or a heuristic. Upstream only
    # flushes inside the uncached/unignored branch and can silently lose this tail.
    if pending:
        flush()
    if not self.test_run:
        Path(self.posthoc_filtering_output_result_json_path).write_text(json.dumps(results))
        output.write_text(json.dumps(self.retain_sarif_json_with_code_flow_ids(original, retained)))
        Path(self.posthoc_filtering_output_stats_json_path).write_text(json.dumps(stats))


def install_compatibility(api_class, context_class):
    """Install only in the worker process; never edit the pinned checkout."""
    api_class.parse_json = _parse_labels
    context_class.parse_posthoc_filter_json_result = _parse_context
    context_class.run = _run_context
    return {
        "schema_version": "iris-adapter-compatibility-v1",
        "json_parsing": "STRICT_WITHOUT_STRING_REWRITES",
        "context_tail_flush": True,
        "semantic_schema_validation": True,
        "positive_only_label_omissions": "UNCHANGED",
        "negative_endpoint_cache": "UNCHANGED",
        "heuristic_filter": "UNCHANGED",
        "deviations": [
            "Valid JSON is parsed without upstream string/comment rewrites.",
            "Queued context paths are flushed after the final cached or ignored path.",
            "IRIS model responses require the fields and types declared by their prompts.",
        ],
    }
