"""Process adapter for pinned IRIS v1, with explicit stages and no GT evaluation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

STAGE_METHODS = {
    "candidate_extract": ("collect_invoked_external_apis", "collect_internal_function_parameters"),
    "llm_specs": ("query_gpt_for_api_src_tp_sink_batched", "query_gpt_for_func_param_src"),
    "static_taint": (
        "build_project_specific_query",
        "find_vulnerability",
        "post_process_cwe_query_result",
    ),
    "context_filter": ("query_gpt_for_posthoc_filtering",),
}


def run_stage(pipeline, stage: str) -> None:
    from maxvera.llm import IrisProvider

    for method in STAGE_METHODS[stage]:
        getattr(pipeline, method)()
    # Upstream filtering catches transport exceptions and writes partial output.
    # A rejected/uncertain/budget-stopped request must fail the enclosing stage.
    IrisProvider.raise_if_failed()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    request = json.loads(args.request.read_text())
    # Keep MaxVera imports alive locally before giving upstream its own `src` namespace.
    import src.reproduction.iris_subprocess as old_adapter
    from maxvera.llm import IrisProvider
    from src.reproduction.iris_subprocess import (
        _CodeQLRamSubprocessProxy,
        _compatible_query_source,
        _install_local_readme,
        _install_model_stubs,
        _unload_maxvera_package_before_iris_import,
    )

    old_adapter.GPTOSS20BProvider = IrisProvider
    IrisProvider.configure(request)
    _unload_maxvera_package_before_iris_import()
    sys.path.insert(0, request["iris_root"])
    _install_model_stubs()
    import src.config as config
    import src.modules.codeql_query_runner as runner
    import src.neusym_vul as upstream

    binary = Path(request["codeql"])
    values = {
        "CODEQL_DIR": str(binary.parent),
        "CODEQL_DB_PATH": request["database_root"],
        "PACKAGE_MODULES_PATH": request["package_root"],
        "OUTPUT_DIR": request["output_root"],
        "ALL_METHOD_INFO_DIR": request["fix_info"],
        "PROJECT_SOURCE_CODE_DIR": request["source_root"],
        "CVES_MAPPED_W_COMMITS_DIR": request["project_info"],
    }
    for name, value in values.items():
        setattr(config, name, value)
        setattr(upstream, name, value)
    upstream.CODEQL = runner.CODEQL = str(binary)
    upstream.CODEQL_CUSTOM_QUERY_DIR = runner.CODEQL_CUSTOM_QUERY_DIR = (
        request["query_pack"] + "/myqueries"
    )
    upstream.CODEQL_CUSTOM_YML_DIR = request["query_pack"] + "/ext"
    # Original patched toolchain needs the original queries, not mechanical 2.26 migrations.
    if request["compatibility"] == "modern_2_26":
        source = _compatible_query_source(
            Path(request["iris_root"]) / "src", Path(request["workspace"])
        )
        upstream.THIS_SCRIPT_DIR = runner.ENTRY_SCRIPT_DIR = str(source)
    proxy = _CodeQLRamSubprocessProxy(runner.sp, binary, request["ram_mb"])
    runner.sp = upstream.sp = proxy
    p = upstream.SAPipeline(
        request["slug"],
        f"cwe-{int(request['cwe'].split('-')[1]):03d}wLLM",
        run_id=request["adapter_run"],
        llm="gpt-oss-20b-openrouter",
        label_api_batch_size=30,
        label_func_param_batch_size=50,
        num_threads=1,
        seed=1234,
        use_exhaustive_qll=True,
        skip_evaluation=True,
        posthoc_filtering_skip_fp=False,
    )
    _install_local_readme(p)
    run_stage(p, request["stage"])
    attributes = {
        "candidate_extract": ["candidate_apis_csv_path", "source_func_param_candidates_path"],
        "llm_specs": [
            "llm_labelled_source_apis_path",
            "llm_labelled_sink_apis_path",
            "llm_labelled_taint_prop_apis_path",
            "llm_labelled_source_func_params_path",
        ],
        "static_taint": [
            "source_qll_path",
            "sink_qll_path",
            "summary_qll_path",
            "spec_yml_path",
            "query_output_result_sarif_path",
            "query_output_result_sarif_pp_path",
        ],
        "context_filter": ["posthoc_filtering_output_result_sarif_path"],
    }
    if request["stage"] == "context_filter":
        p.extract_class_locations()
        p.extract_func_locations()
        attributes["context_filter"] += ["class_locs_path", "func_locs_path"]
    outputs = {name: str(getattr(p, name)) for name in attributes[request["stage"]]}
    missing = [name for name, path in outputs.items() if not Path(path).is_file()]
    if missing:
        raise RuntimeError(f"IRIS stage missing required artifacts: {missing}")
    Path(request["response"]).write_text(json.dumps(outputs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
