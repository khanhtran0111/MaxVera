"""Run pinned IRIS with only oracle CWE, opaque sources and Phase 13 budgets."""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path
from typing import Any

from src.baselines.context import estimate_tokens
from src.baselines.runner import _usage
from src.llm.providers.openrouter import OpenRouterClient, OpenRouterSettings
from src.reproduction import iris_subprocess as adapter
from src.reproduction.common import read_jsonl


def check_budget(messages: Any, records: list[dict[str, Any]]) -> None:
    if any(row.get("status") == "BUDGET_EXCEEDED" for row in records):
        raise RuntimeError("IRIS budget failure already recorded for this project")
    usage = _usage(records)
    estimated = estimate_tokens(json.dumps(messages, ensure_ascii=False)) + 256
    if int(usage["calls"]) >= 30:
        raise RuntimeError("IRIS per-project call budget exhausted")
    if estimated > 8192:
        raise RuntimeError("IRIS input request exceeds 8192-token conservative gate")
    if int(usage["input_tokens"]) + estimated > 160000:
        raise RuntimeError("IRIS per-project input-token budget exhausted")


class BudgetedProvider(adapter.GPTOSS20BProvider):
    def __init__(
        self, model_name: str = "gpt-oss-20b-openrouter", logger: Any = None, **kwargs: Any
    ) -> None:
        self.model_name, self.logger = model_name, logger
        self.call_log = Path(os.environ["MAXVERA_IRIS_LLM_LOG"])
        self.max_tokens = min(int(kwargs.get("max_new_tokens", 2048)), 2048)
        self.client = OpenRouterClient(OpenRouterSettings.load(Path.cwd()), self.call_log)
        self.logprobs = None

    def _one(self, messages: Any, expect_json: bool) -> str:
        try:
            check_budget(messages, read_jsonl(self.call_log))
        except RuntimeError as error:
            self.client._append_log({"status": "BUDGET_EXCEEDED", "reason": str(error)})
            raise
        response = self.client.complete(
            messages, expect_json=expect_json, max_tokens=self.max_tokens
        )
        records = read_jsonl(self.call_log)
        usage = _usage(records)
        if int(usage["calls"]) > 30 or int(usage["input_tokens"]) > 160000:
            self.client._append_log(
                {"status": "BUDGET_EXCEEDED", "reason": "actual project budget exceeded"}
            )
            raise RuntimeError("IRIS actual project token/call budget exceeded")
        if any(
            int(row.get("usage", {}).get("prompt_tokens", 0) or 0) > 8192
            or int(row.get("usage", {}).get("completion_tokens", 0) or 0) > 2048
            for row in records
            if row.get("status") == "SUCCESS"
        ):
            self.client._append_log(
                {"status": "BUDGET_EXCEEDED", "reason": "actual per-call budget exceeded"}
            )
            raise RuntimeError("IRIS actual per-call token budget exceeded")
        return response


class LLM:
    @staticmethod
    def get_llm(model_name: str, kwargs: dict[str, Any], logger: Any) -> BudgetedProvider:
        return BudgetedProvider(model_name=model_name, logger=logger, **kwargs)


def main() -> int:
    if os.environ.get("MAXVERA_DATA_ROLE") != "evaluator":
        raise RuntimeError("oracle IRIS requires evaluator role")
    args = adapter._parser().parse_args()
    iris_root = args.iris_root.resolve()
    adapter._unload_maxvera_package_before_iris_import()
    sys.path.insert(0, str(iris_root))
    llm_module = types.ModuleType("src.models.llm")
    llm_module.__dict__["LLM"] = LLM
    gpt_module = types.ModuleType("src.models.gpt")
    gpt_module.__dict__["GPTModel"] = BudgetedProvider
    sys.modules["src.models.llm"] = llm_module
    sys.modules["src.models.gpt"] = gpt_module

    import src.config as iris_config  # type: ignore[import-untyped]
    import src.modules.codeql_query_runner as query_runner  # type: ignore[import-untyped]
    import src.neusym_vul as iris_pipeline  # type: ignore[import-untyped]

    codeql_home = args.codeql_home.resolve()
    codeql_binary = codeql_home / "codeql"
    subprocess_proxy = adapter._CodeQLRamSubprocessProxy(
        query_runner.sp, codeql_binary, args.codeql_ram_mb
    )
    query_runner.sp = subprocess_proxy
    iris_pipeline.sp = subprocess_proxy
    for name, value in {
        "CODEQL_DIR": str(codeql_home),
        "CODEQL_DB_PATH": str(args.database_root.resolve()),
        "PACKAGE_MODULES_PATH": str(args.package_root.resolve()),
        "OUTPUT_DIR": str(args.output_root.resolve()),
        "ALL_METHOD_INFO_DIR": str(args.fix_info.resolve()),
        "PROJECT_SOURCE_CODE_DIR": str(args.source_root.resolve()),
        "CVES_MAPPED_W_COMMITS_DIR": str(args.project_info.resolve()),
    }.items():
        setattr(iris_config, name, value)
        setattr(iris_pipeline, name, value)
    iris_pipeline.CODEQL = str(codeql_binary)
    iris_pipeline.CODEQL_CUSTOM_QUERY_DIR = str(args.query_pack.resolve() / "myqueries")
    iris_pipeline.CODEQL_CUSTOM_YML_DIR = str(args.query_pack.resolve() / "ext")
    query_runner.CODEQL = str(codeql_binary)
    query_runner.CODEQL_CUSTOM_QUERY_DIR = str(args.query_pack.resolve() / "myqueries")
    compatible_source = adapter._compatible_query_source(
        iris_root / "src", args.query_pack.resolve().parent
    )
    iris_pipeline.THIS_SCRIPT_DIR = str(compatible_source)
    query_runner.ENTRY_SCRIPT_DIR = str(compatible_source)
    pipeline = iris_pipeline.SAPipeline(
        args.project,
        f"cwe-{int(args.cwe):03d}wLLM",
        run_id=args.run_id,
        llm="gpt-oss-20b-openrouter",
        label_api_batch_size=30,
        label_func_param_batch_size=20,
        num_threads=1,
        seed=1234,
        use_exhaustive_qll=True,
        skip_evaluation=True,
        filter_by_module=False,
        filter_by_module_large=False,
        posthoc_filtering_skip_fp=False,
    )
    adapter._install_local_readme(pipeline)
    pipeline.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
