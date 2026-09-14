"""Standalone adapter that runs the pinned IRIS pipeline through OpenRouter."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import types
from pathlib import Path
from typing import Any

from src.llm.providers.openrouter import OpenRouterClient, OpenRouterSettings


class GPTOSS20BProvider:
    """IRIS model interface backed by the pinned OpenRouter GPT-OSS route."""

    def __init__(
        self, model_name: str = "gpt-oss-20b-openrouter", logger: Any = None, **kwargs: Any
    ):
        self.model_name = model_name
        self.logger = logger
        self.call_log = Path(os.environ["MAXVERA_IRIS_LLM_LOG"])
        self.max_tokens = min(int(kwargs.get("max_new_tokens", 2048)), 2048)
        self.client = OpenRouterClient(
            OpenRouterSettings.load(
                Path.cwd(), Path("configs/models/gpt_oss_20b_openrouter_groq.yaml")
            ),
            self.call_log,
        )
        self.logprobs = None

    def _one(self, messages: Any, expect_json: bool) -> str:
        return self.client.complete(
            messages,
            expect_json=expect_json,
            max_tokens=self.max_tokens,
        )

    def predict(
        self,
        prompt: Any,
        expect_json: bool = False,
        batch_size: int = 0,
        no_progress_bar: bool = False,
    ) -> Any:
        del no_progress_bar
        if batch_size > 0:
            return [self._one(messages, expect_json) for messages in prompt]
        return self._one(prompt, expect_json)


class LLM:
    @staticmethod
    def get_llm(model_name: str, kwargs: dict[str, Any], logger: Any) -> GPTOSS20BProvider:
        return GPTOSS20BProvider(model_name=model_name, logger=logger, **kwargs)


def _inject_codeql_ram(command: Any, codeql_binary: Path, ram_mb: int) -> Any:
    """Add a deterministic RAM ceiling to the two CodeQL commands used by IRIS."""
    if not isinstance(command, (list, tuple)) or len(command) < 3:
        return command
    parts = list(command)
    try:
        is_codeql = Path(str(parts[0])).resolve() == codeql_binary.resolve()
    except (OSError, ValueError):
        return command
    operation = tuple(str(part) for part in parts[1:3])
    if (
        is_codeql
        and operation in {("query", "run"), ("database", "analyze")}
        and not any(str(part).startswith("--ram") for part in parts[3:])
    ):
        parts.insert(3, f"--ram={ram_mb}")
    return parts


class _CodeQLRamSubprocessProxy:
    """Delegate subprocess calls while constraining IRIS CodeQL heap sizing."""

    def __init__(self, module: Any, codeql_binary: Path, ram_mb: int):
        self._module = module
        self._codeql_binary = codeql_binary
        self._ram_mb = ram_mb

    def run(self, command: Any, *args: Any, **kwargs: Any) -> Any:
        return self._module.run(
            _inject_codeql_ram(command, self._codeql_binary, self._ram_mb),
            *args,
            **kwargs,
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._module, name)


def _install_model_stubs() -> None:
    llm_module = types.ModuleType("src.models.llm")
    llm_module.__dict__["LLM"] = LLM
    gpt_module = types.ModuleType("src.models.gpt")
    gpt_module.__dict__["GPTModel"] = GPTOSS20BProvider
    sys.modules["src.models.llm"] = llm_module
    sys.modules["src.models.gpt"] = gpt_module


def _unload_maxvera_package_before_iris_import() -> None:
    """Release MaxVera's src package name so the pinned IRIS src package can own it."""
    for module_name in tuple(sys.modules):
        if module_name == "src" or module_name.startswith("src."):
            del sys.modules[module_name]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iris-root", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--cwe", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--codeql-home", type=Path, required=True)
    parser.add_argument("--codeql-ram-mb", type=int, required=True)
    parser.add_argument("--database-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--query-pack", type=Path, required=True)
    parser.add_argument("--project-info", type=Path, required=True)
    parser.add_argument("--fix-info", type=Path, required=True)
    return parser


def _compatible_query_source(original: Path, workspace: Path) -> Path:
    """Create a run-local copy with mechanical CodeQL 2.26 API migrations."""
    target = workspace / "iris-src-codeql-2.26"
    if not target.exists():
        shutil.copytree(original, target)
    for path in target.rglob("*"):
        if not path.is_file() or path.suffix not in {".ql", ".qll"}:
            continue
        content = path.read_text(encoding="utf-8")
        migrated = content.replace("import semmle.code.java.security.PathCreation\n", "").replace(
            "ThreatModelFlowSource", "ActiveThreatModelSource"
        )
        migrated = re.sub(
            r"DataFlow::Node getReportingNode\(DataFlow::Node sink\) \{.*?\n\}\n\n(?=bindingset)",
            "DataFlow::Node getReportingNode(DataFlow::Node sink) { result = sink }\n\n",
            migrated,
            flags=re.DOTALL,
        )
        if migrated != content:
            path.write_text(migrated, encoding="utf-8")
    return target


def _install_local_readme(pipeline: Any) -> None:
    """Keep IRIS prompts repository-only instead of fetching mutable network content."""

    def local_description(instance: Any) -> str:
        source = Path(instance.project_source_code_dir)
        for name in ("README.md", "README.adoc", "README", "readme.md", "readme"):
            candidate = source / name
            if candidate.is_file():
                lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
                paragraph = str(instance.first_project_description_paragraph(lines))
                log_root = Path(instance.label_func_params_log_path)
                log_root.mkdir(parents=True, exist_ok=True)
                (log_root / "readme.txt").write_text("\n".join(lines), encoding="utf-8")
                (log_root / "readme_head.txt").write_text(paragraph, encoding="utf-8")
                return paragraph
        return ""

    pipeline.fetch_project_description_from_readme = types.MethodType(local_description, pipeline)


def main() -> int:
    args = _parser().parse_args()
    iris_root = args.iris_root.resolve()
    _unload_maxvera_package_before_iris_import()
    sys.path.insert(0, str(iris_root))
    _install_model_stubs()

    import src.config as iris_config  # type: ignore[import-untyped]
    import src.modules.codeql_query_runner as query_runner  # type: ignore[import-untyped]
    import src.neusym_vul as iris_pipeline  # type: ignore[import-untyped]

    codeql_home = args.codeql_home.resolve()
    codeql_binary = codeql_home / "codeql" if codeql_home.is_dir() else codeql_home
    subprocess_proxy = _CodeQLRamSubprocessProxy(query_runner.sp, codeql_binary, args.codeql_ram_mb)
    query_runner.sp = subprocess_proxy
    iris_pipeline.sp = subprocess_proxy
    values = {
        "CODEQL_DIR": str(codeql_home),
        "CODEQL_DB_PATH": str(args.database_root.resolve()),
        "PACKAGE_MODULES_PATH": str(args.package_root.resolve()),
        "OUTPUT_DIR": str(args.output_root.resolve()),
        "ALL_METHOD_INFO_DIR": str(args.fix_info.resolve()),
        "PROJECT_SOURCE_CODE_DIR": str(args.source_root.resolve()),
        "CVES_MAPPED_W_COMMITS_DIR": str(args.project_info.resolve()),
    }
    for name, value in values.items():
        setattr(iris_config, name, value)
        setattr(iris_pipeline, name, value)
    iris_pipeline.CODEQL = str(codeql_binary)
    iris_pipeline.CODEQL_CUSTOM_QUERY_DIR = str(args.query_pack.resolve() / "myqueries")
    iris_pipeline.CODEQL_CUSTOM_YML_DIR = str(args.query_pack.resolve() / "ext")
    query_runner.CODEQL = str(codeql_binary)
    query_runner.CODEQL_CUSTOM_QUERY_DIR = str(args.query_pack.resolve() / "myqueries")
    compatible_source = _compatible_query_source(
        iris_root / "src", args.query_pack.resolve().parent
    )
    iris_pipeline.THIS_SCRIPT_DIR = str(compatible_source)
    query_runner.ENTRY_SCRIPT_DIR = str(compatible_source)

    pipeline = iris_pipeline.SAPipeline(
        args.project,
        f"cwe-{int(args.cwe):03d}wLLM",
        run_id=args.run_id,
        # IRIS embeds this value in cache filenames; keep it filesystem-safe.
        # The OpenRouter client independently pins the actual API model ID.
        llm="gpt-oss-20b-openrouter",
        label_api_batch_size=30,
        label_func_param_batch_size=20,
        num_threads=1,
        seed=1234,
        use_exhaustive_qll=True,
    )
    _install_local_readme(pipeline)
    pipeline.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
