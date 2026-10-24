"""Enter a deny-by-default OS read sandbox before executing the research DAG."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from maxvera.orchestration import Orchestrator
from maxvera.sandbox import resolver_runtime_paths, restrict_reads


def main():
    request = json.load(sys.stdin)
    root = Path(request["root"]).resolve()
    mode = request["mode"]
    output = root / "results" / "_smoke/research" if mode == "smoke" else root / "results/research"
    output.mkdir(parents=True, exist_ok=True)
    for home in (
        root / ".cache/research-home" / request["run_id"],
        root / ".cache/research-tmp" / request["run_id"],
    ):
        home.mkdir(parents=True, exist_ok=True)
    code_root = Path(__file__).resolve().parent.parent
    runtime = [
        code_root / "maxvera",
        code_root / "src",
        Path(sys.prefix),
        Path("/usr"),
        Path("/lib"),
        Path("/lib64"),
        Path("/bin"),
        Path("/etc"),
        *resolver_runtime_paths(),
        Path("/dev/null"),
        Path("/dev/urandom"),
        Path("/proc/self"),
        Path("/proc/meminfo"),
        Path("/proc/cpuinfo"),
        Path("/sys"),
        Path(sys.executable).resolve().parent.parent,
        root / ".venv",
        root / "maxvera",
        root / "src",
        root / ".cache/toolchains",
        root / ".cache/research-home" / request["run_id"],
        root / ".cache/research-tmp" / request["run_id"],
        root / "data/processed/analysis_input",
        output,
    ]
    # No repo root, raw metadata, canonical manifests, evaluator_only, .env or other results.
    os.environ["HOME"] = str(root / ".cache/research-home" / request["run_id"])
    os.environ["TMPDIR"] = str(root / ".cache/research-tmp" / request["run_id"])
    os.environ["MAXVERA_DATA_ROLE"] = "analysis"
    os.environ["JAVA_TOOL_OPTIONS"] = (
        "-Djava.io.tmpdir=" + os.environ["TMPDIR"] + " -Duser.home=" + os.environ["HOME"]
    )
    os.environ["GRADLE_USER_HOME"] = str(Path(os.environ["HOME"]) / ".gradle")
    from maxvera.research import finalize, stages

    if request["config"].get("selected_variant", {}).get("llm_enabled"):
        from maxvera.research_reasoning import configure_model
        from src.llm.providers.openrouter import OpenRouterSettings

        configure_model(OpenRouterSettings(**request.pop("llm_settings")))

    runner = Orchestrator(
        root,
        "research",
        request["run_id"],
        request["config"],
        request["cases"],
        stages(),
        mode=mode,
        implementation_hash=request["implementation_hash"],
        resume=request["resume"],
        finalizer=finalize,
        isolation=lambda run_path: restrict_reads(
            [p for p in runtime if p != output] + [run_path],
            write_paths=[
                run_path,
                root / ".cache/research-home" / request["run_id"],
                root / ".cache/research-tmp" / request["run_id"],
                Path("/dev/null"),
            ],
        ),
    )
    result = runner.execute()
    print(json.dumps({"run_id": request["run_id"], "status": result, "run_dir": str(runner.path)}))
    return 0 if result == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
