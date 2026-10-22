"""Trusted metadata preparation and strictly label-free analyzer case selection."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from maxvera.contracts import ORACLE_PATTERN, safe_id
from src.common.provenance import sha256_file
from src.data.phase2 import acquire_dataset, load_dataset_config, materialize_release
from src.reproduction.common import read_csv


def select_cases(
    root: Path, dataset: dict, mode: str, limit: int | None = None, *, oracle: bool = False
) -> list[dict]:
    if mode == "full" and limit is not None:
        raise ValueError("full mode cannot be truncated by --limit")
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive")
    key = "oracle_manifest" if oracle else "analysis_manifest"
    path = (root / dataset[key]).resolve()
    rows = read_csv(path)
    if not oracle:
        allowed = {
            "project_id",
            "case_id",
            "source_dir",
            "source_required",
            "database_dir",
            "jdk_version",
            "maven_version",
            "gradle_version",
            "use_gradlew",
        }
        if any(set(row) - allowed for row in rows):
            raise ValueError("protected field in analysis manifest")
        if ORACLE_PATTERN.search(json.dumps(rows)) or "evaluator_only" in json.dumps(rows):
            raise ValueError("protected label/path in analysis manifest")
    cases = [{**r, "case_id": safe_id(r.get("case_id", r.get("project_id", "")))} for r in rows]
    if len({c["case_id"] for c in cases}) != len(cases):
        raise ValueError("duplicate case IDs")
    expected = dataset.get("expected_cases", len(cases))
    if mode == "full" and len(cases) != expected:
        raise ValueError(f"case coverage: expected {expected}, got {len(cases)}")
    if dataset.get("split"):
        selected = {r["project_id"] for r in read_csv(root / dataset["split"])}
        cases = [c for c in cases if c["case_id"] in selected]
        if {c["case_id"] for c in cases} != selected:
            raise ValueError("split coverage mismatch")
    if not cases:
        raise ValueError("empty case selection")
    return cases[: limit or 2] if mode == "smoke" else cases


def prepare(root: Path, config: Path, *, sources: bool = False) -> dict:
    """Metadata-only by default; --sources explicitly fetches pinned snapshots."""
    cfg = load_dataset_config(config)
    raw = (
        root
        / "data/raw"
        / ("cwe_bench_java_v1" if cfg.dataset_id == "D_repro_v1" else "cwe_bench_java_extended")
    )
    acquire_dataset(cfg, raw)
    summary = materialize_release(root, raw, cfg, write_splits=cfg.dataset_id != "D_repro_v1")
    if sources:
        from src.data.build_projects import _fetch_source

        rows = read_csv(
            root
            / "data/processed/manifests"
            / ("cwe_bench_v1.csv" if cfg.dataset_id == "D_repro_v1" else "cwe_bench_extended.csv")
        )
        view = root / "data/processed/analysis_input"
        for row in rows:
            ok, reason, _ = _fetch_source(
                row,
                raw,
                root / "data/interim/project_sources",
                root / "data/interim/dataset_logs",
                7200,
            )
            if not ok:
                raise RuntimeError(reason)
            source = root / "data/interim/project_sources" / row["project_id"]
            target = view / "projects" / row["project_id"]
            if target.exists():
                raise ValueError("snapshot exists; refusing to overwrite")
            if any(p.is_symlink() for p in source.rglob("*") if ".git" not in p.parts):
                raise ValueError(
                    "source symlinks require explicit audit before snapshot preparation"
                )
            shutil.copytree(
                source,
                target,
                symlinks=False,
                ignore=shutil.ignore_patterns(
                    ".git", "target", "build", ".gradle", "*.patch", "*.diff"
                ),
            )
            import yaml

            from src.common.envfile import effective_env
            from src.data.build_projects import build_command_and_env

            toolchains = yaml.safe_load(
                (root / "configs/toolchains/cwe_bench_java.yaml").read_text()
            )
            machine = effective_env(root / ".env")
            attempts = []
            for option in toolchains["build_attempts"]:
                try:
                    args, env = build_command_and_env(root, target, option, toolchains, machine)
                    attempts.append(
                        {
                            "command": args,
                            "environment": {
                                k: v for k, v in env.items() if k in {"JAVA_HOME", "PATH"}
                            },
                        }
                    )
                except ValueError:
                    continue
            (target / "build.runtime.json").write_text(
                json.dumps({"attempts": attempts}, sort_keys=True)
            )
            files = {
                p.relative_to(target).as_posix(): sha256_file(p)
                for p in target.rglob("*")
                if p.is_file()
            }
            (target / "snapshot.files.json").write_text(json.dumps(files, sort_keys=True))
    return summary
