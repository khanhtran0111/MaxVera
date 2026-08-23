"""Small display/orchestration helpers shared by canonical phase notebooks."""

from __future__ import annotations

import html
import json
import os
import shutil
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class StepResult:
    title: str
    argv: tuple[str, ...]
    returncode: int
    runtime_seconds: float
    output: str
    executed: bool


def find_project_root(start: str | Path | None = None) -> Path:
    """Find the repository root without assuming the notebook server working directory."""

    current = Path(start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / "workflows").is_dir():
            return candidate
    raise FileNotFoundError("could not locate MaxVera project root")


def _display_html(markup: str) -> None:
    from IPython.display import HTML, display

    display(HTML(markup))


def status_table(rows: Sequence[tuple[str, str, str]]) -> None:
    """Render a compact status table without requiring pandas."""

    body = []
    colors = {"PASS": "#166534", "WARN": "#a16207", "FAIL": "#b91c1c", "SKIP": "#475569"}
    for name, status, detail in rows:
        color = colors.get(status, "#334155")
        body.append(
            "<tr>"
            f"<td style='padding:6px 10px'>{html.escape(name)}</td>"
            f"<td style='padding:6px 10px;color:{color};font-weight:700'>{html.escape(status)}</td>"
            f"<td style='padding:6px 10px'><code>{html.escape(detail)}</code></td>"
            "</tr>"
        )
    _display_html(
        "<table style='border-collapse:collapse;width:100%'>"
        "<thead><tr><th align='left'>Check</th><th align='left'>Status</th>"
        "<th align='left'>Detail</th></tr></thead><tbody>" + "".join(body) + "</tbody></table>"
    )


def command_probe(name: str, argv: Sequence[str], *, required: bool = True) -> tuple[str, str, str]:
    executable = shutil.which(argv[0])
    if executable is None:
        return name, "FAIL" if required else "WARN", f"not found: {argv[0]}"
    process = subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    output = (process.stdout or process.stderr).strip().splitlines()
    detail = output[0] if output else executable
    return name, "PASS" if process.returncode == 0 else "WARN", detail[:180]


def run_step(
    title: str,
    argv: Sequence[str],
    *,
    root: Path,
    execute: bool = True,
    timeout_seconds: float | None = None,
) -> StepResult:
    """Run one visible notebook step and fail immediately on a non-zero exit code."""

    rendered = subprocess.list2cmdline(list(argv))
    if not execute:
        status_table([(title, "SKIP", rendered)])
        return StepResult(title, tuple(argv), 0, 0.0, "", executed=False)
    started = time.monotonic()
    process = subprocess.run(
        list(argv),
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
    )
    runtime = time.monotonic() - started
    output = "\n".join(part.rstrip() for part in (process.stdout, process.stderr) if part)
    status_table(
        [
            (
                title,
                "PASS" if process.returncode == 0 else "FAIL",
                f"{runtime:.1f}s | {rendered}",
            )
        ]
    )
    if output:
        print(output[-12000:])
    if process.returncode != 0:
        raise RuntimeError(f"{title} failed with exit code {process.returncode}")
    return StepResult(title, tuple(argv), process.returncode, runtime, output, executed=True)


def artifact_links(paths: Sequence[str | Path], *, root: Path) -> None:
    """Display clickable notebook-relative links and absolute paths."""

    from IPython.display import Markdown, display

    lines = ["**Artifacts**", ""]
    for raw_path in paths:
        path = Path(raw_path)
        absolute = path if path.is_absolute() else (root / path).resolve()
        relative = Path(os.path.relpath(absolute, root)).as_posix()
        marker = "✅" if absolute.exists() else "⚠️"
        lines.append(f"- {marker} [`{relative}`](../../{relative}) — `{absolute}`")
    display(Markdown("\n".join(lines)))


def json_dashboard(path: str | Path, keys: Sequence[str]) -> dict[str, Any]:
    """Render selected top-level JSON values as status cards and return the document."""

    target = Path(path)
    with target.open("r", encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError(f"expected a JSON object: {target}")
    cards = []
    for key in keys:
        value = document.get(key, "—")
        cards.append(
            "<div style='border:1px solid #cbd5e1;border-radius:8px;padding:10px;min-width:150px'>"
            f"<div style='color:#64748b'>{html.escape(key)}</div>"
            f"<div style='font-size:1.35rem;font-weight:700'>{html.escape(str(value))}</div>"
            "</div>"
        )
    _display_html("<div style='display:flex;gap:10px;flex-wrap:wrap'>" + "".join(cards) + "</div>")
    return document
