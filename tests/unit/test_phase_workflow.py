from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NOTEBOOK = PROJECT_ROOT / "workflows" / "notebooks" / "phase_00_reproducibility.ipynb"


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_phase0_notebook_is_clean_and_has_one_parameter_cell() -> None:
    notebook = _json(NOTEBOOK)
    assert notebook["nbformat"] == 4
    cells = notebook["cells"]
    assert isinstance(cells, list) and cells
    parameter_cells = []
    for cell in cells:
        assert isinstance(cell, dict)
        if cell.get("cell_type") != "code":
            continue
        assert cell.get("execution_count") is None
        assert cell.get("outputs") == []
        if "parameters" in cell.get("metadata", {}).get("tags", []):
            parameter_cells.append(cell)
    assert len(parameter_cells) == 1


def test_only_implemented_phase_has_a_canonical_notebook() -> None:
    notebooks = sorted(path.name for path in NOTEBOOK.parent.glob("phase_*.ipynb"))
    assert notebooks == ["phase_00_reproducibility.ipynb"]
    workflow_readme = (PROJECT_ROOT / "workflows" / "README.md").read_text(encoding="utf-8")
    for phase in range(10):
        assert f"| {phase} |" in workflow_readme


def test_primary_model_config_targets_p2000_without_cuda13() -> None:
    path = PROJECT_ROOT / "configs" / "models" / "qwen25_coder_3b_q4_k_m.yaml"
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert config["model_id"] == "Qwen/Qwen2.5-Coder-3B-Instruct-GGUF"
    assert config["quantization"] == "Q4_K_M"
    assert config["cuda"] == {
        "toolkit": "12.4",
        "architecture": "61",
        "minimum_windows_driver": "551.61",
        "forbid_toolkit_major": 13,
    }
    assert config["target_hardware"]["vram_mib"] == 4096


def test_phase0_frozen_results_use_the_new_partition() -> None:
    root = PROJECT_ROOT / "results" / "phases" / "phase_00"
    assert (root / "report.md").is_file()
    assert (root / "status.json").is_file()
    assert (root / "baselines" / "codeql").is_dir()
    assert (root / "baselines" / "iris").is_dir()
