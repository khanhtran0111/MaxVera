.PHONY: sync sync-notebook bootstrap test lint typecheck doctor phase0-data phase0

sync:
	uv sync --extra dev --locked

sync-notebook:
	uv sync --extra dev --extra notebook --locked

bootstrap:
	uv run python scripts/data/bootstrap_upstream.py
	uv run python scripts/toolchain/fetch_codeql.py
	uv run python scripts/toolchain/fetch_qwen_gguf.py

test:
	uv run pytest

lint:
	uv run ruff check .

typecheck:
	uv run mypy

doctor:
	uv run openiris-doctor --config configs/toolchain/phase0.yaml

phase0-data:
	uv run python scripts/data/prepare_phase0.py

phase0:
	uv run python scripts/data/prepare_phase0.py
	uv run python scripts/analysis/import_reference_results.py
	uv run openiris-doctor --config configs/toolchain/phase0.yaml --strict
	uv run pytest
	uv run python scripts/phase0.py
