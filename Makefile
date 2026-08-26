.PHONY: setup preflight preflight-full test lint typecheck check manifest

setup:
	bash scripts/tools/setup_environment.sh

preflight:
	bash scripts/tools/preflight.sh --profile phase1

preflight-full:
	bash scripts/tools/preflight.sh --profile full

test:
	uv run --frozen pytest

lint:
	uv run --frozen ruff check .

typecheck:
	uv run --frozen mypy src

check: test lint typecheck

manifest:
	uv run --frozen python -m src.common.provenance --output .cache/manifests/development.json --mode development
