.PHONY: setup setup-phase3 setup-phase4 preflight preflight-full test lint typecheck check manifest phase2-data phase2-build phase2-validate phase3-smoke phase4-pilot phase4-validate phase5-budget phase5-check

setup:
	bash scripts/tools/setup_environment.sh

setup-phase3:
	bash scripts/tools/setup_phase3_dependencies.sh

setup-phase4:
	bash scripts/tools/setup_phase4.sh

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

phase2-data:
	bash scripts/tools/fetch_cwe_bench_v1.sh
	bash scripts/tools/create_data_manifests.sh

phase2-build:
	bash scripts/tools/build_codeql_databases.sh

phase2-validate:
	bash scripts/tools/validate_phase2.sh

phase3-smoke:
	bash scripts/tools/run_smoke_suite.sh --run-id phase3_gate_pass
	! bash scripts/tools/run_smoke_suite.sh --run-id phase3_gate_fail --fail-after analysis
	bash scripts/tools/assert_no_smoke_artifacts.sh

phase4-pilot:
	bash scripts/tools/run_phase4_reproduction.sh --mode pilot --limit 1 --run-id phase4_gptoss20b_pilot_002

phase4-validate:
	bash scripts/tools/validate_phase4.sh --run-id "$${RUN_ID}"

phase5-budget:
	bash scripts/tools/estimate_phase5_budget.sh

phase5-check: check phase5-budget
	bash scripts/tools/assert_no_smoke_artifacts.sh
