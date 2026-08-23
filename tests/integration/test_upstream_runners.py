from __future__ import annotations

import sys
from pathlib import Path

from openiris.codeql import CodeQLRunner
from openiris.experiments import BaselineStatus
from openiris.iris import IrisRunner


def test_codeql_runner_orchestrates_upstream_entrypoint(tmp_path: Path) -> None:
    iris_root = tmp_path / "iris"
    script = iris_root / "src" / "codeql_vul.py"
    script.parent.mkdir(parents=True)
    script.write_text(
        """
import json
import pathlib
import sys
project = sys.argv[1]
query = sys.argv[sys.argv.index('--query') + 1]
target = pathlib.Path('output') / project / 'common' / query
target.mkdir(parents=True)
(target / 'results.sarif').write_text(json.dumps({
    'version': '2.1.0', 'runs': [{'results': [{'codeFlows': [{}]}]}]
}), encoding='utf-8')
(target / 'results.json').write_text(json.dumps({'num_paths': 1}), encoding='utf-8')
print('upstream codeql ran')
""".strip(),
        encoding="utf-8",
    )

    record = CodeQLRunner(timeout_seconds=5).run_pinned_iris_baseline(
        run_id="r1",
        project="owner__repo_CVE-2020-1234_v1",
        query="cwe-022wCodeQL",
        iris_root=iris_root,
        artifact_dir=tmp_path / "command",
        python_executable=sys.executable,
    )

    assert record.status is BaselineStatus.COMPLETE
    assert record.number_of_paths == 1
    assert record.vulnerability_detected is True
    assert "upstream codeql ran" in (tmp_path / "command" / "stdout.log").read_text(
        encoding="utf-8"
    )


def test_iris_runner_orchestrates_upstream_entrypoint(tmp_path: Path) -> None:
    iris_root = tmp_path / "iris"
    script = iris_root / "src" / "neusym_vul.py"
    script.parent.mkdir(parents=True)
    script.write_text(
        """
import json
import pathlib
import sys
project = sys.argv[1]
query = sys.argv[sys.argv.index('--query') + 1]
run_id = sys.argv[sys.argv.index('--run-id') + 1]
target = pathlib.Path('output') / project / run_id / f'{query}-final'
target.mkdir(parents=True)
(target / 'results.json').write_text(json.dumps({
    'posthoc_filter_result': {'num_paths': 2, 'recall_method': True}
}), encoding='utf-8')
print('upstream iris ran')
""".strip(),
        encoding="utf-8",
    )

    record = IrisRunner(iris_root, timeout_seconds=5).run(
        run_id="r1",
        project="owner__repo_CVE-2020-1234_v1",
        query="cwe-078wLLM",
        model="local-model",
        seed=345,
        artifact_dir=tmp_path / "command",
    )

    assert record.status is BaselineStatus.COMPLETE
    assert record.number_of_paths == 2
    assert record.vulnerability_detected is True
    assert record.metadata["orchestrator"] == "iris_v1_upstream"
    assert "upstream iris ran" in (tmp_path / "command" / "stdout.log").read_text(encoding="utf-8")
