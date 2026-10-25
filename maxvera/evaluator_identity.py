"""Pin evaluator semantics independently of analyzer/run identity."""

import hashlib
import subprocess
from pathlib import Path

from maxvera.contracts import digest
from src.common.provenance import sha256_file


def verified_upstream(iris_root: Path) -> dict:
    from src.reproduction.runner import IRIS_COMMIT, _git_head

    if _git_head(iris_root) != IRIS_COMMIT:
        raise ValueError("IRIS evaluator checkout differs from pinned v1 commit")
    relative = "src/modules/evaluation_pipeline.py"
    pinned = subprocess.run(
        ["git", "show", IRIS_COMMIT + ":" + relative],
        cwd=iris_root,
        capture_output=True,
        check=False,
    )
    current = iris_root / relative
    if (
        pinned.returncode
        or not current.is_file()
        or sha256_file(current) != hashlib.sha256(pinned.stdout).hexdigest()
    ):
        raise ValueError("IRIS evaluator code differs from pinned upstream source")
    return {"commit": IRIS_COMMIT, "sha256": sha256_file(current)}


def evaluator_identity(root: Path, protocol: str, policy_version: str) -> dict:
    from maxvera.evaluation import ORACLE_PROTOCOLS, metric_semantics

    package = Path(__file__).resolve().parent
    files = [
        package / name for name in ("evaluation.py", "evaluator_worker.py", "evaluator_identity.py")
    ]
    if protocol == "zero_hint":
        files.append(package / "truth_alignment.py")
    files.append(package.parent / "src/reproduction/common.py")
    identity = {
        "policy_version": policy_version,
        "implementation_hash": digest({p.name: sha256_file(p) for p in files}),
        "upstream": verified_upstream(root / "third_party/iris")
        if protocol in ORACLE_PROTOCOLS
        else None,
    }
    if protocol in ORACLE_PROTOCOLS:
        identity.update(metric_semantics(protocol))
    return identity
