"""Research DB identity binds relation bytes to the frozen source checkpoint."""

import json
from dataclasses import replace

import pytest

from maxvera.orchestration import Context, Orchestrator, Stage, StageFailure


def database_fixture(path):
    (path / "db-java/default/strings").mkdir(parents=True)
    (path / "codeql-database.yml").write_text("primaryLanguage: java\nfinalised: true\n")
    (path / "src.zip").write_bytes(b"source archive fixture")
    (path / "db-java/semmlecode.dbscheme").write_text("schema")
    (path / "db-java/default/data.rel").write_bytes(b"relations")
    (path / "db-java/default/strings/data").write_bytes(b"strings")


def context(root):
    run = root / "run"
    stage = run / "stages/opaque-case/static_extract"
    stage.mkdir(parents=True)
    database_fixture(run / "databases/opaque-case")
    return Context(root, run, stage, {"case_id": "opaque-case"}, {}, {})


def test_identity_covers_schema_relations_strings_archive_but_allows_query_caches(tmp_path):
    from maxvera.research_database import freeze_database, validate_database

    ctx = context(tmp_path)
    result = freeze_database(ctx, "snapshot")
    ctx.results["static_extract"] = {"result": {**result, "analyzed_snapshot_id": "snapshot"}}
    identity = json.loads((ctx.stage_dir / "db_identity.json").read_text())
    assert set(identity["files"]) == {
        "codeql-database.yml",
        "src.zip",
        "db-java/semmlecode.dbscheme",
        "db-java/default/data.rel",
        "db-java/default/strings/data",
    }
    database = ctx.run_dir / "databases/opaque-case"
    for name in ("db-java/default/cache/query", "db-java/default/pools/entities", "log/query.log"):
        path = database / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("query-mutated bookkeeping")
    validate_database(ctx)


@pytest.mark.parametrize("attack", ["relation", "strings", "schema", "new_file", "missing_file"])
def test_critical_inventory_mutation_requires_new_extraction(tmp_path, attack):
    from maxvera.research_database import freeze_database, validate_database

    ctx = context(tmp_path)
    result = freeze_database(ctx, "snapshot")
    ctx.results["static_extract"] = {"result": {**result, "analyzed_snapshot_id": "snapshot"}}
    db = ctx.run_dir / "databases/opaque-case"
    if attack == "new_file":
        (db / "db-java/default/new.rel").write_text("new")
    elif attack == "missing_file":
        (db / "src.zip").unlink()
    else:
        target = {
            "relation": "db-java/default/data.rel",
            "strings": "db-java/default/strings/data",
            "schema": "db-java/semmlecode.dbscheme",
        }[attack]
        (db / target).write_text("changed")
    with pytest.raises(StageFailure, match="database"):
        validate_database(ctx)


@pytest.mark.parametrize(
    "attack", ["critical_file", "critical_dir", "database_parent", "new_symlink"]
)
def test_database_inventory_rejects_symlink_files_directories_and_parents(tmp_path, attack):
    from maxvera.research_database import freeze_database, validate_database

    ctx = context(tmp_path)
    result = freeze_database(ctx, "snapshot")
    ctx.results["static_extract"] = {"result": {**result, "analyzed_snapshot_id": "snapshot"}}
    db = ctx.run_dir / "databases/opaque-case"
    if attack == "database_parent":
        parent = db.parent
        replacement = parent.with_name("moved-databases")
        parent.rename(replacement)
        parent.symlink_to(replacement, target_is_directory=True)
    elif attack == "critical_dir":
        target = db / "db-java/default/strings"
        replacement = db / "moved-strings"
        target.rename(replacement)
        target.symlink_to(replacement, target_is_directory=True)
    else:
        target = (
            db / "db-java/default/data.rel" if attack == "critical_file" else db / "db-java/new"
        )
        if target.exists():
            target.unlink()
        target.symlink_to(db / "src.zip")
    with pytest.raises(StageFailure, match=r"symlink|database"):
        validate_database(ctx)


def test_incomplete_resume_validates_external_database_before_reusing_static_stage(tmp_path):
    from maxvera.research import stages
    from maxvera.research_database import freeze_database

    called = []

    def extract(ctx):
        database_fixture(ctx.run_dir / "databases/opaque-case")
        called.append("extract")
        return {
            **freeze_database(ctx, "snapshot"),
            "analyzed_snapshot_id": "snapshot",
            "artifacts": ["db_identity.json"],
        }

    def later(ctx):
        called.append("later")
        raise KeyboardInterrupt("interrupted before verifier")

    static = next(stage for stage in stages() if stage.name == "static_extract")
    options = dict(
        root=tmp_path,
        pipeline="research",
        run_id="resume",
        config={},
        cases=[{"case_id": "opaque-case"}],
        implementation_hash="code",
        stages=[
            replace(static, action=extract, dependencies=()),
            Stage("later", later, ("static_extract",)),
        ],
    )
    runner = Orchestrator(**options)
    with pytest.raises(KeyboardInterrupt):
        runner.execute()
    (runner.path / "databases/opaque-case/db-java/default/data.rel").write_text("replaced")
    with pytest.raises(StageFailure, match="database"):
        Orchestrator(**options, resume=True).execute()
    assert called == ["extract", "later"]
