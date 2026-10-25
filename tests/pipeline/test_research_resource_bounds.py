"""Large repositories stop at declared resource bounds without losing failures."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from maxvera.orchestration import Context, StageFailure
from maxvera.process import command


def test_graph_csv_stops_at_first_row_over_limit(tmp_path, monkeypatch):
    from maxvera.research import build_graph

    folder = tmp_path / "stages/opaque/static_extract"
    folder.mkdir(parents=True)
    (folder / "program_nodes.csv").write_text("key\nfirst\nsecond\nthird\n")

    def rows(stream):
        yield {"key": "first"}
        yield {"key": "second"}
        yield {"key": "third"}
        pytest.fail("oversized CSV consumed beyond the configured row bound")

    monkeypatch.setattr("maxvera.research.csv.DictReader", rows)
    context = Context(
        tmp_path,
        tmp_path,
        tmp_path / "out",
        {"case_id": "opaque"},
        {"research": {"max_nodes": 2, "max_edges": 2}},
        {"static_extract": {"result": {"graph_enabled": True}}},
    )
    with pytest.raises(StageFailure) as error:
        build_graph(context)
    assert error.value.status == "GRAPH_LIMIT"


def test_command_caps_newline_free_output_and_redacts_split_tokens(tmp_path):
    secret = "sk-or-v1-" + "s" * 30
    script = (
        "import os\n"
        "os.write(1,b'x'* (20*1024*1024))\n"
        f"os.write(1,{(' ' + secret + ' Bearer another-private-token done').encode()!r})\n"
    )
    log = tmp_path / "output.log"
    command([sys.executable, "-c", script], cwd=tmp_path, log=log, timeout=10)
    content = log.read_text()
    assert log.stat().st_size < 1024 * 1024
    assert "OMITTED" in content
    assert secret not in content
    assert "another-private-token" not in content
    assert "done" in content


def test_command_kills_descendant_on_timeout(tmp_path):
    pidfile = tmp_path / "child.pid"
    script = (
        "import pathlib,subprocess,sys,time\n"
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
        f"pathlib.Path({str(pidfile)!r}).write_text(str(p.pid))\n"
        "print('started',flush=True)\n"
        "time.sleep(60)\n"
    )
    with pytest.raises(StageFailure) as error:
        command([sys.executable, "-c", script], cwd=tmp_path, log=tmp_path / "log", timeout=1)
    assert error.value.status == "TIMEOUT"
    proc = Path(f"/proc/{pidfile.read_text()}/stat")
    assert not proc.exists() or proc.read_text().split()[2] == "Z"


def test_command_stops_when_disk_reserve_is_crossed(tmp_path, monkeypatch):
    calls = 0

    def disk(path):
        nonlocal calls
        calls += 1
        return SimpleNamespace(free=100 * 1024**3 if calls == 1 else 1)

    monkeypatch.setattr("shutil.disk_usage", disk)
    marker = tmp_path / "finished"
    script = f"import pathlib,time;time.sleep(5);pathlib.Path({str(marker)!r}).write_text('bad')"
    with pytest.raises(StageFailure) as error:
        command(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            log=tmp_path / "log",
            timeout=10,
            min_free_gib=20,
        )
    assert error.value.status == "RESOURCE_EXHAUSTED"
    assert not marker.exists()


def test_log_bearer_token_redaction_survives_every_chunk_boundary(tmp_path):
    from maxvera.process import _SafeLog

    secret = "Bearer secret-value sk-or-v1-" + "z" * 20
    for split in range(1, len(secret)):
        path = tmp_path / f"log-{split}"
        with path.open("w") as handle:
            output = _SafeLog(handle)
            output.feed(secret[:split])
            output.feed(secret[split:])
            output.finish()
        assert "secret-value" not in path.read_text()
        assert "sk-or-v1" not in path.read_text()
