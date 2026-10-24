"""Exercise run-local IRIS repairs without importing or calling a remote model."""

import ast
import copy
import json
import os
import re
import warnings
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

REPO = Path(__file__).resolve().parents[2]


def upstream_classes():
    """Load real upstream method bodies while excluding model imports."""
    classes = []
    for relative, name in [
        ("src/neusym_vul.py", "SAPipeline"),
        ("src/modules/contextual_analysis_pipeline.py", "ContextualAnalysisPipeline"),
    ]:
        path = REPO / "third_party/iris" / relative
        with warnings.catch_warnings():
            # Preserve actual upstream bodies without surfacing their legacy
            # invalid-escape warnings from AST parsing in every test case.
            warnings.simplefilter("ignore", DeprecationWarning)
            tree = ast.parse(path.read_text())
        node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name)
        namespace = dict(os=os, pd=pd, json=json, copy=copy, re=re)
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
        classes.append(namespace[name])
    return classes


def context_pipeline(tmp_path, cls, *, final_status):
    for name in ("classes.csv", "methods.csv"):
        (tmp_path / name).write_text("file,name,start_line,end_line\nX.java,m,1,10\n")

    def location(line, message):
        return {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": "X.java"},
                    "region": {"startLine": line, "endColumn": 2},
                },
                "message": {"text": message},
            }
        }

    flows = [
        {"threadFlows": [{"locations": [location(1, "source"), location(2, "sink")]}]},
        {"threadFlows": [{"locations": [location(3, final_status), location(4, "sink")]}]},
    ]
    (tmp_path / "raw.sarif").write_text(json.dumps({"runs": [{"results": [{"codeFlows": flows}]}]}))
    pipeline = cls.__new__(cls)
    pipeline.__dict__.update(
        class_locs_path=str(tmp_path / "classes.csv"),
        func_locs_path=str(tmp_path / "methods.csv"),
        project_fixed_methods=pd.DataFrame(),
        query_output_result_sarif_path=str(tmp_path / "raw.sarif"),
        posthoc_filtering_output_result_json_path=str(tmp_path / "out.json"),
        posthoc_filtering_output_result_sarif_path=str(tmp_path / "out.sarif"),
        posthoc_filtering_output_stats_json_path=str(tmp_path / "stats.json"),
        project_logger=SimpleNamespace(info=lambda *args: None, error=lambda *args: None),
        overwrite=False,
        overwrite_posthoc_filter=False,
        test_run=False,
        posthoc_filtering_skip_fp=False,
        skip_check_fixed_method=True,
        batch_size=3,
        alarm_results={},
    )
    pipeline.use_cache_on_code_flow = lambda rid, fid, path, *args: (
        {"is_vulnerable": False, "source_is_false_positive": True, "sink_is_false_positive": False}
        if final_status == "cached" and fid == 1
        else None
    )
    pipeline.ignore_code_flow = lambda path: path[0]["message"] == "ignored"
    pipeline.batched_query_gpt_on_code_flow = lambda entries, *args: [
        (rid, fid, {"path": path, "using_cache": False, "result": {"is_vulnerable": True}})
        for rid, fid, path in entries
    ]
    return pipeline


@pytest.mark.parametrize(
    "raw,kind",
    [
        ("{}", "iris_context"),
        (
            '{"is_vulnerable":"true","source_is_false_positive":false,"sink_is_false_positive":false,"explanation":""}',
            "iris_context",
        ),
        (
            '{"is_vulnerable":true,"source_is_false_positive":false,"explanation":""}',
            "iris_context",
        ),
        ('[{"type":"sink"}]', "iris_api_labels"),
        (
            '[{"package":"p","class":"C","method":"m","signature":"m()","type":"other","sink_args":[]}]',
            "iris_api_labels",
        ),
        (
            '[{"package":"p","class":"C","method":"m","signature":"m()","type":"sink","sink_args":"p0"}]',
            "iris_api_labels",
        ),
        (
            '[{"package":"p","class":"C","method":"m","signature":"m()","type":[],"sink_args":[]}]',
            "iris_api_labels",
        ),
        (
            '[{"package":"p","class":"C","method":"m","signature":"m()","tainted_input":[1]}]',
            "iris_param_labels",
        ),
    ],
)
def test_invalid_semantic_schema_cannot_enter_successful_journal(raw, kind):
    from maxvera.llm import _validate_output

    with pytest.raises(ValueError):
        _validate_output(raw, kind)


def test_positive_only_labels_accept_empty_result_without_inventing_missing_ids():
    from maxvera.llm import _validate_output

    for kind in ("iris_api_labels", "iris_param_labels"):
        _validate_output("[]", kind)


@pytest.mark.parametrize("explanation", ["See http://example.invalid/path", "", 'quoted "value"'])
def test_context_parser_preserves_valid_strings(explanation):
    from maxvera.iris_compat import install_compatibility

    api_cls, context_cls = upstream_classes()
    install_compatibility(api_cls, context_cls)
    pipeline = context_cls.__new__(context_cls)
    payload = {
        "is_vulnerable": True,
        "source_is_false_positive": False,
        "sink_is_false_positive": False,
        "explanation": explanation,
    }
    assert pipeline.parse_posthoc_filter_json_result(json.dumps(payload)) == payload


def test_api_parser_preserves_valid_empty_list_and_strings():
    from maxvera.iris_compat import install_compatibility

    api_cls, context_cls = upstream_classes()
    install_compatibility(api_cls, context_cls)
    pipeline = api_cls.__new__(api_cls)
    payload = [
        {
            "package": "p",
            "class": "C",
            "method": "m",
            "signature": "m()",
            "type": "source",
            "sink_args": [],
            "explanation": "http://example.invalid",
        }
    ]
    assert pipeline.parse_json(json.dumps(payload)) == payload
    assert pipeline.parse_json("```json\n[]\n```") == []


@pytest.mark.parametrize("final_status", ["ignored", "cached"])
def test_context_tail_is_processed_when_final_path_does_not_need_a_call(tmp_path, final_status):
    from maxvera.iris_compat import install_compatibility

    api_cls, context_cls = upstream_classes()
    install_compatibility(api_cls, context_cls)
    pipeline = context_pipeline(tmp_path, context_cls, final_status=final_status)
    pipeline.run()
    entries = json.loads((tmp_path / "out.json").read_text())
    assert {entry["code_flow_id"] for entry in entries} == {0, 1}
    result = json.loads((tmp_path / "out.sarif").read_text())
    assert len(result["runs"][0]["results"][0]["codeFlows"]) == 1
    assert (
        result["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"][0][
            "location"
        ]["physicalLocation"]["region"]["startLine"]
        == 1
    )
    stats = json.loads((tmp_path / "stats.json").read_text())
    assert stats["num_gpt_calls"] == 1
    assert stats["num_failure"] == 0


def test_installer_declares_parser_and_batch_compatibility_deviations():
    from maxvera.iris_compat import install_compatibility

    api_cls, context_cls = upstream_classes()
    metadata = install_compatibility(api_cls, context_cls)
    assert metadata["positive_only_label_omissions"] == "UNCHANGED"
    assert metadata["negative_endpoint_cache"] == "UNCHANGED"
    assert metadata["context_tail_flush"] is True
    assert metadata["json_parsing"] == "STRICT_WITHOUT_STRING_REWRITES"


def test_worker_dispatch_retries_invalid_api_and_parameter_schemas(tmp_path, monkeypatch):
    from maxvera.iris_worker import run_stage
    from maxvera.llm import IrisProvider
    from src.llm.providers.openrouter import OpenRouterSettings

    counts = {}

    def remote(client, messages, **kwargs):
        kind = messages[0]["content"]
        counts[kind] = counts.get(kind, 0) + 1
        client._append_log({"usage": {"cost": 0}, "finish_reason": "stop"})
        return "[{}]" if counts[kind] == 1 else "[]"

    settings = OpenRouterSettings(
        "https://openrouter.ai/api/v1",
        "fixture-key",
        "openai/gpt-oss-20b",
        "fixture",
        64,
        0,
        1,
        1234,
        "low",
        5,
        1,
    )
    monkeypatch.setattr("src.llm.providers.openrouter.OpenRouterClient.complete", remote)
    monkeypatch.setattr(IrisProvider, "settings", settings)
    monkeypatch.setattr(
        IrisProvider,
        "request",
        {
            "journal": str(tmp_path),
            "budgets": {},
            "stage": "llm_specs",
        },
    )
    monkeypatch.setattr(IrisProvider, "_failure", None)
    monkeypatch.setattr(IrisProvider, "_failure_request", None)
    provider = IrisProvider()

    class Pipeline:
        def query_gpt_for_api_src_tp_sink_batched(self):
            assert provider.predict([[{"role": "user", "content": "api"}]], batch_size=1) == ["[]"]

        def query_gpt_for_func_param_src(self):
            assert provider.predict([[{"role": "user", "content": "param"}]], batch_size=1) == [
                "[]"
            ]

    run_stage(Pipeline(), "llm_specs")
    attempts = list(tmp_path.glob("requests/*/attempt-*.json"))
    assert len(attempts) == 4
    assert len(list(tmp_path.glob("requests/*/response-1.txt"))) == 2
    assert all(
        json.loads(path.read_text())["status"] == "SUCCESS"
        for path in tmp_path.glob("requests/*/request.json")
    )


def test_semantic_validation_cannot_bypass_existing_uncertain_billing_identity(tmp_path):
    from maxvera.llm import JournaledClient
    from src.llm.providers.openrouter import OpenRouterSettings

    settings = OpenRouterSettings(
        "https://openrouter.ai/api/v1",
        "fixture-key",
        "openai/gpt-oss-20b",
        "fixture",
        64,
        0,
        1,
        1234,
        "low",
        5,
        1,
    )
    client = JournaledClient(settings, tmp_path, {})
    messages = [{"role": "user", "content": "original prompt"}]
    key = client.key(messages, False, 64, True, "array")
    folder = tmp_path / "requests" / key
    folder.mkdir(parents=True)
    (folder / "request.json").write_text(json.dumps({"status": "UNCERTAIN"}))
    with pytest.raises(RuntimeError, match="uncertain"):
        client.complete(messages, validate_json=True, expected_kind="iris_api_labels")


def test_context_run_keeps_original_negative_endpoint_pruning(tmp_path):
    from maxvera.iris_compat import install_compatibility

    api_cls, context_cls = upstream_classes()
    install_compatibility(api_cls, context_cls)
    pipeline = context_pipeline(tmp_path, context_cls, final_status="normal")
    del pipeline.use_cache_on_code_flow
    del pipeline.batched_query_gpt_on_code_flow
    raw = json.loads((tmp_path / "raw.sarif").read_text())
    flows = raw["runs"][0]["results"][0]["codeFlows"]
    flows[:] = [copy.deepcopy(flows[0]) for _ in range(4)]
    for index, flow in enumerate(flows):
        flow["threadFlows"][0]["locations"][-1]["location"]["message"]["text"] = f"sink-{index}"
    (tmp_path / "raw.sarif").write_text(json.dumps(raw))
    pipeline.posthoc_filtering_output_log_path = str(tmp_path)
    pipeline.build_prompt_for_code_flow = lambda *args: [
        {"role": "system", "content": "fixture"},
        {"role": "user", "content": "fixture"},
    ]
    verdict = {
        "is_vulnerable": False,
        "source_is_false_positive": True,
        "sink_is_false_positive": False,
        "explanation": "source is safe",
    }
    pipeline.get_model = lambda: SimpleNamespace(
        predict=lambda prompts, **kwargs: [json.dumps(verdict) for _ in prompts]
    )
    pipeline.run()
    stats = json.loads((tmp_path / "stats.json").read_text())
    assert stats["num_gpt_calls"] == 3
    assert stats["num_cached"] == 1
    assert stats["num_failure"] == 0
    assert (
        json.loads((tmp_path / "out.sarif").read_text())["runs"][0]["results"][0]["codeFlows"] == []
    )
