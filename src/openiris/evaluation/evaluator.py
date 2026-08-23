"""SARIF path evaluator compatible with the IRIS v1 benchmark protocol."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass
from os import PathLike
from pathlib import Path
from typing import Any, cast

from openiris.evaluation.ground_truth import GroundTruth
from openiris.evaluation.locations import LocationIndex
from openiris.evaluation.paths import normalize_uri
from openiris.utils.io import write_json

JsonObject = Mapping[str, Any]
MetricValue = int | bool


class SarifFormatError(ValueError):
    """Raised when SARIF lacks structure required for path evaluation."""


@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    """The eight values returned by IRIS v1 ``evaluate_sarif_result``."""

    num_results: int
    num_paths: int
    recall_file: bool
    num_tp_paths_file: int
    num_tp_results_file: int
    recall_method: bool
    num_tp_paths_method: int
    num_tp_results_method: int

    def to_dict(self) -> dict[str, MetricValue]:
        return cast(dict[str, MetricValue], asdict(self))


def _as_mapping(value: object, context: str) -> JsonObject:
    if not isinstance(value, Mapping):
        raise SarifFormatError(f"{context} must be a JSON object")
    return cast(JsonObject, value)


def _as_sequence(value: object, context: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise SarifFormatError(f"{context} must be a JSON array")
    return value


def _load_json_object(path: str | PathLike[str]) -> JsonObject:
    with Path(path).open("r", encoding="utf-8-sig") as handle:
        value: object = json.load(handle)
    return _as_mapping(value, str(path))


def _first_run_results(sarif: JsonObject) -> Sequence[Any]:
    runs = _as_sequence(sarif.get("runs"), "SARIF runs")
    if not runs:
        raise SarifFormatError("SARIF must contain at least one run")
    first_run = _as_mapping(runs[0], "SARIF runs[0]")
    return _as_sequence(first_run.get("results"), "SARIF runs[0].results")


def _thread_flow_locations(code_flow: JsonObject) -> Sequence[Any]:
    thread_flows = _as_sequence(code_flow.get("threadFlows"), "codeFlow.threadFlows")
    if not thread_flows:
        raise SarifFormatError("codeFlow must contain at least one threadFlow")
    first_thread_flow = _as_mapping(thread_flows[0], "codeFlow.threadFlows[0]")
    locations = _as_sequence(
        first_thread_flow.get("locations"),
        "codeFlow.threadFlows[0].locations",
    )
    if not locations:
        raise SarifFormatError("threadFlow must contain at least one location")
    return locations


def _nested_location(thread_location: object) -> JsonObject:
    wrapper = _as_mapping(thread_location, "threadFlow location")
    return _as_mapping(wrapper.get("location"), "threadFlow location.location")


def _artifact_uri(thread_location: object) -> str:
    location = _nested_location(thread_location)
    physical = _as_mapping(location.get("physicalLocation"), "location.physicalLocation")
    artifact = _as_mapping(
        physical.get("artifactLocation"),
        "location.physicalLocation.artifactLocation",
    )
    uri = artifact.get("uri")
    if not isinstance(uri, str):
        raise SarifFormatError("artifactLocation.uri must be a string")
    return uri


def _start_line(thread_location: object) -> int:
    location = _nested_location(thread_location)
    physical = _as_mapping(location.get("physicalLocation"), "location.physicalLocation")
    region = _as_mapping(physical.get("region"), "location.physicalLocation.region")
    line = region.get("startLine")
    if isinstance(line, bool) or not isinstance(line, int):
        raise SarifFormatError("region.startLine must be an integer")
    return line


def _message_text(thread_location: object) -> str:
    """Return endpoint text; absent text behaves as a non-ignored endpoint."""

    location = _nested_location(thread_location)
    message = location.get("message")
    if not isinstance(message, Mapping):
        return ""
    text = message.get("text")
    return text if isinstance(text, str) else ""


class SarifEvaluator:
    """Evaluate CodeQL path-query SARIF using IRIS v1 overlap semantics.

    Only the first SARIF run and the first thread flow of each code flow are
    considered, matching the reference implementation exactly.
    """

    def __init__(
        self,
        ground_truth: GroundTruth | object,
        class_locations: LocationIndex | object,
        method_locations: LocationIndex | object,
        *,
        repository_root: str | PathLike[str] | None = None,
    ) -> None:
        self.repository_root = repository_root
        self.ground_truth = (
            ground_truth
            if isinstance(ground_truth, GroundTruth)
            else GroundTruth.from_records(ground_truth, repository_root=repository_root)
        )
        self.class_locations = (
            class_locations
            if isinstance(class_locations, LocationIndex)
            else LocationIndex.from_records(class_locations, repository_root=repository_root)
        )
        self.method_locations = (
            method_locations
            if isinstance(method_locations, LocationIndex)
            else LocationIndex.from_records(method_locations, repository_root=repository_root)
        )

    @classmethod
    def from_files(
        cls,
        ground_truth_path: str | PathLike[str],
        class_locations_path: str | PathLike[str],
        method_locations_path: str | PathLike[str],
        *,
        repository_root: str | PathLike[str] | None = None,
        project_slug: str | None = None,
        cve_id: str | None = None,
    ) -> SarifEvaluator:
        ground_truth = GroundTruth.from_records(
            ground_truth_path,
            repository_root=repository_root,
            project_slug=project_slug,
            cve_id=cve_id,
        )
        return cls(
            ground_truth,
            class_locations_path,
            method_locations_path,
            repository_root=repository_root,
        )

    @staticmethod
    def iter_code_flows(sarif: JsonObject) -> Iterator[tuple[int, int, JsonObject]]:
        """Yield ``(result_index, code_flow_index, code_flow)`` from run zero."""

        for result_index, result_value in enumerate(_first_run_results(sarif)):
            result = _as_mapping(result_value, f"SARIF result {result_index}")
            if "codeFlows" not in result:
                continue
            code_flows = _as_sequence(
                result["codeFlows"],
                f"SARIF result {result_index}.codeFlows",
            )
            for flow_index, code_flow_value in enumerate(code_flows):
                yield (
                    result_index,
                    flow_index,
                    _as_mapping(code_flow_value, "SARIF codeFlow"),
                )

    @staticmethod
    def ignore_code_flow(code_flow: JsonObject) -> bool:
        """Apply IRIS v1's source/sink endpoint message filter."""

        locations = _thread_flow_locations(code_flow)
        first_text = _message_text(locations[0])
        last_text = _message_text(locations[-1])
        return (
            "toString" in first_text
            or "println" in first_text
            or "toString" in last_text
            or "println" in last_text
        )

    def extract_code_flow_passing_files(self, code_flow: JsonObject) -> Iterator[str]:
        for location in _thread_flow_locations(code_flow):
            uri = _artifact_uri(location)
            yield normalize_uri(uri, self.repository_root)

    def extract_code_flow_passing_method_keys(
        self,
        code_flow: JsonObject,
    ) -> Iterator[tuple[str, str, str]]:
        for location in _thread_flow_locations(code_flow):
            # The reference implementation skips a location if any part of its
            # file/line/class/method lookup fails.
            try:
                file = normalize_uri(_artifact_uri(location), self.repository_root)
                line = _start_line(location)
            except (SarifFormatError, TypeError, ValueError):
                continue

            enclosing_class = self.class_locations.closest_enclosing(file, line)
            if enclosing_class is None:
                continue
            enclosing_method = self.method_locations.closest_enclosing(file, line)
            if enclosing_method is None:
                continue
            yield (file, enclosing_class.name, enclosing_method.name)

    def extract_code_flow_passing_methods(self, code_flow: JsonObject) -> Iterator[str]:
        """Yield IRIS's historical colon-delimited method identifiers."""

        for file, class_name, method_name in self.extract_code_flow_passing_method_keys(code_flow):
            yield f"{file}:{class_name}:{method_name}"

    def evaluate_document(self, sarif: JsonObject) -> EvaluationMetrics:
        results = _first_run_results(sarif)
        fixed_files = self.ground_truth.fixed_files
        fixed_methods = self.ground_truth.fixed_method_keys

        recall_file = False
        recall_method = False
        num_tp_paths_file = 0
        num_tp_paths_method = 0
        tp_result_file_ids: set[int] = set()
        tp_result_method_ids: set[int] = set()
        num_paths = 0

        for result_index, _, code_flow in self.iter_code_flows(sarif):
            if self.ignore_code_flow(code_flow):
                continue

            passing_files = set(self.extract_code_flow_passing_files(code_flow))
            if fixed_files.intersection(passing_files):
                recall_file = True
                num_tp_paths_file += 1
                tp_result_file_ids.add(result_index)

            passing_methods = set(self.extract_code_flow_passing_method_keys(code_flow))
            if fixed_methods.intersection(passing_methods):
                recall_method = True
                num_tp_paths_method += 1
                tp_result_method_ids.add(result_index)

            num_paths += 1

        return EvaluationMetrics(
            num_results=len(results),
            num_paths=num_paths,
            recall_file=recall_file,
            num_tp_paths_file=num_tp_paths_file,
            num_tp_results_file=len(tp_result_file_ids),
            recall_method=recall_method,
            num_tp_paths_method=num_tp_paths_method,
            num_tp_results_method=len(tp_result_method_ids),
        )

    def evaluate_path(self, sarif_path: str | PathLike[str]) -> EvaluationMetrics:
        return self.evaluate_document(_load_json_object(sarif_path))


def evaluate_sarif(
    sarif: JsonObject | str | PathLike[str],
    ground_truth: GroundTruth | object,
    class_locations: LocationIndex | object,
    method_locations: LocationIndex | object,
    *,
    repository_root: str | PathLike[str] | None = None,
) -> dict[str, MetricValue]:
    """Convenience API returning the reference-compatible metrics mapping."""

    evaluator = SarifEvaluator(
        ground_truth,
        class_locations,
        method_locations,
        repository_root=repository_root,
    )
    metrics = (
        evaluator.evaluate_document(sarif)
        if isinstance(sarif, Mapping)
        else evaluator.evaluate_path(sarif)
    )
    return metrics.to_dict()


class EvaluationPipeline:
    """Dependency-free compatibility facade for IRIS v1 ``EvaluationPipeline``.

    The constructor retains the reference argument names so existing baseline
    orchestration can switch to this implementation without pandas.
    """

    def __init__(
        self,
        project_fixed_methods: GroundTruth | object,
        class_locs_path: LocationIndex | object,
        func_locs_path: LocationIndex | object,
        project_source_code_dir: str | PathLike[str] | None = None,
        external_apis_csv_path: str | PathLike[str] | None = None,
        candidate_apis_csv_path: str | PathLike[str] | None = None,
        llm_labelled_sink_apis_path: str | PathLike[str] | None = None,
        llm_labelled_source_apis_path: str | PathLike[str] | None = None,
        llm_labelled_taint_prop_apis_path: str | PathLike[str] | None = None,
        source_func_param_candidates_path: str | PathLike[str] | None = None,
        llm_labelled_source_func_params_path: str | PathLike[str] | None = None,
        query_output_result_sarif_path: str | PathLike[str] | None = None,
        posthoc_filtering_output_result_sarif_path: str | PathLike[str] | None = None,
        final_output_json_path: str | PathLike[str] | None = None,
        project_logger: object | None = None,
        overwrite: bool = False,
        test_run: bool = False,
    ) -> None:
        self.project_fixed_methods = project_fixed_methods
        self.class_locs_path = class_locs_path
        self.func_locs_path = func_locs_path
        self.project_source_code_dir = project_source_code_dir
        self.external_apis_csv_path = external_apis_csv_path
        self.candidate_apis_csv_path = candidate_apis_csv_path
        self.llm_labelled_sink_apis_path = llm_labelled_sink_apis_path
        self.llm_labelled_source_apis_path = llm_labelled_source_apis_path
        self.llm_labelled_taint_prop_apis_path = llm_labelled_taint_prop_apis_path
        self.source_func_param_candidates_path = source_func_param_candidates_path
        self.llm_labelled_source_func_params_path = llm_labelled_source_func_params_path
        self.query_output_result_sarif_path = query_output_result_sarif_path
        self.posthoc_filtering_output_result_sarif_path = posthoc_filtering_output_result_sarif_path
        self.final_output_json_path = final_output_json_path
        self.project_logger = project_logger
        self.overwrite = overwrite
        self.test_run = test_run
        self._evaluator = SarifEvaluator(
            project_fixed_methods,
            class_locs_path,
            func_locs_path,
            repository_root=project_source_code_dir,
        )

    def get_source_line(self, location: JsonObject) -> str:
        try:
            file = normalize_uri(_artifact_uri(location), self.project_source_code_dir)
            line_number = _start_line(location)
        except (SarifFormatError, TypeError, ValueError):
            return ""
        if self.project_source_code_dir is None:
            return ""
        source_path = Path(self.project_source_code_dir) / Path(file)
        try:
            with source_path.open("r", encoding="utf-8", errors="replace") as handle:
                for current_line, text in enumerate(handle, start=1):
                    if current_line == line_number:
                        return text
        except OSError:
            return ""
        return ""

    def compute_statistics(self) -> dict[str, int]:
        if self.test_run:
            counts = [0] * 7
        else:
            csv_paths = [
                self.external_apis_csv_path,
                self.candidate_apis_csv_path,
                self.source_func_param_candidates_path,
            ]
            json_paths = [
                self.llm_labelled_sink_apis_path,
                self.llm_labelled_source_apis_path,
                self.llm_labelled_taint_prop_apis_path,
                self.llm_labelled_source_func_params_path,
            ]
            csv_counts = [_count_csv(path) for path in csv_paths]
            json_counts = [_count_json(path) for path in json_paths]
            counts = [
                csv_counts[0],
                csv_counts[1],
                json_counts[0],
                json_counts[1],
                json_counts[2],
                csv_counts[2],
                json_counts[3],
            ]
        return {
            "num_external_api_calls": counts[0],
            "num_api_candidates": counts[1],
            "num_labelled_sinks": counts[2],
            "num_labelled_sources": counts[3],
            "num_labelled_taint_propagators": counts[4],
            "num_public_func_candidates": counts[5],
            "num_labelled_func_param_sources": counts[6],
            "num_gpt_calls_for_posthoc_filtering": 0,
            "num_cached_during_posthoc_filtering": 0,
        }

    def extract_code_flow_passing_files(self, code_flow: JsonObject) -> Iterator[str]:
        yield from self._evaluator.extract_code_flow_passing_files(code_flow)

    def extract_code_flow_passing_methods(
        self,
        project_classes: LocationIndex | object,
        project_methods: LocationIndex | object,
        code_flow: JsonObject,
    ) -> Iterator[str]:
        evaluator = SarifEvaluator(
            self._evaluator.ground_truth,
            project_classes,
            project_methods,
            repository_root=self.project_source_code_dir,
        )
        yield from evaluator.extract_code_flow_passing_methods(code_flow)

    @staticmethod
    def iter_code_flows(sarif_json: JsonObject) -> Iterator[tuple[int, int, JsonObject]]:
        yield from SarifEvaluator.iter_code_flows(sarif_json)

    @staticmethod
    def ignore_code_flow(code_flow: JsonObject) -> bool:
        return SarifEvaluator.ignore_code_flow(code_flow)

    def evaluate_sarif_result(
        self,
        sarif_path: str | PathLike[str],
    ) -> dict[str, MetricValue]:
        if self.test_run:
            return {}
        return self._evaluator.evaluate_path(sarif_path).to_dict()

    def run_vanilla_only(self) -> dict[str, MetricValue]:
        output = _required_path(self.final_output_json_path, "final_output_json_path")
        if output.exists() and not self.overwrite:
            return cast(dict[str, MetricValue], _load_json_object(output))
        sarif = _required_path(
            self.query_output_result_sarif_path,
            "query_output_result_sarif_path",
        )
        result = self.evaluate_sarif_result(sarif)
        write_json(output, result)
        return result

    def run(self) -> dict[str, object]:
        output = _required_path(self.final_output_json_path, "final_output_json_path")
        if output.exists() and not self.overwrite:
            existing = _load_json_object(output)
            if "vanilla_result" in existing and "posthoc_filter_result" in existing:
                return dict(existing)

        result: dict[str, object] = {"statistics": self.compute_statistics()}
        if self.query_output_result_sarif_path is not None:
            vanilla_path = Path(self.query_output_result_sarif_path)
            if vanilla_path.exists():
                result["vanilla_result"] = self.evaluate_sarif_result(vanilla_path)
        if self.posthoc_filtering_output_result_sarif_path is not None:
            posthoc_path = Path(self.posthoc_filtering_output_result_sarif_path)
            if posthoc_path.exists():
                result["posthoc_filter_result"] = self.evaluate_sarif_result(posthoc_path)
        write_json(output, result)
        return result


def _required_path(
    value: str | PathLike[str] | None,
    argument_name: str,
) -> Path:
    if value is None:
        raise ValueError(f"{argument_name} is required")
    return Path(value)


def _count_csv(path: str | PathLike[str] | None) -> int:
    target = _required_path(path, "statistics CSV path")
    with target.open("r", encoding="utf-8-sig", newline="") as handle:
        return sum(1 for _ in csv.DictReader(handle))


def _count_json(path: str | PathLike[str] | None) -> int:
    target = _required_path(path, "statistics JSON path")
    with target.open("r", encoding="utf-8-sig") as handle:
        value: object = json.load(handle)
    if not isinstance(value, (list, dict)):
        raise ValueError(f"statistics JSON must contain an array or object: {target}")
    return len(value)
