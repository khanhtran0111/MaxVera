"""Phase 10 structured vulnerability specification synthesis."""

from src.specification.compiler import compile_query, render_query
from src.specification.schema import parse_specification, specification_json_schema

__all__ = [
    "compile_query",
    "parse_specification",
    "render_query",
    "specification_json_schema",
]
