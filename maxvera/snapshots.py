"""One source inventory policy shared by selection, ingestion and build provenance."""

from pathlib import Path

from maxvera.graph import relative_file
from src.common.provenance import sha256_file


def source_inventory(source: Path, *, include_generated: bool = False) -> dict[str, str]:
    ignored = {".git", ".gradle", "__pycache__"}
    if not include_generated:
        ignored |= {"target", "build", "classes"}
    files = {}
    for p in sorted(source.rglob("*")):
        rel = p.relative_to(source)
        if ignored & set(rel.parts):
            continue
        if p.is_symlink():
            raise ValueError("source snapshot symlink requires audit")
        if p.is_file():
            if include_generated and p.suffix in {".class", ".jar", ".war", ".zip", ".bqrs"}:
                continue
            files[relative_file(rel.as_posix())] = sha256_file(p)
    return files
