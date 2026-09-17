"""Materialize pinned Phase 8 knowledge sources before offline KG construction."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import requests
import yaml

from src.common.envfile import effective_env
from src.common.provenance import sha256_file
from src.reproduction.common import atomic_json


def _mapping(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected YAML mapping: {path}")
    return cast(dict[str, Any], loaded)


def model_tree_digest(pack_root: Path) -> tuple[int, str]:
    """Hash model paths and content hashes without depending on an absolute path."""
    digest = hashlib.sha256()
    paths = sorted(pack_root.glob("ext/**/*.model.yml"))
    for path in paths:
        relative = path.relative_to(pack_root).as_posix()
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
        digest.update(b"\n")
    return len(paths), digest.hexdigest()


def _assert_sha256(path: Path, expected: object) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"missing pinned knowledge source: {path}")
    actual = sha256_file(path)
    if actual != str(expected):
        raise ValueError(f"knowledge source checksum mismatch: {path} ({actual})")


def _download(url: str, target: Path, expected_sha256: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        size = 0
        with (
            os.fdopen(descriptor, "wb") as handle,
            requests.get(url, timeout=(15, 120), stream=True) as response,
        ):
            response.raise_for_status()
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                size += len(chunk)
                if size > 128 * 1024 * 1024:
                    raise ValueError(f"knowledge source exceeds 128 MiB limit: {url}")
                handle.write(chunk)
        _assert_sha256(temporary, expected_sha256)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _resolve_codeql_pack(
    repo_root: Path, config: Mapping[str, Any], override: Path | None
) -> Path:
    codeql = cast(Mapping[str, Any], config["codeql_java_models"])
    if override is not None:
        candidates = [override.resolve()]
    else:
        configured = effective_env(repo_root / ".env").get("MAXVERA_CODEQL_HOME", "")
        homes = [Path(configured).expanduser().resolve()] if configured else []
        homes.append(repo_root / ".cache/toolchains/codeql-2.26.2")
        candidates = [home / str(codeql["pack_relative_path"]) for home in homes]
    pack_root = next((candidate for candidate in candidates if candidate.is_dir()), None)
    if pack_root is None:
        raise FileNotFoundError(
            "pinned codeql/java-all@9.2.2 is unavailable; run setup_codeql.sh or "
            "provide --codeql-pack-root"
        )
    _assert_sha256(pack_root / "qlpack.yml", codeql["qlpack_sha256"])
    count, digest = model_tree_digest(pack_root)
    if count != int(codeql["model_file_count"]) or digest != codeql["model_tree_sha256"]:
        raise ValueError("installed CodeQL Java model pack does not match the Phase 8 pin")
    return pack_root


def validate_source_bundle(
    repo_root: Path, config_path: Path, config: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    resolved = dict(config or _mapping(config_path))
    raw_root = repo_root / str(resolved["raw_root"])
    manifest_path = raw_root / "source_manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError("Phase 8 source bundle is not materialized")
    import json

    loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("Phase 8 source manifest is not an object")
    manifest = cast(dict[str, Any], loaded)
    if manifest.get("source_bundle_id") != resolved["source_bundle_id"]:
        raise ValueError("Phase 8 source bundle ID mismatch")
    if manifest.get("source_config_sha256") != sha256_file(config_path):
        raise ValueError("Phase 8 source config changed after materialization")

    mitre = cast(Mapping[str, Any], resolved["mitre_cwe"])
    for filename, checksum in (
        (mitre["archive_filename"], mitre["archive_sha256"]),
        (mitre["xml_filename"], mitre["xml_sha256"]),
        (mitre["license_filename"], mitre["license_sha256"]),
    ):
        _assert_sha256(raw_root / str(filename), checksum)

    owasp = cast(Mapping[str, Any], resolved["owasp_top10"])
    artifacts = cast(Mapping[str, Any], owasp["artifacts"])
    for artifact in artifacts.values():
        item = cast(Mapping[str, Any], artifact)
        _assert_sha256(raw_root / str(item["filename"]), item["sha256"])

    codeql = cast(Mapping[str, Any], resolved["codeql_java_models"])
    _assert_sha256(raw_root / str(codeql["qlpack_filename"]), codeql["qlpack_sha256"])
    _assert_sha256(raw_root / str(codeql["license_filename"]), codeql["license_sha256"])
    materialized_pack = (raw_root / str(codeql["qlpack_filename"])).parent
    count, digest = model_tree_digest(materialized_pack)
    if count != int(codeql["model_file_count"]) or digest != codeql["model_tree_sha256"]:
        raise ValueError("materialized CodeQL model tree does not match the Phase 8 pin")
    return manifest


def materialize_sources(
    repo_root: Path, config_path: Path, *, codeql_pack_root: Path | None = None
) -> dict[str, Any]:
    config = _mapping(config_path)
    raw_root = repo_root / str(config["raw_root"])
    if raw_root.exists():
        return validate_source_bundle(repo_root, config_path, config)
    raw_root.parent.mkdir(parents=True, exist_ok=True)
    work = raw_root.parent / f".{raw_root.name}.inprogress"
    if work.exists():
        raise FileExistsError(f"partial Phase 8 source preparation exists: {work}")
    work.mkdir()
    try:
        mitre = cast(Mapping[str, Any], config["mitre_cwe"])
        archive = work / str(mitre["archive_filename"])
        _download(str(mitre["archive_url"]), archive, str(mitre["archive_sha256"]))
        xml_target = work / str(mitre["xml_filename"])
        xml_target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as bundle:
            member = str(mitre["xml_member"])
            if bundle.namelist() != [member]:
                raise ValueError("MITRE CWE archive contains unexpected members")
            with bundle.open(member) as source, xml_target.open("wb") as target:
                shutil.copyfileobj(source, target)
        _assert_sha256(xml_target, mitre["xml_sha256"])
        _download(
            str(mitre["license_url"]),
            work / str(mitre["license_filename"]),
            str(mitre["license_sha256"]),
        )

        owasp = cast(Mapping[str, Any], config["owasp_top10"])
        raw_base = (
            "https://raw.githubusercontent.com/OWASP/Top10/" + str(owasp["commit"])
        )
        for artifact in cast(Mapping[str, Any], owasp["artifacts"]).values():
            item = cast(Mapping[str, Any], artifact)
            _download(
                f"{raw_base}/{item['repository_path']}",
                work / str(item["filename"]),
                str(item["sha256"]),
            )

        codeql = cast(Mapping[str, Any], config["codeql_java_models"])
        source_pack = _resolve_codeql_pack(repo_root, config, codeql_pack_root)
        target_pack = (work / str(codeql["qlpack_filename"])).parent
        target_pack.mkdir(parents=True)
        shutil.copy2(source_pack / "qlpack.yml", target_pack / "qlpack.yml")
        for model_source in sorted(source_pack.glob("ext/**/*.model.yml")):
            model_target = target_pack / model_source.relative_to(source_pack)
            model_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(model_source, model_target)
        _download(
            f"https://raw.githubusercontent.com/github/codeql/{codeql['commit']}/"
            f"{codeql['license_repository_path']}",
            work / str(codeql["license_filename"]),
            str(codeql["license_sha256"]),
        )
        count, tree_sha256 = model_tree_digest(target_pack)
        if count != int(codeql["model_file_count"]) or tree_sha256 != codeql["model_tree_sha256"]:
            raise ValueError("copied CodeQL model tree does not match the Phase 8 pin")

        manifest = {
            "schema_version": 1,
            "source_bundle_id": str(config["source_bundle_id"]),
            "source_config": config_path.relative_to(repo_root).as_posix(),
            "source_config_sha256": sha256_file(config_path),
            "network_boundary": "preparation_only",
            "mitre_cwe": {
                "version": str(mitre["version"]),
                "archive_sha256": str(mitre["archive_sha256"]),
                "xml_sha256": str(mitre["xml_sha256"]),
                "license": str(mitre["license_name"]),
            },
            "owasp_top10": {
                "version": str(owasp["version"]),
                "commit": str(owasp["commit"]),
                "license": str(owasp["license_name"]),
            },
            "codeql_java_models": {
                "version": str(codeql["version"]),
                "commit": str(codeql["commit"]),
                "model_files": count,
                "model_tree_sha256": tree_sha256,
                "license": str(codeql["license_name"]),
            },
        }
        atomic_json(work / "source_manifest.json", manifest)
        os.replace(work, raw_root)
        return validate_source_bundle(repo_root, config_path, config)
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path("configs/knowledge/phase8_sources.yaml")
    )
    parser.add_argument("--codeql-pack-root", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        root = args.repo_root.resolve()
        config = args.config if args.config.is_absolute() else root / args.config
        manifest = materialize_sources(root, config, codeql_pack_root=args.codeql_pack_root)
        print(
            "Phase 8 sources ready: "
            f"{manifest['source_bundle_id']} ({manifest['codeql_java_models']['model_files']} "
            "CodeQL model files)"
        )
        return 0
    except (OSError, ValueError, requests.RequestException, zipfile.BadZipFile) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
