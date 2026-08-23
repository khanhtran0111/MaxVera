from __future__ import annotations

from openiris.data import BuildInfo, RuntimeInstance, RuntimeRepository, create_repository_split


def _runtime(index: int, repository: int) -> RuntimeInstance:
    return RuntimeInstance(
        instance_id=f"oi_{index:032x}",
        snapshot_id="fixture",
        track="legacy",
        repository=RuntimeRepository(
            host="github.com",
            owner="acme",
            name=f"repository-{repository}",
            url=f"https://github.com/acme/repository-{repository}",
        ),
        revision=f"{index:040x}",
        build=BuildInfo(status="success"),
    )


def test_repository_split_is_order_independent_and_has_no_repo_overlap() -> None:
    # Two versions of repository 0 exercise the grouping invariant.
    instances = [_runtime(1, 0), _runtime(2, 0), *[_runtime(i + 3, i + 1) for i in range(9)]]
    options = {
        "dataset_snapshot_id": "fixture",
        "dataset_manifest_sha256": "e" * 64,
        "seed": 42,
        "ratios": {"train": 0.6, "dev": 0.2, "test": 0.2},
    }

    forward = create_repository_split(instances, **options)
    reverse = create_repository_split(reversed(instances), **options)

    assert forward == reverse
    repository_sets = [
        set(forward["repository_assignments"][name]) for name in ("train", "dev", "test")
    ]
    assert repository_sets[0].isdisjoint(repository_sets[1])
    assert repository_sets[0].isdisjoint(repository_sets[2])
    assert repository_sets[1].isdisjoint(repository_sets[2])
    assert sum(item["repositories"] for item in forward["counts"].values()) == 10


def test_all_versions_of_repository_land_in_one_split() -> None:
    instances = [_runtime(1, 0), _runtime(2, 0), _runtime(3, 1)]
    split = create_repository_split(
        instances,
        dataset_snapshot_id="fixture",
        dataset_manifest_sha256="e" * 64,
        seed=1,
    )
    containing = [
        name
        for name in ("train", "dev", "test")
        if {instances[0].instance_id, instances[1].instance_id} <= set(split["assignments"][name])
    ]
    assert len(containing) == 1
