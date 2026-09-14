from src.graphs.program.model import edge_id, node_id


def test_phase7_v1_node_and_edge_ids_remain_stable() -> None:
    descriptor = {
        "kind": "EXPR",
        "subkind": "VarRead",
        "file": "src/Example.java",
        "start_line": 2,
        "start_column": 1,
        "end_line": 2,
        "end_column": 8,
        "symbol": "value",
        "type_name": "String",
    }
    source_id = node_id("proj_test", descriptor)
    assert source_id == "pgn_87e3718982917f58bfe46820"
    assert (
        edge_id("proj_test", "DATA_FLOW", source_id, "pgn_target") == "pge_05d08f210ac97fbab02d9d22"
    )
