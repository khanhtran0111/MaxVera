from src.graphs.knowledge.model import edge_id, node_id


def test_phase8_v1_node_and_edge_ids_remain_stable() -> None:
    source = node_id("CWE", "CWE-22")
    target = node_id("CWE", "CWE-73")
    assert source == "skgn_cf2f26b663e159e32ea13cff"
    assert target == "skgn_8079920452409f7b4da4d45c"
    assert (
        edge_id("RELATED_CWE", source, target, {"nature": "ChildOf", "view_id": "1000"})
        == "skge_4ce60a969883e3724c3c7170"
    )
