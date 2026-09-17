from src.graphs.evidence.model import evidence_node_id, useg_edge_id


def test_phase9_v1_node_and_edge_ids_remain_stable() -> None:
    hypothesis = evidence_node_id(
        "HYPOTHESIS", "proj_fixture", "hyp_fixture", analysis_iteration=0
    )
    assertion = evidence_node_id(
        "ASSERTION", "proj_fixture", "hyp_fixture:location:1", analysis_iteration=0
    )
    edge = useg_edge_id(
        "DERIVED_FROM",
        assertion,
        hypothesis,
        {"derivation": "phase6_location_assertion"},
        analysis_iteration=0,
    )
    assert hypothesis == "evn_2da346071062d002ae78b0ca"
    assert assertion == "evn_a4c0ca48e8673aa14b480b7d"
    assert edge == "uve_30a365522010e135e044209e"
