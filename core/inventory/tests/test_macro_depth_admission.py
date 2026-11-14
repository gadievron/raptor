"""Depth admission with scalar tables; no macro grammar or target reads."""

from core.inventory import macro_resolve as mr


def test_direct_roots_keep_their_dependency_depth_budget(tmp_path, monkeypatch):
    for outer, inner in [("FIRST", "SECOND"), ("SECOND", "FIRST")]:
        table = {outer: ("", inner), inner: ("", "LEAF"), "LEAF": ("", "42")}
        result = mr.resolve_macros(tmp_path, "FIRST SECOND", max_depth=1, table=table)
        assert {name for name, _ in result} == {"FIRST", "SECOND", "LEAF"}
        rust = {outer: inner + "!()", inner: "LEAF!()", "LEAF": "42"}
        monkeypatch.setattr(mr, "build_rust_macro_table", lambda target: rust)
        result = mr.resolve_rust_macros(tmp_path, "FIRST!(); SECOND!();", max_depth=1)
        assert {name for name, _ in result} == {"FIRST", "SECOND", "LEAF"}


def test_depth_limit_cycles_and_chain_order_remain_bounded(tmp_path, monkeypatch):
    table = {"TOP": ("", "MID"), "MID": ("", "LEAF"), "LEAF": ("", "TOP")}
    assert [name for name, _ in mr.resolve_macros(tmp_path, "TOP", max_depth=2, table=table)] == ["LEAF", "MID", "TOP"]
    assert [name for name, _ in mr.resolve_macros(tmp_path, "TOP", max_depth=0, table=table)] == ["TOP"]
    rust = {"TOP": "MID!()", "MID": "LEAF!()", "LEAF": "TOP!()"}
    monkeypatch.setattr(mr, "build_rust_macro_table", lambda target: rust)
    assert [name for name, _ in mr.resolve_rust_macros(tmp_path, "TOP!()", max_depth=2)] == ["LEAF", "MID", "TOP"]
    assert [name for name, _ in mr.resolve_rust_macros(tmp_path, "TOP!()", max_depth=0)] == ["TOP"]
