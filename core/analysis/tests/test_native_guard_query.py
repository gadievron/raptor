"""Native guard queries use selected branch identities and value epochs."""
from core.analysis.cfg_builder import build_python_cfg
from core.analysis.guard_bypass import query


def _query(source, *, positive=True):
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    source_line = next(i for i, line in enumerate(source.splitlines(), 1) if "raw = value" in line)
    sink_line = next(i for i, line in enumerate(source.splitlines(), 1) if "consume(raw)" in line)
    return query(cfg, "raw", source_line, sink_line,
                 guard_classifier=lambda condition, variable: condition.text == "raw > 0"
                                  and condition.polarity is positive)


def test_reconverged_predicate_does_not_guard_its_false_path():
    source = "def handle(value):\n    raw = value\n    if raw > 0:\n        pass\n    consume(raw)\n"
    result = _query(source)
    assert result.is_bypassed()
    assert result.must_visit_guards == []
    assert result.confidence == "structural"


def test_selected_positive_arm_can_guard_every_path():
    source = "def handle(value):\n    raw = value\n    if raw > 0:\n        consume(raw)\n"
    result = _query(source)
    assert not result.is_bypassed()
    assert len(result.must_visit_guards) == 1
    assert result.must_visit_guards[0].condition.polarity is True


def test_false_arm_does_not_satisfy_a_positive_classifier():
    source = "def handle(value):\n    raw = value\n    if raw > 0:\n        return\n    consume(raw)\n"
    assert _query(source).is_bypassed()


def test_negative_classifier_retains_the_selected_false_arm():
    source = "def handle(value):\n    raw = value\n    if raw > 0:\n        return\n    consume(raw)\n"
    result = _query(source, positive=False)
    assert not result.is_bypassed()
    assert result.must_visit_guards[0].condition.polarity is False


def test_changed_guard_values_cannot_get_structural_coverage():
    source = "def handle(value):\n    raw = value\n    if raw > 0:\n        raw = 0\n        consume(raw)\n"
    result = _query(source)
    assert result.confidence == "incomplete"
    assert result.must_visit_guards == []


def test_distributed_selected_guards_form_a_collective_cut():
    source = "def handle(value, flag):\n    raw = value\n    if flag:\n        if raw > 0:\n            pass\n        else:\n            return\n    else:\n        if raw > 0:\n            pass\n        else:\n            return\n    consume(raw)\n"
    result = _query(source)
    assert not result.is_bypassed()
    assert len(result.constraining_guards) == 2
    assert result.must_visit_guards == []
    assert result.confidence == "structural"


def test_native_visit_cap_is_incomplete_evidence(monkeypatch):
    import core.analysis.guard_bypass as guard_bypass

    monkeypatch.setattr(guard_bypass, "_MAX_NATIVE_QUERY_VISITS", 0)
    source = "def handle(value):\n    raw = value\n    if raw > 0:\n        consume(raw)\n"
    result = _query(source)
    assert result.confidence == "incomplete"
    assert result.must_visit_guards == []


def test_unreachable_sink_does_not_mint_a_guard_certificate():
    source = "def handle(value):\n    raw = value\n    return\n    consume(raw)\n"
    result = _query(source)
    assert not result.is_bypassed()
    assert result.must_visit_guards == []
    assert result.constraining_guards == []


def test_c_source_query_uses_native_branch_polarity():
    import pytest
    pytest.importorskip("tree_sitter_c")
    from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg

    source = "void handle(int value) {\n int raw = value;\n if (raw > 0) { int marker = 1; }\n consume(raw);\n}\n"
    cfg = build_cpp_intraproc_cfg(source, "handle", language="c")
    assert cfg is not None
    result = query(cfg, "raw", 2, 4, guard_classifier=lambda condition, variable: condition.polarity
                   and condition.text == "raw > 0")
    assert result.is_bypassed()
    assert result.must_visit_guards == []
    assert result.confidence == "structural"


def test_native_coverage_can_exceed_legacy_path_depth():
    prefix = "".join(f"    unrelated_{i} = 0\n" for i in range(100))
    source = "def handle(value):\n    raw = value\n" + prefix + "    if raw > 0:\n        consume(raw)\n"
    result = _query(source)
    assert not result.is_bypassed()
    assert len(result.must_visit_guards) == 1
    assert result.confidence == "structural"
