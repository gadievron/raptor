"""Java for-loop phases must survive CFG lowering before proof queries."""
import pytest

from core.analysis.cfg_builder_java import build_java_intraproc_cfg

pytest.importorskip("tree_sitter_java")


def _build(loop):
    source = "class T { void handle(boolean flag) {\n int i = 0; int j = 0;\n" + loop + "\n consume();\n} }\n"
    cfg = build_java_intraproc_cfg(source, "handle")
    assert cfg is not None
    return cfg


def _node(cfg, label):
    return next(node for node in cfg.nodes() if node.label == label)


def _reaches(cfg, start, target, excluded=frozenset()):
    seen = set(excluded)
    pending = [start]
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        if node == target:
            return True
        seen.add(node)
        pending.extend(cfg.successors(node))
    return False


def test_for_continue_executes_update_before_retesting_condition():
    cfg = _build(" for (; i < 3; i++) {\n  if (flag) continue;\n }\n")
    continuation = _node(cfg, "continue;")
    update = _node(cfg, "i++")
    header = next(node for node in cfg.nodes() if node.label.startswith("for "))
    assert update in cfg.successors(continuation)
    assert header in cfg.successors(update)
    assert header not in cfg.successors(continuation)


def test_all_update_expressions_are_retained_in_order():
    cfg = _build(" for (; i < 3; i++, j++) { continue; }\n")
    first = _node(cfg, "i++")
    second = _node(cfg, "j++")
    assert first in cfg.successors(_node(cfg, "continue;"))
    assert second in cfg.successors(first)
    assert any(node.label.startswith("for ") for node in cfg.successors(second))


def test_all_initializer_expressions_are_retained_in_order():
    cfg = _build(" for (i = 1, j = 2; flag; i++) {}\n")
    first = _node(cfg, "i = 1")
    second = _node(cfg, "j = 2")
    assert second in cfg.successors(first)
    assert any(node.label.startswith("for ") for node in cfg.successors(second))


def test_break_skips_update_and_condition():
    cfg = _build(" for (; i < 3; i++) { break; }\n")
    header = next(node for node in cfg.nodes() if node.label.startswith("for "))
    assert _reaches(cfg, _node(cfg, "break;"), _node(cfg, "consume();"), {header, _node(cfg, "i++")})


def test_continue_without_update_retests_the_condition():
    cfg = _build(" for (; flag;) { continue; }\n")
    header = next(node for node in cfg.nodes() if node.label.startswith("for "))
    assert header in cfg.successors(_node(cfg, "continue;"))


def test_unconditional_loop_has_no_invented_normal_exit():
    cfg = _build(" for (;;) { i++; }\n")
    assert not _reaches(cfg, cfg.entry_node, _node(cfg, "consume();"))


def test_unconditional_loop_can_exit_by_break():
    cfg = _build(" for (;;) { break; }\n")
    assert _reaches(cfg, cfg.entry_node, _node(cfg, "consume();"))


def test_update_exception_keeps_ambient_catch_edge():
    cfg = _build(" try { for (; flag; step()) { continue; } } catch (Exception e) { recover(); }\n")
    update = _node(cfg, "step()")
    assert any(node.label.startswith("catch ") for node in cfg.successors(update))


def test_refused_construct_in_later_update_cannot_be_ignored():
    source = "class T { void handle(boolean flag) { int i = 0; for (; flag; i++, call(x -> x)) {} } }"
    assert build_java_intraproc_cfg(source, "handle") is None


def test_normal_body_fallthrough_executes_the_update_chain():
    cfg = _build(" for (; flag; i++, j++) { work(); }\n")
    assert _node(cfg, "i++") in cfg.successors(_node(cfg, "work();"))
    assert _node(cfg, "j++") in cfg.successors(_node(cfg, "i++"))


def test_later_update_definition_reaches_post_loop_consumer():
    from core.analysis.dataflow import reaching_defs

    cfg = _build(" for (; flag; i++, j = i) { continue; }\n")
    update = _node(cfg, "j = i")
    assert update in reaching_defs(cfg).at(_node(cfg, "consume();"), "j")


def test_later_initializer_kills_the_old_definition_at_the_condition():
    from core.analysis.dataflow import reaching_defs

    cfg = _build(" for (i = 1, j = 2; flag; i++) {}\n")
    header = next(node for node in cfg.nodes() if node.label.startswith("for "))
    assert reaching_defs(cfg).at(header, "j") == frozenset({_node(cfg, "j = 2")})


def test_same_line_body_retains_positive_condition_model_edge():
    from core.analysis.cfg_conditions import extract_conditions_from_cfg

    cfg = _build(" for (; flag; i++) { continue; }\n")
    header = next(node for node in cfg.nodes() if node.label.startswith("for "))
    positives = [edge for edge in extract_conditions_from_cfg(cfg)
                 if edge.src_line == header.lineno and edge.condition is not None
                 and edge.condition.polarity]
    assert len(positives) == 1
    assert positives[0].dst_line == _node(cfg, "continue;").lineno
