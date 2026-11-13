"""Local variable annotations do not execute or bind a new value."""

from textwrap import indent

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.dataflow import reaching_defs
from core.analysis.sanitizer_cut import evaluate_finding


def build(body):
    source = "import werkzeug\ndef handle(raw, store):\n" + indent(body, "    ")
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    return cfg


def call(cfg, name):
    return next(node for node in cfg.nodes() if name in node.calls)


def verdict(cfg):
    return evaluate_finding(cfg, [cfg.entry], call(cfg, "open"), cwe="CWE-22", language="python",
                            source_symbols={"raw"}, sink_arg="tmp")


def test_annotation_only_preserves_the_existing_sanitized_value():
    cfg = build("tmp=werkzeug.utils.secure_filename(raw)\ntmp: str\nopen(tmp)\n")
    annotation = next(node for node in cfg.nodes() if node.label.startswith("AnnAssign"))
    assert not annotation.defs
    assert not annotation.uses
    assert call(cfg, "werkzeug.utils.secure_filename") in reaching_defs(cfg).at(call(cfg, "open"), "tmp")
    assert verdict(cfg).suppress is True


def test_local_annotation_call_is_not_an_evaluated_call():
    cfg = build("tmp: annotation_only(raw)=werkzeug.utils.secure_filename(raw)\nopen(tmp)\n")
    assert all("annotation_only" not in node.calls for node in cfg.nodes())
    assert verdict(cfg).suppress is True


def test_annotated_rhs_rebinding_still_defeats_sanitizer_proof():
    cfg = build("tmp=werkzeug.utils.secure_filename(raw)\ntmp: str=raw\nopen(tmp)\n")
    annotation = next(node for node in cfg.nodes() if node.label.startswith("AnnAssign"))
    assert annotation.defs == frozenset({"tmp"})
    assert "raw" in annotation.uses
    assert verdict(cfg).suppress is False


def test_annotation_without_rhs_still_evaluates_subscript_target():
    cfg = build("tmp=werkzeug.utils.secure_filename(raw)\nstore[(tmp:=raw)]: annotation_only()\nopen(tmp)\n")
    annotation = next(node for node in cfg.nodes() if node.label.startswith("AnnAssign"))
    assert "tmp" in annotation.defs
    assert {"store", "raw"} <= annotation.uses
    assert "annotation_only" not in annotation.calls
    assert verdict(cfg).suppress is False


def test_annotation_still_declares_a_compile_time_local_module_shadow():
    cfg = build("werkzeug: object\ntmp=werkzeug.utils.secure_filename(raw)\nopen(tmp)\n")
    assert verdict(cfg).suppress is False


def test_parenthesized_annotation_name_also_preserves_existing_value():
    cfg = build("tmp=werkzeug.utils.secure_filename(raw)\n(tmp): str\nopen(tmp)\n")
    annotation = next(node for node in cfg.nodes() if node.label.startswith("AnnAssign"))
    assert not annotation.defs
    assert not annotation.uses
    assert verdict(cfg).suppress is True
