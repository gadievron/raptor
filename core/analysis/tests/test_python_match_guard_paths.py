"""Failed match guards preserve their writes when trying later cases."""

from textwrap import indent

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.dataflow import reaching_defs
from core.analysis.sanitizer_cut import evaluate_finding


def build(body):
    source = "import werkzeug\ndef handle(raw, subject):\n" + indent(body, "    ")
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    return cfg


def call(cfg, name):
    return next(node for node in cfg.nodes() if name in node.calls)


def test_false_guard_rebinding_reaches_fallback_sink():
    cfg = build("tmp = werkzeug.utils.secure_filename(raw)\nmatch subject:\n    case _ if (tmp := raw) and False:\n        pass\n    case _:\n        open(tmp)\n")
    sink = call(cfg, "open")
    result = evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-22", language="python",
                              source_symbols={"raw"}, sink_arg="tmp")
    assert result.all_matched_bindings
    assert result.suppress is False
    guard = next(node for node in cfg.nodes() if node.label.startswith("case") and "tmp" in node.defs)
    assert guard in reaching_defs(cfg).at(sink, "tmp")


def test_failed_final_guard_with_return_body_reaches_post_match_sink():
    cfg = build("tmp = werkzeug.utils.secure_filename(raw)\nmatch subject:\n    case _ if (tmp := raw) and False:\n        return\nopen(tmp)\n")
    sink = call(cfg, "open")
    guard = next(node for node in cfg.nodes() if node.label.startswith("case") and "tmp" in node.defs)
    assert guard in reaching_defs(cfg).at(sink, "tmp")
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-22", language="python",
                            source_symbols={"raw"}, sink_arg="tmp").suppress is False


def test_guarded_capture_reaches_later_case():
    cfg = build("tmp = werkzeug.utils.secure_filename(raw)\nmatch subject:\n    case tmp if False:\n        pass\n    case _:\n        consume(tmp)\n")
    capture = next(node for node in cfg.nodes() if node.label.startswith("case") and "tmp" in node.defs)
    assert capture in reaching_defs(cfg).at(call(cfg, "consume"), "tmp")


def test_selected_case_body_does_not_flow_into_later_case():
    cfg = build("match subject:\n    case 0:\n        tmp = raw\n        first(tmp)\n    case _:\n        second(raw)\n")
    pending = [call(cfg, "first")]
    seen = set()
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        pending.extend(cfg.successors(node))
    assert call(cfg, "second") not in seen


def test_post_match_sanitizer_retains_value_bound_proof():
    cfg = build("match subject:\n    case _ if (tmp := raw) and False:\n        pass\ntmp = werkzeug.utils.secure_filename(raw)\nopen(tmp)\n")
    result = evaluate_finding(cfg, [cfg.entry], call(cfg, "open"), cwe="CWE-22", language="python",
                              source_symbols={"raw"}, sink_arg="tmp")
    assert result.value_bound_bindings
    assert result.suppress is True
