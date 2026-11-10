"""Catalogue recognition is not evidence for conditional source contracts."""
from pathlib import Path
import json

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.sanitizer_cut import (
    VERDICT_CANDIDATE_ONLY, evaluate_finding, record_sanitizer_cut_suppression,
)
from core.dataflow.sanitizer_catalog import (
    SanitizerBinding, match_sanitizers_in_cfg, source_contracts_for_callable,
)


HTML = "import html\ndef handle(raw):\n    safe = html.escape(raw)\n    return render(safe)\n"
REQUIREMENT = "exact_builtin_str_default_call"


def _graph(source, sink_name="render"):
    graph = build_python_cfg(source, "handle")
    assert graph is not None
    sink = next(node for node in graph.nodes() if sink_name in node.calls)
    return graph, sink


def _check(graph, sink, *, cwe="CWE-79", legacy=False, extra=()):
    kwargs = {} if legacy else {"source_symbols": {"raw"}, "sink_arg": "safe"}
    return evaluate_finding(graph, [graph.entry_node], sink, cwe=cwe, language="python",
                            extra_bindings=extra, **kwargs)


@pytest.mark.parametrize("legacy", [False, True], ids=["value-bound", "legacy"])
def test_direct_conditional_candidate_cannot_prune_without_source_contract(legacy):
    graph, sink = _graph(HTML)
    result = _check(graph, sink, legacy=legacy)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and result.suppress is False
    assert result.cut_set == frozenset()
    binding, = result.all_matched_bindings
    assert binding.callable == "html.escape"
    assert binding.unverified_source_contracts == frozenset({REQUIREMENT})
    assert "html.escape" in result.candidate_callables
    assert "unverified source contracts" in result.reason
    if not legacy:
        assert result.value_bound_bindings == result.all_matched_bindings


def test_manual_direct_binding_cannot_omit_live_catalogue_requirements():
    graph, sink = _graph(HTML)
    binding, = match_sanitizers_in_cfg(graph, "CWE-79", "python")
    older = SanitizerBinding(binding.node, binding.callable, binding.input_symbols,
                             binding.output_symbols, binding.lineno)
    assert not older.unverified_source_contracts
    result = _check(graph, sink, extra=[older])
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress
    assert all(REQUIREMENT in item.unverified_source_contracts for item in result.all_matched_bindings)


def test_conditional_overwrite_is_not_an_allowed_eligible_definer():
    source = (
        "import werkzeug\ndef handle(raw, flag):\n"
        "    safe = werkzeug.utils.secure_filename(raw)\n"
        "    if flag:\n        safe = werkzeug.security.safe_join(raw)\n"
        "    return open(safe)\n"
    )
    graph, sink = _graph(source, "open")
    result = _check(graph, sink, cwe="CWE-22")
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress
    # Structural role witnesses remain visible, but the conditional join overwrite
    # cannot validate condition 3 for the earlier unconditional candidate.
    assert any(item.callable == "werkzeug.utils.secure_filename" for item in result.value_bound_bindings)
    assert any(item.callable == "werkzeug.security.safe_join" and item.unverified_source_contracts
               for item in result.all_matched_bindings)


def test_unconditional_profile_still_has_a_real_positive_cut():
    graph, sink = _graph(
        "import werkzeug\ndef handle(raw):\n"
        "    safe = werkzeug.utils.secure_filename(raw)\n    return open(safe)\n", "open",
    )
    result = _check(graph, sink, cwe="CWE-22")
    assert result.suppress is True
    assert result.value_bound_bindings
    assert all(not item.unverified_source_contracts for item in result.value_bound_bindings)


def test_candidate_audit_records_contract_loss_without_dropping(tmp_path: Path):
    graph, sink = _graph(HTML)
    result = _check(graph, sink)
    record_sanitizer_cut_suppression(
        tmp_path, {"file_path": "app.py", "line": 4, "sink_line": 4, "cwe": "CWE-79"},
        result, enforce=True,
    )
    records = [json.loads(line) for line in (tmp_path / "suppressions.jsonl").read_text().splitlines()]
    record, = records
    assert record["dropped"] is False
    assert record["enforced"] is False
    assert record["catalog_matches"][0]["unverified_source_contracts"] == [REQUIREMENT]
    assert record["bindings"][0]["unverified_source_contracts"] == [REQUIREMENT]


def test_contract_query_is_cwe_and_language_scoped():
    assert source_contracts_for_callable("html.escape", "CWE-79", "python") == frozenset({REQUIREMENT})
    assert source_contracts_for_callable("html.escape", "CWE-22", "python") == frozenset()
    assert source_contracts_for_callable("html.escape", "CWE-79", "java") == frozenset()
