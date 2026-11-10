"""Finite contract for manual review-record copies in the orchestrator.

These are the fourteen current direct copies, independently of the separate
nine-site tools_errored census. Panel dictionaries are separate producers:
the owner rebuilds their combined live scope after merging members.
"""

import ast
from pathlib import Path


_ORCHESTRATOR = Path(__file__).resolve().parents[1] / "orchestrator.py"
_EXPECTED_COPIES = {
    ("_multi_pass_review", 0): "outcome.review_input_scope",
    ("_apply_reachability_gate", 0): "outcome.review_input_scope",
    ("_apply_reachability_gate", 1): "outcome.review_input_scope",
    ("_sweep_validate", 0): "outcome.review_input_scope",
    ("_promote_suspicious_preconditions", 0): "outcome.review_input_scope",
    ("_hold_smt_promotion", 0): "outcome.review_input_scope",
    ("_promote_clean_refuted", 0): "_l2_selected.review_input_scope",
    ("_dispatch_secondary_hypotheses", 0): "outcome.review_input_scope",
    ("_demote_self_contradictions", 0): "outcome.review_input_scope",
    ("_demote_absent_promotions", 0): "outcome.review_input_scope",
    ("_promote_outcome", 0): "outcome.review_input_scope",
    ("_resolve_gate_demoted", 0): "outcome.review_input_scope",
    ("_resolve_gate_demoted", 1): "outcome.review_input_scope",
    ("_demote_outcome", 0): "outcome.review_input_scope",
}


def _copies(tree):
    found = []

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.owners = []

        def visit_FunctionDef(self, node):
            self.owners.append(node.name)
            self.generic_visit(node)
            self.owners.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id == "ReviewOutcome":
                keywords = {keyword.arg: keyword.value for keyword in node.keywords}
                # The explicit existing-record and source-occurrence copy
                # shape distinguishes these from new model/panel producers.
                if ("review_result" in keywords
                        and isinstance(keywords.get("file"), ast.Attribute)):
                    found.append((".".join(self.owners), node))
            self.generic_visit(node)

    Visitor().visit(tree)
    result = {}
    ordinals = {}
    for owner, call in sorted(found, key=lambda entry: entry[1].lineno):
        ordinal = ordinals.get(owner, 0)
        ordinals[owner] = ordinal + 1
        result[owner, ordinal] = call
    return result


def _scope_expression(call):
    values = [keyword.value for keyword in call.keywords if keyword.arg == "review_input_scope"]
    return ast.unparse(values[0]) if len(values) == 1 else None


def _violations(tree):
    calls = _copies(tree)
    return {site for site in set(calls) | set(_EXPECTED_COPIES)
            if site not in calls or site not in _EXPECTED_COPIES
            or _scope_expression(calls[site]) != _EXPECTED_COPIES[site]}


def test_manual_review_copies_keep_their_actual_source_scope():
    tree = ast.parse(_ORCHESTRATOR.read_text())
    assert len(_EXPECTED_COPIES) == 14
    assert _violations(tree) == set()


def test_removing_a_scope_copy_fails_the_exact_site_inventory():
    tree = ast.parse(_ORCHESTRATOR.read_text())
    site = ("_hold_smt_promotion", 0)
    call = _copies(tree)[site]
    assert _scope_expression(call) == _EXPECTED_COPIES[site]
    call.keywords = [keyword for keyword in call.keywords if keyword.arg != "review_input_scope"]
    assert _violations(tree) == {site}


def test_selected_rescue_does_not_take_the_canonical_outcomes_scope():
    tree = ast.parse(_ORCHESTRATOR.read_text())
    site = ("_promote_clean_refuted", 0)
    call = _copies(tree)[site]
    field = next(keyword for keyword in call.keywords if keyword.arg == "review_input_scope")
    field.value = ast.parse("outcome.review_input_scope", mode="eval").body
    assert _violations(tree) == {site}


def test_current_explicit_study_configuration_supplies_the_root_mapping(tmp_path):
    from core.audit.orchestrator import OrchestratorConfig, _review_source_roots

    target, study = tmp_path / "target", tmp_path / "study"
    config = OrchestratorConfig(target_path=target, out_dir=tmp_path / "out")
    assert _review_source_roots(config) == {"target": target.resolve()}
    config.study_root = study
    assert _review_source_roots(config) == {"target": target.resolve(), "study": study.resolve()}


def test_scope_field_is_transient_and_appended_after_existing_positional_fields():
    from dataclasses import fields
    from core.audit.orchestrator import ReviewOutcome

    definitions = fields(ReviewOutcome)
    assert definitions[-2].name == "weaknesses"
    field = definitions[-1]
    assert field.name == "review_input_scope" and field.default is None
    assert field.repr is False and field.compare is False


def test_orchestrator_writers_use_current_trusted_roots():
    tree = ast.parse(_ORCHESTRATOR.read_text())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name)
             and node.func.id in ("append_journal_for_outcome", "Collector", "compute_gaps")]
    assert len(calls) == 10, "eight direct journal sites, Collector and gap computation"
    roots = []
    for call in calls:
        value, = [keyword.value for keyword in call.keywords if keyword.arg == "source_roots"]
        roots.append(ast.unparse(value))
    assert roots.count("_review_source_roots(config)") == 8
    assert roots.count("runtime.source_roots()") == 2


def test_panel_reconstructions_bind_the_combined_runtime_scope():
    tree = ast.parse(_ORCHESTRATOR.read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_multi_pass_review")
    calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute)
             and ast.unparse(node.func) == "knowledge_runtime.bind_review_input_scope"]
    assert {ast.unparse(call.args[0]) for call in calls} == {"panel_outcome", "consistency_outcome"}
    assert len(calls) == 2
