"""Prepared source selection controls requiring reviewed C++ parser resources.

These controls use fixture-only build labels, not a live build producer. They
exercise actual tree-sitter selection but fence arithmetic binding before any
solver/replay. Broad anchors, including a trailing newline, are deliberately
refused by the new exact-range contract rather than silently repaired here.
"""

from dataclasses import replace
import hashlib
import threading

import pytest

from core.audit import prepared_claim_context as module
from core.audit.arithmetic_operation import ArithmeticOperation
from core.audit.claim_support_contracts import PreparedTargetBinding
from core.audit.claims import ClaimRevision
from core.audit.integer_abi import integer_abi_key
from core.audit.integer_witness import source_model_scope
from core.audit.probe_function_scope import source_binding, source_for_function
from core.audit.refutation_source import SourceIdentity
from core.audit.smt_claim_contracts import PreparedSMTAnchor
from core.audit.verification_results import VerificationScope


@pytest.fixture(autouse=True)
def _owned_parser_cache(monkeypatch):
    # Replace borrowed cache owners; never clear their contents in place.
    from core.inventory import _ts_cache, extractors

    parser_local = threading.local()
    monkeypatch.setattr(_ts_cache, "_GRAMMAR_CACHE", {})
    monkeypatch.setattr(_ts_cache, "_TS_PARSER_LOCAL", parser_local)
    monkeypatch.setattr(extractors, "_TS_PARSER_LOCAL", parser_local)


def _inputs(raw, start, end, *, line=None, function="Outer::Box::Read"):
    statement = "integer overflow in `Value + 1`"
    identity = SourceIdentity(hashlib.sha256(raw).hexdigest(), (1, 2, len(raw), 4, 5))
    if line is None:
        line = raw[:start].count(b"\n") + 1
    revision = ClaimRevision({"mechanism": statement}, pass_id="fixture-pass",
                             file="unit.cpp", function=function, line_start=line)
    scope = VerificationScope("unit.cpp", function, line, statement, identity)
    anchor = PreparedSMTAnchor("unit.cpp", identity, raw, start, end, raw[start:end])
    target = PreparedTargetBinding(
        "fixture-unit", "fixture-snapshot", "fixture-build-not-live",
        ("fixture-dependency", "integer-abi:" + integer_abi_key("ilp32")),
        tuple(source_model_scope()["assumptions"]), "source", "source-language")
    return dict(revision=revision, scope=scope, anchor=anchor, target=target,
                integer_abi="ilp32", current_prepared=lambda: (target, anchor))


def _source(newline=b"\n", *, nested=False):
    prefix = "// café".encode() + newline + b"namespace Outer {" + newline + b"struct Box {" + newline
    body = b"int Read(int Value) { return Value + 1; }"
    if nested:
        body = (b"int Read(int Value) { auto nested = [=]() { return Value + 2; }; "
                b"return Value + 1; }")
    raw = prefix + body + newline + b"};" + newline + b"}" + newline
    return raw, len(prefix), len(prefix) + len(body)


def _capture_scope(monkeypatch):
    selected, operations, bindings = [], [], []

    def select(source, file, name):
        result = source_for_function(source, file, name)
        selected.append((source, result))
        return result

    def bind(source, *args, **kwargs):
        operations.append(source)
        return ArithmeticOperation("unavailable")

    def binding(source, *args, **kwargs):
        result = source_binding(source, *args, **kwargs)
        bindings.append(result)
        return result

    monkeypatch.setattr(module, "source_for_function", select)
    monkeypatch.setattr(module, "bind_arithmetic_operation", bind)
    monkeypatch.setattr(module, "source_binding", binding)
    return selected, operations, bindings


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["LF", "CRLF"])
def test_qualified_cpp_selection_uses_full_file_and_utf8_offsets(monkeypatch, newline):
    raw, start, end = _source(newline)
    selected, operations, bindings = _capture_scope(monkeypatch)
    args = _inputs(raw, start, end)
    # A literal method slice loses its namespace/class parents.
    isolated, isolated_source = source_for_function(raw[start:end].decode(), "unit.cpp",
                                                   args["scope"].function)
    assert isolated.status == "missing" and isolated_source is None
    result = module.prepare_overflow_claim_context(**args)
    assert result == module.PreparationUnavailable("source-operation-unavailable")
    assert selected[0][0].encode() == raw
    actual_scope, masked = selected[0][1]
    assert actual_scope.status == "selected"
    assert (actual_scope.start, actual_scope.end) == (start, end)
    assert start != len(raw[:start].decode())  # UTF-8 prefix is measured in bytes.
    assert masked is not None and len(masked.encode()) == len(raw)
    assert operations == [masked]
    assert bindings == [source_binding(masked, args["scope"].function,
                                       verb="check-overflow", integer_abi="ilp32",
                                       hypothesis=args["scope"].hypothesis)]
    assert bindings[0]["sha256"] != hashlib.sha256(raw[start:end]).hexdigest()


@pytest.mark.parametrize("shape", ["shifted-start", "trailing-newline", "whole-file"])
def test_nonexact_anchor_range_is_refused_before_arithmetic(monkeypatch, shape):
    raw, start, end = _source()
    if shape == "shifted-start":
        start += 1
    elif shape == "trailing-newline":
        end += 1
    else:
        start, end = 0, len(raw)
    selected, operations, bindings = _capture_scope(monkeypatch)
    result = module.prepare_overflow_claim_context(**_inputs(raw, start, end))
    assert result == module.PreparationUnavailable("prepared-function-anchor-range-mismatch")
    assert selected and operations == [] and bindings == []


def test_duplicate_qualified_occurrence_refuses_before_arithmetic(monkeypatch):
    raw, start, end = _source()
    raw += raw
    selected, operations, bindings = _capture_scope(monkeypatch)
    result = module.prepare_overflow_claim_context(**_inputs(raw, start, end))
    assert result == module.PreparationUnavailable("prepared-function-occurrence-unavailable")
    assert selected[0][1][0].status == "ambiguous"
    assert operations == [] and bindings == []


def test_nested_callable_is_excluded_from_full_length_probe(monkeypatch):
    raw, start, end = _source(nested=True)
    selected, operations, bindings = _capture_scope(monkeypatch)
    result = module.prepare_overflow_claim_context(**_inputs(raw, start, end))
    assert result == module.PreparationUnavailable("source-operation-unavailable")
    actual_scope, masked = selected[0][1]
    assert actual_scope.excluded
    assert masked is not None and len(masked.encode()) == len(raw)
    assert masked.count("\n") == raw.count(b"\n")
    assert "Value + 2" not in masked and "Value + 1" in masked
    for left, right in actual_scope.excluded:
        assert start < left < right <= end
        assert set(masked.encode()[left:right]) <= {32, 10, 13}
    assert operations == [masked] and len(bindings) == 1


def test_bare_cr_line_model_conflict_refuses_before_parser(monkeypatch):
    raw, start, end = _source(b"\r")
    selected, operations, bindings = _capture_scope(monkeypatch)
    result = module.prepare_overflow_claim_context(**_inputs(raw, start, end))
    # Existing _prepared_binding_matches uses normalized CR lines; caller LF
    # coordinates disagree. No inert geometry draft is wired into production.
    assert result == module.PreparationUnavailable("prepared-exact-source-anchor-unavailable")
    assert selected == [] and operations == [] and bindings == []


@pytest.mark.parametrize("field", ["build", "abi", "currentness", "literal-span"])
def test_qualified_selection_retains_existing_preconditions(monkeypatch, field):
    raw, start, end = _source()
    args = _inputs(raw, start, end)
    if field == "build":
        args["target"] = replace(args["target"], build_identity="")
    elif field == "abi":
        args["integer_abi"] = None
    elif field == "currentness":
        args["current_prepared"] = lambda: None
    else:
        anchor = replace(args["anchor"], expected_span=b"not the source interval")
        args["anchor"] = anchor
        args["current_prepared"] = lambda: (args["target"], anchor)
    selected, operations, bindings = _capture_scope(monkeypatch)
    result = module.prepare_overflow_claim_context(**args)
    assert isinstance(result, module.PreparationUnavailable)
    assert selected == [] and operations == [] and bindings == []
