"""Negative evidence remains valid only for the source actually checked."""

import hashlib
import os
from dataclasses import asdict, replace

import pytest

from core.audit import orchestrator as orch
from core.audit import refutation_source as source
from core.audit.sweep import SweepResult
from core.audit.tests.test_legacy_refutation_resolution import case, retain, resolve
from core.audit.verification_results import ToolChainResult


def test_identity_hashes_raw_bytes_and_ignores_access_time(tmp_path):
    data = b"int Read(void) { return 0; }\r\n"
    (tmp_path / "record.c").write_bytes(data)
    first = source.capture_source_identity(tmp_path, "record.c")
    assert first.sha256 == hashlib.sha256(data).hexdigest()
    assert first == source.capture_source_identity(tmp_path, "record.c")


@pytest.mark.parametrize("file", ["missing.c", "../outside.c"])
def test_missing_or_escaping_source_has_no_identity(tmp_path, file):
    assert source.capture_source_identity(tmp_path, file) is None


def test_symlink_outside_root_is_refused(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    outside = tmp_path / "outside.c"
    outside.write_text("int Read(void) { return 0; }\n")
    (root / "record.c").symlink_to(outside)
    assert source.capture_source_identity(root, "record.c") is None


def test_fifo_is_refused_without_waiting_for_a_writer(tmp_path):
    os.mkfifo(tmp_path / "record.c")
    assert source.capture_source_identity(tmp_path, "record.c") is None


def test_oversize_source_is_not_prefix_hashed(tmp_path, monkeypatch):
    monkeypatch.setattr(source, "MAX_SOURCE_BYTES", 8)
    path = tmp_path / "record.c"
    path.write_bytes(b"12345678")
    assert source.capture_source_identity(tmp_path, path.name) is not None
    path.write_bytes(b"123456789")
    assert source.capture_source_identity(tmp_path, path.name) is None


def test_byte_changes_are_detected_even_when_decoding_would_hide_them(tmp_path):
    path = tmp_path / "record.c"
    path.write_bytes(b"//\xff\n")
    first = source.capture_source_identity(tmp_path, path.name)
    path.write_bytes(b"//\xfe\n")
    assert source.capture_source_identity(tmp_path, path.name).sha256 != first.sha256


@pytest.mark.parametrize("whole", [False, True])
def test_current_whole_file_and_anchored_excerpt_are_accepted(tmp_path, whole):
    text = "// header\r\nint Read(void) {\r\n    return 0;\r\n}\r\n"
    (tmp_path / "record.c").write_bytes(text.encode())
    excerpt = text if whole else "int Read(void) {\n    return 0;\n}\n"
    assert source.capture_source_identity(tmp_path, "record.c", excerpt=excerpt, line_start=2)


@pytest.mark.parametrize("excerpt,line", [("int Read(void) { return 1; }", 2),
                                         ("int Read(void) { return 0; }", 3)])
def test_stale_excerpt_or_wrong_anchor_cannot_bind_to_current_source(tmp_path, excerpt, line):
    (tmp_path / "record.c").write_text("// header\nint Read(void) { return 0; }\n")
    assert source.capture_source_identity(tmp_path, "record.c", excerpt=excerpt, line_start=line) is None


def test_identical_byte_replacement_still_changes_file_version(tmp_path):
    path = tmp_path / "record.c"
    path.write_text("int Read(void) { return 0; }\n")
    first = source.capture_source_identity(tmp_path, path.name)
    replacement = tmp_path / "new.c"
    replacement.write_bytes(path.read_bytes())
    replacement.replace(path)
    second = source.capture_source_identity(tmp_path, path.name)
    assert first.sha256 == second.sha256
    assert first != second


def test_modification_during_read_has_no_identity(tmp_path, monkeypatch):
    path = tmp_path / "record.c"
    path.write_bytes(b"original")
    real_open = source.open_regular_beneath

    class ChangingRead:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.stream.close()
        def fileno(self):
            return self.stream.fileno()
        def read(self, size):
            data = self.stream.read(size)
            path.write_bytes(b"modified")
            return data

    monkeypatch.setattr(source, "open_regular_beneath", lambda *a, **kw: ChangingRead(real_open(*a, **kw)))
    assert source.capture_source_identity(tmp_path, path.name) is None


@pytest.mark.parametrize("mutation", ["edit", "outside_excerpt", "delete", "identical_replacement"])
def test_collected_refutation_is_invalidated_by_later_source_changes(tmp_path, monkeypatch, mutation):
    outcome, config = case(tmp_path, monkeypatch)
    retain(outcome, config)
    path = tmp_path / outcome.file
    if mutation == "edit":
        path.write_text("int Read(int n) { return n + 1; }\n")
    elif mutation == "outside_excerpt":
        path.write_text(path.read_text() + "int helper(void) { return 1; }\n")
    elif mutation == "identical_replacement":
        replacement = tmp_path / "new.c"
        replacement.write_bytes(path.read_bytes())
        replacement.replace(path)
    else:
        path.unlink()
    assert resolve(outcome, config, {"joern": True}).status == "dark"


@pytest.mark.parametrize("restore", [False, True])
def test_edits_during_checker_execution_cannot_create_a_refutation(tmp_path, monkeypatch, restore):
    outcome, config = case(tmp_path, monkeypatch)
    path = tmp_path / outcome.file
    original = path.read_text()
    stamp = path.stat()

    def checker(**kwargs):
        path.write_text("int Read(int n) { return n + 1; }\n")
        if restore:
            path.write_text(original)
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        return SweepResult(tool="smt", file_path=outcome.file, function_name=outcome.function,
                           outcome="refuted", rule_id="check-overflow")

    monkeypatch.setattr(orch, "run_smt_verb_direct", checker)
    inconclusive = set()
    result = orch._run_tool_chain([{"type": "smt", "config": {"verb": "check-overflow"}}],
        config=config, file_path=outcome.file, function_name=outcome.function, line_start=outcome.line,
        source=original, hypothesis=outcome.hypothesis, inconclusive_types=inconclusive)
    assert result.outcomes[0].verdict == "inconclusive"
    assert "smt" in inconclusive
    assert not orch._retain_claim_refutation(outcome, result, config, hypothesis=outcome.hypothesis, phase="test")


def test_cannot_bind_an_old_result_to_a_new_file_at_retention_time(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    result = ToolChainResult(file=outcome.file, function=outcome.function, line_start=outcome.line,
        hypothesis=outcome.hypothesis, source_identity=source.capture_source_identity(tmp_path, outcome.file))
    result.observe("smt", "refuted", "check-overflow")
    (tmp_path / outcome.file).write_text("int Read(int n) { return n + 1; }\n")
    assert not orch._retain_claim_refutation(outcome, result, config, hypothesis=outcome.hypothesis, phase="test")
    assert outcome.claim_refutations == ()


@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("basis", ["ihv", "legacy"])
def test_final_pass_rechecks_already_clean_refutation_verdicts(tmp_path, monkeypatch, changed, basis):
    outcome, config = case(tmp_path, monkeypatch)
    retain(outcome, config)
    outcome.status = "clean"
    if basis == "ihv":
        outcome.review_result.update(ihv_all_refuted=True, immediate_verified=True)
    else:
        outcome.clean_basis = "gate_resolved"
    if changed:
        (tmp_path / outcome.file).write_text("int Read(int n) { return n + 1; }\n")
    result = orch.OrchestratorResult(outcomes=[outcome], clean=1)
    orch._resolve_gate_demoted(result, config)
    assert result.outcomes[0].status == ("dark" if changed else "clean")
    assert result.clean == (0 if changed else 1)
    if changed:
        assert not result.outcomes[0].review_result.get("immediate_verified")


def test_persisted_refutation_includes_source_identity(tmp_path, monkeypatch):
    from core.audit.record import load_audit_log

    outcome, config = case(tmp_path, monkeypatch)
    retain(outcome, config)
    row = next(r for r in load_audit_log(config.out_dir) if r["action"] == "claim_refutation")
    assert row["source_identity"]["sha256"] == hashlib.sha256((tmp_path / outcome.file).read_bytes()).hexdigest()
    assert row["source_identity"]["version"]


@pytest.mark.parametrize("broken", ["missing", "wrong_digest", "wrong_version", "model_dictionary"])
def test_missing_or_forged_source_binding_cannot_clear_a_claim(tmp_path, monkeypatch, broken):
    outcome, config = case(tmp_path, monkeypatch)
    retain(outcome, config)
    receipt = outcome.claim_refutations[0]
    identity = receipt.source_identity
    bad = {"missing": None, "wrong_digest": replace(identity, sha256="0" * 64),
           "wrong_version": replace(identity, version=(0,)), "model_dictionary": asdict(identity)}[broken]
    outcome.claim_refutations = (replace(receipt, source_identity=bad),)
    assert resolve(outcome, config, {"joern": True}).status == "dark"


def test_stale_cached_excerpt_does_not_get_the_new_files_identity(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    path = tmp_path / outcome.file
    old = path.read_text()
    path.write_text("int Read(int n) { return n + 1; }\n")
    monkeypatch.setattr(orch, "run_smt_verb_direct", lambda **kw: SweepResult(
        tool="smt", file_path=outcome.file, function_name=outcome.function,
        outcome="refuted", rule_id="check-overflow"))
    result = orch._run_tool_chain([{"type": "smt", "config": {"verb": "check-overflow"}}],
        config=config, file_path=outcome.file, function_name=outcome.function, line_start=outcome.line,
        source=old, hypothesis=outcome.hypothesis)
    assert result.outcomes[0].verdict == "inconclusive"
    assert result.source_identity is None


def test_aggregation_rechecks_source_after_refutation_is_recorded(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    config.immediate_verify = True
    path = tmp_path / outcome.file
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [{"type": "semgrep", "config": {}}])

    def run_chain(chain, **kw):
        result = ToolChainResult(file=outcome.file, function=outcome.function, line_start=outcome.line,
            hypothesis=outcome.hypothesis, source_identity=source.capture_source_identity(tmp_path, outcome.file))
        result.observe("semgrep", "refuted", "query-bound")
        return result

    real_append = orch.append_audit_log
    def record_then_change(out_dir, row):
        real_append(out_dir, row)
        path.write_text("int Read(int n) { return n + 1; }\n")

    monkeypatch.setattr(orch, "_run_tool_chain", run_chain)
    monkeypatch.setattr(orch, "append_audit_log", record_then_change)
    result = orch._verify_hypotheses_immediate(outcome, config, orch.OrchestratorResult())
    assert result.status == "suspicious"
    assert not result.review_result.get("immediate_verified")
    assert result.review_result["ihv_refuted"] == 0


def test_a_new_refutation_of_edited_source_can_resolve_again(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    retain(outcome, config)
    (tmp_path / outcome.file).write_text("int Read(int n) { return n + 1; }\n")
    assert resolve(outcome, config, {"joern": True}).status == "dark"
    retain(outcome, config)
    assert resolve(outcome, config, {"joern": True}).status == "clean"


@pytest.mark.parametrize("mutation", ["unchanged", "edit", "outside_excerpt", "delete", "replacement", "restore"])
def test_confirmation_is_usable_only_while_its_captured_source_stays_current(tmp_path, monkeypatch, mutation):
    outcome, config = case(tmp_path, monkeypatch)
    path = tmp_path / outcome.file
    original = path.read_text()
    before = path.stat()

    def checker(**kwargs):
        if mutation == "edit":
            path.write_text("int Read(int n) { return n + 2; }\n")
        elif mutation == "outside_excerpt":
            path.write_text(original + "int helper(void) { return 0; }\n")
        elif mutation == "delete":
            path.unlink()
        elif mutation == "replacement":
            replacement = tmp_path / "replacement.c"
            replacement.write_text(original)
            replacement.replace(path)
        elif mutation == "restore":
            path.write_text("int Read(int n) { return n + 2; }\n")
            path.write_text(original)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        return SweepResult(tool="smt", file_path=outcome.file, function_name=outcome.function,
                           outcome="confirmed", rule_id="smt:check-overflow", details={"reason": "fixture witness"})

    monkeypatch.setattr(orch, "run_smt_verb_direct", checker)
    inconclusive = set()
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-overflow"}}], config=config,
        file_path=outcome.file, function_name=outcome.function, line_start=outcome.line,
        source=original, hypothesis=outcome.hypothesis, inconclusive_types=inconclusive,
    )
    assert list(result) == (["smt:check-overflow"] if mutation == "unchanged" else [])
    assert result.outcomes[0].verdict == ("confirmed" if mutation == "unchanged" else "inconclusive")
    assert inconclusive == (set() if mutation == "unchanged" else {"smt"})


def test_a_later_chain_entry_cannot_preserve_an_earlier_confirmation_for_changed_source(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    path = tmp_path / outcome.file
    original = path.read_text()
    calls = []

    def checker(**kwargs):
        calls.append(kwargs)
        if len(calls) == 2:
            path.write_text(original + "// changed after first probe\n")
        return SweepResult(tool="smt", file_path=outcome.file, function_name=outcome.function,
                           outcome="confirmed" if len(calls) == 1 else "inconclusive", rule_id="smt:check-overflow")

    monkeypatch.setattr(orch, "run_smt_verb_direct", checker)
    inconclusive = set()
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-overflow"}},
         {"type": "smt", "config": {"verb": "check-oob"}}],
        config=config, file_path=outcome.file, function_name=outcome.function,
        source=original, hypothesis=outcome.hypothesis, inconclusive_types=inconclusive,
    )
    assert len(calls) == 2
    assert result == []
    assert [probe.verdict for probe in result.outcomes] == ["inconclusive", "inconclusive"]
    assert inconclusive == {"smt"}


def test_source_change_after_early_exit_still_withdraws_the_receipt_without_extra_dispatch(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    path = tmp_path / outcome.file
    original = path.read_text()
    calls = []

    def checker(**kwargs):
        calls.append(kwargs)
        return SweepResult(tool="smt", file_path=outcome.file, function_name=outcome.function,
                           outcome="confirmed", rule_id="smt:check-overflow")

    def qualifies(receipt):
        path.write_text(original + "// edit during early-exit admission\n")
        return True

    monkeypatch.setattr(orch, "run_smt_verb_direct", checker)
    skipped, inconclusive = set(), set()
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-overflow"}},
         {"type": "codeql", "config": {"query": "must-not-run.ql"}}],
        config=config, file_path=outcome.file, function_name=outcome.function,
        source=original, hypothesis=outcome.hypothesis, early_exit_check=qualifies,
        skipped_types=skipped, inconclusive_types=inconclusive,
    )
    assert len(calls) == 1
    assert result == []
    assert skipped == {"codeql"}
    assert inconclusive == {"smt"}


def test_source_invalidation_is_enforced_when_its_trace_writer_fails(tmp_path, monkeypatch, caplog):
    from core.audit import check_trace

    outcome, config = case(tmp_path, monkeypatch)
    path = tmp_path / outcome.file
    original = path.read_text()

    def checker(**kwargs):
        path.write_text(original + "// changed\n")
        return SweepResult(tool="smt", file_path=outcome.file, function_name=outcome.function,
                           outcome="confirmed", rule_id="smt:check-overflow")

    def fail(*args, **kwargs):
        raise OSError("fixture telemetry failure")

    monkeypatch.setattr(orch, "run_smt_verb_direct", checker)
    monkeypatch.setattr(check_trace, "record_source_invalidation", fail)
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-overflow"}}], config=config,
        file_path=outcome.file, function_name=outcome.function, source=original,
        hypothesis=outcome.hypothesis,
    )
    assert result == []
    assert result.outcomes[0].verdict == "inconclusive"
    assert "could not record source invalidation" in caplog.text


def test_immediate_verification_exports_the_raw_witness_and_its_source_invalidation(tmp_path, monkeypatch):
    from core.audit.findings_export import export_findings, write_graded_findings
    from core.json import load_json

    outcome, config = case(tmp_path, monkeypatch)
    outcome.hypothesis = "signed addition can overflow"
    outcome.review_result = {"hypothesis": outcome.hypothesis, "cwe": "CWE-190"}
    outcome.tools_dispatched = None
    config.immediate_verify = True
    path = tmp_path / outcome.file
    original = path.read_text()

    def checker(**kwargs):
        path.write_text(original + "// changed during check\n")
        return SweepResult(tool="smt", file_path=outcome.file, function_name=outcome.function,
                           outcome="confirmed", rule_id="smt:check-overflow", details={"reason": "fixture witness"})

    monkeypatch.setattr(orch, "run_smt_verb_direct", checker)
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [
        {"type": "smt", "config": {"verb": "check-overflow"}},
    ])
    final = orch._verify_hypotheses_immediate(outcome, config, orch.OrchestratorResult(), source=original)
    assert final.status == "suspicious"
    assert not final.evidence_tool
    assert not final.review_result.get("immediate_verified")
    assert final.tools_inconclusive == {"smt"}
    write_graded_findings(export_findings([final]), config.out_dir)
    sidecar = load_json(config.out_dir / "verification-checks.json")
    graded = load_json(config.out_dir / "findings-graded.json")
    witness, invalidation = sidecar["checks"]
    assert witness["outcome"] == witness["result"]["data"]["outcome"] == "confirmed"
    assert witness["source_applicability"] == {"status": "invalidated", "validation_ids": [invalidation["id"]]}
    assert invalidation["tool"] == "source_binding"
    assert invalidation["result"]["data"]["details"]["prior_receipts"] == ["smt:check-overflow"]
    assert invalidation["result"]["data"]["details"]["source_identity_after"]["sha256"] != witness["scope"]["source_identity"]["sha256"]
    assert sidecar["source_validation"]["invalidated_observations"] == 1
    assert graded["verification_summary"]["source_validation"] == sidecar["source_validation"]
    assert graded["findings"][0]["status"] == "suspicious"
    assert graded["findings"][0]["discovery"]["confirmed_by"] == []


def test_retry_with_stale_excerpt_cannot_reuse_a_confirmed_memo_entry(tmp_path, monkeypatch):
    from core.audit.findings_export import export_findings, write_graded_findings
    from core.json import load_json

    outcome, config = case(tmp_path, monkeypatch)
    path = tmp_path / outcome.file
    original = path.read_text()
    calls = []

    def checker(**kwargs):
        calls.append(kwargs)
        return SweepResult(tool="smt", file_path=outcome.file, function_name=outcome.function,
                           outcome="confirmed", rule_id="smt:check-overflow")

    monkeypatch.setattr(orch, "run_smt_verb_direct", checker)
    chain = [{"type": "smt", "config": {"verb": "check-overflow"}}]
    kwargs = dict(config=config, file_path=outcome.file, function_name=outcome.function,
                  source=original, hypothesis=outcome.hypothesis)
    assert orch._run_tool_chain(chain, **kwargs) == ["smt:check-overflow"]
    path.write_text(original.replace("return n;", "return n + 1;"))
    skipped, inconclusive = set(), set()
    result = orch._run_tool_chain(chain, **kwargs, skipped_types=skipped, inconclusive_types=inconclusive)
    assert result == []
    assert result.source_identity is None
    assert len(calls) == 1
    assert skipped == {"smt"} and inconclusive == set()  # no checker executed on the retry
    assert result.outcomes[0].tool == "source_binding"
    assert result.outcomes[0].rule_id == "source-input-unbound"
    write_graded_findings(export_findings([outcome]), config.out_dir)
    sidecar = load_json(config.out_dir / "verification-checks.json")
    rejected = sidecar["checks"][-1]
    assert rejected["scope"]["source_identity"] is None
    assert rejected["result"]["data"]["details"]["checker_execution"] == "not_run"
    assert rejected["result"]["data"]["details"]["requested_tools"] == ["smt"]
    assert sidecar["source_validation"]["unbound_inputs"] == 1


def test_unbound_excerpt_remains_skipped_when_rejection_reporting_fails(tmp_path, monkeypatch, caplog):
    from core.audit import check_trace

    outcome, config = case(tmp_path, monkeypatch)
    path = tmp_path / outcome.file
    original = path.read_text()
    path.write_text(original.replace("return n;", "return n + 1;"))

    def forbidden(**kwargs):
        pytest.fail("unbound input must not reach the checker")

    def fail(*args, **kwargs):
        raise OSError("fixture telemetry failure")

    monkeypatch.setattr(orch, "run_smt_verb_direct", forbidden)
    monkeypatch.setattr(check_trace, "record_source_input_rejection", fail)
    skipped = set()
    result = orch._run_tool_chain(
        [{"type": "smt", "config": {"verb": "check-overflow"}}], config=config,
        file_path=outcome.file, function_name=outcome.function, source=original,
        hypothesis=outcome.hypothesis, skipped_types=skipped,
    )
    assert result == [] and skipped == {"smt"}
    assert "could not record source input rejection" in caplog.text


def test_an_unchanged_excerpt_can_still_use_the_memo_after_an_unrelated_file_edit(tmp_path, monkeypatch):
    outcome, config = case(tmp_path, monkeypatch)
    path = tmp_path / outcome.file
    original = path.read_text()
    calls = []

    def checker(**kwargs):
        calls.append(kwargs)
        return SweepResult(tool="smt", file_path=outcome.file, function_name=outcome.function,
                           outcome="confirmed", rule_id="smt:check-overflow")

    monkeypatch.setattr(orch, "run_smt_verb_direct", checker)
    chain = [{"type": "smt", "config": {"verb": "check-overflow"}}]
    kwargs = dict(config=config, file_path=outcome.file, function_name=outcome.function,
                  source=original, hypothesis=outcome.hypothesis)
    assert orch._run_tool_chain(chain, **kwargs) == ["smt:check-overflow"]
    path.write_text(original + "// edit outside the supplied excerpt\n")
    result = orch._run_tool_chain(chain, **kwargs)
    assert result == ["smt:check-overflow"]
    assert len(calls) == 1
    assert result.source_identity == source.capture_source_identity(tmp_path, outcome.file)
