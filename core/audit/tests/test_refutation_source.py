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
