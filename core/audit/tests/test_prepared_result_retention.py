"""Complete durable result acknowledgements, without executing a checker."""
from dataclasses import asdict
import json
import os
import stat

import pytest

from core.audit import prepared_result_retention as module
from core.audit.sweep import SweepResult


@pytest.fixture
def result():
    return SweepResult(tool="smt", file_path="unit.c", function_name="Read",
                       outcome="inconclusive", rule_id="smt:check-overflow",
                       raw_output="complete output " * 7000,
                       details={"smt_execution": {"request_id": "existing-invocation"}})


def test_complete_result_acknowledges_real_durable_bytes(tmp_path, result, monkeypatch):
    before = asdict(result)
    flushed = []
    original_fsync = os.fsync

    def fsync(fd):
        flushed.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        original_fsync(fd)

    monkeypatch.setattr(module.os, "fsync", fsync)
    reference = module.retain_smt_result(tmp_path, result)
    retained = tmp_path / reference
    assert retained.parent == tmp_path / module.RESULT_DIRECTORY
    assert json.loads(retained.read_bytes()) == before
    assert len(retained.read_bytes()) > 65536
    assert stat.S_IMODE(retained.stat().st_mode) == 0o600
    assert flushed == [True, False, True]
    assert asdict(result) == before
    assert module.retained_smt_result_matches(tmp_path, reference, result)
    assert module.retain_smt_result(tmp_path, result) != reference


@pytest.mark.parametrize("failure_stage", [0, 1, 2])
def test_fsync_failure_never_acknowledges(tmp_path, result, monkeypatch, failure_stage):
    reached = []
    original_fsync = os.fsync

    def fail(fd):
        stage = len(reached)
        reached.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        if stage == failure_stage:
            raise OSError("injected durability failure")
        original_fsync(fd)

    monkeypatch.setattr(module.os, "fsync", fail)
    with pytest.raises(OSError, match="injected durability failure"):
        module.retain_smt_result(tmp_path, result)
    assert reached == [True, False, True][:failure_stage + 1]
    assert not list((tmp_path / module.RESULT_DIRECTORY).glob("*.json"))


@pytest.mark.parametrize("value", [object(), float("nan"), {1: "non-string key"}])
def test_non_json_payload_never_stringifies_into_ack(tmp_path, result, value):
    result.details = {"unsupported": value}
    with pytest.raises(ValueError, match="non-JSON"):
        module.retain_smt_result(tmp_path, result)
    assert not (tmp_path / module.RESULT_DIRECTORY).exists()


@pytest.mark.parametrize("component", ["output", "results", "ancestor"])
def test_symlinked_output_components_are_refused(tmp_path, result, component):
    real = tmp_path / "real"
    real.mkdir()
    output = real
    if component == "output":
        output = tmp_path / "output-link"
        output.symlink_to(real, target_is_directory=True)
    elif component == "ancestor":
        (real / "child").mkdir()
        (tmp_path / "ancestor-link").symlink_to(real, target_is_directory=True)
        output = tmp_path / "ancestor-link" / "child"
    else:
        (real / module.RESULT_DIRECTORY).symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        module.retain_smt_result(output, result)
    assert not list(tmp_path.glob("*.json"))


def test_changed_complete_readback_does_not_acknowledge(tmp_path, result, monkeypatch):
    reached = []
    original_read = os.read

    def altered(fd, size):
        data = original_read(fd, size)
        if data and not reached:
            reached.append(True)
            return bytes([data[0] ^ 1]) + data[1:]
        return data

    monkeypatch.setattr(module.os, "read", altered)
    with pytest.raises(OSError, match="complete readback"):
        module.retain_smt_result(tmp_path, result)
    assert reached == [True]
    assert not list((tmp_path / module.RESULT_DIRECTORY).glob("*.json"))


def test_oversized_result_is_refused_before_filesystem(tmp_path, result, monkeypatch):
    monkeypatch.setattr(module, "MAX_RESULT_BYTES", 32)
    with pytest.raises(ValueError, match="byte limit"):
        module.retain_smt_result(tmp_path, result)
    assert not (tmp_path / module.RESULT_DIRECTORY).exists()


@pytest.mark.parametrize("changed", ["bytes", "missing", "symlink", "result"])
def test_export_revalidation_withdraws_changed_result(tmp_path, result, changed):
    reference = module.retain_smt_result(tmp_path, result)
    path = tmp_path / reference
    if changed == "bytes":
        path.write_bytes(b"changed")
    elif changed == "missing":
        path.unlink()
    elif changed == "symlink":
        saved = path.read_bytes()
        path.unlink()
        target = tmp_path / "replacement.json"
        target.write_bytes(saved)
        path.symlink_to(target)
    else:
        result.outcome = "confirmed"
    assert not module.retained_smt_result_matches(tmp_path, reference, result)


@pytest.mark.parametrize("reference", ["../result.json", "/result.json", "prepared-smt-results/x.json"])
def test_export_revalidation_refuses_unowned_reference(tmp_path, result, reference):
    assert not module.retained_smt_result_matches(tmp_path, reference, result)
