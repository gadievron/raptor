"""SCA overlays must not consume their own output or destroy inputs."""

from unittest.mock import Mock

import pytest

from core.json import JsonCache
from packages.sca import verify


import packages.sca.verify as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize(
    "relative", ["overlay", "reports/overlay", "reports/deep/overlay"]
)
def test_nested_overlay_never_copies_itself(tmp_path, monkeypatch, relative):
    from packages.sca.resolvers import _safe_io

    source = tmp_path / "target"
    source.mkdir()
    (source / "requirements.txt").write_text("sample==1\n")
    overlay = source / relative
    copy = _safe_io.copy_regular_file
    copies = []

    def bounded(src, dst, **kwargs):
        copies.append(dst)
        if len(copies) > 12:
            raise RuntimeError("recursive overlay copy")
        return copy(src, dst, **kwargs)

    monkeypatch.setattr(_safe_io, "copy_regular_file", bounded)
    verify._copy_target(source, overlay)
    assert (overlay / "requirements.txt").read_text() == "sample==1\n"
    assert len(copies) == 1


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    target = tmp_path / "target"
    proposed = tmp_path / "proposed"
    target.mkdir()
    proposed.mkdir()
    (target / "requirements.txt").write_text("old==1\n")
    (proposed / "requirements.txt").write_text("new==2\n")
    monkeypatch.setattr(
        verify, "run_sca", Mock(side_effect=RuntimeError("stop after preparation"))
    )
    return target, proposed, tmp_path / "result"


def run_verify(target, proposed, output, tmp_path):
    return verify.main(
        [str(target), "--proposed", str(proposed), "--out", str(output)],
        http=object(),
        cache=JsonCache(root=tmp_path / "cache"),
    )


@pytest.mark.parametrize("protected", ["target", "proposed"])
@pytest.mark.parametrize("nested", [False, True])
def test_overlay_output_cannot_erase_an_input(tmp_path, monkeypatch, protected, nested):
    output = tmp_path / "result"
    victim = output / "overlay"
    if nested:
        victim = victim / "nested"
    victim.mkdir(parents=True)
    (victim / "requirements.txt").write_text("keep==1\n")
    other = tmp_path / "other"
    other.mkdir()
    (other / "requirements.txt").write_text("other==2\n")
    target, proposed = (victim, other) if protected == "target" else (other, victim)
    monkeypatch.setattr(
        verify, "run_sca", Mock(side_effect=RuntimeError("unexpected analysis"))
    )
    assert run_verify(target, proposed, output, tmp_path) == 2
    assert (victim / "requirements.txt").read_text() == "keep==1\n"
    verify.run_sca.assert_not_called()


@pytest.mark.parametrize("stage", ["copy", "apply"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_failed_preparation_preserves_previous_overlay(
    inputs, tmp_path, monkeypatch, stage, error
):
    target, proposed, output = inputs
    old = output / "overlay"
    old.mkdir(parents=True)
    (old / "keep").write_text("previous result")
    failure = error("preparation failed")

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(
        verify, "_copy_target" if stage == "copy" else "_apply_overlay", fail
    )
    if error is OSError:
        assert run_verify(target, proposed, output, tmp_path) == 3
    else:
        with pytest.raises(error) as caught:
            run_verify(target, proposed, output, tmp_path)
        assert caught.value is failure
    assert (old / "keep").read_text() == "previous result"
    assert not list(output.glob(".verify-overlay-*"))
    verify.run_sca.assert_not_called()


def test_proposed_symlink_is_refused_without_reading_target(tmp_path):
    proposed = tmp_path / "proposed"
    proposed.mkdir()
    source = tmp_path / "keep"
    source.write_text("keep")
    (proposed / "requirements.txt").symlink_to(source)
    overlay = tmp_path / "overlay"
    overlay.mkdir()
    with pytest.raises(ValueError):
        verify._apply_overlay(proposed, overlay)
    assert not (overlay / "requirements.txt").exists()
    assert source.read_text() == "keep"


@pytest.mark.parametrize(
    "slot", ["overlay", "verify-before", "verify-after", "delta.json", "delta.md"]
)
def test_findings_input_cannot_be_overwritten_by_outputs(inputs, tmp_path, slot):
    target, proposed, output = inputs
    baseline = output / slot
    if not slot.startswith("delta"):
        baseline = baseline / "findings.json"
    baseline.parent.mkdir(parents=True)
    baseline.write_text("[]")
    rc = verify.main(
        [
            str(target),
            "--proposed",
            str(proposed),
            "--out",
            str(output),
            "--findings",
            str(baseline),
        ],
        http=object(),
        cache=JsonCache(root=tmp_path / "cache"),
    )
    assert rc == 2
    assert baseline.read_text() == "[]"
    verify.run_sca.assert_not_called()


@pytest.mark.parametrize("protected", ["target", "proposed"])
@pytest.mark.parametrize("slot", ["verify-before", "verify-after"])
def test_reserved_analysis_output_cannot_contain_an_input(
    tmp_path, monkeypatch, protected, slot
):
    output = tmp_path / "result"
    victim = output / slot / "source"
    victim.mkdir(parents=True)
    (victim / "requirements.txt").write_text("keep==1\n")
    other = tmp_path / "other"
    other.mkdir()
    (other / "requirements.txt").write_text("other==2\n")
    target, proposed = (victim, other) if protected == "target" else (other, victim)
    monkeypatch.setattr(verify, "run_sca", Mock())
    assert run_verify(target, proposed, output, tmp_path) == 2
    assert (victim / "requirements.txt").read_text() == "keep==1\n"
    verify.run_sca.assert_not_called()


@pytest.mark.parametrize("quota", ["bytes", "entries"])
def test_preparation_quota_failure_retains_previous_overlay(
    inputs, tmp_path, monkeypatch, quota
):
    target, proposed, output = inputs
    old = output / "overlay"
    old.mkdir(parents=True)
    (old / "keep").write_text("previous")
    monkeypatch.setattr(
        verify, "_OVERLAY_MAX_BYTES" if quota == "bytes" else "_OVERLAY_MAX_ENTRIES", 2
    )
    assert run_verify(target, proposed, output, tmp_path) == 3
    assert (old / "keep").read_text() == "previous"
    assert not list(output.glob(".verify-overlay-*"))
    verify.run_sca.assert_not_called()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("phase", ["retire-before", "retire-after", "publish"])
def test_publication_failure_restores_previous_overlay(
    inputs, tmp_path, monkeypatch, phase, error
):
    import os

    target, proposed, output = inputs
    old = output / "overlay"
    old.mkdir(parents=True)
    (old / "keep").write_text("previous")
    failure = error("publication failed")
    rename = os.rename

    def fail(src, dst):
        retiring = src == old
        publishing = dst == old and src.parent.name.startswith(".verify-overlay-")
        if retiring and phase == "retire-before":
            raise failure
        if retiring and phase == "retire-after":
            rename(src, dst)
            raise failure
        if publishing and phase == "publish":
            raise failure
        return rename(src, dst)

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", "rename", fail)
    if error is OSError:
        assert run_verify(target, proposed, output, tmp_path) == 3
    else:
        with pytest.raises(error) as caught:
            run_verify(target, proposed, output, tmp_path)
        assert caught.value is failure
    assert (old / "keep").read_text() == "previous"
    assert not list(output.glob(".verify-overlay-*"))
    assert not list(output.glob(".verify-retired-*"))
    verify.run_sca.assert_not_called()


def test_failed_rollback_keeps_recovery_copy(inputs, tmp_path, monkeypatch):
    import os

    target, proposed, output = inputs
    old = output / "overlay"
    old.mkdir(parents=True)
    (old / "keep").write_text("previous")
    rename = os.rename

    def fail(src, dst):
        if dst == old:
            raise OSError("cannot publish or restore")
        return rename(src, dst)

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", "rename", fail)
    assert run_verify(target, proposed, output, tmp_path) == 3
    retained = list(output.glob(".verify-retired-*"))
    assert len(retained) == 1
    assert (retained[0] / "keep").read_text() == "previous"
    assert not list(output.glob(".verify-overlay-*"))


@pytest.mark.parametrize("mode", [0, 0o500, 0o555])
def test_successful_replacement_reclaims_restricted_previous_tree(
    inputs, tmp_path, mode
):
    from core.testing.restricted_tree import restricted_tree

    target, proposed, output = inputs
    old = output / "overlay"
    with restricted_tree(old, mode):
        assert (
            run_verify(target, proposed, output, tmp_path) == 3
        )  # Mocked analysis stops after preparation.
        assert (old / "requirements.txt").read_text() == "new==2\n"
        assert not (old / "locked").exists()
        assert not list(output.glob(".verify-retired-*"))
        assert not list(output.glob(".verify-overlay-*"))


def test_empty_proposal_keeps_previous_overlay(inputs, tmp_path):
    target, proposed, output = inputs
    (proposed / "requirements.txt").unlink()
    old = output / "overlay"
    old.mkdir(parents=True)
    (old / "keep").write_text("previous")
    assert run_verify(target, proposed, output, tmp_path) == 2
    assert (old / "keep").read_text() == "previous"
    verify.run_sca.assert_not_called()


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory-link"])
def test_proposed_nonregular_inputs_are_not_partially_applied(tmp_path, kind):
    import os

    proposed = tmp_path / "proposed"
    proposed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("keep")
    if kind == "fifo":
        os.mkfifo(proposed / "requirements.txt")
    elif kind == "directory-link":
        (proposed / "linked").symlink_to(outside, target_is_directory=True)
    else:
        (proposed / "requirements.txt").symlink_to(outside / "keep")
    overlay = tmp_path / "overlay"
    overlay.mkdir()
    with pytest.raises(ValueError):
        verify._apply_overlay(proposed, overlay)
    assert (outside / "keep").read_text() == "keep"
    assert list(overlay.iterdir()) == []


def test_output_inside_target_excludes_prior_results_and_proposed_files(
    inputs, tmp_path
):
    target, proposed, _output = inputs
    output = target / "reports"
    output.mkdir()
    (output / "requirements.txt").write_text("stale==3\n")
    nested_proposed = target / "changes"
    proposed.rename(nested_proposed)
    assert run_verify(target, nested_proposed, output, tmp_path) == 3
    overlay = output / "overlay"
    assert (overlay / "requirements.txt").read_text() == "new==2\n"
    assert not (overlay / "reports").exists()
    assert not (overlay / "changes").exists()


def test_walk_error_refuses_incomplete_source_copy(inputs, tmp_path, monkeypatch):
    target, proposed, output = inputs
    old = output / "overlay"
    old.mkdir(parents=True)
    (old / "keep").write_text("previous")

    def failed_walk(root, **kwargs):
        kwargs["onerror"](PermissionError("unreadable source subtree"))
        yield

    patch_module_attribute(monkeypatch, verify, 'os', "walk", failed_walk)
    assert run_verify(target, proposed, output, tmp_path) == 3
    assert (old / "keep").read_text() == "previous"
    assert not list(output.glob(".verify-overlay-*"))
    verify.run_sca.assert_not_called()


def test_copy_and_proposed_share_one_byte_budget(inputs, tmp_path, monkeypatch):
    target, proposed, output = inputs
    # Each input fits alone; copying both exceeds the shared budget.
    monkeypatch.setattr(verify, "_OVERLAY_MAX_BYTES", 10)
    assert run_verify(target, proposed, output, tmp_path) == 3
    assert not (output / "overlay").exists()
    assert not list(output.glob(".verify-overlay-*"))
    verify.run_sca.assert_not_called()


@pytest.mark.parametrize("existing", [False, True])
def test_concurrent_destination_replacement_is_preserved(
    inputs, tmp_path, monkeypatch, existing
):
    target, proposed, output = inputs
    old = output / "overlay"
    if existing:
        old.mkdir(parents=True)
        (old / "keep").write_text("previous")
    apply = verify._apply_overlay

    def changed(*args, **kwargs):
        result = apply(*args, **kwargs)
        if existing:
            old.rename(output / "operator-moved")
        old.mkdir()
        (old / "operator").write_text("keep")
        return result

    monkeypatch.setattr(verify, "_apply_overlay", changed)
    assert run_verify(target, proposed, output, tmp_path) == 3
    assert (old / "operator").read_text() == "keep"
    assert not list(output.glob(".verify-overlay-*"))
    verify.run_sca.assert_not_called()


def test_required_output_lock_failure_never_prepares_overlay(
    inputs, tmp_path, monkeypatch
):
    from contextlib import contextmanager

    target, proposed, output = inputs

    @contextmanager
    def refuse(*args, **kwargs):
        assert kwargs["required"] is True
        raise OSError("lock unavailable")
        yield

    monkeypatch.setattr(verify, "artifact_lock", refuse)
    assert run_verify(target, proposed, output, tmp_path) == 3
    assert not (output / "overlay").exists()
    assert not list(output.glob(".verify-overlay-*"))
    verify.run_sca.assert_not_called()


def test_shared_output_cannot_change_while_analysis_uses_overlay(
    inputs, tmp_path, monkeypatch
):
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import contextmanager
    from threading import Event, Lock

    target, proposed, output = inputs
    proposed2 = tmp_path / "proposed2"
    proposed2.mkdir()
    (proposed2 / "requirements.txt").write_text("next==3\n")
    entered, second_attempt, release = Event(), Event(), Event()
    guard = Lock()
    artifact_lock = verify.artifact_lock
    attempts = 0
    observed = []

    @contextmanager
    def tracking_lock(*args, **kwargs):
        nonlocal attempts
        with guard:
            attempts += 1
            if attempts == 2:
                second_attempt.set()
        with artifact_lock(*args, **kwargs):
            yield

    def analyse(*args, **kwargs):
        overlay = kwargs["target"]
        observed.append((overlay / "requirements.txt").read_text())
        if len(observed) == 1:
            entered.set()
            assert release.wait(10)
            assert (overlay / "requirements.txt").read_text() == "new==2\n"
        raise RuntimeError("stop after checking overlay lifetime")

    monkeypatch.setattr(verify, "artifact_lock", tracking_lock)
    monkeypatch.setattr(verify, "run_sca", analyse)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run_verify, target, proposed, output, tmp_path)
        try:
            assert entered.wait(5)
            second = pool.submit(run_verify, target, proposed2, output, tmp_path)
            assert second_attempt.wait(5)
            assert observed == ["new==2\n"]
        finally:
            release.set()
        assert first.result(timeout=10) == 3
        assert second.result(timeout=10) == 3
    assert observed == ["new==2\n", "next==3\n"]
    assert not list(output.glob(".verify-overlay-*"))
    assert not list(output.glob(".verify-retired-*"))
