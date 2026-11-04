"""Interrupted state writers must leave neither scratch files nor open fds."""

import errno
import json
import os
import tempfile
from types import SimpleNamespace

import pytest

WRITERS = ("ledger", "resume", "summaries", "mutation", "labels", "staging")


@pytest.fixture(params=WRITERS)
def writer(request, tmp_path, monkeypatch):
    root = tmp_path / "state"
    root.mkdir()
    target = root / "state.json"
    target.write_text('{"source":{"line_end":1}}\n')
    private = request.param not in ("mutation", "labels")
    if request.param == "ledger":
        from packages.joern.heap_ledger import _write_rows

        save = lambda: _write_rows(target, [{"mb": 128}])
    elif request.param == "resume":
        from packages.openant.resume import _atomic_write_json

        save = lambda: _atomic_write_json(target, {"checkpoint": "ready"})
    elif request.param == "summaries":
        from core.taint.summary_cache import SummaryCache

        save = lambda: SummaryCache().save(target)
    elif request.param == "mutation":
        from core.audit.corpus import mutation

        label = SimpleNamespace(
            provenance_kind="synthetic_mutant",
            function_id="state:f",
            source=SimpleNamespace(repo="demo", file=target.name),
            mutation={},
        )
        monkeypatch.setattr(
            mutation, "apply_mutation_to_text", lambda text, label: "changed\n"
        )
        save = lambda: mutation.apply_labels_to_tree([label], {"demo": root})
    elif request.param == "labels":
        from core.audit.corpus.lint import PIN_OK, PinCheck, stamp_labels

        label = SimpleNamespace(source=SimpleNamespace(span_sha=""))
        check = PinCheck(
            label=label, path=target, outcome=PIN_OK, current_span_sha="123456789abc"
        )
        save = lambda: stamp_labels([check])
    else:
        from packages.openant import scanner

        target.unlink()
        monkeypatch.setattr(
            scanner, "_operator_config_path", lambda: tmp_path / "absent.json"
        )
        target = root / scanner._XDG_STAGE_DIRNAME / "openant" / "config.json"
        save = lambda: scanner._stage_llm_config(root, "sonnet")
    return SimpleNamespace(
        root=root, target=target, save=save, private=private, kind=request.param
    )


def descriptors(monkeypatch):
    """Track real allocations through either old mkstemp or the shared writer."""
    opened = set()
    original_open = os.open
    original_mkstemp = tempfile.mkstemp

    def tracked_open(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.add(fd)
        return fd

    def tracked_mkstemp(*args, **kwargs):
        fd, path = original_mkstemp(*args, **kwargs)
        opened.add(fd)
        return fd, path

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(tempfile, "mkstemp", tracked_mkstemp)
    return opened


def assert_closed(opened):
    for fd in opened:
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF


def assert_no_scratch(writer):
    assert [p for p in writer.root.rglob("*") if p.is_file()] in ([], [writer.target])


def test_stream_setup_failure_does_not_leak_descriptor(writer, monkeypatch):
    opened = descriptors(monkeypatch)

    def fail(*args, **kwargs):
        raise OSError("stream setup failed")

    # A writer which avoids fdopen entirely can complete successfully.
    monkeypatch.setattr(os, "fdopen", fail)
    try:
        writer.save()
    except OSError:
        pass
    assert_no_scratch(writer)
    assert_closed(opened)


def test_interrupted_permission_setup_closes_descriptor(writer, monkeypatch):
    opened = descriptors(monkeypatch)

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "fchmod", interrupt)
    try:
        writer.save()
    except KeyboardInterrupt:
        pass
    assert_no_scratch(writer)
    assert_closed(opened)


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
def test_failed_commit_preserves_destination_and_removes_scratch(
    writer, monkeypatch, failure
):
    before = writer.target.read_bytes() if writer.target.exists() else None
    opened = descriptors(monkeypatch)

    def fail(*args, **kwargs):
        raise failure("commit failed")

    monkeypatch.setattr(os, "replace", fail)
    try:
        writer.save()
    except (OSError, KeyboardInterrupt):
        pass
    if before is None:
        assert not writer.target.exists()
    else:
        assert writer.target.read_bytes() == before
    assert_no_scratch(writer)
    assert_closed(opened)


def test_writer_sets_private_or_preserves_existing_permissions(writer):
    if writer.target.exists():
        writer.target.chmod(0o751)
    writer.save()
    expected = 0o600 if writer.private else 0o751
    assert writer.target.stat().st_mode & 0o777 == expected
    assert_no_scratch(writer)


def test_heap_ledger_serialization_failure_leaves_no_scratch(tmp_path):
    from packages.joern.heap_ledger import _write_rows

    target = tmp_path / "ledger.json"
    target.write_text("previous ledger")
    with pytest.raises(TypeError):
        _write_rows(target, [{"mb": object()}])
    assert target.read_text() == "previous ledger"
    assert list(tmp_path.iterdir()) == [target]


def test_short_writes_commit_complete_content(writer, monkeypatch):
    original_write = os.write
    calls = []

    def short(fd, content):
        calls.append(len(content))
        return original_write(fd, content[:3])

    monkeypatch.setattr(os, "write", short)
    writer.save()
    assert len(calls) > 1
    if writer.kind == "mutation":
        assert writer.target.read_text() == "changed\n"
    else:
        data = json.loads(writer.target.read_text())
        if writer.kind == "ledger":
            assert data["rows"] == [{"mb": 128}]
        elif writer.kind == "resume":
            assert data == {"checkpoint": "ready"}
        elif writer.kind == "summaries":
            assert data["entries"] == {}
        elif writer.kind == "labels":
            assert data["source"]["span_sha"] == "123456789abc"
        else:
            assert "raptor-sonnet" in data["llm_configs"]
    assert_no_scratch(writer)


def test_disk_full_does_not_commit_partial_state(writer, monkeypatch):
    before = writer.target.read_bytes() if writer.target.exists() else None
    opened = descriptors(monkeypatch)
    original_write = os.write
    calls = []

    def full(fd, content):
        if calls:
            raise OSError(errno.ENOSPC, "no space left")
        calls.append(fd)
        return original_write(fd, content[:1])

    monkeypatch.setattr(os, "write", full)
    try:
        writer.save()
    except OSError as error:
        assert error.errno == errno.ENOSPC
    assert len(calls) == 1
    if before is None:
        assert not writer.target.exists()
    else:
        assert writer.target.read_bytes() == before
    assert_no_scratch(writer)
    assert_closed(opened)
