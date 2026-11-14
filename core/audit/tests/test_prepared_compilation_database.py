"""Actual owned declaration acquisition and rollback, without compiler calls."""

from dataclasses import replace
import hashlib

import pytest

from core.audit import prepared_compilation_database as database
from core.audit import prepared_dependency_material as material
from core.audit.prepared_compilation_database import CompilationDatabaseOwner
from core.audit.prepared_dependency_material import DependencyReference
from core.audit.prepared_invocation_candidate import CandidateUnavailable


RAW = b'[\r\n { "file":"unit.c", "directory":"/declared", "arguments":["cc", "@flags", "unit.c"] }\n]'
REF = DependencyReference("target", "compile_commands.json")
CAPS = dict(declared_build_association="declared", max_database_bytes=4096,
            max_entries=4, max_entry_bytes=2048, max_depth=16)


def owner(root, **caps):
    return CompilationDatabaseOwner({"target": root}, **{
        "max_retained_bytes": 16384, "max_captures": 4, "max_selections": 4, **caps})


def acquire(owned, **caps):
    return owned.acquire(REF, "unit.c", **{**CAPS, **caps})


@pytest.fixture
def root(tmp_path):
    (tmp_path / REF.path).write_bytes(RAW)
    return tmp_path


def test_actual_raw_file_identity_and_entry_are_retained_without_build_authority(root):
    roots = {"target": root}
    owned = CompilationDatabaseOwner(roots, max_retained_bytes=4096,
                                    max_captures=1, max_selections=1)
    roots.clear()
    acquired = acquire(owned)
    assert owned.retains(acquired) and not acquired.authenticated_build
    assert acquired.reference == REF
    assert acquired.source_identity.sha256 == hashlib.sha256(RAW).hexdigest()
    assert len(acquired.source_identity.version) == 5
    capture = acquired.selected.capture
    assert capture.database_bytes == RAW
    assert capture.declared_build_association == "declared"
    start, end = acquired.selected.selected_interval
    assert RAW[start:end] == acquired.selected.selected_entry_bytes
    assert acquired.selected.invocation.ordered_arguments == ("cc", "@flags", "unit.c")
    assert acquired.selected.invocation.response_file_references == ((1, "@flags"),)
    (root / REF.path).write_bytes(b"changed after capture")
    assert capture.database_bytes == RAW and owned.retains(acquired)
    assert acquired.source_identity.sha256 == hashlib.sha256(RAW).hexdigest()


@pytest.mark.parametrize("path", ["../compile_commands.json", "/absolute", "./compile_commands.json",
                                  "missing", "directory", "link"])
def test_actual_containment_refusals_do_not_parse_or_retain(root, monkeypatch, path):
    (root / "directory").mkdir()
    (root / "link").symlink_to(root / REF.path)
    owned = owner(root)
    monkeypatch.setattr(owned._declarations, "capture", lambda *a, **k: pytest.fail("parser reached"))
    with pytest.raises(CandidateUnavailable):
        owned.acquire(DependencyReference("target", path), "unit.c", **CAPS)
    assert owned.retained_payload_bytes == 0


def test_unknown_root_refuses_before_parser(root):
    owned = owner(root)
    with pytest.raises(CandidateUnavailable, match="unknown_dependency_root"):
        owned.acquire(DependencyReference("other", REF.path), "unit.c", **CAPS)
    assert owned.retained_payload_bytes == 0


@pytest.mark.parametrize("raw", [b"[", b'[{"file":"unit.c","file":"unit.c"}]',
                                 b'[{"file":"unit.c","directory":"/b","command":"cc unit.c"}]',
                                 b'[{"file":"different.c","directory":"/b","arguments":["cc"]}]',
                                 b"[" + RAW[1:-1] + b"," + RAW[1:-1] + b"]"])
def test_parse_or_unique_selection_refusal_rolls_back_single_slot(root, raw):
    owned = owner(root, max_captures=1, max_selections=1)
    (root / REF.path).write_bytes(raw)
    with pytest.raises(CandidateUnavailable):
        acquire(owned)
    assert owned.retained_payload_bytes == 0
    (root / REF.path).write_bytes(RAW)
    assert owned.retains(acquire(owned))


@pytest.mark.parametrize("field", ["max_database_bytes", "max_entries", "max_entry_bytes", "max_depth"])
@pytest.mark.parametrize("bad", [True, 0, -1, 1.5])
def test_invalid_limits_refuse_before_any_read(root, monkeypatch, field, bad):
    owned = owner(root)
    monkeypatch.setattr(database, "capture_dependency_materials", lambda *a, **k: pytest.fail("read reached"))
    with pytest.raises(CandidateUnavailable, match="invalid_acquisition_budget"):
        acquire(owned, **{field: bad})


def test_selection_byte_exhaustion_releases_unpublished_capture(root):
    # Enough for one raw database and its association but not its entry slice.
    padded = RAW + b" " * 200
    (root / REF.path).write_bytes(padded)
    owned = owner(root, max_retained_bytes=len(padded) + len("declared"), max_captures=1)
    with pytest.raises(CandidateUnavailable, match="payload_retention_exhausted"):
        acquire(owned)
    assert owned.retained_payload_bytes == 0
    shorter = b'[{"file":"unit.c","directory":"/b","arguments":["c"]}]'
    (root / REF.path).write_bytes(shorter)
    acquired = acquire(owned)
    assert owned.retains(acquired)


def test_exhaustion_does_not_invalidate_previous_handle(root):
    owned = owner(root, max_captures=2, max_selections=1)
    first = acquire(owned)
    before = owned.retained_payload_bytes
    with pytest.raises(CandidateUnavailable, match="selection_retention_exhausted"):
        acquire(owned)
    assert owned.retains(first) and owned.retained_payload_bytes == before
    assert owned.release(first)
    assert owned.retains(acquire(owned))


def test_forged_and_foreign_handles_do_not_adopt_or_release_original(root):
    owned = owner(root)
    first, second = acquire(owned), acquire(owned)
    for forged in [replace(first), replace(first, reference=DependencyReference("other", "x")),
                   replace(first, selected=replace(first.selected))]:
        assert not owned.retains(forged) and not owned.release(forged)
    assert not owner(root).retains(first)
    assert owned.release(first) and not owned.release(first)
    assert not owned.retains(first) and owned.retains(second)
    owned.close()
    owned.close()
    assert not owned.retains(second) and not owned.release(second)
    assert owned.retained_payload_bytes == 0


def test_close_is_terminal_before_file_reader(root, monkeypatch):
    owned = owner(root)
    owned.close()
    monkeypatch.setattr(database, "capture_dependency_materials", lambda *a, **k: pytest.fail("read reached"))
    with pytest.raises(CandidateUnavailable, match="owner_closed"):
        acquire(owned)


class _ReadHook:
    def __init__(self, stream, hook):
        self.stream, self.hook = stream, hook

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *args):
        return self.stream.__exit__(*args)

    def fileno(self):
        return self.stream.fileno()

    def close(self):
        self.stream.close()

    def read(self, size):
        data = self.stream.read(size)
        self.hook()
        return data


def test_observed_file_drift_refusal_has_no_retention(root, monkeypatch):
    original = material.open_regular_beneath
    streams = []

    def open_changed(base, path, mode):
        stream = original(base, path, mode)
        streams.append(stream)
        return _ReadHook(stream, lambda: (root / REF.path).write_bytes(RAW + b" "))

    owned = owner(root)
    with monkeypatch.context() as patch:
        patch.setattr(material, "open_regular_beneath", open_changed)
        with pytest.raises(CandidateUnavailable, match="dependency_changed_during_read"):
            acquire(owned)
    assert owned.retained_payload_bytes == 0 and all(stream.closed for stream in streams)
    (root / REF.path).write_bytes(RAW)
    assert owned.retains(acquire(owned))


def test_interrupted_selection_keeps_primary_and_rolls_back(root, monkeypatch):
    owned = owner(root, max_captures=1, max_selections=1)
    primary = KeyboardInterrupt("owned interrupt")
    original_release = owned._declarations.release_capture

    def interrupt(*args, **kwargs):
        raise primary

    def retire_then_raise(capture):
        original_release(capture)
        raise RuntimeError("cleanup diagnostic")

    with monkeypatch.context() as patch:
        patch.setattr(owned._declarations, "select", interrupt)
        patch.setattr(owned._declarations, "release_capture", retire_then_raise)
        with pytest.raises(KeyboardInterrupt) as caught:
            acquire(owned)
        assert caught.value is primary
    assert owned.retained_payload_bytes == 0
    assert owned.retains(acquire(owned))


@pytest.mark.parametrize("unissued", [None, 0, object()])
def test_non_records_are_not_retained_or_releasable(root, unissued):
    owned = owner(root)
    assert not owned.retains(unissued) and not owned.release(unissued)


def test_after_effect_publication_interrupt_releases_registry(tmp_path):
    raw = b'[ {"file":"a.c","directory":"/b","arguments":["cc"]} ]'
    (tmp_path / "compile_commands.json").write_bytes(raw)
    owner = CompilationDatabaseOwner({"r":tmp_path}, max_retained_bytes=4096,max_captures=1,max_selections=1)
    primary = KeyboardInterrupt("after registry publication")
    class InterruptingRegistry(dict):
        def __setitem__(self, key, value):
            super().__setitem__(key,value)
            raise primary
    owner._issued = InterruptingRegistry()
    with pytest.raises(KeyboardInterrupt) as caught:
        owner.acquire(DependencyReference("r","compile_commands.json"),"a.c", declared_build_association="b",max_database_bytes=1024,max_entries=1,max_entry_bytes=1024,max_depth=8)
    assert caught.value is primary
    assert owner.retained_payload_bytes == 0
    assert owner._issued == {}
