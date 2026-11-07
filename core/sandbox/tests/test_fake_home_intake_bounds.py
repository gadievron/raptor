"""Fake-HOME intake bounds enumeration and closes traversal resources."""
import errno
import os

import pytest

from core.sandbox import context
from core.testing.module_bindings import patch_module_attribute


class _Scan:
    def __init__(self, owner, native, fail):
        self.owner, self.native, self.fail = owner, native, fail
        self.closed = False
        self.seen = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.fail and self.owner.failure is not None:
            raise self.owner.failure
        entry = next(self.native)
        self.seen += 1
        return entry

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.native.close()
        if self.owner.close_error and self.fail:
            raise OSError(errno.EIO, "owned scanner close failed after release")


class _Resources:
    def __init__(self):
        self.native_scan = os.scandir
        self.native_open = os.open
        self.native_close = os.close
        self.native_home = context._open_fake_home
        self.live = {}
        self.scans = []
        self.duplicates = []
        self.failure = None
        self.fail_child = False
        self.close_error = False
        self.directory_close_error = False
        self.open_error = None
        self.peak = 0

    def home(self, path):
        fd = self.native_home(path)
        self.live[fd] = "root"
        return fd

    def open(self, path, flags, *args, **kwargs):
        directory = bool(flags & os.O_DIRECTORY)
        if directory and self.open_error is not None:
            raise self.open_error
        fd = self.native_open(path, flags, *args, **kwargs)
        self.live[fd] = "directory" if directory else "file"
        self.peak = max(self.peak, len(self.live))
        return fd

    def close(self, fd):
        if fd not in self.live:
            self.duplicates.append(fd)
            raise OSError(errno.EBADF, "owned descriptor already released")
        kind = self.live.pop(fd)
        self.native_close(fd)
        if kind == "directory" and self.directory_close_error:
            raise OSError(errno.EIO, "owned directory close failed after release")

    def scan(self, fd):
        native = self.native_scan(fd)
        fail = self.live.get(fd) == "directory" if self.fail_child else True
        scanner = _Scan(self, native, fail)
        self.scans.append(scanner)
        return scanner

    def finish(self):
        for scanner in self.scans:
            if not scanner.closed:
                scanner.closed = True
                scanner.native.close()
        for fd in list(self.live):
            self.native_close(fd)
            del self.live[fd]


@pytest.fixture
def resources(monkeypatch, request):
    owner = _Resources()
    request.addfinalizer(owner.finish)
    monkeypatch.setattr(context, "_open_fake_home", owner.home)
    patch_module_attribute(monkeypatch, context, "os", "open", owner.open)
    patch_module_attribute(monkeypatch, context, "os", "close", owner.close)
    patch_module_attribute(monkeypatch, context, "os", "scandir", owner.scan)
    return owner


def _home(tmp_path):
    home = tmp_path / ".home"
    home.mkdir()
    return home


def _released(resources):
    assert resources.scans, "the bounded scanner was not used"
    assert all(scan.closed for scan in resources.scans)
    assert not resources.live
    assert resources.duplicates == []


@pytest.mark.parametrize("shape", ["wide", "deep", "split"])
def test_directory_budget_accepts_limit_and_refuses_excess(tmp_path, monkeypatch, resources, shape):
    monkeypatch.setattr(context, "_FAKE_HOME_INGEST_MAX_DIRS", 2, raising=False)
    intake = _home(tmp_path)
    first = intake / "first"
    first.mkdir()
    second = (first if shape == "deep" else intake) / "second"
    second.mkdir()
    staged = context._stage_fake_home_intake(str(intake))
    assert staged is not None and len(staged[1]) == 3
    third = (second if shape in ("deep", "split") else intake) / "third"
    third.mkdir()
    assert context._stage_fake_home_intake(str(intake)) is None
    _released(resources)


@pytest.mark.parametrize("kind", ["directories", "files"])
def test_wide_intake_consumes_only_the_budget_plus_one(tmp_path, monkeypatch, resources, kind):
    monkeypatch.setattr(context, "_FAKE_HOME_INGEST_MAX_DIRS", 2, raising=False)
    monkeypatch.setattr(context, "_FAKE_HOME_INGEST_MAX_FILES", 2)
    intake = _home(tmp_path)
    for index in range(25):
        path = intake / str(index)
        path.mkdir() if kind == "directories" else path.write_bytes(b"x")
    assert context._stage_fake_home_intake(str(intake)) is None
    _released(resources)
    assert sum(scan.seen for scan in resources.scans) == 3


@pytest.mark.parametrize("children", [False, True], ids=["root-only", "one-child"])
def test_zero_directory_budget_retains_root_only(tmp_path, monkeypatch, resources, children):
    monkeypatch.setattr(context, "_FAKE_HOME_INGEST_MAX_DIRS", 0, raising=False)
    intake = _home(tmp_path)
    if children:
        (intake / "child").mkdir()
    staged = context._stage_fake_home_intake(str(intake))
    assert (staged is None) if children else (staged == ({}, [context._TMP_FAKE_HOME]))
    _released(resources)


@pytest.mark.parametrize("kind", ["io", "interrupt", "exit"])
@pytest.mark.parametrize("nested", [False, True], ids=["root", "nested"])
def test_scanner_errors_release_resources_and_preserve_cancellation(tmp_path, resources, kind, nested):
    intake = _home(tmp_path)
    (intake / "child").mkdir()
    failure = {"io": OSError(errno.EIO, "owned scan failed"),
               "interrupt": KeyboardInterrupt("owned scan interrupted"),
               "exit": SystemExit(17)}[kind]
    resources.failure = failure
    resources.fail_child = nested
    resources.close_error = True
    resources.directory_close_error = True
    if kind == "io":
        assert context._stage_fake_home_intake(str(intake)) is None
    else:
        with pytest.raises(type(failure)) as caught:
            context._stage_fake_home_intake(str(intake))
        assert caught.value is failure
    _released(resources)


@pytest.mark.parametrize("point", ["open-directory", "close-directory", "close-scanner"])
def test_traversal_io_errors_keep_existing_fallback(tmp_path, resources, point):
    intake = _home(tmp_path)
    (intake / "child").mkdir()
    resources.open_error = OSError(errno.EIO, "owned directory open failed") if point == "open-directory" else None
    resources.directory_close_error = point == "close-directory"
    resources.close_error = point == "close-scanner"
    assert context._stage_fake_home_intake(str(intake)) is None
    _released(resources)


@pytest.mark.parametrize("kind", ["oversize", "symlink", "fifo"])
def test_nested_early_refusal_closes_suspended_walk(tmp_path, monkeypatch, resources, kind):
    intake = _home(tmp_path)
    child = intake / "child"
    child.mkdir()
    member = child / "member"
    if kind == "oversize":
        monkeypatch.setattr(context, "_FAKE_HOME_INGEST_MAX_BYTES", 1)
        member.write_bytes(b"xx")
    elif kind == "symlink":
        target = tmp_path / "outside"
        target.write_bytes(b"private")
        member.symlink_to(target)
    else:
        os.mkfifo(member)
    assert context._stage_fake_home_intake(str(intake)) is None
    _released(resources)
