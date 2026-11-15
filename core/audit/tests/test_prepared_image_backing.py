"""Synthetic OS-seam controls only; never call memfd, fcntl or real descriptor IO."""
from dataclasses import replace
import hashlib
import stat
from types import SimpleNamespace

import pytest

from core.audit import prepared_image_backing as module


class SyntheticKernel:
    """In-memory fake OS/fcntl pair exercising the actual _LinuxSeals methods."""

    MFD_CLOEXEC = 1
    MFD_ALLOW_SEALING = 2
    F_ADD_SEALS = 10
    F_GET_SEALS = 11
    F_SEAL_WRITE = 1
    F_SEAL_GROW = 2
    F_SEAL_SHRINK = 4
    F_SEAL_SEAL = 8

    def __init__(self, data=b"explicit supplied image"):
        self.data = {9: bytearray(data)}
        self.seals = {}
        self.inherit = {9: True}
        self.events = []
        self.fault = None
        self.partial = False
        self.source_mode = stat.S_IFREG
        self.next_fd = 100

    def hit(self, name, *args):
        self.events.append((name, *args))
        if self.fault:
            self.fault(name, *args)

    def memfd_create(self, name, flags):
        self.hit("create", flags)
        fd = self.next_fd
        self.next_fd += 1
        self.data[fd] = bytearray()
        self.inherit[fd] = not bool(flags & self.MFD_CLOEXEC)
        return fd

    def set_inheritable(self, fd, value):
        self.hit("private", fd)
        self.inherit[fd] = value

    def get_inheritable(self, fd):
        self.hit("get_inheritable", fd)
        return self.inherit[fd]

    def fstat(self, fd):
        self.hit("info", fd)
        return SimpleNamespace(st_mode=self.source_mode if fd == 9 else stat.S_IFREG,
                               st_size=len(self.data[fd]))

    def pread(self, fd, size, offset):
        self.hit("read", fd, size, offset)
        if self.partial:
            size = min(size, 3)
        return bytes(self.data[fd][offset:offset + size])

    def write(self, fd, data):
        self.hit("write", fd)
        assert fd != 9
        assert not self.seals.get(fd, 0) & self.F_SEAL_WRITE
        data = data[:2] if self.partial else data
        self.data[fd].extend(data)
        return len(data)

    def fcntl(self, fd, command, value=None):
        self.hit("seal" if command == self.F_ADD_SEALS else "read_seals", fd)
        if command == self.F_ADD_SEALS:
            self.seals[fd] = value
            return 0
        assert command == self.F_GET_SEALS
        return self.seals.get(fd, 0)

    def close(self, fd):
        assert fd != 9
        self.hit("close", fd)
        del self.data[fd]


@pytest.fixture
def setup(monkeypatch):
    kernel = SyntheticKernel()
    clock = [100.0]
    monkeypatch.setattr(module, "_linux_api", lambda: (kernel, kernel))
    monkeypatch.setattr(module, "_production_backing_backend", module._LinuxSeals)
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    owners = []

    def owner(**overrides):
        budgets = dict(max_images=3, max_artifact_bytes=1024,
                       max_retained_bytes=2048, lifetime_seconds=20)
        budgets.update(overrides)
        value = module.ImageBackingOwner(**budgets)
        owners.append(value)
        return value

    identity = module.SuppliedArtifactIdentity(len(kernel.data[9]),
                                              hashlib.sha256(kernel.data[9]).hexdigest())
    yield kernel, clock, owner, identity
    kernel.fault = None
    for item in owners:
        item.close()


def test_production_factory_is_unavailable_without_os_discovery(monkeypatch):
    monkeypatch.setattr(module, "_linux_api", lambda: pytest.fail("OS discovery reached"))
    owner = module.ImageBackingOwner(max_images=1, max_artifact_bytes=10,
                                    max_retained_bytes=10, lifetime_seconds=1)
    assert module._production_backing_backend() is None
    assert isinstance(owner.acquire(9, module.SuppliedArtifactIdentity(1, "0" * 64)),
                      module.ImageBackingUnavailable)
    owner.close()


@pytest.mark.parametrize("partial", [False, True])
def test_complete_private_copy_seal_readback_then_sealed_rehash(setup, partial):
    kernel, _, make_owner, identity = setup
    kernel.partial = partial
    owner = make_owner()
    reference = owner.acquire(9, identity)
    assert type(reference) is module.ImageBackingReference
    description = owner.describe(reference)
    assert description.identity == identity
    assert not description.authenticated_build and not description.observed_child_context
    assert description.state == "retained_backing_bytes_only"
    events = [event[0] for event in kernel.events]
    assert events.index("private") < events.index("write") < events.index("seal")
    first_seal = events.index("seal")
    first_backing_read = next(i for i, e in enumerate(kernel.events)
                              if e[0] == "read" and e[1] == 100)
    assert first_seal < events.index("read_seals") < first_backing_read
    assert kernel.seals[100] == 15 and not kernel.inherit[100]
    assert kernel.inherit[9] and bytes(kernel.data[9]) == bytes(kernel.data[100])
    owner.retire(reference)
    owner.retire(reference)
    assert [e for e in kernel.events if e == ("close", 100)] == [("close", 100)]
    assert isinstance(owner.describe(reference), module.ImageBackingUnavailable)


@pytest.mark.parametrize("seam", ["create", "private", "get_inheritable", "info",
                                  "read", "write", "seal", "read_seals"])
@pytest.mark.parametrize("error", [OSError, MemoryError, KeyboardInterrupt])
def test_actual_adapter_faults_close_only_owned_descriptors(setup, seam, error):
    kernel, _, make_owner, identity = setup
    owner = make_owner()

    def fail(name, *args):
        if name == seam and (name != "info" or args[0] != 9):
            raise error("injected seam")

    kernel.fault = fail
    if error is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            owner.acquire(9, identity)
    else:
        assert isinstance(owner.acquire(9, identity), module.ImageBackingUnavailable)
    assert 9 in kernel.data
    assert not owner._entries
    assert not any(fd != 9 for fd in kernel.data)


@pytest.mark.parametrize("case", ["mismatch", "early_eof", "growth", "zero_write",
                                  "seal_missing", "sealed_corruption", "inheritable"])
def test_nonpublishable_backing_is_closed(setup, monkeypatch, case):
    kernel, _, make_owner, identity = setup
    owner = make_owner()
    if case == "mismatch":
        identity = replace(identity, sha256="0" * 64)
    elif case == "early_eof":
        monkeypatch.setattr(kernel, "pread", lambda fd, size, offset: b"")
    elif case == "growth":
        def grow(name, *args):
            if name == "read" and args[0] == 9 and args[2] == identity.byte_count:
                kernel.data[9].extend(b"x")
        kernel.fault = grow
    elif case == "zero_write":
        monkeypatch.setattr(kernel, "write", lambda fd, data: 0)
    elif case == "seal_missing":
        monkeypatch.setattr(kernel, "fcntl", lambda *args: 0)
    elif case == "sealed_corruption":
        def corrupt(name, *args):
            if name == "read_seals":
                kernel.data[args[0]][0] ^= 1
        kernel.fault = corrupt
    elif case == "inheritable":
        monkeypatch.setattr(kernel, "get_inheritable", lambda fd: True)
    assert isinstance(owner.acquire(9, identity), module.ImageBackingUnavailable)
    assert not owner._entries
    assert list(kernel.data) == [9]


@pytest.mark.parametrize("mode", [stat.S_IFDIR, stat.S_IFCHR, stat.S_IFIFO, stat.S_IFSOCK])
def test_nonregular_source_refused_before_allocation(setup, mode):
    kernel, _, make_owner, identity = setup
    kernel.source_mode = mode
    assert isinstance(make_owner().acquire(9, identity), module.ImageBackingUnavailable)
    assert not any(e[0] == "create" for e in kernel.events)


@pytest.mark.parametrize("budget", [dict(max_images=1), dict(max_artifact_bytes=1),
                                    dict(max_retained_bytes=25)])
def test_budget_caps_reject_before_additional_allocation(setup, budget):
    kernel, _, make_owner, identity = setup
    owner = make_owner(**budget)
    first = owner.acquire(9, identity)
    before = sum(e[0] == "create" for e in kernel.events)
    assert isinstance(owner.acquire(9, identity), module.ImageBackingUnavailable)
    assert sum(e[0] == "create" for e in kernel.events) == before
    if "max_artifact_bytes" not in budget:
        assert type(first) is module.ImageBackingReference


@pytest.mark.parametrize("seam", ["write", "read_seals"])
def test_expiry_during_acquisition_prevents_publication(setup, seam):
    kernel, clock, make_owner, identity = setup
    owner = make_owner()

    def expire(name, *args):
        if name == seam:
            clock[0] = 121
    kernel.fault = expire
    assert isinstance(owner.acquire(9, identity), module.ImageBackingUnavailable)
    assert list(kernel.data) == [9]


def test_lifetime_foreign_reference_and_readback_revocation(setup):
    kernel, clock, make_owner, identity = setup
    first, second = make_owner(), make_owner()
    reference = first.acquire(9, identity)
    assert isinstance(second.describe(reference), module.ImageBackingUnavailable)
    kernel.seals[100] = 0
    assert isinstance(first.describe(reference), module.ImageBackingUnavailable)
    assert 100 not in kernel.data
    reference = first.acquire(9, identity)
    clock[0] = 120
    assert isinstance(first.describe(reference), module.ImageBackingUnavailable)
    assert 101 not in kernel.data
    assert type(first.acquire(9, identity)) is module.ImageBackingReference


def test_close_attempts_all_handles_preserves_cancel_and_never_retries_fd(setup):
    kernel, _, make_owner, identity = setup
    owner = make_owner()
    owner.acquire(9, identity)
    owner.acquire(9, identity)
    owner.acquire(9, identity)

    def fail(name, *args):
        if name == "close":
            if args[0] == 100:
                del kernel.data[100]  # Linux close consumes number even when reporting error.
                raise OSError("close failure")
            if args[0] == 101:
                del kernel.data[101]
                raise KeyboardInterrupt()
    kernel.fault = fail
    with pytest.raises(KeyboardInterrupt):
        owner.close()
    assert [e[1] for e in kernel.events if e[0] == "close"] == [100, 101, 102]
    kernel.fault = None
    owner.close()
    assert not owner._entries and list(kernel.data) == [9]


def test_failed_cleanup_cancels_acquisition_and_poison_blocks_more_allocation(setup):
    kernel, _, make_owner, identity = setup
    owner = make_owner()

    def fail(name, *args):
        if name == "seal":
            raise OSError("seal failure")
        if name == "close":
            del kernel.data[args[0]]
            raise KeyboardInterrupt()
    kernel.fault = fail
    with pytest.raises(KeyboardInterrupt):
        owner.acquire(9, identity)
    kernel.fault = None
    assert isinstance(owner.acquire(9, identity), module.ImageBackingUnavailable)
    assert not owner._entries


def test_owner_reentry_cannot_retire_or_allocate_during_acquisition(setup):
    kernel, _, make_owner, identity = setup
    owner = make_owner()
    seen = []

    def reenter(name, *args):
        if name == "seal":
            seen.append(owner.acquire(9, identity))
            with pytest.raises(RuntimeError):
                owner.close()
    kernel.fault = reenter
    assert type(owner.acquire(9, identity)) is module.ImageBackingReference
    assert isinstance(seen[0], module.ImageBackingUnavailable)


@pytest.mark.parametrize("value", [False, 0, -1, 1.5, float("nan"), float("inf")])
def test_invalid_byte_budget_rejected(value):
    with pytest.raises(ValueError):
        module.ImageBackingOwner(max_images=1, max_artifact_bytes=value,
                                 max_retained_bytes=1, lifetime_seconds=1)


@pytest.mark.parametrize("value", [False, 0, -1, float("nan"), float("inf")])
def test_invalid_lifetime_rejected(value):
    with pytest.raises(ValueError):
        module.ImageBackingOwner(max_images=1, max_artifact_bytes=1,
                                 max_retained_bytes=1, lifetime_seconds=value)


@pytest.mark.parametrize("data", [None, "text", b"", b"x" * 1025])
def test_invalid_copy_read_cannot_publish(setup, monkeypatch, data):
    kernel, _, make_owner, identity = setup
    monkeypatch.setattr(kernel, "pread", lambda *args: data)
    assert isinstance(make_owner().acquire(9, identity), module.ImageBackingUnavailable)
    assert list(kernel.data) == [9]


@pytest.mark.parametrize("written", [None, True, -1, 0, 1025])
def test_invalid_write_progress_cannot_publish(setup, monkeypatch, written):
    kernel, _, make_owner, identity = setup
    monkeypatch.setattr(kernel, "write", lambda *args: written)
    assert isinstance(make_owner().acquire(9, identity), module.ImageBackingUnavailable)
    assert list(kernel.data) == [9]


def test_platform_api_unavailable_refuses_before_any_allocation(setup, monkeypatch):
    kernel, _, make_owner, identity = setup
    def unsupported():
        raise OSError("unsupported")
    monkeypatch.setattr(module, "_linux_api", unsupported)
    assert isinstance(make_owner().acquire(9, identity), module.ImageBackingUnavailable)
    assert kernel.events == []


def test_expiry_after_final_seal_readback_does_not_publish(setup):
    kernel, clock, make_owner, identity = setup
    calls = []
    def expire(name, *args):
        if name == "read_seals":
            calls.append(name)
            if len(calls) == 2:
                clock[0] = 120
    kernel.fault = expire
    assert isinstance(make_owner().acquire(9, identity), module.ImageBackingUnavailable)
    assert len(calls) == 2 and list(kernel.data) == [9]


def test_cancel_during_sealed_rehash_closes_before_propagating(setup):
    kernel, _, make_owner, identity = setup
    def cancel(name, *args):
        if name == "read" and args[0] != 9:
            raise KeyboardInterrupt()
    kernel.fault = cancel
    with pytest.raises(KeyboardInterrupt):
        make_owner().acquire(9, identity)
    assert list(kernel.data) == [9]


@pytest.mark.parametrize("identity", [None, module.SuppliedArtifactIdentity(True, "0" * 64),
                                      module.SuppliedArtifactIdentity(1, "G" * 64),
                                      module.SuppliedArtifactIdentity(1, "0" * 63)])
def test_malformed_identity_refuses_before_allocation(setup, identity):
    kernel, _, make_owner, _ = setup
    assert isinstance(make_owner().acquire(9, identity), module.ImageBackingUnavailable)
    assert kernel.events == []


@pytest.mark.parametrize("error", [MemoryError, KeyboardInterrupt])
def test_publication_aftereffect_rolls_back_before_single_close(setup, error):
    kernel, _, make_owner, identity = setup
    owner = make_owner()
    class InsertThenRaise(dict):
        def __setitem__(self, key, value):
            super().__setitem__(key, value)
            raise error("publication aftereffect")
    owner._entries = InsertThenRaise()
    if error is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            owner.acquire(9, identity)
    else:
        assert isinstance(owner.acquire(9, identity), module.ImageBackingUnavailable)
    assert not owner._entries
    assert list(kernel.data) == [9]
    owner.close()
    assert [e for e in kernel.events if e[0] == "close"] == [("close", 100)]


def test_private_reader_is_disabled_without_explicit_budget(setup):
    kernel, _, make_owner, identity = setup
    owner = make_owner()
    reference = owner.acquire(9, identity)
    before = len(kernel.events)
    assert isinstance(owner._read(reference, 0, 1), module.ImageBackingUnavailable)
    assert len(kernel.events) == before
    assert owner.describe(reference).identity == identity


@pytest.mark.parametrize("partial", [False, True])
def test_private_reader_returns_exact_sealed_slice_with_finite_debit(setup, partial):
    kernel, _, make_owner, identity = setup
    owner = make_owner(max_read_bytes=9)
    reference = owner.acquire(9, identity)
    kernel.partial = partial
    assert owner._read(reference, 2, 6) == bytes(kernel.data[9][2:8])
    assert owner._read_bytes_remaining == 3
    before = len(kernel.events)
    assert isinstance(owner._read(reference, 0, 4), module.ImageBackingUnavailable)
    assert len(kernel.events) == before
    assert owner._read(reference, 0, 3) == bytes(kernel.data[9][:3])
    assert owner._read_bytes_remaining == 0
    assert owner.describe(reference).state == "retained_backing_bytes_only"


@pytest.mark.parametrize("offset,size", [(-1, 1), (True, 1), (0, True), (0, 0),
                                        (0, -1), (0, 65537), (23, 1), (22, 2)])
def test_private_reader_invalid_range_does_not_reach_backend_or_spend(setup, offset, size):
    kernel, _, make_owner, identity = setup
    owner = make_owner(max_read_bytes=10)
    reference = owner.acquire(9, identity)
    before = len(kernel.events)
    assert isinstance(owner._read(reference, offset, size), module.ImageBackingUnavailable)
    assert len(kernel.events) == before and owner._read_bytes_remaining == 10
    assert owner.describe(reference).identity == identity


@pytest.mark.parametrize("error", [OSError, MemoryError, KeyboardInterrupt])
@pytest.mark.parametrize("seam", ["read", "read_seals"])
def test_private_reader_failure_spends_budget_revokes_and_closes_once(setup, error, seam):
    kernel, _, make_owner, identity = setup
    owner = make_owner(max_read_bytes=20)
    reference = owner.acquire(9, identity)
    def fail(name, *args):
        if name == seam:
            raise error("private reader failure")
    kernel.fault = fail
    if error is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            owner._read(reference, 0, 10)
    else:
        assert isinstance(owner._read(reference, 0, 10), module.ImageBackingUnavailable)
    assert owner._read_bytes_remaining == 10 and not owner._entries
    kernel.fault = None
    owner.close()
    assert list(kernel.data) == [9]
    assert [e for e in kernel.events if e[0] == "close"] == [("close", 100)]


@pytest.mark.parametrize("data", [None, "foreign", b"", b"longer than requested"])
def test_private_reader_invalid_bytes_revoke_without_returning_partial_content(setup, monkeypatch, data):
    kernel, _, make_owner, identity = setup
    owner = make_owner(max_read_bytes=10)
    reference = owner.acquire(9, identity)
    monkeypatch.setattr(kernel, "pread", lambda *args: data)
    assert isinstance(owner._read(reference, 0, 5), module.ImageBackingUnavailable)
    assert owner._read_bytes_remaining == 5 and not owner._entries
    assert list(kernel.data) == [9]


def test_private_reader_expiry_after_readback_discards_bytes(setup):
    kernel, clock, make_owner, identity = setup
    owner = make_owner(max_read_bytes=10)
    reference = owner.acquire(9, identity)
    seen = []
    def expire(name, *args):
        if name == "read_seals":
            seen.append(name)
            if len(seen) == 2:
                clock[0] = 120
    kernel.fault = expire
    assert isinstance(owner._read(reference, 0, 5), module.ImageBackingUnavailable)
    assert len(seen) == 2 and owner._read_bytes_remaining == 5
    assert not owner._entries and list(kernel.data) == [9]


def test_private_reader_does_not_accept_foreign_or_retired_reference(setup):
    kernel, _, make_owner, identity = setup
    first, second = make_owner(max_read_bytes=10), make_owner(max_read_bytes=10)
    reference = first.acquire(9, identity)
    before = len(kernel.events)
    assert isinstance(second._read(reference, 0, 1), module.ImageBackingUnavailable)
    assert len(kernel.events) == before and second._read_bytes_remaining == 10
    first.retire(reference)
    assert isinstance(first._read(reference, 0, 1), module.ImageBackingUnavailable)
    assert first._read_bytes_remaining == 10


def test_private_reader_reentry_cannot_spend_more_or_retire_handle(setup):
    kernel, _, make_owner, identity = setup
    owner = make_owner(max_read_bytes=10)
    reference = owner.acquire(9, identity)
    def reenter(name, *args):
        if name == "read":
            assert isinstance(owner._read(reference, 0, 1), module.ImageBackingUnavailable)
            with pytest.raises(RuntimeError):
                owner.retire(reference)
    kernel.fault = reenter
    assert owner._read(reference, 0, 5) == bytes(kernel.data[9][:5])
    assert owner._read_bytes_remaining == 5


def test_private_reader_cleanup_cancellation_overrides_ordinary_read_error(setup):
    kernel, _, make_owner, identity = setup
    owner = make_owner(max_read_bytes=10)
    reference = owner.acquire(9, identity)
    def fail(name, *args):
        if name == "read":
            raise OSError("read failure")
        if name == "close":
            del kernel.data[args[0]]
            raise KeyboardInterrupt()
    kernel.fault = fail
    with pytest.raises(KeyboardInterrupt):
        owner._read(reference, 0, 5)
    assert owner._poisoned and not owner._entries and owner._read_bytes_remaining == 5
    kernel.fault = None
    owner.close()
    assert list(kernel.data) == [9]


@pytest.mark.parametrize("budget", [False, -1, 1.5, float("nan"), float("inf")])
def test_private_reader_invalid_budget_is_rejected(budget):
    with pytest.raises(ValueError):
        module.ImageBackingOwner(max_images=1, max_artifact_bytes=1,
                                 max_retained_bytes=1, lifetime_seconds=1, max_read_bytes=budget)


def test_private_reader_refuses_hash_equality_alias_without_spend_or_retirement(setup):
    kernel, _, make_owner, identity = setup
    owner = make_owner(max_read_bytes=10)
    reference = owner.acquire(9, identity)
    class ForgedReference:
        def __hash__(self):
            return hash(reference)
        def __eq__(self, other):
            return True
    forged = ForgedReference()
    before = len(kernel.events)
    assert isinstance(owner._read(forged, 0, 5), module.ImageBackingUnavailable)
    assert isinstance(owner.describe(forged), module.ImageBackingUnavailable)
    owner.retire(forged)
    assert len(kernel.events) == before and owner._read_bytes_remaining == 10
    assert reference in owner._entries
    assert owner._read(reference, 0, 5) == bytes(kernel.data[9][:5])
