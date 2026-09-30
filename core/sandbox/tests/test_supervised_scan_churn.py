"""Seam-level pins for the group scan's mount-churn verdict —
hermetic on any Linux host (no mount capability needed; the kernel
latch contract itself is pinned live in
test_supervised_scan_churn_live.py).

The two-sided race these pin: a mount attached after the pre-scan
declaration read and detached before the post-scan one is applied to
the scan yet appears in neither read. The scan therefore latches a
mount-event signal at its fd OPEN and takes exactly ONE verdict poll
after the last evidence read; a pending signal is occlusion. The poll
CONSUMES the signal, which makes any extra poll-type operation on the
fd a silent-verify vector of its own — the single-consumer contract
gets its own pins here (call count, position, and the fresh-fd-per-
attempt retry shape).

Fleet-kill doctrine: no test here signals anything; all scans run
against this process's own group with the /proc listing pinned to the
test's own pid.
"""

import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="supervised trees are Linux-only (fork/pidfd/procfs)",
)

if sys.platform == "linux":
    from core.sandbox import supervised as sup


def _pin_listing_to_self(monkeypatch):
    """Pin the /proc listing to this process only, so no per-entry
    condition (foreign EACCES entries and the like) can set occlusion
    before the signals under test do."""
    own = str(os.getpid())
    real_listdir = os.listdir
    monkeypatch.setattr(
        os, "listdir",
        lambda path: ([own] if str(path) == "/proc"
                      else real_listdir(path)))


def _clean_detector(monkeypatch, log=None):
    """Declaration seam reports clean at BOTH reads (the exact
    both-ends-missed condition of the two-sided race)."""
    def detector(*_table):
        if log is not None:
            log.append("declare")
        return None

    monkeypatch.setattr(sup, "_proc_pid_view_filtered", detector)


def _counting_latch(monkeypatch):
    """Record every latch open and the fd it returned."""
    real = sup._mounts_latch_open
    opened: list[int] = []

    def counting():
        fd = real()
        opened.append(fd)
        return fd

    monkeypatch.setattr(sup, "_mounts_latch_open", counting)
    return opened


class TestChurnVerdict:
    """The verdict poll's occlusion contract: churn is occlusion,
    signals are only ever ADDED, absence of the mechanism is absence
    of churn."""

    def test_midscan_churn_is_occlusion(self, monkeypatch):
        # The vector class the latch closes: both declaration reads
        # clean, yet the churn seam reports a pending mount event —
        # an attach-and-detach inside the scan window. The view MUST
        # come back occluded, naming the mid-scan table change; a
        # mutant that drops the verdict poll (or pre-fix code, which
        # never consults the seam) returns a clean view here and
        # feeds the permanent _group_verified latch a false verify.
        _pin_listing_to_self(monkeypatch)
        _clean_detector(monkeypatch)
        monkeypatch.setattr(sup, "_mounts_churn_pending",
                            lambda fd: True)
        view = sup._group_sighted_members(os.getpgrp())
        assert view is not None
        assert view.occlusion is not None, (
            "mid-scan mount churn produced a CLEAN view — the "
            "two-sided attach-and-detach race is undetected")
        assert "changed during the scan" in view.occlusion

    def test_verdict_poll_exactly_once_after_post_read(self, monkeypatch):
        # Single-consumer contract: the poll consumes the pending
        # signal and re-latches, so each signal is delivered exactly
        # once — a stray select(), a second call into the churn
        # helper, or an EPOLL_CTL_ADD registration before the verdict
        # poll would EAT the signal and turn real churn into a silent
        # clean scan (a silent-verify vector introduced by the
        # mechanism itself). Pin the real code's call shape: per scan
        # attempt, both declaration reads first, then EXACTLY ONE
        # verdict poll, last.
        events: list[str] = []
        _pin_listing_to_self(monkeypatch)
        _clean_detector(monkeypatch, log=events)

        def verdict(fd):
            events.append("verdict")
            return True

        monkeypatch.setattr(sup, "_mounts_churn_pending", verdict)
        view = sup._group_sighted_members(os.getpgrp())
        assert view is not None and view.occlusion is not None
        # Sustained churn exhausts the bounded retry: three attempts,
        # each declare(pre), declare(post), then one verdict poll.
        assert events == ["declare", "declare", "verdict"] * 3, (
            f"verdict poll count/position violates the "
            f"single-consumer contract: {events}")

    def test_quiet_churn_seam_leaves_view_unchanged(self, monkeypatch):
        # Degradation pin, direction (a): no pending signal (the
        # no-mounts-poll-hook kernel, or simply no churn) must add
        # nothing — one scan attempt, both declaration reads, a clean
        # view with this process sighted. Exactly the pre-latch
        # behaviour.
        events: list[str] = []
        _pin_listing_to_self(monkeypatch)
        _clean_detector(monkeypatch, log=events)
        monkeypatch.setattr(sup, "_mounts_churn_pending",
                            lambda fd: False)
        view = sup._group_sighted_members(os.getpgrp())
        assert view is not None
        assert view.occlusion is None
        assert [m.pid for m in view.members] == [os.getpid()]
        assert events == ["declare", "declare"]

    def test_churn_poll_oserror_is_occlusion(self, monkeypatch):
        # Degradation pin, direction (b): the verdict poll erroring is
        # occlusion (fail-closed — the fd is process-private, so no
        # external party can provoke this), and it is NOT the
        # retriable churn shape: exactly one scan attempt.
        events: list[str] = []
        _pin_listing_to_self(monkeypatch)
        _clean_detector(monkeypatch, log=events)

        def broken(fd):
            raise OSError(5, "poll failed")

        monkeypatch.setattr(sup, "_mounts_churn_pending", broken)
        view = sup._group_sighted_members(os.getpgrp())
        assert view is not None
        assert view.occlusion is not None and "verdict poll" in view.occlusion
        assert events == ["declare", "declare"], (
            "a failed verdict poll must fail closed in ONE attempt, "
            "not be retried as churn")


class TestChurnRetryBound:
    """Churn-only occlusion is retried on a FRESH fd (a re-latch is a
    re-open — the consumed signal died with the closed fd), bounded to
    _SCAN_CHURN_RETRIES scans total, then returned occluded."""

    def test_sustained_churn_bounded_at_three_scans(self, monkeypatch):
        _pin_listing_to_self(monkeypatch)
        _clean_detector(monkeypatch)
        opened = _counting_latch(monkeypatch)
        polled: list[int] = []

        def verdict(fd):
            polled.append(fd)
            return True

        monkeypatch.setattr(sup, "_mounts_churn_pending", verdict)
        view = sup._group_sighted_members(os.getpgrp())
        assert view is not None
        assert view.occlusion is not None
        assert "changed during the scan" in view.occlusion
        # The bound is the livelock guard: exactly three scans, no
        # more (sustained churn — e.g. an unprivileged co-resident
        # looping a setuid mount helper — must terminate in the
        # callers' fail-closed refusal plumbing, not spin here).
        assert len(polled) == sup._SCAN_CHURN_RETRIES == 3
        # A re-latch is a re-open: every attempt polled the fd it
        # opened, one fresh fd per attempt.
        assert polled == opened
        assert len(opened) == 3

    def test_transient_churn_recovered_by_relatch_retry(self, monkeypatch):
        # Churn on attempt 1 only: attempt 2 re-latches and its CLEAN
        # view is returned — transient unrelated mount events (pod/
        # exec churn bursts) must not convert one-shot call sites into
        # spurious occlusion refusals.
        _pin_listing_to_self(monkeypatch)
        _clean_detector(monkeypatch)
        opened = _counting_latch(monkeypatch)
        answers = iter([True, False, False])
        monkeypatch.setattr(sup, "_mounts_churn_pending",
                            lambda fd: next(answers))
        view = sup._group_sighted_members(os.getpgrp())
        assert view is not None
        assert view.occlusion is None
        assert [m.pid for m in view.members] == [os.getpid()]
        assert len(opened) == 2, (
            "the retry must re-latch on a fresh fd — the consumed "
            "signal died with the first attempt's closed fd")

    def test_retry_bound_within_sane_ceiling(self) -> None:
        # Named ceiling pin on the constant ITSELF: the behavioural
        # `== 3` pin above can only run after _group_sighted_members
        # returns, so an absurd bound (say 10_000_000) surfaces only
        # as a suite hang under sustained churn — precisely the
        # livelock the bound exists to prevent. Pin the value into a
        # small sane range so bound drift fails by name instead. Not
        # lower than 2: one scan is no retry at all, and transient
        # unrelated mount events would turn the one-shot call sites
        # into spurious occlusion refusals. Not higher than 10: each
        # attempt costs a full /proc scan (~25-45 ms at ~1000
        # entries) and the loop-shaped callers rescan every ~20 ms
        # inside 5 s budgets — a larger bound only lets sustained
        # churn hold every caller longer without changing the verdict
        # class.
        assert 2 <= sup._SCAN_CHURN_RETRIES <= 10, (
            f"_SCAN_CHURN_RETRIES={sup._SCAN_CHURN_RETRIES} is outside "
            f"the sane retry ceiling — an absurd bound livelocks the "
            f"scan's callers under sustained churn")


class TestMountsFdMagic:
    """The fstatfs superblock-magic rider: a non-procfs object bind-
    mounted at /proc/self/mounts serves an attacker-authored table, so
    the latched fd must provably be procfs (or the check must
    truthfully degrade to no signal where fstatfs is unavailable)."""

    def test_fstatfs_magic_discriminates_procfs(self):
        mounts_fd = os.open("/proc/self/mounts", os.O_RDONLY)
        try:
            if sup._fstatfs_f_type(mounts_fd) is None:
                pytest.skip("fstatfs unavailable on this host — the "
                            "magic check degrades to no signal by "
                            "design")
            assert sup._mounts_fd_not_procfs(mounts_fd) is None
        finally:
            os.close(mounts_fd)
        with open(__file__, "rb") as regular:
            verdict = sup._mounts_fd_not_procfs(regular.fileno())
        assert verdict is not None and "not served by procfs" in verdict


class TestUnreadableMountsArms:
    """The scan's three unreadable-mounts arms fail CLOSED: a failed
    latch open, a pre-read OSError, and a post-read OSError each map to
    the unreadable-table occlusion. None is the retriable churn shape —
    a rescan cannot honestly clear a table it cannot read — and a scan
    that cannot read its own mount declarations must never take (or
    trust) a churn verdict."""

    @staticmethod
    def _counting_poll(monkeypatch: pytest.MonkeyPatch) -> list[int]:
        """Quiet verdict-poll seam that records every call — the pins
        below assert it never runs once the table is unreadable."""
        polled: list[int] = []

        def verdict(fd: int) -> bool:
            polled.append(fd)
            return False

        monkeypatch.setattr(sup, "_mounts_churn_pending", verdict)
        return polled

    def test_latch_open_failure_is_occlusion_without_poll(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        # An EMFILE-class failure of the latch open: no latch fd means
        # no declaration reads, no magic check, and no churn verdict —
        # every one of them is guarded by the fd — so the ONLY honest
        # result is the unreadable-table occlusion, in a single
        # attempt. A mutant mapping the failed open to a clean
        # declaration (filtered = None) silently disables EVERY mount
        # defence the scan has and returns clean views; fd exhaustion
        # in the supervising process must degrade to refusal, never to
        # trust.
        _pin_listing_to_self(monkeypatch)
        declares: list[str] = []
        _clean_detector(monkeypatch, log=declares)
        polled = self._counting_poll(monkeypatch)
        opens: list[None] = []

        def failing_open() -> None:
            opens.append(None)
            return None

        monkeypatch.setattr(sup, "_mounts_latch_open", failing_open)
        view = sup._group_sighted_members(os.getpgrp())
        assert view is not None
        assert view.occlusion is not None, (
            "a failed latch open produced a CLEAN view — fd "
            "exhaustion silently disables the mount defences")
        assert "unreadable" in view.occlusion
        assert len(opens) == 1, (
            "an unreadable mounts table is not the retriable churn "
            "shape — exactly one attempt")
        assert declares == [] and polled == [], (
            "no declaration read or verdict poll may run without the "
            "latch fd")

    def test_pre_read_oserror_is_occlusion_single_attempt(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The pre-scan declaration read failing on the latched fd is
        # the unreadable-table occlusion in ONE attempt: no
        # declaration rendered, no post-read, no verdict poll, no
        # retry. A fail-open mutant of this arm claims a clean
        # declaration off a table it never saw.
        _pin_listing_to_self(monkeypatch)
        declares: list[str] = []
        _clean_detector(monkeypatch, log=declares)
        polled = self._counting_poll(monkeypatch)
        opened = _counting_latch(monkeypatch)
        reads: list[int] = []

        def broken_read(fd: int) -> bytes:
            reads.append(fd)
            raise OSError(5, "read failed")

        monkeypatch.setattr(sup, "_mounts_table_read", broken_read)
        view = sup._group_sighted_members(os.getpgrp())
        assert view is not None
        assert view.occlusion is not None, (
            "a failed pre-scan table read produced a CLEAN view")
        assert "unreadable" in view.occlusion
        assert len(opened) == 1 and len(reads) == 1, (
            "a failed table read must fail closed in ONE attempt "
            "with no further reads")
        assert declares == [] and polled == []

    def test_post_read_oserror_is_occlusion_single_attempt(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The post-scan declaration re-read failing: the pre-read's
        # clean declaration is already stale evidence — a mount can
        # have landed during the scan — so the arm must occlude, skip
        # the verdict poll (a clean poll answer cannot rehabilitate an
        # unreadable table), and not retry.
        _pin_listing_to_self(monkeypatch)
        declares: list[str] = []
        _clean_detector(monkeypatch, log=declares)
        polled = self._counting_poll(monkeypatch)
        opened = _counting_latch(monkeypatch)
        reads: list[int] = []

        def read_then_break(fd: int) -> bytes:
            reads.append(fd)
            if len(reads) > 1:
                raise OSError(5, "read failed")
            return b""

        monkeypatch.setattr(sup, "_mounts_table_read", read_then_break)
        view = sup._group_sighted_members(os.getpgrp())
        assert view is not None
        assert view.occlusion is not None, (
            "a failed post-scan table read produced a CLEAN view")
        assert "unreadable" in view.occlusion
        assert len(opened) == 1 and len(reads) == 2, (
            "a failed post-read must fail closed in ONE attempt")
        assert declares == ["declare"] and polled == []


class TestTaskReadsInsideLatchedWindow:
    """The per-member death proofs (``_member_provably_dead``'s
    /proc/<pid>/task reads) are evidence reads INSIDE the latched
    window: per scan attempt they run after the membership walk and
    BEFORE the post-scan declaration re-read and the single verdict
    poll, and the verdict travels on the returned member
    (``provably_dead``). A task read taken after the poll — or after
    the scan returned, as the corroboration paths once did — sits
    outside any latched window, where an overmount forging an all-Z
    (or absent) task tree is polled by no one: the false-verify gap
    the live probe in test_supervised_scan_churn_live.py demonstrates
    end to end."""

    def test_task_reads_precede_single_verdict_poll_every_attempt(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Call-shape pin under sustained churn: every attempt is
        # pre-declare, task read, post-declare, then EXACTLY ONE
        # verdict poll, last — the poll must postdate the last
        # evidence read of ANY kind, task reads included, and a retry
        # attempt must re-read the task trees afresh (evidence never
        # crosses attempts).
        events: list[str] = []
        _pin_listing_to_self(monkeypatch)
        _clean_detector(monkeypatch, log=events)

        def task_read(pid: int, state: bytes) -> bool:
            assert pid == os.getpid()
            events.append("task")
            return False

        def verdict(fd: int) -> bool:
            events.append("verdict")
            return True

        monkeypatch.setattr(sup, "_member_provably_dead", task_read)
        monkeypatch.setattr(sup, "_mounts_churn_pending", verdict)
        view = sup._group_sighted_members(os.getpgrp())
        assert view is not None and view.occlusion is not None
        assert events == ["declare", "task", "declare", "verdict"] * 3, (
            f"task reads are not inside the latched window (after the "
            f"walk, before the post-read and the single last verdict "
            f"poll) on every attempt: {events}")

    def test_scan_bakes_in_window_death_verdict_onto_members(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The in-window verdict must TRAVEL on the member: a consumer
        # that re-derives it post-scan re-opens the gap, so the view
        # itself carries provably_dead for the verify paths to consume
        # without touching /proc again.
        _pin_listing_to_self(monkeypatch)
        _clean_detector(monkeypatch)
        monkeypatch.setattr(sup, "_mounts_churn_pending",
                            lambda fd: False)
        monkeypatch.setattr(sup, "_member_provably_dead",
                            lambda pid, state: True)
        view = sup._group_sighted_members(os.getpgrp())
        assert view is not None and view.occlusion is None
        assert [m.pid for m in view.members] == [os.getpid()]
        assert view.members[0].provably_dead is True, (
            "the scan's in-window death verdict does not travel on "
            "the sighted member")
