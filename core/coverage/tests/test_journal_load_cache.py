"""Process-local incremental load cache for the sharded journal reader.

The loader chokepoint (``load_entries_checked``) caches each run
dir's shard-set parse: an unchanged set serves from memory, a grown
active shard extends over just the appended bytes, and a rolled set
seals the old active shard and parses only the new files. The
invariant under test: for any in-budget byte sequence, a
cached/extended load is indistinguishable from a cold parse of the
same bytes — and every guard (shard-set shape, sealed pins, active
identity/size/mtime/tail fingerprint, budget/backend config, racy
window, orphan anomaly) fails toward a full re-parse, never toward a
stale serve.
"""

from __future__ import annotations

import json
import os
import random
import threading
import time
from pathlib import Path
from typing import IO, Any

import pytest

import core.source as core_source
from core.coverage import journal as journal_mod
from core.coverage.journal import (
    JOURNAL_FILENAME,
    JournalLoad,
    ReviewJournalEntry,
    append_entry,
    journal_shard_paths,
    load_entries,
    load_entries_checked,
    now_iso,
    require_complete_entries,
)


@pytest.fixture(autouse=True)
def _clean_cache():
    """Each test starts and ends with an empty load cache."""
    with journal_mod._load_cache_lock:
        journal_mod._load_cache.clear()
    yield
    with journal_mod._load_cache_lock:
        journal_mod._load_cache.clear()


# ── helpers ──────────────────────────────────────────────────────────

def _row(i: int, *, verdict: str = "clean", pad: int = 0,
         reused: bool = False, dup_of: int | None = None) -> bytes:
    """One journal line; ``dup_of`` builds a prunable re-emission
    duplicate (same identity as row ``dup_of``)."""
    ident = dup_of if dup_of is not None else i
    d: dict[str, Any] = {
        "ts": f"2026-01-01T00:00:{i % 60:02d}.{i:06d}Z",
        "run_id": "run-x",
        "file": f"src/f{ident}.c",
        "function": f"fn{ident}",
        "verdict": verdict,
        "source_hash": f"hash{ident}",
        "schema_version": 1,
    }
    if reused or dup_of is not None:
        d["reused"] = True
    if pad:
        d["body"] = "x" * pad
    return json.dumps(d).encode() + b"\n"


def _age(path: Path, seconds: int = 60) -> None:
    """Back-date one file's mtime past the racy window."""
    st = os.stat(path)
    ns = st.st_mtime_ns - seconds * 1_000_000_000
    os.utime(path, ns=(ns, ns))


def _age_all(out_dir: Path, seconds: int = 60) -> None:
    """Back-date every shard so identity-serves and sealed pins are
    eligible (a just-written file is deliberately racy)."""
    for shard in journal_shard_paths(out_dir):
        if shard.is_file():
            _age(shard, seconds)


def _cold_dir(tmp_path: Path, src_dir: Path, tag: str) -> JournalLoad:
    """Reference cold parse: the same shard-set bytes (including any
    planted orphans) at a NEVER-CACHED run dir."""
    ref = tmp_path / f"cold-ref-{tag}"
    ref.mkdir()
    for f in sorted(Path(src_dir).glob("review-journal*")):
        if f.is_file():
            (ref / f.name).write_bytes(f.read_bytes())
    with journal_mod._load_cache_lock:
        journal_mod._load_cache.pop(os.path.realpath(ref), None)
    result = load_entries_checked(ref)
    # Drop the reference's own record so repeated references cannot
    # LRU-evict the record under test.
    with journal_mod._load_cache_lock:
        journal_mod._load_cache.pop(os.path.realpath(ref), None)
    return result


class _CountingFile:
    """Delegating file wrapper that counts read traffic."""

    def __init__(self, fh: IO[bytes], counter: dict[str, int]) -> None:
        self._fh = fh
        self._counter = counter

    def readline(self, limit: int = -1) -> bytes:
        data = self._fh.readline(limit)
        self._counter["readline_calls"] += 1
        self._counter["bytes"] += len(data)
        return data

    def read(self, n: int = -1) -> bytes:
        data = self._fh.read(n)
        self._counter["read_calls"] += 1
        self._counter["bytes"] += len(data)
        return data

    def __enter__(self) -> "_CountingFile":
        self._fh.__enter__()
        return self

    def __exit__(self, *exc: object) -> Any:
        return self._fh.__exit__(*exc)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._fh, name)


@pytest.fixture()
def read_counter(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Counts bytes/calls through every journal ``open_regular``
    stream (the loader resolves the symbol per call)."""
    counter = {"opens": 0, "readline_calls": 0, "read_calls": 0,
               "bytes": 0}
    real = core_source.open_regular

    def wrapper(path: str | Path, mode: str, **kwargs: Any):
        fh = real(path, mode, **kwargs)
        counter["opens"] += 1
        if fh is None or "b" not in mode:
            return fh
        return _CountingFile(fh, counter)

    monkeypatch.setattr(core_source, "open_regular", wrapper)
    return counter


def _reset(counter: dict[str, int]) -> None:
    for k in counter:
        counter[k] = 0


def _entry(i: int, verdict: str = "clean") -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(), run_id="run-x", file=f"src/f{i}.c",
        function=f"fn{i}", verdict=verdict, source_hash=f"hash{i}",
    )


def _journal_size_total(out_dir: Path) -> int:
    return sum(
        shard.stat().st_size
        for shard in journal_shard_paths(out_dir) if shard.is_file()
    )


# ── cold/incremental equivalence (the load-bearing property) ────────

class TestColdIncrementalEquivalence:
    def _shrink_budgets(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Small retained budgets exercise the prune + incomplete
        # paths, and a small roll threshold makes batches cross shard
        # rolls; the read multiplier stays large so the PER-CALL read
        # budget (fresh per consume call by documented semantics)
        # never binds — read-budget exhaustion is the one documented
        # divergence between an extension chain and a cold parse.
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", 4096)
        monkeypatch.setattr(journal_mod, "_MAX_RETAINED_ENTRIES", 40)
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_LINE_BYTES", 512)
        monkeypatch.setattr(journal_mod, "_READ_BUDGET_MULTIPLIER", 1000)
        monkeypatch.setattr(
            journal_mod, "_JOURNAL_SHARD_ROLL_BYTES", 900)

    def test_randomized_append_sequences_across_rolls(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self._shrink_budgets(monkeypatch)
        # Spy on the streaming loop so the test can PROVE it exercised
        # real extensions (consume starting past byte 0), not just a
        # chain of cold reloads that would pass trivially.
        #
        # Coverage honesty: because every batch is appended within
        # the racy window and many batches roll, this property leans
        # on the extension arms and cold parity; its coverage of
        # serving/extending COMPLETE multi-shard cached records is
        # thinner than the deterministic tests' — the sealed-shard
        # reuse guard's mutants are killed specifically by
        # test_roll_extension_never_reparses_sealed_shards and
        # test_sealed_shard_tamper_forces_cold_reload, not here.
        consume_positions: list[int] = []
        orig_consume = journal_mod._consume_shard_stream

        def spy(fh: Any, path: Path, state: Any) -> None:
            consume_positions.append(fh.tell())
            orig_consume(fh, path, state)

        monkeypatch.setattr(journal_mod, "_consume_shard_stream", spy)

        rolled = 0
        for seed in (1, 7, 23):
            rng = random.Random(seed)
            run = tmp_path / f"run-{seed}"
            run.mkdir()
            carry = b""    # row fragment straddling into the next batch
            for batch in range(6):
                chunks: list[bytes] = [carry]
                carry = b""
                for _ in range(rng.randint(1, 12)):
                    kind = rng.random()
                    i = rng.randint(0, 10_000)
                    if kind < 0.40:
                        chunks.append(_row(i, pad=rng.randint(0, 200)))
                    elif kind < 0.70:
                        # Duplicate re-emission rows for the prune
                        # path: a handful of shared identities.
                        chunks.append(_row(i, dup_of=rng.randint(0, 3)))
                    elif kind < 0.80:
                        chunks.append(b"not json at all\n")
                    elif kind < 0.90:
                        chunks.append(b'["valid", "json", "not dict"]\n')
                    else:
                        # Over the 512-byte per-line bound.
                        chunks.append(
                            b'{"pad": "' + b"A" * 600 + b'"}\n')
                delta = b"".join(chunks)
                # Occasionally SPLIT the trailing row across batches:
                # this batch then ends mid-line (unterminated tail —
                # the non-extensible arm) and the next append
                # completes the straddled line. A generator that only
                # emits newline-terminated lines never exercises the
                # at_line_boundary guard.
                if delta and batch < 5 and rng.random() < 0.35:
                    cut = len(delta) - rng.randint(
                        1, min(20, len(delta)))
                    carry = delta[cut:]
                    delta = delta[:cut]
                # Append through the roll rule, one chunk at a time,
                # like the real appender: chunks land in the active
                # shard and roll to the next number past the
                # threshold.
                pos = 0
                while pos < len(delta):
                    nl = delta.find(b"\n", pos)
                    piece = (delta[pos:] if nl < 0
                             else delta[pos:nl + 1])
                    pos += len(piece)
                    target = journal_mod._append_shard_path(run)
                    with target.open("ab") as f:
                        f.write(piece)
                shards_after = len(journal_shard_paths(run))
                rolled = max(rolled, shards_after)
                incremental = load_entries_checked(run)
                cold = _cold_dir(tmp_path, run, f"{seed}-{batch}")
                assert incremental == cold, (
                    f"seed={seed} batch={batch}: incremental load "
                    "diverged from a cold parse of the same bytes"
                )
        assert any(pos > 0 for pos in consume_positions), (
            "no load ever extended a cached parse — the equivalence "
            "property was tested only against cold reloads"
        )
        assert rolled > 1, (
            "no batch ever rolled the journal — the property never "
            "crossed a shard boundary"
        )


# ── cache hit / extension mechanics ──────────────────────────────────

class TestCacheHit:
    def test_unchanged_file_served_without_reparsing(
        self, tmp_path: Path, read_counter: dict[str, int],
    ) -> None:
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(5)))
        _age(journal)
        first = load_entries_checked(tmp_path)
        assert first.complete and len(first.entries) == 5
        _reset(read_counter)
        second = load_entries_checked(tmp_path)
        assert second == first
        assert read_counter["readline_calls"] == 0, (
            "unchanged file was re-parsed line by line"
        )
        # Only the O(1) tail-fingerprint probe touches the bytes.
        assert read_counter["bytes"] <= journal_mod._TAIL_FINGERPRINT_BYTES

    def test_fresh_write_is_racy_and_reparses_once(
        self, tmp_path: Path, read_counter: dict[str, int],
    ) -> None:
        # Direction test for _MTIME_RACE_WINDOW_NS: a file whose
        # mtime is "now" must NOT be identity-served (a same-size
        # rewrite inside one clock tick would be invisible) — the
        # next load re-parses and re-stores, clearing the racy mark.
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(3)))
        size = journal.stat().st_size
        load_entries_checked(tmp_path)
        _reset(read_counter)
        load_entries_checked(tmp_path)
        assert read_counter["bytes"] >= size, (
            "a just-written (racy-mtime) file was identity-served"
        )

    def test_extension_parses_only_the_delta(
        self, tmp_path: Path, read_counter: dict[str, int],
    ) -> None:
        journal = tmp_path / JOURNAL_FILENAME
        base = b"".join(_row(i, pad=100) for i in range(200))
        journal.write_bytes(base)
        _age(journal)
        load_entries_checked(tmp_path)
        delta = b"".join(_row(200 + i) for i in range(2))
        with journal.open("ab") as f:
            f.write(delta)
        _reset(read_counter)
        result = load_entries_checked(tmp_path)
        assert [e.function for e in result.entries] == [
            f"fn{i}" for i in range(202)
        ]
        # Delta lines + fingerprint probes (verify + re-pin) + the
        # EOF readline; far below the base prefix.
        bound = len(delta) + 3 * journal_mod._TAIL_FINGERPRINT_BYTES
        assert read_counter["bytes"] <= bound, (
            f"extension read {read_counter['bytes']} bytes for a "
            f"{len(delta)}-byte delta"
        )
        assert result == _cold_dir(tmp_path, tmp_path, "ext")

    def test_roll_extension_never_reparses_sealed_shards(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        read_counter: dict[str, int],
    ) -> None:
        # New shards appearing extend the cached parse: the sealed
        # shards' cached rows are reused (their pins verified with
        # zero content reads), the old active shard is delta-parsed
        # to its EOF and sealed, and only the NEW files are parsed
        # from byte 0.
        monkeypatch.setattr(
            journal_mod, "_JOURNAL_SHARD_ROLL_BYTES", 600)
        for i in range(12):
            append_entry(tmp_path, _entry(i))
        assert len(journal_shard_paths(tmp_path)) > 1
        _age_all(tmp_path)
        first = load_entries_checked(tmp_path)
        assert first.complete and len(first.entries) == 12
        size_before = _journal_size_total(tmp_path)
        for i in range(12, 20):     # rolls at least once more
            append_entry(tmp_path, _entry(i))
        shards_now = journal_shard_paths(tmp_path)
        assert len(shards_now) > 2, "appends never rolled a new shard"
        delta = _journal_size_total(tmp_path) - size_before
        _reset(read_counter)
        result = load_entries_checked(tmp_path)
        assert [e.function for e in result.entries] == [
            f"fn{i}" for i in range(20)
        ]
        # Sealed pins cost an open+fstat each but no content reads;
        # the parse traffic is the delta plus per-shard fingerprint
        # probes.
        bound = delta + (len(shards_now) + 3) * (
            journal_mod._TAIL_FINGERPRINT_BYTES)
        assert read_counter["bytes"] <= bound, (
            f"roll extension read {read_counter['bytes']} bytes for "
            f"a {delta}-byte delta — sealed shards were re-parsed"
        )
        assert result == _cold_dir(tmp_path, tmp_path, "roll")


class TestInvalidationGuards:
    def test_inode_swap_forces_full_reload(self, tmp_path: Path) -> None:
        # Pins the (dev, ino) identity guard specifically: the
        # replacement is crafted so every OTHER guard passes — the
        # swapped-in file is LARGER than the cached offset, keeps the
        # identical boundary row (tail fingerprint matches), and only
        # differs in a same-length row below the fingerprint reach.
        # Without the identity guard the extension arm would glue the
        # stale head (fn11) onto the new tail.
        journal = tmp_path / JOURNAL_FILENAME
        original = _row(11) + _row(22)
        journal.write_bytes(original)
        _age(journal)
        assert len(load_entries(tmp_path)) == 2
        replaced_head = _row(33)
        assert len(replaced_head) == len(_row(11))
        replacement = replaced_head + _row(22) + _row(44)
        tmp_file = tmp_path / ".swap.jsonl"
        tmp_file.write_bytes(replacement)
        os.replace(tmp_file, journal)     # compaction-style swap
        result = load_entries_checked(tmp_path)
        functions = [e.function for e in result.entries]
        assert functions == ["fn33", "fn22", "fn44"], (
            "an inode swap with a fingerprint-compatible tail was "
            "extended instead of reloaded"
        )
        assert result == _cold_dir(tmp_path, tmp_path, "swap")

    def test_truncation_forces_full_reload(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Pins the ``size < offset`` guard specifically: the tail
        # fingerprint's short-read-at-EOF refusal subsumes it on
        # clean code, so neutralize the fingerprint (contract-shaped:
        # seek to the cached offset, report a match) and prove the
        # size guard alone still forces the full reload.
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(5)))
        _age(journal)
        assert len(load_entries(tmp_path)) == 5

        def always_match(fh: Any, state: Any) -> bool:
            fh.seek(state.offset)    # seeking past EOF is legal
            return True

        monkeypatch.setattr(journal_mod, "_tail_matches", always_match)
        shorter = b"".join(_row(i) for i in range(2))
        journal.write_bytes(shorter)   # same inode, size < cached offset
        result = load_entries_checked(tmp_path)
        assert [e.function for e in result.entries] == ["fn0", "fn1"], (
            "a truncated-below-offset journal was served/extended"
        )
        assert result == _cold_dir(tmp_path, tmp_path, "trunc")

    def test_tail_fingerprint_mismatch_forces_full_reload(
        self, tmp_path: Path,
    ) -> None:
        # Rewrite the boundary line IN PLACE (same length, same
        # inode) and grow the file: without the fingerprint the
        # rewritten row would be glued onto the cached parse.
        journal = tmp_path / JOURNAL_FILENAME
        prefix = b"".join(_row(i) for i in range(3))
        old_tail = _row(88)
        journal.write_bytes(prefix + old_tail)
        _age(journal)
        assert len(load_entries(tmp_path)) == 4
        new_tail = _row(99)
        assert len(new_tail) == len(old_tail)
        rewritten = prefix + new_tail + _row(4)
        journal.write_bytes(rewritten)
        result = load_entries_checked(tmp_path)
        functions = [e.function for e in result.entries]
        assert "fn99" in functions and "fn88" not in functions
        assert result == _cold_dir(tmp_path, tmp_path, "tailrw")

    def test_sealed_shard_tamper_forces_cold_reload(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A sealed (non-last) shard never legitimately changes; a
        # same-size in-place rewrite of one must break its exact
        # (dev, ino, size, mtime_ns) pin and force a cold parse —
        # never be served through the cached rows.
        monkeypatch.setattr(
            journal_mod, "_JOURNAL_SHARD_ROLL_BYTES", 600)
        for i in range(12):
            append_entry(tmp_path, _entry(i))
        shards = journal_shard_paths(tmp_path)
        assert len(shards) >= 3
        _age_all(tmp_path)
        first = load_entries_checked(tmp_path)
        assert first.complete
        middle = shards[1]
        original = middle.read_bytes()
        # Same-length function-name flip on the first row actually
        # inside the sealed shard.
        import re
        m = re.search(rb'"function":"(fn\d+)"', original)
        assert m is not None
        victim = m.group(1)
        flipped = b"fx" + victim[2:]
        tampered = original.replace(
            b'"' + victim + b'"', b'"' + flipped + b'"', 1)
        assert len(tampered) == len(original) and tampered != original
        middle.write_bytes(tampered)
        result = load_entries_checked(tmp_path)
        functions = [e.function for e in result.entries]
        assert flipped.decode() in functions, (
            "a tampered sealed shard was served from cached rows"
        )
        assert victim.decode() not in functions
        assert result == _cold_dir(tmp_path, tmp_path, "seal-tamper")

    def test_planted_orphan_matches_cold_behavior(
        self, tmp_path: Path,
    ) -> None:
        # A planted non-contiguous shard file is a per-load anomaly:
        # the serve path must detect it and fall back to the cold
        # behavior (incomplete, orphan-flagged), never serve the
        # cached complete view.
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(3)))
        _age(journal)
        first = load_entries_checked(tmp_path)
        assert first.complete
        (tmp_path / "review-journal.009.jsonl").write_bytes(_row(9))
        result = load_entries_checked(tmp_path)
        assert not result.complete
        assert "non-contiguous" in (result.reason or "")
        assert result == _cold_dir(tmp_path, tmp_path, "orphan")

    def test_budget_change_forces_full_reload(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        read_counter: dict[str, int],
    ) -> None:
        # The containment tests monkeypatch loader budgets between
        # loads of an unchanged file; a cached view computed under
        # other budgets is not cold-equivalent and must not serve.
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(4)))
        size = journal.stat().st_size
        _age(journal)
        load_entries_checked(tmp_path)
        monkeypatch.setattr(journal_mod, "_MAX_JOURNAL_BYTES", size - 1)
        _reset(read_counter)
        load_entries_checked(tmp_path)
        assert read_counter["bytes"] >= size

    def test_roll_threshold_change_forces_full_reload(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        read_counter: dict[str, int],
    ) -> None:
        # The roll threshold is a loader-config member too (the
        # shard tests monkeypatch it, and it decides which shard the
        # appender writes next): a cached view computed under another
        # threshold must not serve.
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(4)))
        size = journal.stat().st_size
        _age(journal)
        load_entries_checked(tmp_path)
        monkeypatch.setattr(
            journal_mod, "_JOURNAL_SHARD_ROLL_BYTES", 600)
        _reset(read_counter)
        load_entries_checked(tmp_path)
        assert read_counter["bytes"] >= size, (
            "a roll-threshold change was served through the cache"
        )

    def test_interrupted_extension_leaves_the_key_cold(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A BaseException (KeyboardInterrupt, SystemExit) escaping the
        # streaming loop mid-extension must leave the key cold: the
        # record's lists already carry (part of) the delta while its
        # offset still points at the old boundary, so re-serving that
        # torn record would consume the delta twice — duplicated
        # entries on every later load.
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(3)))
        _age(journal)
        load_entries_checked(tmp_path)          # warm (extensible)
        with journal.open("ab") as f:
            f.write(_row(3))
        orig = journal_mod._consume_shard_stream

        def interrupting(fh: Any, path: Path, state: Any) -> None:
            orig(fh, path, state)
            raise KeyboardInterrupt

        monkeypatch.setattr(
            journal_mod, "_consume_shard_stream", interrupting)
        with pytest.raises(KeyboardInterrupt):
            load_entries_checked(tmp_path)
        monkeypatch.setattr(
            journal_mod, "_consume_shard_stream", orig)
        result = load_entries_checked(tmp_path)
        assert [e.function for e in result.entries] == [
            f"fn{i}" for i in range(4)
        ], "a torn extension record re-served duplicated entries"
        assert result == _cold_dir(tmp_path, tmp_path, "torn")


class TestUncoveredGuards:
    def test_boundary_straddling_append_never_extends(
        self, tmp_path: Path,
    ) -> None:
        # A load that consumed an unterminated tail must not extend:
        # the writer completing that line merges it with the next
        # append into ONE line that a cold parse reads differently.
        # Without the ``at_line_boundary`` guard the extension glued
        # the fragments as separate rows (3 entries where a cold
        # parse of the same bytes sees 1 corrupt line).
        journal = tmp_path / JOURNAL_FILENAME
        half = _row(2)
        journal.write_bytes(_row(1) + half[:10])   # unterminated tail
        _age(journal)
        load_entries_checked(tmp_path)
        with journal.open("ab") as f:
            f.write(half[10:] + _row(3))           # completes the line
        _age(journal)
        result = load_entries_checked(tmp_path)
        assert result == _cold_dir(tmp_path, tmp_path, "straddle"), (
            "a load whose parse ended mid-line was extended — the "
            "completed straddled line diverged from a cold parse"
        )

    def test_io_degraded_load_is_never_cached(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A mid-read OSError degrades THIS call only; caching the
        # degraded view would serve a permanently-incomplete result
        # for a file that reads fine.
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(3)))
        _age(journal)
        orig = journal_mod._consume_shard_stream

        def flaky(fh: Any, path: Path, state: Any) -> None:
            real_readline = fh.readline
            calls = {"n": 0}

            def readline(limit: int = -1) -> bytes:
                calls["n"] += 1
                if calls["n"] == 2:
                    raise OSError(5, "injected EIO")
                return real_readline(limit)

            fh.readline = readline
            orig(fh, path, state)

        monkeypatch.setattr(journal_mod, "_consume_shard_stream", flaky)
        degraded = load_entries_checked(tmp_path)
        assert not degraded.complete
        monkeypatch.setattr(journal_mod, "_consume_shard_stream", orig)
        with journal_mod._load_cache_lock:
            assert (os.path.realpath(tmp_path)
                    not in journal_mod._load_cache), (
                "an I/O-degraded parse was cached"
            )
        recovered = load_entries_checked(tmp_path)
        assert recovered.complete and len(recovered.entries) == 3, (
            "the degraded view was served after reads recovered"
        )


class TestIncompleteLoads:
    def _over_budget(self, tmp_path: Path,
                     monkeypatch: pytest.MonkeyPatch,
                     *, shards: bool = False) -> None:
        # Unique (non-prunable) rows over a tiny retained budget:
        # pruning frees nothing, so the load flags incomplete. The
        # multi-shard variant needs a PER-SHARD budget below what one
        # rolled shard holds (rolling exists precisely to keep shards
        # under the budgets, so a same-order budget stays complete).
        monkeypatch.setattr(
            journal_mod, "_MAX_RETAINED_ENTRIES", 2 if shards else 5)
        monkeypatch.setattr(journal_mod, "_READ_BUDGET_MULTIPLIER", 1000)
        if shards:
            monkeypatch.setattr(
                journal_mod, "_JOURNAL_SHARD_ROLL_BYTES", 600)
            for i in range(30):
                target = journal_mod._append_shard_path(tmp_path)
                with target.open("ab") as f:
                    f.write(_row(i))
        else:
            (tmp_path / JOURNAL_FILENAME).write_bytes(
                b"".join(_row(i) for i in range(30)))
        _age_all(tmp_path)

    def test_incomplete_load_served_while_unchanged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        read_counter: dict[str, int],
    ) -> None:
        self._over_budget(tmp_path, monkeypatch)
        first = load_entries_checked(tmp_path)
        assert not first.complete and first.reason
        _reset(read_counter)
        second = load_entries_checked(tmp_path)
        assert second == first
        assert read_counter["readline_calls"] == 0, (
            "the observed reload storm: an unchanged over-budget "
            "journal was re-parsed (and re-warned) per call"
        )
        assert read_counter["bytes"] <= journal_mod._TAIL_FINGERPRINT_BYTES

    def test_incomplete_over_shards_pins_whole_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        read_counter: dict[str, int],
    ) -> None:
        # A multi-shard incomplete load pins EVERY shard exactly and
        # re-serves while the whole set is unchanged.
        self._over_budget(tmp_path, monkeypatch, shards=True)
        shard_count = len(journal_shard_paths(tmp_path))
        assert shard_count > 1
        first = load_entries_checked(tmp_path)
        assert not first.complete and first.reason
        _reset(read_counter)
        second = load_entries_checked(tmp_path)
        assert second == first
        assert read_counter["readline_calls"] == 0
        # One fingerprint probe per pinned shard, no line parsing.
        assert read_counter["bytes"] <= (
            shard_count * journal_mod._TAIL_FINGERPRINT_BYTES)

    def test_incomplete_load_never_extends(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        read_counter: dict[str, int],
    ) -> None:
        self._over_budget(tmp_path, monkeypatch)
        load_entries_checked(tmp_path)
        appended = _row(999)
        with (tmp_path / JOURNAL_FILENAME).open("ab") as f:
            f.write(appended)
        _reset(read_counter)
        result = load_entries_checked(tmp_path)
        # A real reload of an over-budget journal still stops at the
        # budget break, so "full re-read" here means: parsed from
        # byte 0 well past what a delta extension would have touched
        # (the appended row plus fingerprint probes).
        assert read_counter["bytes"] > len(appended) + 2 * (
            journal_mod._TAIL_FINGERPRINT_BYTES
        ), (
            "an appended-to incomplete journal was served/extended "
            "instead of fully reloaded"
        )
        assert result == _cold_dir(tmp_path, tmp_path, "inc")


class TestFreshContract:
    def test_fresh_bypasses_and_repopulates(
        self, tmp_path: Path, read_counter: dict[str, int],
    ) -> None:
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(4)))
        size = journal.stat().st_size
        _age(journal)
        load_entries_checked(tmp_path)
        _reset(read_counter)
        result = load_entries_checked(tmp_path, fresh=True)
        assert read_counter["bytes"] >= size
        assert len(result.entries) == 4

    def test_require_complete_entries_never_serves_cache(
        self, tmp_path: Path, read_counter: dict[str, int],
    ) -> None:
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(4)))
        size = journal.stat().st_size
        _age(journal)
        load_entries_checked(tmp_path)   # warm the cache
        for _ in range(2):
            _reset(read_counter)
            entries = require_complete_entries(tmp_path)
            assert len(entries) == 4
            assert read_counter["bytes"] >= size, (
                "the spend-authorizing chokepoint read the cache"
            )


class TestWriterIntegration:
    def test_append_entry_visible_to_next_load(
        self, tmp_path: Path,
    ) -> None:
        append_entry(tmp_path, _entry(0))
        assert [e.function for e in load_entries(tmp_path)] == ["fn0"]
        append_entry(tmp_path, _entry(1))
        result = load_entries_checked(tmp_path)
        assert [e.function for e in result.entries] == ["fn0", "fn1"]
        assert result == _cold_dir(tmp_path, tmp_path, "app")

    def test_compaction_invalidates_same_process_cache(
        self, tmp_path: Path,
    ) -> None:
        from core.coverage.journal_compact import compact_journal
        # Two re-emissions of one identity: compaction drops the older.
        for ts_i in range(3):
            e = _entry(0)
            e.ts = f"2026-01-01T00:00:0{ts_i}.000000Z"
            e.reused = True
            append_entry(tmp_path, e)
        append_entry(tmp_path, _entry(1))
        _age_all(tmp_path)
        assert len(load_entries(tmp_path)) == 4   # cache warmed
        stats = compact_journal(tmp_path)
        assert stats.dropped_reemissions == 2
        with journal_mod._load_cache_lock:
            assert (os.path.realpath(tmp_path)
                    not in journal_mod._load_cache)
        result = load_entries_checked(tmp_path)
        assert len(result.entries) == 2
        assert result == _cold_dir(tmp_path, tmp_path, "compact")


class TestAliasing:
    def test_mutating_a_result_list_does_not_poison_the_cache(
        self, tmp_path: Path,
    ) -> None:
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(3)))
        _age(journal)
        first = load_entries_checked(tmp_path)
        first.entries.clear()
        first_again = load_entries_checked(tmp_path)
        assert [e.function for e in first_again.entries] == [
            "fn0", "fn1", "fn2",
        ]
        first_again.entries.append("junk")  # type: ignore[arg-type]
        assert len(load_entries(tmp_path)) == 3


class TestCacheBounds:
    def test_lru_cap_holds_and_hot_path_survives(
        self, tmp_path: Path,
    ) -> None:
        # Both directions of _LOAD_CACHE_MAX_PATHS: the dict never
        # exceeds the cap, and the most-recently-used record is the
        # one that survives eviction.
        hot = tmp_path / "hot"
        hot.mkdir()
        (hot / JOURNAL_FILENAME).write_bytes(_row(0))
        _age(hot / JOURNAL_FILENAME)
        load_entries(hot)
        for n in range(journal_mod._LOAD_CACHE_MAX_PATHS + 2):
            d = tmp_path / f"d{n}"
            d.mkdir()
            (d / JOURNAL_FILENAME).write_bytes(_row(n))
            _age(d / JOURNAL_FILENAME)
            load_entries(hot)   # keep the hot path recent
            load_entries(d)
            with journal_mod._load_cache_lock:
                assert (len(journal_mod._load_cache)
                        <= journal_mod._LOAD_CACHE_MAX_PATHS)
        with journal_mod._load_cache_lock:
            assert os.path.realpath(hot) in journal_mod._load_cache

    def test_under_byte_cap_record_cached(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Direction 1 of _LOAD_CACHE_MAX_BYTES: a record under the
        # aggregate cap is cached normally.
        monkeypatch.setattr(
            journal_mod, "_LOAD_CACHE_MAX_BYTES", 10_000)
        journal = tmp_path / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(4)))
        _age(journal)
        load_entries_checked(tmp_path)
        with journal_mod._load_cache_lock:
            assert os.path.realpath(tmp_path) in journal_mod._load_cache

    def test_oversized_record_not_cached_load_still_correct(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        read_counter: dict[str, int],
    ) -> None:
        # Direction 2: a single record over the aggregate byte cap is
        # not cached — the load still returns the full correct result,
        # later loads simply re-parse (pre-cache behavior), and the
        # refused store must NOT flush OTHER cached run dirs (routing
        # an oversized record through the eviction loop instead would
        # evict every older record before self-evicting).
        small = tmp_path / "small"
        small.mkdir()
        (small / JOURNAL_FILENAME).write_bytes(_row(0))
        _age(small / JOURNAL_FILENAME)
        run = tmp_path / "run"
        run.mkdir()
        journal = run / JOURNAL_FILENAME
        journal.write_bytes(b"".join(_row(i) for i in range(4)))
        size = journal.stat().st_size
        assert size > 200
        _age(journal)
        monkeypatch.setattr(journal_mod, "_LOAD_CACHE_MAX_BYTES", 200)
        load_entries(small)          # under the cap: cached
        first = load_entries_checked(run)
        assert first.complete and len(first.entries) == 4
        with journal_mod._load_cache_lock:
            assert (os.path.realpath(run)
                    not in journal_mod._load_cache), (
                "an over-cap record was cached"
            )
            assert (os.path.realpath(small)
                    in journal_mod._load_cache), (
                "an over-cap store evicted an unrelated cached dir"
            )
        _reset(read_counter)
        second = load_entries_checked(run)
        assert second == first
        assert read_counter["bytes"] >= size

    def test_aggregate_byte_cap_evicts_oldest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A store that pushes the AGGREGATE over the cap evicts the
        # LRU-oldest record, never the just-inserted one.
        a = tmp_path / "a"
        b = tmp_path / "b"
        for d in (a, b):
            d.mkdir()
            (d / JOURNAL_FILENAME).write_bytes(
                b"".join(_row(i) for i in range(4)))
            _age(d / JOURNAL_FILENAME)
        size = (a / JOURNAL_FILENAME).stat().st_size
        monkeypatch.setattr(
            journal_mod, "_LOAD_CACHE_MAX_BYTES", int(size * 1.5))
        load_entries(a)
        with journal_mod._load_cache_lock:
            assert os.path.realpath(a) in journal_mod._load_cache
        result_b = load_entries_checked(b)
        assert result_b.complete and len(result_b.entries) == 4
        with journal_mod._load_cache_lock:
            assert os.path.realpath(b) in journal_mod._load_cache
            assert (os.path.realpath(a)
                    not in journal_mod._load_cache), (
                "the aggregate byte cap did not evict the oldest"
            )
        # The evicted dir still loads correctly, just cold.
        assert len(load_entries(a)) == 4


class TestThreadSafety:
    def test_concurrent_loads_during_appends_across_rolls(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Loads race an appender whose rows roll the journal across
        # shards; every result must be a cold-load-equivalent view of
        # SOME prefix of the append sequence.
        monkeypatch.setattr(
            journal_mod, "_JOURNAL_SHARD_ROLL_BYTES", 600)
        total = 30
        errors: list[BaseException] = []
        done = threading.Event()
        # Pre-create the journal: the empty-vs-refused probe on a
        # not-yet-existing file races its creation (pre-existing
        # loader semantics, out of scope here).
        append_entry(tmp_path, _entry(0))

        def appender() -> None:
            try:
                for i in range(1, total):
                    append_entry(tmp_path, _entry(i))
                    time.sleep(0.001)
            except BaseException as exc:  # noqa: BLE001 — test collector
                errors.append(exc)
            finally:
                done.set()

        def loader() -> None:
            try:
                while not done.is_set():
                    result = load_entries_checked(tmp_path)
                    if not result.complete:
                        # Pre-existing loader race, cache or no cache:
                        # the shard-set scan and the orphan sweep are
                        # two directory reads, so a roll landing
                        # between them transiently reads as a
                        # non-contiguous leftover. The cache falls
                        # back to a cold parse there; only the
                        # transient orphan shape is tolerated.
                        assert "non-contiguous" in (result.reason or "")
                        continue
                    functions = [e.function for e in result.entries]
                    assert functions == [
                        f"fn{i}" for i in range(len(functions))
                    ]
            except BaseException as exc:  # noqa: BLE001 — test collector
                errors.append(exc)

        threads = [threading.Thread(target=appender)] + [
            threading.Thread(target=loader) for _ in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert not errors, errors
        assert len(journal_shard_paths(tmp_path)) > 1
        assert len(load_entries(tmp_path)) == total
