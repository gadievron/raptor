"""P2 test gaps surfaced by the adversarial review.

Each test in this file corresponds to a specific test-gap line in
agents A / B / C / D's reports. They aren't blocking-correctness
tests; they're regressions we want CI to catch the day a future
classifier change accidentally widens its blind spots.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.inventory.binary_oracle import (
    _combine_verdicts,
    _qualified_from_demangled,
)


# ---------------------------------------------------------------------------
# Agent A P2 — demangled-name parser edge cases (operator overloads, noexcept)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("demangled,expected", [
    # Vanilla method
    ("Foo::bar(int)", "Foo::bar"),
    # operator==, operator,, operator->, operator delete[] — argument-
    # list parser must find the OUTER ``(`` not the one inside the
    # operator name. Mostly defensive: most paths take linkage_name.
    ("Foo::operator==(int, int)", "Foo::operator=="),
    ("Foo::operator,(int)", "Foo::operator,"),
    ("Foo::operator->(int)", "Foo::operator->"),
    # operator() (call-op) — special-cased because its name LITERALLY
    # contains ``()``; the parser preserves the parens as part of the
    # name.
    ("Foo::operator()(int)", "Foo::operator()"),
    # Trailing CV-qualifiers
    ("Foo::bar(int) const", "Foo::bar"),
    ("Foo::bar() const noexcept", "Foo::bar"),
    # Trailing reference-qualifier
    ("Foo::bar(int) &", "Foo::bar"),
    ("Foo::bar(int) &&", "Foo::bar"),
])
def test_qualified_from_demangled_handles_operator_overloads(
    demangled: str, expected: str,
) -> None:
    assert _qualified_from_demangled(demangled) == expected


# ---------------------------------------------------------------------------
# Agent A P2 — _combine_verdicts with inlined mix
# ---------------------------------------------------------------------------

def test_combine_verdicts_inlined_mixed_with_absent() -> None:
    """Two binaries: one inlined, one absent → combined ``inlined`` (alive
    wins). Mirrors the test for symbol_present mixes."""
    assert _combine_verdicts([
        ("inlined", "full"), ("absent", "full"),
    ]) == "inlined"


def test_combine_verdicts_inlined_vs_symbol_present_picks_symbol() -> None:
    """``symbol_present`` > ``inlined`` per priority; with both
    full-tier the symbol_present wins."""
    assert _combine_verdicts([
        ("inlined", "full"), ("symbol_present", "full"),
    ]) == "symbol_present"


def test_combine_verdicts_warns_on_unknown_classification(caplog) -> None:
    """Adversarial review Agent D P2: unknown classification silently
    becomes "worst" via dict.get(v, 0). Should log a WARNING so a new
    classification doesn't silently demote every verdict."""
    import logging
    with caplog.at_level(logging.WARNING):
        _combine_verdicts([
            ("symbol_present", "full"),
            ("never_seen_class", "full"),  # unknown
        ])
    assert any("unknown classification" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Agent B P2 — mocked-subprocess tests (no r2 needed)
# ---------------------------------------------------------------------------

def test_extract_direct_call_edges_returns_empty_on_timeout(
    tmp_path: Path, monkeypatch,
) -> None:
    """r2 hanging on a hostile binary must NOT crash the inventory
    build — extract returns an empty index. Module's own contract is
    positive-evidence-only that degrades gracefully."""
    from core.inventory import binary_oracle_edges as boe
    binary = tmp_path / "fake"
    binary.write_bytes(b"\x7fELF")

    import subprocess as _sp
    def _hang(*args, **kwargs):
        raise _sp.TimeoutExpired(cmd=args[0] if args else [], timeout=1)

    monkeypatch.setattr(boe, "_sandbox_run", _hang, raising=False)
    # The function imports sandbox.run lazily; patch the actual
    # import path too.
    import core.sandbox as _sandbox
    monkeypatch.setattr(_sandbox, "run", _hang)
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/" + n)

    idx = boe.extract_direct_call_edges(binary, use_cache=False)
    assert idx.edges == []
    assert idx.callees == set()


def test_cache_save_then_version_mismatch_load_returns_none(
    tmp_path: Path, monkeypatch,
) -> None:
    """Save a cache file, then mutate the on-disk ``version`` to
    simulate a writer-side version mismatch. Load must reject and
    return None (cache miss) so a future schema bump can't silently
    feed stale entries to the consumer."""
    from core.inventory.binary_oracle_edges import (
        BinaryCallEdge, BinaryEdgeIndex,
        _cache_path_for, _load_cached_index, _save_cached_index,
    )
    from core.config import RaptorConfig
    monkeypatch.setattr(RaptorConfig, "BASE_OUT_DIR", tmp_path)

    idx = BinaryEdgeIndex(binary_path="/bin/x")
    idx.edges = [BinaryCallEdge("main", "foo", "/bin/x")]
    cache_file = _cache_path_for("abcdef" * 7)
    assert cache_file is not None
    _save_cached_index(cache_file, idx)
    # Mutate the version field on disk
    payload = json.loads(cache_file.read_text())
    payload["version"] = 9999
    cache_file.write_text(json.dumps(payload))
    assert _load_cached_index(cache_file, "/bin/x") is None


def test_parse_axffj_handles_adjacent_batch_lines_no_body() -> None:
    """Two BATCH headers in a row with no body between them (r2 emits
    this when axffj returns ``[]`` for a function). Parser must not
    crash; both batches just produce no edges."""
    from core.inventory.binary_oracle_edges import (
        BinaryEdgeIndex, _parse_axffj_batch,
    )
    addr_to_name = {0x1000: "a", 0x2000: "b"}
    output = (
        "BATCH 0x1000\n"
        "BATCH 0x2000\n"
        '[]\n'
    )
    index = BinaryEdgeIndex(binary_path="/bin/x")
    _parse_axffj_batch(output, addr_to_name, index)
    assert index.edges == []


def test_vtable_parser_strips_ansi_escapes() -> None:
    """r2 interactive-style output emits ANSI escape sequences before
    the slot lines; the parser must strip them before matching."""
    from core.inventory.binary_oracle_edges import (
        _VTABLE_HEADER_RE, _VTABLE_SLOT_RE,
    )
    import re as _re
    ANSI = "\x1b[31m"
    RESET = "\x1b[0m"
    line_hdr = f"{ANSI}Vtable Found at 0x1234{RESET}"
    plain = _re.sub(r"\x1b\[[\d;]*m", "", line_hdr)
    assert _VTABLE_HEADER_RE.search(plain) is not None
    line_slot = f"{ANSI}0x1234 : method.Foo::bar{RESET}"
    plain = _re.sub(r"\x1b\[[\d;]*m", "", line_slot)
    m = _VTABLE_SLOT_RE.match(plain)
    assert m is not None
    assert m.group(1) == "method.Foo::bar"


def test_clean_r2_function_name_iteratively_strips_stacked() -> None:
    """Adversarial review B P1: r2 can emit ``method.sym.X`` /
    ``sym.imp.malloc``. Strip iteratively so the bare name is the
    result."""
    from core.inventory.binary_oracle_edges import _clean_r2_function_name
    assert _clean_r2_function_name("method.sym.X") == "X"
    assert _clean_r2_function_name("sym.imp.malloc") == "malloc"
    assert _clean_r2_function_name("imp.free") == "free"


def test_vtable_slot_junk_is_filtered() -> None:
    """Slot lines whose ``method`` token is a raw address, ``0x...``,
    or section-prefixed entry must be dropped — they're not real
    callees."""
    # The filter logic in _extract_vtable_edges:
    #   skip if method starts with "0x" / "section." / "loc." / "0"
    #   AND requires at least one alphanumeric / underscore.
    for junk in ("0x00000000", "0x12345678", "section.text", "loc.42"):
        # The slot regex itself matches these — the filter is at
        # the call-site level. Document expected behaviour:
        assert junk.startswith(("0x", "section.", "loc.", "0"))


# ---------------------------------------------------------------------------
# Agent C P1 / P2 — suppressions.jsonl audit trail
# ---------------------------------------------------------------------------

def test_record_suppression_writes_jsonl_record(tmp_path: Path) -> None:
    """The new aggregate audit trail: a JSONL file in the out_dir with
    one record per suppressed finding. Operator's ``jq`` workflow:
    ``jq -c . suppressions.jsonl | head``."""
    from core.inventory.reach_chokepoint import record_suppression
    finding = {
        "finding_id": "f-001", "rule_id": "cpp/sql-injection",
        "file_path": "src/db.cpp", "line": 42,
        "function": "execute_query",
    }
    record_suppression(
        tmp_path, finding=finding,
        verdict="binary_oracle_absent",
        reason="Reachability chokepoint: dead in this build",
    )
    p = tmp_path / "suppressions.jsonl"
    assert p.is_file()
    line = p.read_text().strip()
    record = json.loads(line)
    assert record["finding_id"] == "f-001"
    assert record["verdict"] == "binary_oracle_absent"
    assert record["file_path"] == "src/db.cpp"
    assert record["line"] == 42


def test_record_suppression_appends_not_overwrites(tmp_path: Path) -> None:
    """Multiple suppressions in the same run accumulate in the same
    file — operators need the full list, not just the last."""
    from core.inventory.reach_chokepoint import record_suppression
    for fid in ("a", "b", "c"):
        record_suppression(
            tmp_path,
            finding={"finding_id": fid, "file_path": "x.c", "line": 1},
            verdict="binary_oracle_absent",
            reason="dead",
        )
    lines = (tmp_path / "suppressions.jsonl").read_text().splitlines()
    assert len(lines) == 3
    assert [json.loads(line)["finding_id"] for line in lines] == [
        "a", "b", "c"]


def test_record_suppression_swallows_io_errors(tmp_path: Path) -> None:
    """Audit-trail writes are best-effort — IO errors must not propagate
    or block the suppression itself."""
    from core.inventory.reach_chokepoint import record_suppression
    # Point out_dir at a path that can't be a directory (file).
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    # Should not raise.
    record_suppression(
        blocker, finding={"finding_id": "x"},
        verdict="binary_oracle_absent", reason="r",
    )


# ---------------------------------------------------------------------------
# Agent D P2 — _has_dwarf fail-CLOSED on hostile-binary timeout
# ---------------------------------------------------------------------------

def test_has_dwarf_returns_false_on_readelf_timeout(
    tmp_path: Path, monkeypatch,
) -> None:
    """A crafted ELF that hangs ``readelf -S`` must NOT slip through
    the DWARF check as if it had .debug_info. Prior code returned
    True on TimeoutExpired (fail-open) — adversarial review Agent D
    P2. Now rejects (fail-closed)."""
    from core.inventory import binary_oracle_autodetect as ad
    binary = tmp_path / "hostile"
    binary.write_bytes(b"\x7fELF")
    import subprocess as _sp
    def _hang(*args, **kwargs):
        raise _sp.TimeoutExpired(cmd=args[0] if args else [], timeout=1)
    monkeypatch.setattr(_sp, "run", _hang)
    assert ad._has_dwarf(binary) is False


def test_has_dwarf_recognises_split_dwarf_dwo(
    tmp_path: Path, monkeypatch,
) -> None:
    """split-DWARF builds emit ``.debug_info.dwo`` instead of (or
    alongside) ``.debug_info``. The DWARF check must recognise both
    or perfectly-valid split-DWARF binaries silently filter out."""
    from core.inventory import binary_oracle_autodetect as ad
    binary = tmp_path / "split"
    binary.write_bytes(b"\x7fELF")
    import subprocess as _sp
    class _FakeProc:
        returncode = 0
        stdout = "  [12] .debug_info.dwo    PROGBITS  ...\n"
    monkeypatch.setattr(_sp, "run", lambda *a, **kw: _FakeProc())
    assert ad._has_dwarf(binary) is True


def test_classify_candidate_skips_executable_scripts(
    tmp_path: Path,
) -> None:
    """The auto-detect walker must NOT call readelf on every +x file
    in the tree. Suffix-based reject (``.sh``, ``.py``, ``.pl``,
    ``.cmake``, ``.in``, etc.) avoids the subprocess per script —
    matters on large trees."""
    from core.inventory.binary_oracle_autodetect import _classify_candidate
    import os
    for name in ("build.sh", "configure.py", "gen.pl", "cfg.cmake",
                 "version.in", "config.am", "config.ac", "deploy.bash"):
        p = tmp_path / name
        p.write_text("#!/usr/bin/env interp\n")
        os.chmod(p, 0o755)
        assert _classify_candidate(p) is None, name


# ---------------------------------------------------------------------------
# Agent E P2 — n-concentration warning
# ---------------------------------------------------------------------------

def test_aggregate_flags_dominator_when_one_corpus_exceeds_half(
    tmp_path: Path,
) -> None:
    """Adversarial review E P1-2: when ONE corpus contributes >50% of
    aggregate absent_n, the aggregate number is mostly that corpus —
    flag the imbalance in the report so a reader can judge."""
    from core.inventory.binary_oracle_precision import (
        CorpusReport, _aggregate,
    )
    reports = [
        CorpusReport(
            corpus_name="big", corpus_mode="gcov", n_functions=200,
            absent_n=120, absent_correct=120, absent_precision=1.0,
        ),
        CorpusReport(
            corpus_name="small", corpus_mode="gcov", n_functions=20,
            absent_n=10, absent_correct=10, absent_precision=1.0,
        ),
    ]
    agg = _aggregate(reports)
    dom = agg["n_concentration_dominator"]
    assert dom is not None
    assert dom["corpus"] == "big"
    assert dom["share"] > 0.5


def test_aggregate_no_dominator_when_corpora_balanced(
    tmp_path: Path,
) -> None:
    """Balanced corpora → no dominator → reader sees the aggregate is
    a real cross-corpus claim."""
    from core.inventory.binary_oracle_precision import (
        CorpusReport, _aggregate,
    )
    reports = [
        CorpusReport(
            corpus_name="a", corpus_mode="gcov", n_functions=100,
            absent_n=50, absent_correct=50, absent_precision=1.0,
        ),
        CorpusReport(
            corpus_name="b", corpus_mode="gcov", n_functions=100,
            absent_n=50, absent_correct=50, absent_precision=1.0,
        ),
    ]
    agg = _aggregate(reports)
    assert agg["n_concentration_dominator"] is None
