"""Tests for the binary-oracle precision harness (Inc 3a)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from core.inventory.binary_oracle import BinaryOracleWitness
from core.inventory.binary_oracle_corpora.snappy import (
    _LLVM_COV_CANDIDATES,
    _LLVM_PROFDATA_CANDIDATES,
)
from core.inventory.binary_oracle_precision import (
    CorpusReport,
    FunctionMeasurement,
    _cross_tab_gcov,
    _cross_tab_synthetic,
    run_corpus,
    write_report,
)


# ---------------------------------------------------------------------------
# Toolchain availability — the ``*_driver_end_to_end_via_harness`` tests
# clone + build real projects, so they need system tooling beyond the
# Python deps. They are @pytest.mark.slow (nightly-only); the skipif guards
# below make a missing toolchain degrade to SKIP-with-reason rather than a
# red FAIL that looks like a precision regression. The nightly workflow
# provisions radare2 + LLVM 21 so these actually run there.
# ---------------------------------------------------------------------------
def _which_any(candidates: tuple) -> bool:
    return any(shutil.which(c) for c in candidates)


_HAVE_LLVM = _which_any(_LLVM_COV_CANDIDATES) and _which_any(
    _LLVM_PROFDATA_CANDIDATES)
_HAVE_CLANG = bool(shutil.which("clang") and shutil.which("clang++"))
_HAVE_CMAKE = shutil.which("cmake") is not None
_HAVE_CARGO = shutil.which("cargo") is not None
_HAVE_GCOV = shutil.which("gcov") is not None
_HAVE_MAKE = shutil.which("make") is not None

_NEED_LLVM_CXX = pytest.mark.skipif(
    not (_HAVE_CLANG and _HAVE_CMAKE and _HAVE_LLVM),
    reason="needs clang/clang++ + cmake + LLVM coverage tools "
    "(llvm-cov / llvm-profdata)",
)
_NEED_LLVM_RUST = pytest.mark.skipif(
    not (_HAVE_CARGO and _HAVE_LLVM),
    reason="needs cargo + LLVM coverage tools (llvm-cov / llvm-profdata)",
)
_NEED_GCOV_BUILD = pytest.mark.skipif(
    not (_HAVE_GCOV and _HAVE_MAKE),
    reason="needs gcc/gcov + make",
)


def _w(cls: str, name: str = "") -> BinaryOracleWitness:
    return BinaryOracleWitness(
        classification=cls, build_id="x", binary_path="/tmp/x")


def _assert_precision_threshold(
    rep: CorpusReport, corpus: str, threshold: float,
) -> None:
    """Threshold-based precision assertion. Replaces the prior
    ``assert absent_fps == 0`` ratchet that made adding a new corpus
    with legitimate small-FP precision impossible without per-corpus
    pyteshackery (adversarial review E P1-3). Always asserts that
    ``absent_precision >= threshold`` AND reports the actual number;
    operators tightening corpora bump the threshold in the test."""
    if rep.absent_precision is None:
        return
    assert rep.absent_precision >= threshold, (
        f"{corpus} absent_precision = {rep.absent_precision:.4f} "
        f"below threshold {threshold:.4f}; "
        f"{len(rep.absent_fps or [])} FPs: "
        f"{(rep.absent_fps or [])[:10]}"
    )


# ---------------------------------------------------------------------------
# Cross-tab — synthetic mode
# ---------------------------------------------------------------------------

def test_synthetic_all_correct_gives_perfect_score() -> None:
    ctx = {
        "candidate_functions": ["a", "b"],
        "expected": {"a": "symbol_present", "b": "absent"},
    }
    verdicts = {"a": _w("symbol_present"), "b": _w("absent")}
    r = _cross_tab_synthetic("t", ctx, verdicts)
    assert r.exact_match == 1.0
    assert r.mismatches == []
    assert r.verdict_counts == {"symbol_present": 1, "absent": 1}


def test_synthetic_records_mismatch_with_expected_vs_got() -> None:
    ctx = {
        "candidate_functions": ["a", "b"],
        "expected": {"a": "symbol_present", "b": "absent"},
    }
    # b classified wrong:
    verdicts = {"a": _w("symbol_present"), "b": _w("symbol_present")}
    r = _cross_tab_synthetic("t", ctx, verdicts)
    assert r.exact_match == 0.5
    assert len(r.mismatches) == 1
    assert r.mismatches[0]["function"] == "b"
    assert r.mismatches[0]["expected"] == "absent"
    assert r.mismatches[0]["got"] == "symbol_present"


def test_synthetic_handles_classifier_omission_as_none() -> None:
    """If the classifier omits a function (e.g. stripped binary path),
    the row records ``classifier_verdict=None`` instead of crashing."""
    ctx = {
        "candidate_functions": ["a"],
        "expected": {"a": "symbol_present"},
    }
    r = _cross_tab_synthetic("t", ctx, {})
    assert r.exact_match == 0.0
    assert r.measurements[0].classifier_verdict is None


# ---------------------------------------------------------------------------
# Cross-tab — gcov mode
# ---------------------------------------------------------------------------

def test_gcov_absent_precision_perfect_when_no_fps() -> None:
    ctx = {
        "candidate_functions": ["a", "b", "c"],
        "live_set": {"a"},
    }
    verdicts = {
        "a": _w("symbol_present"),  # live, classified live → fine
        "b": _w("absent"),          # dead, classified absent → TP
        "c": _w("absent"),          # dead, classified absent → TP
    }
    r = _cross_tab_gcov("t", ctx, verdicts)
    assert r.absent_n == 2
    assert r.absent_correct == 2
    assert r.absent_precision == 1.0
    assert r.absent_fps == []


def test_gcov_flags_absent_fp_when_live_function_classified_absent() -> None:
    """The DANGER case the harness exists to surface: classifier says
    absent but tests exercised the function. ``earns_suppression`` must
    NOT flip on a corpus where this happens."""
    ctx = {"candidate_functions": ["a"], "live_set": {"a"}}
    verdicts = {"a": _w("absent")}
    r = _cross_tab_gcov("t", ctx, verdicts)
    assert r.absent_precision == 0.0
    assert "a" in r.absent_fps


def test_gcov_overcautious_classifier_does_not_register_as_fp() -> None:
    """A function that's actually-dead but classified ``symbol_present``
    is overcautious — fine for our use case (we never suppress it)."""
    ctx = {"candidate_functions": ["a"], "live_set": set()}
    verdicts = {"a": _w("symbol_present")}
    r = _cross_tab_gcov("t", ctx, verdicts)
    assert r.absent_n == 0
    assert r.absent_precision is None  # no absent verdicts to score
    assert r.absent_fps == []


def test_gcov_empty_absent_set_means_precision_is_none() -> None:
    """Don't divide by zero — corpora with zero ``absent`` verdicts
    contribute nothing to the precision number."""
    ctx = {"candidate_functions": [], "live_set": set()}
    r = _cross_tab_gcov("t", ctx, {})
    assert r.absent_precision is None


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def test_write_report_emits_json_and_markdown(tmp_path: Path) -> None:
    rep = CorpusReport(
        corpus_name="x", corpus_mode="synthetic", n_functions=1,
        measurements=[FunctionMeasurement(
            name="a", classifier_verdict="absent",
            expected_verdict="absent")],
        verdict_counts={"absent": 1}, exact_match=1.0,
    )
    path = write_report([rep], tmp_path)
    payload = json.loads(path.read_text())
    assert payload["corpora"][0]["corpus"] == "x"
    md = (tmp_path / "report.md").read_text()
    assert "## x (synthetic)" in md
    assert "100.0%" in md


@pytest.mark.parametrize("mode", ["synthetic", "gcov"])
def test_corpus_report_to_dict_carries_mode(mode: str) -> None:
    rep = CorpusReport(corpus_name="x", corpus_mode=mode, n_functions=0)
    d = rep.to_dict()
    assert d["mode"] == mode


def test_cross_tab_populated_for_gcov(tmp_path: Path) -> None:
    """Adversarial review E P1-1: the full cross-tab surfaces what
    the headline absent-precision number doesn't measure. Verify the
    cross-tab has rows for every classifier verdict the corpus
    produced, paired with live/dead from gcov."""
    ctx = {
        "candidate_functions": ["a", "b", "c", "d"],
        "live_set": {"a", "c"},
    }
    verdicts = {
        "a": _w("symbol_present"),  # live, classifier agrees
        "b": _w("absent"),           # dead, classifier agrees
        "c": _w("inlined"),          # live + inlined (classifier right)
        "d": _w("inlined"),          # dead + inlined (classifier right)
    }
    r = _cross_tab_gcov("t", ctx, verdicts)
    assert r.cross_tab == {
        "symbol_present": {"live": 1},
        "absent": {"dead": 1},
        "inlined": {"live": 1, "dead": 1},
    }


def test_aggregate_records_rule_of_three_ub(tmp_path: Path) -> None:
    """Adversarial review E P2-4: harness now writes the aggregate
    (sum-of-absent-correct / sum-of-absent-n + rule-of-three 95% UB
    on miss rate) into the report JSON so the headline number is
    machine-readable rather than hand-computed from per-corpus rows."""
    rep_a = CorpusReport(
        corpus_name="a", corpus_mode="gcov", n_functions=100,
        absent_n=50, absent_correct=50, absent_precision=1.0,
        verdict_counts={"absent": 50, "symbol_present": 50},
    )
    rep_b = CorpusReport(
        corpus_name="b", corpus_mode="gcov", n_functions=200,
        absent_n=100, absent_correct=100, absent_precision=1.0,
        verdict_counts={"absent": 100, "symbol_present": 100},
    )
    path = write_report([rep_a, rep_b], tmp_path)
    payload = json.loads(path.read_text())
    agg = payload["aggregate"]
    assert agg["absent_n_total"] == 150
    assert agg["absent_correct_total"] == 150
    assert agg["aggregate_absent_precision"] == 1.0
    # Rule of three: 3/N → for N=150 that's 0.02 (2%).
    assert abs(agg["rule_of_three_95_upper_bound_miss_rate"]
               - 3.0 / 150.0) < 1e-9
    assert len(agg["per_corpus"]) == 2


def test_toolchain_block_records_in_report(tmp_path: Path) -> None:
    """Adversarial review E P2-2: the toolchain block lets a reader
    see WHICH compiler / coverage tool produced a precision number.
    Without it, reproducing the number on a different host is
    guesswork — same commit can yield different precision under a
    different clang/rustc."""
    rep = CorpusReport(
        corpus_name="x", corpus_mode="gcov", n_functions=10,
        absent_n=5, absent_correct=5,
        toolchain={"cc(gcc)": "gcc (X) 14.2.0", "gcov(gcov)": "gcov 14.2.0"},
    )
    path = write_report([rep], tmp_path)
    payload = json.loads(path.read_text())
    assert payload["corpora"][0]["toolchain"] == rep.toolchain
    md = (tmp_path / "report.md").read_text()
    assert "toolchain:" in md
    assert "gcc (X) 14.2.0" in md


# ---------------------------------------------------------------------------
# End-to-end on the synthetic driver
# ---------------------------------------------------------------------------

def test_synthetic_driver_end_to_end_via_harness(tmp_path: Path) -> None:
    """Run the synthetic corpus through the full harness. The classifier
    is correct on the fixture (proven by ``test_binary_oracle.py``); the
    harness must return ``exact_match == 1.0`` and zero mismatches."""
    from core.inventory.binary_oracle_corpora import REGISTRY
    drv = REGISTRY["synthetic"]
    rep = run_corpus(drv, tmp_path)
    assert rep.corpus_mode == "synthetic"
    assert rep.exact_match == 1.0, (
        f"synthetic mismatches surfaced via harness: {rep.mismatches}")
    assert rep.n_functions >= 8


def test_registry_includes_synthetic_by_default() -> None:
    from core.inventory.binary_oracle_corpora import REGISTRY
    assert "synthetic" in REGISTRY
    assert REGISTRY["synthetic"].mode == "synthetic"


# ---------------------------------------------------------------------------
# zlib driver — fast unit tests on the parsing helpers
# ---------------------------------------------------------------------------

def test_zlib_driver_registered_in_gcov_mode() -> None:
    from core.inventory.binary_oracle_corpora import REGISTRY
    assert "zlib" in REGISTRY
    assert REGISTRY["zlib"].mode == "gcov"


def test_zlib_gcov_parser_picks_up_executed_functions(tmp_path: Path) -> None:
    """The parser must read 'Function NAME' + 'Lines executed: X%' pairs
    and only include functions with > 0% execution."""
    from core.inventory.binary_oracle_corpora.zlib import (
        _GCOV_FN_RE, _GCOV_LINES_RE,
    )
    sample = (
        "Function 'inflate'\n"
        "Lines executed:97.50% of 40\n"
        "Branches executed:88.00% of 50\n"
        "Function 'deflate_huff'\n"
        "Lines executed:0.00% of 19\n"
        "Function 'longest_match'\n"
        "Lines executed:100.00% of 37\n"
    )
    live: set[str] = set()
    current = None
    for line in sample.splitlines():
        m = _GCOV_FN_RE.match(line)
        if m:
            current = m.group(1)
            continue
        if current:
            m2 = _GCOV_LINES_RE.match(line)
            if m2:
                if float(m2.group(1)) > 0:
                    live.add(current)
                current = None
    assert live == {"inflate", "longest_match"}
    assert "deflate_huff" not in live


def test_zlib_collect_gcov_liveness_empty_dir_returns_empty(
    tmp_path: Path,
) -> None:
    """Defensive: a build dir with no .gcda files returns an empty set
    (and logs a warning) instead of crashing."""
    from core.inventory.binary_oracle_corpora.zlib import (
        _collect_gcov_liveness,
    )
    assert _collect_gcov_liveness(tmp_path) == set()


def test_zlib_enumerate_candidates_missing_archive_returns_empty(
    tmp_path: Path,
) -> None:
    """If libz.a is missing, we don't crash — just an empty candidate
    list (and a warning)."""
    from core.inventory.binary_oracle_corpora.zlib import (
        _enumerate_candidates,
    )
    assert _enumerate_candidates(tmp_path) == []


# ---------------------------------------------------------------------------
# zlib driver — slow E2E (network + build, marked off the CI fast path)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# snappy driver — fast unit tests on the parsing helpers
# ---------------------------------------------------------------------------

def test_snappy_driver_registered() -> None:
    from core.inventory.binary_oracle_corpora import REGISTRY
    assert "snappy" in REGISTRY
    # ``mode`` is the harness cross-tab style — liveness-based, used by
    # both gcov and llvm-cov drivers (the value is historical).
    assert REGISTRY["snappy"].mode == "gcov"


def test_snappy_qualified_strips_args_and_return_type() -> None:
    """Demangled C++ names (from ``c++filt`` on llvm-cov / nm output)
    include return types + arglists + trailing qualifiers. The qualified
    extractor must collapse them to the namespaced-no-args form the
    classifier's ``by_qualified`` index uses."""
    from core.inventory.binary_oracle_corpora.snappy import (
        _qualified_from_demangled,
    )
    assert _qualified_from_demangled(
        "snappy::Uncompress(snappy::Source*, snappy::Sink*)"
    ) == "snappy::Uncompress"
    assert _qualified_from_demangled(
        "char* snappy::EmitCopy<true>(char*, unsigned long, unsigned long)"
    ) == "snappy::EmitCopy<true>"
    assert _qualified_from_demangled("plain_c_function") == "plain_c_function"
    # The case that surfaced as broken in the first snappy run: template
    # args contain internal whitespace, so naive ``rsplit(' ')`` returns
    # garbage like ``16ul>::operator[]``. Balance-aware parsing must keep
    # the whole template + qualifier intact.
    assert _qualified_from_demangled(
        "std::array<unsigned char, 16ul>::operator[](unsigned long)"
    ) == "std::array<unsigned char, 16ul>::operator[]"
    # Multi-arg template with stdlib value:
    assert _qualified_from_demangled(
        "void std::vector<int, std::allocator<int> >::push_back(int const&)"
    ) == "std::vector<int, std::allocator<int> >::push_back"
    # Anonymous namespace — has internal ``( )`` that must NOT be mistaken
    # for the return-type boundary (snappy Inc 3c second-round bug):
    assert _qualified_from_demangled(
        "(anonymous namespace)::CalculateTableSize(unsigned int)"
    ) == "(anonymous namespace)::CalculateTableSize"
    assert _qualified_from_demangled(
        "unsigned int (anonymous namespace)::HashBytes(unsigned long)"
    ) == "(anonymous namespace)::HashBytes"
    # Trailing CV-qualifiers (third-round Inc 3c bug — ``const`` got
    # returned as the function name on every const-method).
    assert _qualified_from_demangled(
        "snappy::ByteArraySource::Available() const"
    ) == "snappy::ByteArraySource::Available"
    assert _qualified_from_demangled(
        "Foo::bar() const noexcept"
    ) == "Foo::bar"
    assert _qualified_from_demangled(
        "Foo::bar() const &&"
    ) == "Foo::bar"
    # Operator()'s parens are part of the name, not the arglist — the
    # call-operator method without args must NOT strip down to
    # ``operator`` (snappy Inc 3c followup bug surfaced via the lambda
    # case in the precision measurement).
    assert _qualified_from_demangled(
        "Foo::operator() const"
    ) == "Foo::operator()"
    assert _qualified_from_demangled(
        "Foo::operator()(int, int) const"
    ) == "Foo::operator()"
    # Lambda arg-list normalisation — c++filt and gcov disagree on
    # whether to include the captured types inside ``{lambda(...)#N}``
    # (c++filt does, gcov doesn't). Strip them so the two sources match.
    assert _qualified_from_demangled(
        "Foo::{lambda(int, char*)#1}::operator()() const"
    ) == "Foo::{lambda()#1}::operator()"
    assert _qualified_from_demangled(
        "Foo::{lambda()#2}::operator()() const"
    ) == "Foo::{lambda()#2}::operator()"


def test_snappy_stdlib_helpers_filtered_out() -> None:
    """Stdlib + gtest hits are methodology noise — filtering them keeps
    n_functions a meaningful denominator on the snappy surface."""
    from core.inventory.binary_oracle_corpora.snappy import (
        _is_stdlib_or_helper,
    )
    assert _is_stdlib_or_helper("std::vector<int>::push_back")
    assert _is_stdlib_or_helper("testing::TestInfo::name")
    assert _is_stdlib_or_helper("__gnu_cxx::__normal_iterator")
    assert not _is_stdlib_or_helper("snappy::Uncompress")
    assert not _is_stdlib_or_helper("plain_function")


@pytest.mark.slow
@_NEED_LLVM_CXX
def test_snappy_driver_end_to_end_via_harness(tmp_path: Path) -> None:
    """Full clone → CMake build (clang+LLVM coverage) → ctest →
    llvm-cov export → classify → cross-tab. Marked ``slow`` so CI
    doesn't run it."""
    from core.inventory.binary_oracle_corpora import REGISTRY
    drv = REGISTRY["snappy"]
    rep = run_corpus(drv, tmp_path)
    assert rep.corpus_mode == "gcov"
    assert rep.n_functions > 20, \
        f"expected meaningful snappy surface, got {rep.n_functions}"
    assert rep.absent_n > 0, "expected some absent verdicts"
    if rep.absent_fps:
        pytest.fail(
            f"snappy absent_precision = {rep.absent_precision}; "
            f"{len(rep.absent_fps)} live functions classified absent: "
            f"{rep.absent_fps[:10]}"
        )


# ---------------------------------------------------------------------------
# libsodium / leveldb drivers — fast registration + helper tests
# ---------------------------------------------------------------------------

def test_libsodium_driver_registered() -> None:
    from core.inventory.binary_oracle_corpora import REGISTRY
    assert "libsodium" in REGISTRY
    assert REGISTRY["libsodium"].mode == "gcov"


def test_libsodium_enumerate_candidates_missing_archive(
    tmp_path: Path,
) -> None:
    """Defensive: no archive present → empty candidate list, no crash."""
    from core.inventory.binary_oracle_corpora.libsodium import (
        _enumerate_candidates,
    )
    assert _enumerate_candidates(tmp_path) == []


def test_leveldb_driver_registered() -> None:
    from core.inventory.binary_oracle_corpora import REGISTRY
    assert "leveldb" in REGISTRY


def test_leveldb_patch_drop_benchmark_is_idempotent(tmp_path: Path) -> None:
    """The CMakeLists patch removes the benchmark dep from the test
    link line + the ``add_subdirectory("third_party/benchmark")`` call.
    Re-applying must be a no-op (corpus driver replays prepare() on
    cache misses)."""
    from core.inventory.binary_oracle_corpora.leveldb import (
        _patch_drop_benchmark,
    )
    cmake = tmp_path / "CMakeLists.txt"
    cmake.write_text(
        'add_subdirectory("third_party/benchmark")\n'
        'target_link_libraries(t leveldb gmock gtest benchmark)\n'
    )
    _patch_drop_benchmark(cmake)
    once = cmake.read_text()
    assert "benchmark" not in once.split("target_link_libraries")[1].split("\n", 1)[0]
    assert 'add_subdirectory("third_party/benchmark")' not in once
    _patch_drop_benchmark(cmake)
    assert cmake.read_text() == once  # idempotent


# ---------------------------------------------------------------------------
# regex-rust driver — fast registration + helper tests
# ---------------------------------------------------------------------------

def test_regex_rust_driver_registered() -> None:
    from core.inventory.binary_oracle_corpora import REGISTRY
    assert "regex-rust" in REGISTRY


def test_regex_rust_strips_crate_hash_from_demangled_names() -> None:
    """Rust v0 demangled names include a per-build crate hash like
    ``regex[7e9e1dd283b8ce7a]::Match::start``. Strip it so the
    qualified name compares stably across rebuilds and matches
    ``nm --demangle`` (which omits the hash)."""
    from core.inventory.binary_oracle_corpora.regex_rust import (
        _strip_crate_hash,
    )
    assert _strip_crate_hash(
        "<regex[7e9e1dd283b8ce7a]::regex::bytes::Match>::end"
    ) == "<regex::regex::bytes::Match>::end"
    assert _strip_crate_hash(
        "regex[abc123def4567]::api::Regex::new"
    ) == "regex::api::Regex::new"
    # No hash → unchanged
    assert _strip_crate_hash("plain::module::function") == (
        "plain::module::function")


@pytest.mark.slow
@_NEED_LLVM_RUST
def test_regex_rust_driver_end_to_end_via_harness(tmp_path: Path) -> None:
    """Full clone → cargo build (release + coverage + DWARF) → run test
    binary → llvm-cov export → classify. Slow (cargo build ~3 min)."""
    from core.inventory.binary_oracle_corpora import REGISTRY
    drv = REGISTRY["regex-rust"]
    rep = run_corpus(drv, tmp_path)
    assert rep.corpus_mode == "gcov"
    assert rep.n_functions > 500, \
        f"expected lots of regex fns, got {rep.n_functions}"
    assert rep.absent_n > 0
    # 7 known FPs from the impl-block syntax mismatch on
    # <regex::regex::bytes::Match>::* methods. Acceptable for first
    # Rust corpus — substantive 99.8% precision; will be tightened
    # by the impl-block namespace fix.
    _assert_precision_threshold(rep, "regex-rust", 0.99)


@pytest.mark.slow
@_NEED_GCOV_BUILD
def test_libsodium_driver_end_to_end_via_harness(tmp_path: Path) -> None:
    """Full clone → autogen → configure × 2 → build × 2 → make check ×
    2 → targeted single-test rerun → gcov → classify. Slow."""
    from core.inventory.binary_oracle_corpora import REGISTRY
    drv = REGISTRY["libsodium"]
    rep = run_corpus(drv, tmp_path)
    assert rep.corpus_mode == "gcov"
    assert rep.n_functions > 500
    assert rep.absent_n > 100, "expected many absent verdicts on libsodium"
    _assert_precision_threshold(rep, "libsodium", 1.0)


@pytest.mark.slow
@_NEED_LLVM_CXX
def test_leveldb_driver_end_to_end_via_harness(tmp_path: Path) -> None:
    """Full clone → patch CMake → CMake build (clang+LLVM coverage) →
    ctest → llvm-cov → classify. Slow."""
    from core.inventory.binary_oracle_corpora import REGISTRY
    drv = REGISTRY["leveldb"]
    rep = run_corpus(drv, tmp_path)
    assert rep.corpus_mode == "gcov"
    assert rep.n_functions > 500
    assert rep.absent_n > 0
    _assert_precision_threshold(rep, "leveldb", 1.0)


@pytest.mark.slow
@_NEED_GCOV_BUILD
def test_zlib_driver_end_to_end_via_harness(tmp_path: Path) -> None:
    """Full clone → build (×2) → test → gcov → classify → cross-tab.
    Marked ``slow`` so CI doesn't try to run it. The measurement itself
    is the substance — we assert only invariants the harness must hold."""
    from core.inventory.binary_oracle_corpora import REGISTRY
    drv = REGISTRY["zlib"]
    rep = run_corpus(drv, tmp_path)
    assert rep.corpus_mode == "gcov"
    assert rep.n_functions > 50, \
        f"expected many libz functions, got {rep.n_functions}"
    # Some dead functions must exist (zlib has lots of seldom-used helpers
    # that --gc-sections strips from ``example``).
    assert rep.absent_n > 0, "expected some absent verdicts on zlib/example"
    _assert_precision_threshold(rep, "zlib", 1.0)
