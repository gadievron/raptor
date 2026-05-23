"""Tests for ``core.reporting.witnesses`` — the on-disk
WitnessStore → operator-summary helper."""

from __future__ import annotations

import sys
from pathlib import Path


# core/reporting/tests/test_witnesses.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.reporting import (  # noqa: E402
    build_witness_summary,
    render_witness_summary,
)
from core.witness import (  # noqa: E402
    Witness,
    WitnessOutcome,
    WitnessSource,
    WitnessStore,
    compute_bytes_hash,
)


def _put(store: WitnessStore, *, source: WitnessSource,
         outcome: WitnessOutcome, data: bytes,
         compiled: bool = None) -> None:
    """Helper: add a Witness with the given source/outcome."""
    detail = {"finding_id": data.decode("utf-8", errors="replace")[:16]}
    if compiled is not None:
        detail["compiled"] = compiled
    w = Witness(
        bytes_hash=compute_bytes_hash(data),
        bytes_len=len(data),
        source=source,
        observed_outcome=outcome,
        outcome_detail=detail,
    )
    store.put(w, data)


# ----------------------------------------------------------------------
# build_witness_summary
# ----------------------------------------------------------------------


def test_empty_store_returns_zero_shape(tmp_path):
    """No directory → empty summary, no exception."""
    summary = build_witness_summary(tmp_path / "does_not_exist")
    assert summary["total"] == 0
    assert summary["by_source"] == {}
    assert summary["by_outcome"] == {}
    assert summary["executed"] == 0
    assert summary["compiled"] == 0


def test_none_dir_returns_zero_shape():
    summary = build_witness_summary(None)
    assert summary["total"] == 0


def test_empty_store_directory_returns_zero(tmp_path):
    """Directory exists but no manifests inside."""
    (tmp_path / "manifests").mkdir(parents=True)
    summary = build_witness_summary(tmp_path)
    assert summary["total"] == 0


def test_counts_by_source_and_outcome(tmp_path):
    store = WitnessStore(tmp_path)
    _put(store, source=WitnessSource.FUZZ,
         outcome=WitnessOutcome.EXIT_SIGNAL, data=b"fuzz crash 1")
    _put(store, source=WitnessSource.FUZZ,
         outcome=WitnessOutcome.EXIT_SIGNAL, data=b"fuzz crash 2")
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.NOT_RUN, data=b"llm exploit not run")
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.SANITIZER_REPORT,
         data=b"llm exploit asan", compiled=True)

    summary = build_witness_summary(tmp_path)
    assert summary["total"] == 4
    assert summary["by_source"]["fuzz"] == 2
    assert summary["by_source"]["llm_emit_run"] == 2
    assert summary["by_outcome"]["exit_signal"] == 2
    assert summary["by_outcome"]["not_run"] == 1
    assert summary["by_outcome"]["sanitizer_report"] == 1


def test_executed_count_excludes_not_run(tmp_path):
    """``executed`` is the count of witnesses with any outcome
    other than NOT_RUN — what actually ran in a sandbox."""
    store = WitnessStore(tmp_path)
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.NOT_RUN, data=b"not run 1")
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.NOT_RUN, data=b"not run 2")
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.EXIT_SIGNAL, data=b"crashed")
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.SANITIZER_REPORT, data=b"asan")
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.NO_OBVIOUS_EFFECT, data=b"clean")

    summary = build_witness_summary(tmp_path)
    assert summary["executed"] == 3  # crashed + asan + clean
    assert summary["total"] == 5


def test_compiled_count_only_when_outcome_detail_says_true(tmp_path):
    """``compiled`` reflects ``outcome_detail.compiled is True``.
    The False / None / missing cases don't count."""
    store = WitnessStore(tmp_path)
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.NOT_RUN, data=b"true",
         compiled=True)
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.NOT_RUN, data=b"false",
         compiled=False)
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.NOT_RUN, data=b"missing")

    summary = build_witness_summary(tmp_path)
    assert summary["compiled"] == 1


# ----------------------------------------------------------------------
# render_witness_summary
# ----------------------------------------------------------------------


def test_render_empty_returns_empty_string(tmp_path):
    """Empty stores produce no output — caller can ``if rendered:``
    to skip printing a header for nothing."""
    assert render_witness_summary(tmp_path / "nope") == ""
    (tmp_path / "manifests").mkdir(parents=True)
    assert render_witness_summary(tmp_path) == ""


def test_render_includes_total_and_source_breakdown(tmp_path):
    store = WitnessStore(tmp_path)
    _put(store, source=WitnessSource.FUZZ,
         outcome=WitnessOutcome.EXIT_SIGNAL, data=b"x")
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.NOT_RUN, data=b"y")
    out = render_witness_summary(tmp_path)
    assert "Witnesses recorded: 2" in out
    assert "fuzz: 1" in out
    assert "llm_emit_run: 1" in out
    assert "exit_signal: 1" in out
    assert "not_run: 1" in out


def test_render_compiled_executed_only_when_llm_present(tmp_path):
    """Fuzz-only stores don't show ``Compiled``/``Executed`` lines
    — those concepts only apply to LLM-emit-run witnesses."""
    store = WitnessStore(tmp_path)
    _put(store, source=WitnessSource.FUZZ,
         outcome=WitnessOutcome.EXIT_SIGNAL, data=b"crash")
    out = render_witness_summary(tmp_path)
    assert "Compiled:" not in out
    assert "Executed:" not in out


def test_render_compiled_executed_appear_with_llm(tmp_path):
    store = WitnessStore(tmp_path)
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.SANITIZER_REPORT,
         data=b"poc1", compiled=True)
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.NOT_RUN,
         data=b"poc2", compiled=False)
    out = render_witness_summary(tmp_path)
    assert "Compiled: 1/2 LLM exploits" in out
    assert "Executed: 1/2" in out


def test_render_respects_indent_kwarg(tmp_path):
    store = WitnessStore(tmp_path)
    _put(store, source=WitnessSource.FUZZ,
         outcome=WitnessOutcome.EXIT_SIGNAL, data=b"x")
    out = render_witness_summary(tmp_path, indent=">>")
    assert ">>By source:" in out
    assert ">>   fuzz: 1" in out


# ----------------------------------------------------------------------
# Robustness
# ----------------------------------------------------------------------


def test_malformed_manifest_does_not_break_summary(tmp_path):
    """One bad manifest doesn't abort the whole enumeration —
    WitnessStore.list_witnesses() already skips them; we just
    pin that the helper inherits that behaviour."""
    store = WitnessStore(tmp_path)
    _put(store, source=WitnessSource.FUZZ,
         outcome=WitnessOutcome.EXIT_SIGNAL, data=b"good crash")

    # Drop a deliberately-malformed manifest in the dir
    bad = tmp_path / "manifests" / "deadbeef.json"
    bad.write_text("{not valid json")

    summary = build_witness_summary(tmp_path)
    # The good one still counted; the bad one silently skipped
    assert summary["total"] == 1
    assert summary["by_source"]["fuzz"] == 1


def test_dir_is_a_regular_file_does_not_crash(tmp_path):
    """When the path resolves to a file rather than a directory,
    treat as empty. ``.is_dir()`` returns False on files,
    symlinks-to-nowhere, etc."""
    f = tmp_path / "not_a_dir"
    f.write_text("hi")
    assert build_witness_summary(f)["total"] == 0


def test_binary_noise_manifest_skipped(tmp_path):
    """A manifest file whose bytes aren't valid UTF-8 / JSON is
    skipped, not fatal. Pre-fix path: an early `read_text` on a
    binary blob raised UnicodeDecodeError that propagated."""
    (tmp_path / "manifests").mkdir(parents=True)
    (tmp_path / "manifests" / "noise.json").write_bytes(
        b"\x00\xffnot json\x00"
    )
    assert build_witness_summary(tmp_path)["total"] == 0


def test_unknown_source_enum_value_skipped(tmp_path):
    """Forward-compat: a manifest with a source string that
    isn't in our WitnessSource enum (e.g. a witness written by
    a newer RAPTOR) is skipped rather than crashing the
    helper. Operator sees a partial count + a log warning."""
    import json
    store = WitnessStore(tmp_path)
    _put(store, source=WitnessSource.FUZZ,
         outcome=WitnessOutcome.EXIT_SIGNAL, data=b"x")
    # Mutate the manifest to use an unknown source value
    manifests = list((tmp_path / "manifests").glob("*.json"))
    j = json.loads(manifests[0].read_text())
    j["source"] = "future_unknown_source"
    manifests[0].write_text(json.dumps(j))

    summary = build_witness_summary(tmp_path)
    assert summary["total"] == 0
    assert summary["by_source"] == {}


def test_outcome_detail_none_does_not_crash(tmp_path):
    """Defensive: ``outcome_detail`` arriving as None (corrupted
    or evolution-of-schema manifest) must not crash the
    compiled-count branch. ``isinstance(..., dict)`` guard in
    the helper."""
    import json
    store = WitnessStore(tmp_path)
    _put(store, source=WitnessSource.LLM_EMIT_RUN,
         outcome=WitnessOutcome.NOT_RUN, data=b"x")
    manifests = list((tmp_path / "manifests").glob("*.json"))
    j = json.loads(manifests[0].read_text())
    j["outcome_detail"] = None
    manifests[0].write_text(json.dumps(j))

    summary = build_witness_summary(tmp_path)
    # The witness still counts; compiled is conservatively 0
    # (no detail dict → can't say it compiled)
    assert summary["total"] == 1
    assert summary["compiled"] == 0


def test_unreadable_dir_does_not_crash(tmp_path):
    """A manifests/ dir we can't read (chmod 000 or similar)
    returns an empty summary rather than raising. The operator's
    end-of-run print should never fail because of a permissions
    glitch."""
    import os
    store = WitnessStore(tmp_path)
    _put(store, source=WitnessSource.FUZZ,
         outcome=WitnessOutcome.EXIT_SIGNAL, data=b"x")
    manifests_dir = tmp_path / "manifests"
    os.chmod(manifests_dir, 0o000)
    try:
        summary = build_witness_summary(tmp_path)
        # Either 0 (glob returns empty) or 1 (root-equivalent
        # process can read anyway) is acceptable — the contract
        # is "doesn't raise."
        assert summary["total"] in (0, 1)
    finally:
        os.chmod(manifests_dir, 0o755)
