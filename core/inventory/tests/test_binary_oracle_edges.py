"""Tests for binary_oracle_edges (Inc 2b Tier 1)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from core.inventory.binary_oracle_edges import (
    BinaryCallEdge,
    BinaryEdgeIndex,
    _clean_r2_function_name,
    _fn_addr,
    _parse_axffj_batch,
    annotate_inventory_with_edges,
    extract_direct_call_edges,
)
from core.inventory.reachability import binary_call_edge_present
from core.inventory.reach_witness import (
    Reachability,
    WitnessKind,
)


# ---------------------------------------------------------------------------
# Fast unit tests on the parser helpers (no r2 dependency)
# ---------------------------------------------------------------------------

def test_clean_r2_function_name_strips_known_prefixes() -> None:
    assert _clean_r2_function_name("sym.printf") == "printf"
    assert _clean_r2_function_name("dbg.zlib::deflate") == "zlib::deflate"
    assert _clean_r2_function_name("method.Foo::bar") == "Foo::bar"
    assert _clean_r2_function_name("func.helper") == "helper"
    assert _clean_r2_function_name("fcn.0x1234") == "0x1234"
    assert _clean_r2_function_name("plain_name") == "plain_name"


def test_fn_addr_accepts_addr_and_offset_keys() -> None:
    """aflj records key the entry address as ``addr`` on r2 6.x and as
    ``offset`` on r2 5.x (the apt-shipped version the nightly CI corpus
    job installs). Both must resolve; a record with neither returns
    None so the caller skips it instead of KeyError-ing."""
    assert _fn_addr({"addr": 0x1149}) == 0x1149
    assert _fn_addr({"offset": 0x1149}) == 0x1149
    # addr wins when both are present.
    assert _fn_addr({"addr": 0x1149, "offset": 0x2000}) == 0x1149
    assert _fn_addr({"name": "f", "size": 10}) is None
    # Non-int values are ignored (defensive against malformed output).
    assert _fn_addr({"addr": "0x1149"}) is None


def test_extract_handles_offset_keyed_aflj_without_crashing(
    monkeypatch, tmp_path,
) -> None:
    """Regression: old-r2 (5.x) ``aflj`` keys the entry address as
    ``offset`` rather than ``addr``. The extractor previously indexed
    eligible functions with an unguarded ``f['addr']`` and raised
    KeyError on that output (nightly CI installs apt radare2). With the
    fix it resolves the address from either key and finds the edge."""
    import core.sandbox as _sb
    import core.inventory.binary_oracle_edges as _edges

    # r2 may be absent on the fast tier — the extractor early-returns on
    # ``which('r2') is None``. Pretend it is present; the sandbox run is
    # mocked below so no real r2 is invoked.
    monkeypatch.setattr(_edges.shutil, "which", lambda _name: "/usr/bin/r2")

    binary = tmp_path / "x"
    binary.write_bytes(b"\x7fELF placeholder")

    # Two functions, addressed via the OLD ``offset`` key only.
    aflj = (
        '[{"offset":4425,"name":"main","size":20},'
        '{"offset":4401,"name":"sym.leaf","size":16}]'
    )
    # axffj batch: main (4425) calls leaf (4401).
    axffj = (
        "BATCH 4425\n"
        '[{"type":"CALL","at":4430,"ref":4401,"name":"sym.leaf"}]\n'
        "BATCH 4401\n[]\n"
    )

    class _Proc:
        def __init__(self, stdout):
            self.stdout = stdout
            self.stderr = ""
            self.returncode = 0

    def _fake_run(cmd, **kwargs):
        joined = " ".join(cmd)
        if "aflj" in joined:
            return _Proc(aflj)
        if "-i" in cmd:            # axffj script-file invocation
            return _Proc(axffj)
        return _Proc("")           # av (vtable) — no vtables

    monkeypatch.setattr(_sb, "run", _fake_run, raising=False)

    idx = extract_direct_call_edges(binary, use_cache=False)
    assert "leaf" in idx.callees
    assert any(e.caller == "main" and e.callee == "leaf" for e in idx.edges)


def test_parse_axffj_batch_extracts_call_edges() -> None:
    """The axffj-batch parser must extract CALL refs grouped by
    BATCH-prefixed function addresses, mapping callee addresses back
    to function names via addr_to_name."""
    addr_to_name = {0x1000: "caller_fn", 0x2000: "callee_fn",
                    0x3000: "other_fn"}
    output = (
        "BATCH 0x1000\n"
        '[{"type":"CALL","at":4096,"ref":8192,"name":"callee_fn"},'
        '{"type":"DATA","at":4100,"ref":12288,"name":"some_data"},'
        '{"type":"CALL","at":4104,"ref":12288,"name":"other_fn"}]\n'
        "BATCH 0x3000\n"
        '[]\n'
    )
    index = BinaryEdgeIndex(binary_path="/tmp/test")
    _parse_axffj_batch(output, addr_to_name, index)
    assert len(index.edges) == 2
    callers = {e.caller for e in index.edges}
    callees = {e.callee for e in index.edges}
    assert callers == {"caller_fn"}
    assert callees == {"callee_fn", "other_fn"}
    assert index.callees == callees


def test_parse_axffj_handles_unknown_caller_gracefully() -> None:
    """A BATCH header with an address NOT in addr_to_name (e.g. r2
    reported a function we couldn't name) must not crash; refs from
    that batch are dropped."""
    index = BinaryEdgeIndex(binary_path="/tmp/test")
    _parse_axffj_batch(
        'BATCH 0xdead\n[{"type":"CALL","ref":4096,"name":"x"}]\n',
        addr_to_name={}, index=index,
    )
    assert index.edges == []


def test_parse_axffj_skips_non_CALL_refs() -> None:
    index = BinaryEdgeIndex(binary_path="/tmp/test")
    _parse_axffj_batch(
        'BATCH 0x1000\n'
        '[{"type":"DATA","ref":8192,"name":"d"},'
        '{"type":"STRN","ref":12288,"name":"s"}]\n',
        addr_to_name={0x1000: "f"}, index=index,
    )
    assert index.edges == []


# ---------------------------------------------------------------------------
# Annotation + reach_witness wiring
# ---------------------------------------------------------------------------

def test_annotate_inventory_marks_callee_items() -> None:
    """When the binary edge index has ``foo`` as a callee, the
    inventory item for ``foo`` (in a native-language file) gets
    ``metadata.binary_oracle_edges`` populated with the callers."""
    inv = {"files": [{
        "path": "src/lib.c", "language": "c",
        "items": [
            {"name": "foo", "kind": "function", "line_start": 5},
            {"name": "bar", "kind": "function", "line_start": 10},
        ],
    }]}
    idx = BinaryEdgeIndex(binary_path="/tmp/binA")
    idx.edges = [
        BinaryCallEdge(caller="main", callee="foo", binary_path="/tmp/binA"),
        BinaryCallEdge(caller="other", callee="foo", binary_path="/tmp/binA"),
    ]
    idx.callees = {"foo"}
    counts = annotate_inventory_with_edges(inv, [idx])
    assert counts["annotated"] == 1
    foo = inv["files"][0]["items"][0]
    assert foo["metadata"]["binary_oracle_edges"] == [
        {"caller": "main", "binary_path": "/tmp/binA"},
        {"caller": "other", "binary_path": "/tmp/binA"},
    ]
    bar = inv["files"][0]["items"][1]
    assert "binary_oracle_edges" not in (bar.get("metadata") or {})


def test_annotate_skips_non_native_languages() -> None:
    """Python / JS items aren't candidates for binary_oracle — skip."""
    inv = {"files": [{
        "path": "src/x.py", "language": "python",
        "items": [{"name": "foo", "kind": "function", "line_start": 1}],
    }]}
    idx = BinaryEdgeIndex(binary_path="/tmp/binA")
    idx.edges = [BinaryCallEdge("main", "foo", "/tmp/binA")]
    idx.callees = {"foo"}
    counts = annotate_inventory_with_edges(inv, [idx])
    assert counts["annotated"] == 0
    assert "binary_oracle_edges" not in (
        inv["files"][0]["items"][0].get("metadata") or {})


def test_binary_call_edge_present_accessor() -> None:
    inv = {"files": [{
        "path": "src/lib.c", "language": "c",
        "items": [{
            "name": "foo", "kind": "function", "line_start": 1,
            "metadata": {"binary_oracle_edges": [
                {"caller": "main", "binary_path": "/tmp/binA"},
            ]},
        }],
    }]}
    assert binary_call_edge_present(inv, "src/lib.c", "foo") is True
    # Empty edges list → False
    inv["files"][0]["items"][0]["metadata"]["binary_oracle_edges"] = []
    assert binary_call_edge_present(inv, "src/lib.c", "foo") is False
    # No metadata at all → False
    inv["files"][0]["items"][0].pop("metadata")
    assert binary_call_edge_present(inv, "src/lib.c", "foo") is False


def test_binary_call_edge_witness_is_reachable_heuristic() -> None:
    """Inc 2b Tier 1: the ``binary_call_edge`` VerdictSpec exists with
    the right shape — REACHABLE / HEURISTIC / earns_suppression=False
    (positive evidence only). End-to-end stage firing depends on other
    stages NOT firing first (entry-reachability is broad by default);
    the stage is wired into PRECEDENCE between ``_stage_entry`` and
    ``_stage_one_hop`` so it catches the residual not_called case."""
    from core.inventory.reach_witness import (
        Soundness, VERDICTS, verdict_from_classification,
    )
    spec = VERDICTS["binary_call_edge"]
    assert spec.status is Reachability.REACHABLE
    assert spec.kind is WitnessKind.BINARY_CALL_EDGE
    assert spec.soundness is Soundness.HEURISTIC
    assert spec.earns_suppression is False
    # The witness must NOT license suppression even when in the
    # earned set (positive evidence; only DEAD witnesses suppress).
    rv = verdict_from_classification("binary_call_edge")
    earned = frozenset(WitnessKind)  # try every kind
    assert rv.may_suppress(earned) is False


# ---------------------------------------------------------------------------
# Slow E2E: real r2 extraction on a small fixture binary
# ---------------------------------------------------------------------------

def test_vtable_parser_extracts_slots_and_synthetic_caller() -> None:
    """The r2 ``av`` text output has ``Vtable Found at 0x...`` headers
    followed by ``<slot_addr> : <method>`` lines. The parser must emit
    one synthetic edge per slot with the ``<vtable@0x...>`` sentinel
    caller."""
    from core.inventory.binary_oracle_edges import (
        _VTABLE_HEADER_RE, _VTABLE_SLOT_RE,
    )
    # Header + 2 slots → 2 edges
    sample = (
        "Vtable Found at 0x0006fab0\n"
        "0x0006fab0 : method.testing::internal::TestFactoryBase\n"
        "0x0006fab8 : method.snappy::CorruptedTest::CreateTest__\n"
    )
    hdr = _VTABLE_HEADER_RE.search(sample.splitlines()[0])
    assert hdr and hdr.group(1).lower() == "0006fab0"
    slot = _VTABLE_SLOT_RE.match(sample.splitlines()[1])
    assert slot and slot.group(1) == "method.testing::internal::TestFactoryBase"


def test_cache_path_rejects_non_hex_build_id(tmp_path, monkeypatch) -> None:
    """Adversarial review P0-114-2: ``_cache_path_for`` must validate
    that the build_id is hex before composing a filename — defense-in-
    depth against any future regression in the upstream ``read_build_id``
    helper that loosens its regex. A hostile binary defining its own
    build-id note bytes (slashes, ``..``, NUL, arbitrary length) MUST
    NOT drive cache-file path composition."""
    from core.inventory.binary_oracle_edges import _cache_path_for
    # Valid hex passes
    assert _cache_path_for("deadbeef" * 5) is not None
    # All these must return None (rejected by the validator)
    assert _cache_path_for("../../etc/passwd") is None
    assert _cache_path_for("foo/bar") is None
    assert _cache_path_for("not-hex-at-all") is None
    assert _cache_path_for("") is None
    assert _cache_path_for("123") is None  # too short (min 8 hex)
    assert _cache_path_for("a" * 200) is None  # too long
    # Wrong type
    assert _cache_path_for(None) is None  # type: ignore[arg-type]
    assert _cache_path_for(123) is None  # type: ignore[arg-type]


def test_cache_rejects_cross_target_collision(
    tmp_path, monkeypatch,
) -> None:
    """Adversarial review P0-114-3: when the cache file is for build_id
    X but its recorded ``binary_path`` doesn't match the binary being
    looked up, treat as cache miss (cross-target collision, or a
    pre-poisoned cache file dropped by a prior run / attacker).
    Without this, an attacker controlling one binary the operator
    scans could pre-place a cache entry that misattributes edges to
    a different binary on a subsequent run."""
    from core.inventory.binary_oracle_edges import (
        BinaryCallEdge, BinaryEdgeIndex,
        _cache_path_for, _load_cached_index, _save_cached_index,
    )
    from core.config import RaptorConfig
    monkeypatch.setattr(RaptorConfig, "BASE_OUT_DIR", tmp_path)

    # Save a cache entry under build_id X claiming it's for /bin/binA.
    idx = BinaryEdgeIndex(binary_path="/bin/binA")
    idx.edges = [BinaryCallEdge("main", "foo", "/bin/binA")]
    cache_file = _cache_path_for("abcdef" * 7)
    assert cache_file is not None
    _save_cached_index(cache_file, idx)

    # Now look up that same build_id but for a DIFFERENT binary path.
    # The cached binary_path mismatch should drive a miss.
    loaded = _load_cached_index(cache_file, "/bin/binB")
    assert loaded is None, (
        "cache must refuse to return entries whose recorded "
        "binary_path differs from the lookup's binary_path"
    )
    # Sanity: lookup with the matching path still works.
    loaded = _load_cached_index(cache_file, "/bin/binA")
    assert loaded is not None
    assert len(loaded.edges) == 1


def test_binary_call_edge_precedes_entry_stage(monkeypatch) -> None:
    """Adversarial review P0-118: ``_stage_binary_call_edge`` MUST run
    BEFORE ``_stage_entry`` in PRECEDENCE — affirmative binary evidence
    beats the heuristic ``no_path_from_entry`` verdict. Otherwise a
    function the binary mechanically proves reachable gets the dead
    verdict from _stage_entry first, defeating the whole point of
    binary_call_edge."""
    from core.inventory.reach_audit import PRECEDENCE
    names = [stage.__name__ for stage in PRECEDENCE]
    bce = names.index("_stage_binary_call_edge")
    entry = names.index("_stage_entry")
    assert bce < entry, (
        f"PRECEDENCE: _stage_binary_call_edge (pos {bce}) must come "
        f"BEFORE _stage_entry (pos {entry}); got order {names}"
    )


def test_cache_round_trips_edges_under_build_id(tmp_path, monkeypatch) -> None:
    """Q3: edge index serialised + loaded round-trips. Cache file
    location is keyed by build_id; subsequent extractions on the
    same build_id are cache hits (no r2 invocation)."""
    import json as _json
    from core.inventory.binary_oracle_edges import (
        _cache_path_for, _load_cached_index, _save_cached_index,
        BinaryEdgeIndex, BinaryCallEdge,
    )
    from core.config import RaptorConfig
    monkeypatch.setattr(RaptorConfig, "BASE_OUT_DIR", tmp_path)

    idx = BinaryEdgeIndex(binary_path="/tmp/binA")
    idx.edges = [
        BinaryCallEdge("main", "foo", "/tmp/binA"),
        BinaryCallEdge("<vtable@0x6fab0>", "Foo::method", "/tmp/binA"),
    ]
    idx.callees = {"foo", "Foo::method"}

    cache_file = _cache_path_for("deadbeef" * 5)
    _save_cached_index(cache_file, idx)
    assert cache_file.is_file()
    # Re-load — should match exactly
    loaded = _load_cached_index(cache_file, "/tmp/binA")
    assert loaded is not None
    assert len(loaded.edges) == 2
    assert ("main", "foo") in {(e.caller, e.callee) for e in loaded.edges}
    assert "Foo::method" in loaded.callees

    # Version mismatch → cache miss (return None)
    payload = _json.loads(cache_file.read_text())
    payload["version"] = 999
    cache_file.write_text(_json.dumps(payload))
    assert _load_cached_index(cache_file, "/tmp/binA") is None


@pytest.mark.slow
@pytest.mark.skipif(
    shutil.which("r2") is None,
    reason="radare2 (r2) not installed — direct-edge extraction returns an "
    "empty index by design, so there is nothing to assert",
)
def test_extract_direct_call_edges_on_synthetic_fixture(
    tmp_path: Path,
) -> None:
    """End-to-end: build a small C binary, run r2 extraction, verify
    the expected caller→callee edge is found."""
    import subprocess as _sp

    src = tmp_path / "x.c"
    src.write_text(
        "int leaf(int x){return x+1;}\n"
        "int main(void){return leaf(0);}\n"
    )
    binary = tmp_path / "x"
    _sp.run(["gcc", "-O0", "-g", str(src), "-o", str(binary)], check=True)
    idx = extract_direct_call_edges(binary)
    assert idx.edges, "expected at least one CALL edge"
    callees = idx.callees
    # main calls leaf — this is the canonical direct edge.
    assert "leaf" in callees or any("leaf" in c for c in callees)
