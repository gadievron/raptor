"""Tests for the mechanical ownership/privilege site enrichment
(``context_map_sites``).

Fully deterministic — no LLM, no cocci. The enricher is driven by a
duck-typed SourceIntelResult.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# packages/code_understanding/tests/test_context_map_sites.py
#   parents[0]=tests  [1]=code_understanding  [2]=packages  [3]=repo
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from packages.code_understanding.context_map_sites import (  # noqa: E402
    enrich_context_map_with_sites,
)


class _Ev:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _SI:
    """Duck-typed stand-in for SourceIntelResult."""

    _FIELDS = (
        "allocations", "checked_allocations", "paired_frees",
        "double_frees", "capabilities", "lsm_hooks", "lock_sites",
        "crypto_calls",
    )

    def __init__(self, **kw):
        for f in self._FIELDS:
            setattr(self, f, tuple(kw.get(f, ())))


# --- enricher -------------------------------------------------------------


def test_ownership_sites_aggregated_with_kinds_and_fields():
    si = _SI(
        allocations=[_Ev(location=("a.c", 10), enclosing_function="f",
                         allocator="kmalloc")],
        double_frees=[_Ev(location=("b.c", 20), enclosing_function="g",
                          free_fn="kfree", role="second")],
        paired_frees=[_Ev(location=("c.c", 5), enclosing_function="h",
                          allocator="kzalloc", free_fn="kfree")],
    )
    cmap: dict = {}
    counts = enrich_context_map_with_sites(cmap, si)
    assert counts["ownership_model"] == 3
    own = cmap["ownership_model"]
    assert {e["kind"] for e in own} == {"alloc", "double_free", "paired_free"}
    alloc = next(e for e in own if e["kind"] == "alloc")
    assert alloc == {
        "kind": "alloc", "file": "a.c", "line": 10,
        "function": "f", "allocator": "kmalloc",
    }
    df = next(e for e in own if e["kind"] == "double_free")
    assert df["free_fn"] == "kfree" and df["role"] == "second"


def test_privilege_sites():
    si = _SI(
        capabilities=[_Ev(location=("k.c", 1), enclosing_function="sys_x",
                          cap_function="capable", grade="same_function")],
        lsm_hooks=[_Ev(location=("k.c", 9), enclosing_function="sys_y",
                       hook_name="security_file_open")],
    )
    cmap: dict = {}
    counts = enrich_context_map_with_sites(cmap, si)
    assert counts["privilege_model"] == 2
    assert {e["kind"] for e in cmap["privilege_model"]} == {
        "capability", "lsm_hook",
    }
    cap = next(e for e in cmap["privilege_model"] if e["kind"] == "capability")
    assert cap["name"] == "capable" and cap["grade"] == "same_function"


def test_shared_state_sites_aggregated_with_kind_op_compound():
    # Coverage: every (op × kind) pair carries fn + lock_var alongside.
    si = _SI(lock_sites=[
        _Ev(location=("d.c", 11), enclosing_function="do_work",
            op="acquire", kind="spin", fn="spin_lock", lock_var="&sl"),
        _Ev(location=("d.c", 14), enclosing_function="do_work",
            op="release", kind="spin", fn="spin_unlock", lock_var="&sl"),
        _Ev(location=("d.c", 22), enclosing_function="do_work",
            op="acquire", kind="mutex", fn="mutex_lock_interruptible",
            lock_var="&m"),
        _Ev(location=("d.c", 25), enclosing_function="do_work",
            op="release", kind="mutex", fn="mutex_unlock", lock_var="&m"),
        _Ev(location=("e.c", 3), enclosing_function="thread_fn",
            op="acquire", kind="pthread_mutex", fn="pthread_mutex_lock",
            lock_var="&pm"),
    ])
    cmap: dict = {}
    counts = enrich_context_map_with_sites(cmap, si)
    assert counts["shared_state"] == 5
    ss = cmap["shared_state"]
    # compound kind = <lock_kind>_<op>; fn + lock_var preserved.
    assert {e["kind"] for e in ss} == {
        "spin_acquire", "spin_release",
        "mutex_acquire", "mutex_release",
        "pthread_mutex_acquire",
    }
    spin_acq = next(e for e in ss if e["kind"] == "spin_acquire")
    assert spin_acq == {
        "kind": "spin_acquire", "file": "d.c", "line": 11,
        "function": "do_work", "fn": "spin_lock", "lock_var": "&sl",
    }


def test_shared_state_section_omitted_when_empty():
    # No lock_sites → no shared_state key written (mirrors the
    # ownership_model / privilege_model contract: never shadow an LLM
    # populator with an empty list).
    cmap: dict = {}
    counts = enrich_context_map_with_sites(cmap, _SI())
    assert counts["shared_state"] == 0
    assert "shared_state" not in cmap


def test_crypto_inventory_sites_aggregated_with_api_and_fn():
    # Coverage: both kinds × across-API mix carries api + fn alongside.
    si = _SI(crypto_calls=[
        _Ev(location=("c.c", 11), enclosing_function="encrypt_record",
            kind="primitive_call", api="openssl", fn="EVP_EncryptInit_ex"),
        _Ev(location=("c.c", 14), enclosing_function="encrypt_record",
            kind="primitive_call", api="openssl", fn="EVP_EncryptUpdate"),
        _Ev(location=("c.c", 22), enclosing_function="seed_state",
            kind="rng_source", api="openssl", fn="RAND_bytes"),
        _Ev(location=("c.c", 33), enclosing_function="legacy_hash",
            kind="primitive_call", api="libsodium",
            fn="crypto_generichash"),
        _Ev(location=("c.c", 40), enclosing_function="legacy_hash",
            kind="rng_source", api="libc", fn="rand"),
    ])
    cmap: dict = {}
    counts = enrich_context_map_with_sites(cmap, si)
    assert counts["crypto_inventory"] == 5
    inv = cmap["crypto_inventory"]
    # kind is the call kind directly (primitive_call / rng_source); api +
    # fn ride alongside so a consumer can filter without re-parsing.
    assert {e["kind"] for e in inv} == {"primitive_call", "rng_source"}
    assert {e["api"] for e in inv} == {"openssl", "libsodium", "libc"}
    evp_init = next(e for e in inv if e["fn"] == "EVP_EncryptInit_ex")
    assert evp_init == {
        "kind": "primitive_call", "file": "c.c", "line": 11,
        "function": "encrypt_record", "api": "openssl",
        "fn": "EVP_EncryptInit_ex",
    }


def test_crypto_inventory_section_omitted_when_empty():
    cmap: dict = {}
    counts = enrich_context_map_with_sites(cmap, _SI())
    assert counts["crypto_inventory"] == 0
    assert "crypto_inventory" not in cmap


def test_empty_result_writes_no_keys():
    cmap = {"entry_points": []}
    counts = enrich_context_map_with_sites(cmap, _SI())
    assert counts == {"ownership_model": 0, "privilege_model": 0,
                      "shared_state": 0, "crypto_inventory": 0}
    assert "ownership_model" not in cmap and "privilege_model" not in cmap


def test_idempotent_overwrite():
    si = _SI(allocations=[_Ev(location=("a.c", 1), enclosing_function="f",
                              allocator="kmalloc")])
    cmap: dict = {}
    enrich_context_map_with_sites(cmap, si)
    enrich_context_map_with_sites(cmap, si)
    assert len(cmap["ownership_model"]) == 1  # overwrite, not append


def test_best_effort_on_malformed_evidence():
    # Missing/!=2-tuple location -> file/line None, no crash.
    si = _SI(allocations=[_Ev(enclosing_function="f")])
    cmap: dict = {}
    counts = enrich_context_map_with_sites(cmap, si)
    assert counts["ownership_model"] == 1
    e = cmap["ownership_model"][0]
    assert e["file"] is None and e["line"] is None


def test_non_dict_cmap_is_noop():
    assert enrich_context_map_with_sites(None, _SI()) == {
        "ownership_model": 0, "privilege_model": 0,
        "shared_state": 0, "crypto_inventory": 0,
    }


def test_relativizes_absolute_paths_to_repo_root():
    # source_intel emits ABSOLUTE paths; the map (and the annotation
    # substrate) want repo-relative. Regression: real-spatch E2E showed
    # absolute paths breaking annotation writes.
    si = _SI(allocations=[_Ev(location=("/repo/src/a.c", 3),
                              enclosing_function="f", allocator="kmalloc")])
    cmap: dict = {}
    enrich_context_map_with_sites(cmap, si, repo_root="/repo")
    assert cmap["ownership_model"][0]["file"] == "src/a.c"


def test_path_outside_repo_root_left_as_is():
    si = _SI(allocations=[_Ev(location=("/other/a.c", 3),
                              enclosing_function="f", allocator="kmalloc")])
    cmap: dict = {}
    enrich_context_map_with_sites(cmap, si, repo_root="/repo")
    assert cmap["ownership_model"][0]["file"] == "/other/a.c"


def test_degrades_gracefully_without_spatch(monkeypatch):
    # Force spatch unavailable (the cocci-missing case the operator asked
    # about). analyze() must RETURN a skipped result, not raise; the
    # enricher must then no-op (no sections written).
    import packages.coccinelle.runner as cocci_runner
    monkeypatch.setattr(cocci_runner, "is_available", lambda: False)

    from packages.source_intel import analyze
    si = analyze(Path("/any/target"))
    assert si.skipped_reason == "spatch_not_available"  # returned, didn't raise

    cmap = {"entry_points": []}
    counts = enrich_context_map_with_sites(cmap, si)
    assert counts == {"ownership_model": 0, "privilege_model": 0,
                      "shared_state": 0, "crypto_inventory": 0}
    assert "ownership_model" not in cmap and "privilege_model" not in cmap



# --- producer shim --------------------------------------------------------

_SHIM = REPO / "libexec" / "raptor-enrich-context-map-sites"


def test_shim_requires_trust_marker():
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDECODE", "_RAPTOR_TRUSTED")}
    r = subprocess.run([sys.executable, str(_SHIM), "/tmp"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 2
    assert "internal dispatch script" in r.stderr


def test_shim_noop_on_non_c_target(tmp_path):
    # source_intel.analyze is skip-silent on a non-C/C++ target, so the shim
    # leaves the map untouched and exits 0 — deterministic, no spatch needed.
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "notes.txt").write_text("not source", encoding="utf-8")
    out = tmp_path / "run"
    out.mkdir()
    (out / "checklist.json").write_text(
        json.dumps({"target_path": str(repo)}), encoding="utf-8",
    )
    cmap = {"entry_points": []}
    (out / "context-map.json").write_text(json.dumps(cmap), encoding="utf-8")

    env = {**os.environ, "_RAPTOR_TRUSTED": "1"}
    r = subprocess.run([sys.executable, str(_SHIM), str(out)],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    after = json.loads((out / "context-map.json").read_text(encoding="utf-8"))
    assert "ownership_model" not in after and "privilege_model" not in after
