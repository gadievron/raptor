"""Reachability audit harness + committed synthetic dead-code corpus.

This is the CI regression gate for the reachability substrate: a small,
generic, multi-shape corpus of dead and live functions (no relation to any
external corpus — deprecation stubs, disabled guards, orphans, framework
handlers). The harness classifies each and the test asserts:

  * coverage == 1.0   — every labelled-dead function is caught, and
  * false_suppress == 0 — no labelled-live function is wrongly called dead
    (the false-negative-critical contract).

The Python corpus runs everywhere (stdlib ast). The C dead-island case is
gated on tree-sitter-c (the call graph it needs), exercising the
no_path_from_entry witness where the grammar is present.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.inventory.reach_audit import audit_corpus, classify_reachability


def _write(root: Path, rel: str, body: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)


def _python_corpus(root: Path) -> dict:
    # live: called from main / framework handler. dead: orphan / disabled
    # module / always-false guard.
    _write(root, "app/main.py",
           "from app.handlers import live_handler\n"
           "def main():\n"
           "    return live_handler(1)\n")
    _write(root, "app/handlers.py",
           "def live_handler(x):\n"
           "    return x + 1\n"
           "def orphan(x):\n"
           "    return x - 1\n")
    _write(root, "app/disabled.py",
           "raise ImportError('module retired')\n"
           "def vuln_below(cmd):\n"
           "    import os; os.system(cmd)\n")
    _write(root, "app/legacy.py",
           "if False:\n"
           "    def dead_guarded(x):\n"
           "        return x\n"
           "def used_here():\n"
           "    return dead_guarded(1)\n")  # references the guarded name
    _write(root, "app/api.py",
           "from flask import Flask\n"
           "app = Flask(__name__)\n"
           "@app.route('/x')\n"
           "def route_handler():\n"
           "    return 'ok'\n")
    return {
        ("app/main.py", "main"): "live",
        ("app/handlers.py", "live_handler"): "live",
        ("app/handlers.py", "orphan"): "dead",
        ("app/disabled.py", "vuln_below"): "dead",
        ("app/legacy.py", "dead_guarded"): "dead",
        ("app/api.py", "route_handler"): "live",
    }


def test_python_corpus_full_coverage_zero_false_suppress(tmp_path):
    labels = _python_corpus(tmp_path)
    report = audit_corpus(str(tmp_path), labels)
    assert report.false_suppress == 0, (
        f"live functions wrongly called dead: {report.false_suppress_detail}"
    )
    assert report.coverage == 1.0, (
        f"dead functions missed: {report.missed_detail}"
    )


def test_c_dead_island_caught(tmp_path):
    pytest.importorskip("tree_sitter_c")
    # static helper reachable only via a static peer that is itself
    # referenced solely from an unread (static) function-pointer table —
    # an orphaned dead-island. A non-static function is a live entry.
    _write(tmp_path, "m.c",
           "static int read_be(const unsigned char *p){ return p[0]; }\n"
           "static int parse(const unsigned char *p){ return read_be(p); }\n"
           "static int (*const table[])(const unsigned char *) = { parse };\n"
           "int public_api(const unsigned char *p){ return p[1]; }\n")
    labels = {
        ("m.c", "read_be"): "dead",
        ("m.c", "parse"): "dead",
        ("m.c", "public_api"): "live",
    }
    report = audit_corpus(str(tmp_path), labels)
    assert report.false_suppress == 0, report.false_suppress_detail
    assert report.coverage == 1.0, report.missed_detail
    # specifically the dead-island verdict, not just "not_called"
    assert report.per_verdict.get("no_path_from_entry", 0) >= 1


def test_missing_function_is_not_found_not_false_suppress(tmp_path):
    # A labelled function that the extractor never produced is an
    # extraction gap, not a reachability misclassification — it must land
    # in not_found, never in false_suppress (which would falsely fail the
    # FN gate).
    _write(tmp_path, "m.py", "def real(): pass\n")
    report = audit_corpus(str(tmp_path), {
        ("m.py", "ghost"): "live",   # never extracted
        ("m.py", "real"): "dead",
    })
    assert report.false_suppress == 0
    assert report.not_found == 1
    assert ("m.py", "ghost") in report.not_found_detail


def test_label_dead_means_statically_dead_not_deployment_isolated(tmp_path):
    # Boundary doc: "dead" labels mean STATICALLY unreachable. Code that
    # genuinely runs but is excluded from a deployment (e.g. a non-static C
    # helper that another TU could link, or Go init() that runs at load)
    # is correctly "reachable" — the substrate doesn't model deployment
    # isolation (operator knowledge). Here: a non-static C function is an
    # entry, so it's reachable, not a coverage miss.
    pytest.importorskip("tree_sitter_c")
    _write(tmp_path, "lib.c",
           "int linkable(int x){ return x; }\n")  # non-static = entry
    report = audit_corpus(str(tmp_path), {("lib.c", "linkable"): "live"})
    assert report.false_suppress == 0
    assert report.live_ok == 1


def test_classify_precedence_module_abort_wins(tmp_path):
    # A function below a top-level abort classifies module_aborts even if
    # it also reads as called by a peer.
    _write(tmp_path, "d.py",
           "raise ImportError('x')\n"
           "def a():\n"
           "    return b()\n"
           "def b():\n"
           "    return a()\n")
    import tempfile
    from core.inventory.builder import build_inventory
    with tempfile.TemporaryDirectory() as td:
        inv = build_inventory(str(tmp_path), td)
    assert classify_reachability(inv, "d.py", "a", 2, "d") == "module_aborts"


def test_classify_build_excluded_whole_file():
    # A build-excluded file (e.g. Go //go:build ignore): every function is
    # dead, even `main` / `init` which are normally Go entries. Synthetic
    # inventory keeps this tree-sitter-independent.
    inv = {"files": [{
        "path": "go/gen.go", "language": "go",
        "build_excluded": {"line": 1, "summary": "//go:build ignore"},
        "items": [{"name": "main", "kind": "function",
                   "line_start": 3, "line_end": 5}],
    }]}
    assert classify_reachability(
        inv, "go/gen.go", "main", 3, "go.gen") == "build_excluded"


def test_classify_sound_witness_beats_build_excluded():
    # When a function sits below a (sound) module-abort in a file that is ALSO
    # build-excluded, the sound verdict wins — it can hard-suppress, whereas
    # build_excluded is heuristic. (A Go file with both a `func init(){panic}`
    # and a build constraint: functions below the init-panic read
    # module_aborts; init itself / functions above read build_excluded.)
    inv = {"files": [{
        "path": "go/m.go", "language": "go",
        "module_aborts_on_load": {"line": 2, "summary": "func init(){panic}"},
        "build_excluded": {"line": 1, "summary": "//go:build ignore"},
        "items": [{"name": "sink", "kind": "function", "line_start": 4}],
    }]}
    assert classify_reachability(
        inv, "go/m.go", "sink", 4, "go.m") == "module_aborts"
