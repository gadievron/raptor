"""Tests for ``core.orchestration.context_map_ast_view`` — AST-view
enrichment for /understand --map's context-map.json output."""

from __future__ import annotations

from pathlib import Path

from core.orchestration.context_map_ast_view import enrich_with_ast_view


def _project(tmp_path: Path, files: dict) -> Path:
    for rel, contents in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contents)
    return tmp_path


# ---------------------------------------------------------------------------
# Happy path: entry_points + sinks both get ast_view
# ---------------------------------------------------------------------------


def test_enrich_entry_point_and_sink_both_attached(tmp_path):
    target = _project(tmp_path, {
        "src/auth.py": (
            "def check_password(user, pw):\n"   # 1
            "    if user is None:\n"             # 2
            "        return -1\n"                # 3
            "    h = compute_hash(pw)\n"         # 4
            "    if compare(user.h, h):\n"       # 5
            "        return 0\n"                 # 6
            "    return 1\n"                     # 7
        ),
    })
    cmap = {
        "entry_points": [{"id": "EP-001", "file": "src/auth.py", "line": 4}],
        "sinks":        [{"id": "SK-001", "file": "src/auth.py", "line": 5}],
    }
    n = enrich_with_ast_view(cmap, target)
    assert n == 2

    ep = cmap["entry_points"][0]
    assert "ast_view" in ep
    assert ep["ast_view"]["function"] == "check_password"
    assert ep["ast_view"]["language"] == "python"

    sk = cmap["sinks"][0]
    assert "ast_view" in sk
    assert sk["ast_view"]["function"] == "check_password"


def test_trust_boundaries_not_walked(tmp_path):
    """Trust boundaries don't have a single host function — the
    enricher only walks entry_points + sinks. Pin the contract."""
    target = _project(tmp_path, {
        "src/auth.py": "def f(): pass\n",
    })
    cmap = {
        "trust_boundaries": [{"id": "TB-001", "description": "cross-VM"}],
    }
    n = enrich_with_ast_view(cmap, target)
    assert n == 0
    assert "ast_view" not in cmap["trust_boundaries"][0]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_context_map(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): pass\n"})
    assert enrich_with_ast_view({}, target) == 0
    assert enrich_with_ast_view({"entry_points": []}, target) == 0


def test_non_dict_context_map(tmp_path):
    """Robustness: a non-dict value (corrupted JSON) returns 0
    rather than raising."""
    target = _project(tmp_path, {"src/x.py": "def f(): pass\n"})
    assert enrich_with_ast_view([], target) == 0  # type: ignore[arg-type]
    assert enrich_with_ast_view("not a dict", target) == 0  # type: ignore[arg-type]


def test_entry_with_missing_file_field_skipped(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f(): pass\n"})
    cmap = {
        "entry_points": [
            {"id": "EP-NO-FILE", "line": 1},
            {"id": "EP-NO-LINE", "file": "src/x.py"},
        ],
    }
    # Neither has the required (file, line) pair.
    assert enrich_with_ast_view(cmap, target) == 0
    assert "ast_view" not in cmap["entry_points"][0]
    assert "ast_view" not in cmap["entry_points"][1]


def test_module_level_line_skipped(tmp_path):
    """A line at module scope (not inside any function) shouldn't
    get an ast_view block — there's no host function."""
    target = _project(tmp_path, {
        "src/x.py": (
            "import os\n"              # 1 — module-level line
            "def f():\n"                # 2
            "    return os.getcwd()\n"  # 3
        ),
    })
    cmap = {
        "entry_points": [{"id": "EP-MODULE", "file": "src/x.py", "line": 1}],
    }
    n = enrich_with_ast_view(cmap, target)
    assert n == 0
    assert "ast_view" not in cmap["entry_points"][0]


def test_stale_path_skipped(tmp_path):
    """A context-map entry whose file is in the inventory but
    missing on disk now (e.g. moved/deleted between /understand run
    and a re-enrich) shouldn't crash or fabricate an ast_view."""
    target = _project(tmp_path, {"src/keep.py": "def f(): pass\n"})
    cmap = {
        "entry_points": [
            {"id": "EP-STALE", "file": "src/keep.py", "line": 1},
            {"id": "EP-MISSING", "file": "src/nope.py", "line": 1},
        ],
    }
    n = enrich_with_ast_view(cmap, target)
    # Only the valid one is enriched; the stale path is silently
    # skipped (not None, not a crash).
    assert n == 1
    assert "ast_view" in cmap["entry_points"][0]
    assert "ast_view" not in cmap["entry_points"][1]


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_idempotent_rerun(tmp_path):
    target = _project(tmp_path, {
        "src/x.py": "def f():\n    g()\n    return 1\n",
    })
    cmap = {
        "entry_points": [{"id": "EP", "file": "src/x.py", "line": 2}],
    }
    enrich_with_ast_view(cmap, target)
    first = dict(cmap["entry_points"][0])
    enrich_with_ast_view(cmap, target)
    second = dict(cmap["entry_points"][0])
    assert first == second


# ---------------------------------------------------------------------------
# Multiple file_path / line key fallbacks
# ---------------------------------------------------------------------------


def test_alternate_field_names(tmp_path):
    """Some context maps emit ``file_path`` instead of ``file`` and
    ``line_start`` instead of ``line``. The enricher accepts either
    (matches the callgraph enricher's fallback)."""
    target = _project(tmp_path, {
        "src/x.py": "def f():\n    return 1\n",
    })
    cmap = {
        "entry_points": [{
            "id": "EP",
            "file_path": "src/x.py",
            "line_start": 1,
        }],
    }
    n = enrich_with_ast_view(cmap, target)
    assert n == 1
    assert cmap["entry_points"][0]["ast_view"]["function"] == "f"


# ---------------------------------------------------------------------------
# Inventory injection (caller already built one)
# ---------------------------------------------------------------------------


def test_inventory_injection_avoids_rebuild(tmp_path):
    """When the caller supplies an inventory (e.g. a sibling enricher
    already built one), the enricher uses it rather than rebuilding."""
    target = _project(tmp_path, {
        "src/x.py": "def f():\n    return 1\n",
    })
    from core.inventory.builder import build_inventory
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        inv = build_inventory(str(target), td)
        cmap = {
            "entry_points": [{"id": "EP", "file": "src/x.py", "line": 1}],
        }
        n = enrich_with_ast_view(cmap, target, inventory=inv)
        assert n == 1


# ---------------------------------------------------------------------------
# Non-dict entries are skipped (defensive — corrupted lists)
# ---------------------------------------------------------------------------


def test_non_dict_entries_skipped(tmp_path):
    target = _project(tmp_path, {"src/x.py": "def f():\n    return 1\n"})
    cmap = {
        "entry_points": [
            "not a dict",            # type: ignore[list-item]
            {"id": "EP", "file": "src/x.py", "line": 1},
            None,                    # type: ignore[list-item]
            42,                      # type: ignore[list-item]
        ],
    }
    n = enrich_with_ast_view(cmap, target)
    assert n == 1
    # The valid one got enriched.
    assert "ast_view" in cmap["entry_points"][1]
