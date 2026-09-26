"""Three-tier detection pins for the seal-time contact gate.

Each contact class the gate exists to catch is reproduced as a tiny
self-contained fixture roster (synthetic code only), so every tier has
a failable oracle:

* tier 1 — an add/add anchor conflict pair (git 3-way markers): the
  gate FAILS naming the pair when the contact is undeclared, and
  defers-without-failing when either seal line declares it;
* tier 2 — a sibling-rename semantic pair: both series apply textually
  clean, the composed tree carries an undefined name (F821) that only
  the union ruff over BOTH units' files can see;
* tier 3 — a census trip: a series that is conflict-free and
  lint-clean but reds a workflow-derived repo gate at the composed
  tree, attributed to the introducing unit; a gate already red at the
  bare base is warned as rot, never charged to the roster.

A clean roster control passes end to end with the machine-parseable
summary contract.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_GATE = Path(__file__).resolve().parents[1] / "scripts" / "contact_gate.py"

_HAS_RUFF = shutil.which("ruff") is not None
_needs_ruff = pytest.mark.skipif(
    not _HAS_RUFF, reason="tier 2 is a ruff probe; runner has no ruff"
)

_IDENT = [
    "-c", "user.name=fixture",
    "-c", "user.email=fixture@localhost",
    "-c", "commit.gpgsign=false",
]

_CENSUS_SCRIPT = '''\
"""Fixture repo-wide census: fails when src/ carries the forbidden marker."""
import sys
from pathlib import Path

bad = [
    str(p)
    for p in sorted(Path("src").rglob("*.py"))
    if "FORBIDDEN_" "MARKER" in p.read_text(encoding="utf-8")
]
if bad:
    print("census: forbidden marker in: " + ", ".join(bad))
    sys.exit(1)
print("census: clean")
'''

_WORKFLOW = """\
name: FixtureGates
on: push
jobs:
  gates:
    runs-on: ubuntu-latest
    steps:
      - name: fixture census
        run: python3 .github/scripts/check_fixture_census.py
"""

# Folded (run: >) block scalar, deliberately: the derivation must fold
# it into one logical pytest invocation (live gates use this shape).
_PYTEST_GATE_STEP = """\
      - name: fixture pin suite
        run: >
          pytest
          .github/tests
          -q
"""

_BASE_PIN_TEST = """\
from pathlib import Path


def test_token():
    assert "ok" in Path("src/data.py").read_text(encoding="utf-8")
"""


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    cp = subprocess.run(
        ["git", *_IDENT, *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode == 0, f"git {' '.join(args)}: {cp.stderr}"
    return cp


def make_base(
    tmp_path: Path, base_red: bool = False, pytest_gate: bool = False
) -> tuple[Path, str]:
    repo = tmp_path / "project"
    (repo / "src").mkdir(parents=True)
    (repo / ".github" / "scripts").mkdir(parents=True)
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "pyproject.toml").write_text(
        '[tool.ruff.lint]\nselect = ["F"]\n', encoding="utf-8"
    )
    (repo / "helpers.py").write_text(
        "def old_helper(x):\n    return x\n", encoding="utf-8"
    )
    (repo / "views.py").write_text(
        "from helpers import old_helper\n"
        "\n"
        "\n"
        "def render(x):\n"
        "    return old_helper(x)\n"
        "\n"
        "\n"
        "SECTION_A = 'a'\n"
        "SECTION_B = 'b'\n"
        "SECTION_C = 'c'\n"
        "SECTION_D = 'd'\n",
        encoding="utf-8",
    )
    (repo / "shared.py").write_text(
        "VALUE = 1\n"
        "LIMIT = 2\n"
        "TAIL = 3\n",
        encoding="utf-8",
    )
    (repo / "src" / "data.py").write_text("TOKEN = 'ok'\n", encoding="utf-8")
    if base_red:
        (repo / "src" / "rot.py").write_text(
            "FORBIDDEN_" + "MARKER = 'pre-existing'\n", encoding="utf-8"
        )
    (repo / ".github" / "scripts" / "check_fixture_census.py").write_text(
        _CENSUS_SCRIPT, encoding="utf-8"
    )
    workflow = _WORKFLOW
    if pytest_gate:
        workflow += _PYTEST_GATE_STEP
        (repo / ".github" / "tests").mkdir(parents=True)
        (repo / ".github" / "tests" / "test_base_pin.py").write_text(
            _BASE_PIN_TEST, encoding="utf-8"
        )
    (repo / ".github" / "workflows" / "gates.yml").write_text(
        workflow, encoding="utf-8"
    )
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fixture base")
    sha = _git(repo, "rev-parse", "HEAD").stdout.strip()
    return repo, sha


def make_series(
    repo: Path,
    base_sha: str,
    out_root: Path,
    name: str,
    files: dict[str, str],
    declared: str = "",
    route: str = "patches",
) -> tuple[Path, str, str]:
    """Commit a mutation on the fixture base; export it as a series.

    Returns (series dir, snapshot line, series tip sha).
    """
    series_dir = out_root / f"patches-{name}"
    series_dir.mkdir(parents=True)
    _git(repo, "checkout", "-q", "--detach", base_sha)
    for rel, content in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", f"fixture series {name}")
    sha = _git(repo, "rev-parse", "HEAD").stdout.strip()
    if route == "patches":
        _git(repo, "format-patch", "-q", "-1", "-o", str(series_dir), sha)
    elif route == "mbox":
        mbox_text = _git(repo, "format-patch", "--stdout", "-1", sha).stdout
        (series_dir / "series.mbox").write_text(mbox_text, encoding="utf-8")
    elif route == "diffs":
        diff = _git(repo, "diff", f"{base_sha}..{sha}").stdout
        (series_dir / "01.diff").write_text(diff, encoding="utf-8")
        (series_dir / "01.commit-msg").write_text(
            f"fixture series {name}\n", encoding="utf-8"
        )
    else:
        raise AssertionError(f"unknown route {route!r}")
    _git(repo, "checkout", "-q", "--detach", base_sha)
    suffix = f" {declared}" if declared else ""
    line = (
        f"# [SEALED 2026-09-25] patches-{name} {series_dir} "
        f"BASE={base_sha[:9]}(fixture) 1-diff fixture unit{suffix}"
    )
    return series_dir, line, sha


def run_gate(
    repo: Path,
    base_sha: str,
    snapshot_lines: list[str],
    tmp_path: Path,
    tiers: str = "1,2,3",
) -> subprocess.CompletedProcess:
    snap = tmp_path / "snapshot.txt"
    snap.write_text("\n".join(snapshot_lines) + "\n", encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            str(_GATE),
            "--snapshot", str(snap),
            "--repo", str(repo),
            "--base", base_sha,
            "--tiers", tiers,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=240,
    )


def summary_line(cp: subprocess.CompletedProcess) -> str:
    lines = [ln for ln in cp.stdout.splitlines() if ln.startswith("CONTACT-GATE: ")]
    assert lines, f"no summary line in output:\n{cp.stdout}\n{cp.stderr}"
    return lines[-1]


def findings(cp: subprocess.CompletedProcess) -> list[str]:
    return [
        ln for ln in cp.stdout.splitlines() if ln.startswith("CONTACT-GATE-FINDING:")
    ]


# ---------------------------------------------------------------------------
# clean-roster control
# ---------------------------------------------------------------------------


@_needs_ruff
def test_clean_roster_passes_all_tiers(tmp_path):
    repo, base = make_base(tmp_path)
    _d1, l1, _s1 = make_series(
        repo, base, tmp_path, "alphaunit",
        {"src/alpha_mod.py": "ALPHA = 1\n"},
    )
    _d2, l2, _s2 = make_series(
        repo, base, tmp_path, "betaunit",
        {"shared.py": "VALUE = 10\nLIMIT = 2\nTAIL = 3\n"},
    )
    cp = run_gate(repo, base, [l1, l2], tmp_path)
    assert cp.returncode == 0, cp.stdout + cp.stderr
    summary = summary_line(cp)
    assert summary.startswith("CONTACT-GATE: PASS ")
    assert "units=2" in summary and "applied=2" in summary
    assert "tier1=ok" in summary and "tier2=ok" in summary
    assert re.search(r"tier3=ok\(gates=\d+", summary)
    assert re.search(r"composed-tree=[0-9a-f]{12}", summary)
    assert not findings(cp)


def test_stacked_pair_reordered_and_composed(tmp_path):
    # The child series is cut on the parent's FINAL (its patch context
    # only exists once the parent applied) and appears FIRST in
    # registry order; the declared stack annotation must reorder the
    # compose or the child cannot apply.
    repo, base = make_base(tmp_path)
    _d1, l1, parent_final = make_series(
        repo, base, tmp_path, "parentunit",
        {"shared.py": "VALUE = 1\nLIMIT = 2\nPARENT = 4\nTAIL = 3\n"},
    )
    # The parent declares its FINAL (the sha the child's stack cites) —
    # tier 0 verifies the citation against it.
    l1 = l1.replace(
        "1-diff fixture unit", f"FINAL={parent_final[:9]} 1-diff fixture unit"
    )
    _d2, l2, _s2 = make_series(
        repo, parent_final, tmp_path, "childunit",
        {"shared.py": "VALUE = 1\nLIMIT = 2\nPARENT = 4\nCHILD = 5\nTAIL = 3\n"},
    )
    l2 = l2.replace(
        f"BASE={parent_final[:9]}(fixture)",
        f"BASE={parent_final[:9]}(=patches-parentunit-FINAL;stack-applies-at-base)",
    )
    cp = run_gate(repo, base, [l2, l1], tmp_path, tiers="1")
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "applied=2" in summary_line(cp)


def test_clean_roster_tier1_only_and_diff_route(tmp_path):
    # One unit delivered as NN.diff + commit-msg (no mbox, no .patch):
    # the git-apply --3way route composes it identically.
    repo, base = make_base(tmp_path)
    _d1, l1, _s1 = make_series(
        repo, base, tmp_path, "alphaunit",
        {"src/alpha_mod.py": "ALPHA = 1\n"}, route="diffs",
    )
    _d2, l2, _s2 = make_series(
        repo, base, tmp_path, "betaunit",
        {"src/beta_mod.py": "BETA = 2\n"},
    )
    cp = run_gate(repo, base, [l1, l2], tmp_path, tiers="1")
    assert cp.returncode == 0, cp.stdout + cp.stderr
    summary = summary_line(cp)
    assert "applied=2" in summary and "tier2=skipped" in summary


# ---------------------------------------------------------------------------
# tier 1 — marker-conflict pair (add/add anchor class)
# ---------------------------------------------------------------------------


def _anchor_pair(repo, base, tmp_path, declared: str = ""):
    # Both series insert a different line at the same anchor (after
    # LIMIT): orthogonal content, colliding anchor — git 3-way markers.
    _d1, l1, _s1 = make_series(
        repo, base, tmp_path, "alphaunit",
        {"shared.py": "VALUE = 1\nLIMIT = 2\nMAX_A = 10\nTAIL = 3\n"},
    )
    _d2, l2, _s2 = make_series(
        repo, base, tmp_path, "betaunit",
        {"shared.py": "VALUE = 1\nLIMIT = 2\nWINDOW = 5\nTAIL = 3\n"},
        declared=declared,
    )
    return l1, l2


def test_tier1_undeclared_anchor_conflict_fails_naming_pair(tmp_path):
    repo, base = make_base(tmp_path)
    l1, l2 = _anchor_pair(repo, base, tmp_path)
    cp = run_gate(repo, base, [l1, l2], tmp_path, tiers="1")
    assert cp.returncode == 1, cp.stdout + cp.stderr
    summary = summary_line(cp)
    assert summary.startswith("CONTACT-GATE: FAIL ")
    assert "tier1=1" in summary
    fnd = findings(cp)
    assert len(fnd) == 1
    assert "tier=1" in fnd[0]
    assert "kind=undeclared-conflict" in fnd[0]
    assert "unit=patches-betaunit" in fnd[0]
    assert "counterpart=patches-alphaunit" in fnd[0]
    assert "shared.py" in fnd[0]


def test_tier1_declared_conflict_defers_without_failing(tmp_path):
    repo, base = make_base(tmp_path)
    l1, l2 = _anchor_pair(
        repo, base, tmp_path,
        declared="(declared contact with alphaunit at the shared.py anchor)",
    )
    cp = run_gate(repo, base, [l1, l2], tmp_path, tiers="1")
    assert cp.returncode == 0, cp.stdout + cp.stderr
    summary = summary_line(cp)
    assert summary.startswith("CONTACT-GATE: PASS ")
    assert "deferred-declared=1" in summary
    assert not findings(cp)


def test_tier1_conflict_against_base_fails(tmp_path):
    # A series whose pre-image no longer matches the base tip (stale
    # seal / moved base) must fail loudly against BASE, not fuzz through.
    repo, base = make_base(tmp_path)
    _d1, l1, _s1 = make_series(
        repo, base, tmp_path, "alphaunit",
        {"shared.py": "VALUE = 1\nLIMIT = 2\nMAX_A = 10\nTAIL = 3\n"},
    )
    # Advance the base so alphaunit's context is gone.
    (repo / "shared.py").write_text("REWRITTEN = True\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base advance")
    new_base = _git(repo, "rev-parse", "HEAD").stdout.strip()
    cp = run_gate(repo, new_base, [l1], tmp_path, tiers="1")
    assert cp.returncode == 1
    fnd = findings(cp)
    assert len(fnd) == 1
    assert "tier=1" in fnd[0] and "counterpart=BASE" in fnd[0]


# ---------------------------------------------------------------------------
# tier 2 — sibling-rename semantic pair (clean apply, composed F821)
# ---------------------------------------------------------------------------


def _rename_pair(repo, base, tmp_path):
    # alphaunit renames the helper at its definition site and updates
    # the import + its own call (top region); betaunit appends a new
    # consumer of the OLD name far below (bottom region). Disjoint
    # hunks: both apply clean; the composed module has an undefined
    # name only the union probe can see.
    _d1, l1, _s1 = make_series(
        repo, base, tmp_path, "alphaunit",
        {
            "helpers.py": "def new_helper(x):\n    return x\n",
            "views.py": (
                "from helpers import new_helper\n"
                "\n"
                "\n"
                "def render(x):\n"
                "    return new_helper(x)\n"
                "\n"
                "\n"
                "SECTION_A = 'a'\n"
                "SECTION_B = 'b'\n"
                "SECTION_C = 'c'\n"
                "SECTION_D = 'd'\n"
            ),
        },
    )
    _d2, l2, _s2 = make_series(
        repo, base, tmp_path, "betaunit",
        {
            "views.py": (
                "from helpers import old_helper\n"
                "\n"
                "\n"
                "def render(x):\n"
                "    return old_helper(x)\n"
                "\n"
                "\n"
                "SECTION_A = 'a'\n"
                "SECTION_B = 'b'\n"
                "SECTION_C = 'c'\n"
                "SECTION_D = 'd'\n"
                "\n"
                "\n"
                "def render_residual(x):\n"
                "    return old_helper(x)\n"
            ),
        },
    )
    return l1, l2


@_needs_ruff
def test_tier2_sibling_rename_f821_fails_naming_pair(tmp_path):
    repo, base = make_base(tmp_path)
    l1, l2 = _rename_pair(repo, base, tmp_path)
    cp = run_gate(repo, base, [l1, l2], tmp_path, tiers="1,2")
    assert cp.returncode == 1, cp.stdout + cp.stderr
    # tier 1 sees no conflict: the semantic break applies clean.
    summary = summary_line(cp)
    assert "tier1=0" in summary and "tier2=" in summary
    fnd = [f for f in findings(cp) if "tier=2" in f]
    assert len(fnd) >= 1
    f821 = [f for f in fnd if "F821" in f]
    assert f821, fnd
    assert "kind=composed-ruff" in f821[0]
    assert "views.py" in f821[0]
    assert "unit=patches-betaunit" in f821[0]
    assert "counterpart=patches-alphaunit" in f821[0]
    assert "old_helper" in f821[0]


@_needs_ruff
def test_tier2_each_side_alone_is_clean(tmp_path):
    # The pair property: either unit composed alone passes — only the
    # COMPOSITION carries the break. (This is what per-series review
    # cannot see and the union probe exists for.)
    for keep in (0, 1):
        repo, base = make_base(tmp_path / f"solo{keep}")
        lines = _rename_pair(repo, base, tmp_path / f"solo{keep}")
        cp = run_gate(repo, base, [lines[keep]], tmp_path / f"solo{keep}", tiers="1,2")
        assert cp.returncode == 0, cp.stdout + cp.stderr


@_needs_ruff
def test_tier2_preexisting_base_finding_not_charged(tmp_path):
    repo, base = make_base(tmp_path)
    # Plant a pre-existing lint finding at the base...
    (repo / "legacy.py").write_text(
        "import os\n\nLEGACY = 1\n", encoding="utf-8"  # F401 at base
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base with legacy lint debt")
    base2 = _git(repo, "rev-parse", "HEAD").stdout.strip()
    # ...and a unit that touches that file without fixing the debt.
    _d1, l1, _s1 = make_series(
        repo, base2, tmp_path, "alphaunit",
        {"legacy.py": "import os\n\nLEGACY = 2\n"},
    )
    cp = run_gate(repo, base2, [l1], tmp_path, tiers="1,2")
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert not findings(cp)


# ---------------------------------------------------------------------------
# tier 3 — composed gate battery (census trip, base-red rot)
# ---------------------------------------------------------------------------


def test_tier3_census_trip_names_unit_and_gate(tmp_path):
    repo, base = make_base(tmp_path)
    _d1, l1, _s1 = make_series(
        repo, base, tmp_path, "alphaunit",
        {"src/alpha_mod.py": "ALPHA = 1\n"},
    )
    # Applies clean, ruff-clean, disjoint from everything — but the
    # composed tree trips the workflow-derived census gate.
    _d2, l2, _s2 = make_series(
        repo, base, tmp_path, "gammaunit",
        {"src/planted.py": "FORBIDDEN_" + "MARKER = 'trip'\n"},
    )
    tiers = "1,2,3" if _HAS_RUFF else "1,3"
    cp = run_gate(repo, base, [l1, l2], tmp_path, tiers=tiers)
    assert cp.returncode == 1, cp.stdout + cp.stderr
    summary = summary_line(cp)
    assert "tier3=1" in summary
    fnd = [f for f in findings(cp) if "tier=3" in f]
    assert len(fnd) == 1
    assert "kind=gate-red" in fnd[0]
    assert "unit=patches-gammaunit" in fnd[0]
    assert "check_fixture_census.py" in fnd[0]


def test_tier3_added_failing_file_attributes_to_the_adding_unit(tmp_path):
    # The middle unit ADDS a failing test file to a workflow-derived
    # (folded run: >) pytest gate. At boundaries before the adder the
    # narrowed probe cannot collect the file (pytest rc 4/5) — that is
    # not-red, so the bisection must name the ADDER, not the innocent
    # preceding unit.
    repo, base = make_base(tmp_path, pytest_gate=True)
    _d1, l1, _s1 = make_series(
        repo, base, tmp_path, "alphaunit", {"src/ok1.py": "OK1 = 1\n"},
    )
    _d2, l2, _s2 = make_series(
        repo, base, tmp_path, "betaunit",
        {
            ".github/tests/test_new_pin.py": (
                "def test_new_pin():\n    assert False, 'composed pin trips'\n"
            ),
        },
    )
    _d3, l3, _s3 = make_series(
        repo, base, tmp_path, "gammaunit", {"src/ok2.py": "OK2 = 2\n"},
    )
    cp = run_gate(repo, base, [l1, l2, l3], tmp_path, tiers="1,3")
    assert cp.returncode == 1, cp.stdout + cp.stderr
    fnd = [f for f in findings(cp) if "tier=3" in f]
    assert len(fnd) == 1
    assert "unit=patches-betaunit" in fnd[0], fnd[0]
    assert "pytest" in fnd[0]


def test_tier3_broken_existing_test_attributes_to_the_breaking_unit(tmp_path):
    # Direction control: the FIRST unit breaks a test that exists at
    # every boundary — the bisection must name that unit, not walk
    # forward past it.
    repo, base = make_base(tmp_path, pytest_gate=True)
    _d1, l1, _s1 = make_series(
        repo, base, tmp_path, "alphaunit",
        {"src/data.py": "TOKEN = 'flipped'\n"},
    )
    _d2, l2, _s2 = make_series(
        repo, base, tmp_path, "betaunit", {"src/ok1.py": "OK1 = 1\n"},
    )
    _d3, l3, _s3 = make_series(
        repo, base, tmp_path, "gammaunit", {"src/ok2.py": "OK2 = 2\n"},
    )
    cp = run_gate(repo, base, [l1, l2, l3], tmp_path, tiers="1,3")
    assert cp.returncode == 1, cp.stdout + cp.stderr
    fnd = [f for f in findings(cp) if "tier=3" in f]
    assert len(fnd) == 1
    assert "unit=patches-alphaunit" in fnd[0], fnd[0]


def test_tier3_base_red_gate_is_rot_not_a_contact(tmp_path):
    repo, base = make_base(tmp_path, base_red=True)
    _d1, l1, _s1 = make_series(
        repo, base, tmp_path, "alphaunit",
        {"src/alpha_mod.py": "ALPHA = 1\n"},
    )
    tiers = "1,2,3" if _HAS_RUFF else "1,3"
    cp = run_gate(repo, base, [l1], tmp_path, tiers=tiers)
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "base-red=1" in summary_line(cp)
    assert "WARNING" in cp.stdout
    assert not findings(cp)


# ---------------------------------------------------------------------------
# tier 1 — already-applied staleness (structural, every payload route)
# ---------------------------------------------------------------------------


def _stale_setup(tmp_path, route: str):
    """A unit whose whole change already landed on the (advanced) base."""
    repo, base = make_base(tmp_path)
    _d, line, _sha = make_series(
        repo, base, tmp_path, "staleunit", {"src/s.py": "S = 1\n"}, route=route,
    )
    _git(repo, "checkout", "-q", "--detach", base)
    (repo / "src" / "s.py").write_text("S = 1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "landed equivalent")
    new_base = _git(repo, "rev-parse", "HEAD").stdout.strip()
    line = line.replace(f"BASE={base[:9]}", f"BASE={new_base[:9]}")
    return repo, new_base, line


@pytest.mark.parametrize("route", ["mbox", "patches", "diffs"])
def test_tier1_already_applied_unit_fails_loudly_on_every_route(tmp_path, route):
    # git exits 0 for an already-applied unit (am creates no commit;
    # apply stages nothing) — the gate must detect it STRUCTURALLY and
    # fail naming the unit, with NO phantom commit: the composed tree
    # must still be the bare base tree.
    repo, new_base, line = _stale_setup(tmp_path, route)
    base_tree = _git(repo, "rev-parse", f"{new_base}^{{tree}}").stdout.strip()
    cp = run_gate(repo, new_base, [line], tmp_path, tiers="1")
    assert cp.returncode == 1, cp.stdout + cp.stderr
    fnd = findings(cp)
    assert len(fnd) == 1
    assert "tier=1" in fnd[0]
    assert "kind=already-applied" in fnd[0]
    assert "unit=patches-staleunit" in fnd[0]
    assert "counterpart=BASE" in fnd[0]
    summary = summary_line(cp)
    assert "applied=0" in summary
    assert f"composed-tree={base_tree[:12]}" in summary  # no phantom commit


def test_tier1_partially_stale_unit_fails_with_commit_shortfall(tmp_path):
    # Two-commit unit whose FIRST commit already landed on the base:
    # git am skips it silently (rc 0, no commit for it) and applies the
    # second — the created-vs-expected commit count catches the
    # shortfall structurally.
    repo, base = make_base(tmp_path)
    series_dir = tmp_path / "patches-partialunit"
    series_dir.mkdir()
    _git(repo, "checkout", "-q", "--detach", base)
    (repo / "src" / "p1.py").write_text("P1 = 1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fixture partial 1")
    (repo / "src" / "p2.py").write_text("P2 = 2\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fixture partial 2")
    _git(repo, "format-patch", "-q", "-2", "-o", str(series_dir), "HEAD")
    _git(repo, "checkout", "-q", "--detach", base)
    (repo / "src" / "p1.py").write_text("P1 = 1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "landed equivalent of partial 1")
    new_base = _git(repo, "rev-parse", "HEAD").stdout.strip()
    line = (
        f"# [SEALED 2026-09-26] patches-partialunit {series_dir} "
        f"BASE={new_base[:9]}(fixture) 2-diffs fixture unit"
    )
    cp = run_gate(repo, new_base, [line], tmp_path, tiers="1")
    assert cp.returncode == 1, cp.stdout + cp.stderr
    fnd = findings(cp)
    assert len(fnd) == 1
    assert "kind=already-applied" in fnd[0]
    assert "1 of 2" in fnd[0]


# ---------------------------------------------------------------------------
# tier 0 — stale rehearsal citation (string check, before any compose)
# ---------------------------------------------------------------------------


def test_tier0_stale_rehearsal_fails_and_current_passes(tmp_path):
    # alphaunit's seal line cites betaunit's r3 tree; betaunit's current
    # line is an r4 carrying a different tree — the rehearsal aged.
    # Both units still COMPOSE clean (tiers 1-3 see nothing), so tier 0
    # is the only arm that can catch it.
    repo, base = make_base(tmp_path)
    _d1, l1, _s1 = make_series(
        repo, base, tmp_path, "alphaunit", {"src/a1.py": "A = 1\n"},
    )
    _d2, l2, _s2 = make_series(
        repo, base, tmp_path, "betaunit", {"src/b1.py": "B = 2\n"},
    )
    fresh_beta = l2.replace("[SEALED 2026-09-25]", "[SEALED 2026-09-26 r4]").replace(
        "1-diff fixture unit", "TREE=9f9e627e4 1-diff fixture unit"
    )
    stale = l1.replace(
        "1-diff fixture unit",
        "STACK=on-patches-betaunit-r3(1-diff-first,tree-0161bd648) 1-diff fixture unit",
    )
    cp = run_gate(repo, base, [fresh_beta, stale], tmp_path, tiers="1")
    assert cp.returncode == 1, cp.stdout + cp.stderr
    fnd = [f for f in findings(cp) if "tier=0" in f]
    assert len(fnd) == 1
    assert "kind=stale-rehearsal" in fnd[0]
    assert "unit=patches-alphaunit" in fnd[0]
    assert "counterpart=patches-betaunit" in fnd[0]
    assert "0161bd648" in fnd[0]
    assert "tier0=1" in summary_line(cp)
    # Control: the citation names the sha the current line carries.
    good = l1.replace(
        "1-diff fixture unit",
        "STACK=on-patches-betaunit-r3(1-diff-first,tree-9f9e627e4) 1-diff fixture unit",
    )
    cp2 = run_gate(repo, base, [fresh_beta, good], tmp_path, tiers="1")
    assert cp2.returncode == 0, cp2.stdout + cp2.stderr
    assert "tier0=ok(citations=1)" in summary_line(cp2)


# ---------------------------------------------------------------------------
# fail-closed infrastructure arms
# ---------------------------------------------------------------------------


def test_missing_series_dir_is_infra_error(tmp_path):
    repo, base = make_base(tmp_path)
    line = (
        f"# [SEALED 2026-09-25] patches-ghost {tmp_path}/patches-ghost "
        f"BASE={base[:9]} 1-diff vanished payload"
    )
    cp = run_gate(repo, base, [line], tmp_path, tiers="1")
    assert cp.returncode == 2
    assert summary_line(cp).startswith("CONTACT-GATE: ERROR")


def test_empty_roster_passes_loudly(tmp_path):
    repo, base = make_base(tmp_path)
    cp = run_gate(repo, base, ["# just a header comment"], tmp_path)
    assert cp.returncode == 0
    assert "units=0" in summary_line(cp)
