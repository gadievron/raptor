"""Line-number accounting in the per-ecosystem import sweeps.

Two contracts:

  * **Correctness** — the rolling-cursor line numbers equal the
    naive per-match ``text.count("\\n", 0, m.start()) + 1`` on a
    mixed fixture (matches on first / middle / last lines, blank
    runs, non-matching noise between matches).
  * **Linearity** — a dense import file (every line a match) parses
    within a hard wall budget. The naive per-match count re-scans
    the whole prefix for every match: O(matches x file-bytes),
    which turns one planted megabyte-scale dense-import source file
    into minutes of scan time on the DEFAULT ``/sca`` path (the
    sweeps walk every file of the ecosystem, ``read_bounded``
    admits multi-megabyte files, and there is no per-file timeout).
    The rolling cursor walks forward from the previous match
    instead — one pass over the file total.
"""

from __future__ import annotations

import time

import pytest

from packages.sca.reachability import (
    cargo as _cargo,
    composer as _composer,
    gemfile as _gemfile,
    gomod as _gomod,
    maven as _maven,
    nodejs as _nodejs,
    nuget as _nuget,
)

# (id, sweep callable, one dense-import line, small mixed fixture)
_SWEEPS = [
    (
        "gomod",
        lambda text: _gomod._imports_in(text),
        'import "example.com/lib"\n',
        'package main\n\nimport "a/b"\n\n\n// noise\nimport x "c/d"\n',
    ),
    (
        "cargo",
        lambda text: _cargo._imports_in(text),
        "use somecrate;\n",
        "fn main() {}\n\nuse alpha;\n\n\nextern crate beta;\n",
    ),
    (
        "nodejs",
        lambda text: _nodejs._imports_in(text),
        "const x = require('pkg');\n",
        "// noise\nrequire('alpha');\n\n\nimport('beta');\n",
    ),
    (
        "maven",
        lambda text: _maven._imports_in(text),
        "import com.example.lib.Widget;\n",
        "package app;\n\nimport a.b.C;\n\n\nimport static d.e.F;\n",
    ),
    (
        "nuget",
        lambda text: _nuget._imports_in(".cs", text),
        "using Example.Lib;\n",
        "// noise\nusing Alpha.One;\n\n\nusing Beta.Two;\n",
    ),
    (
        "composer",
        lambda text: _composer._imports_in(text),
        "use Example\\Lib;\n",
        "<?php\n\nuse Alpha\\One;\n\n\nuse Beta\\Two;\n",
    ),
    (
        "gemfile",
        lambda text: _gemfile._requires_in(text),
        "require 'pkg'\n",
        "# noise\nrequire 'alpha'\n\n\nrequire_relative 'beta'\n",
    ),
]

_IDS = [row[0] for row in _SWEEPS]


@pytest.mark.parametrize("sweep,mixed", [(r[1], r[3]) for r in _SWEEPS],
                         ids=_IDS)
def test_line_numbers_match_naive_count(sweep, mixed) -> None:
    """Rolling-cursor line numbers equal the naive full-prefix count
    (the reference the cursor replaces)."""
    got = list(sweep(mixed))
    assert got, "fixture must produce matches"
    for name, line in got:
        # Every reported line must actually contain the reported
        # name — the strongest available cross-check without
        # re-deriving offsets.
        assert name in mixed.splitlines()[line - 1]
    # Blank-line runs between matches are the classic cursor
    # off-by-N hazard: the last fixture match sits after one.
    assert got[-1][1] == mixed.count("\n", 0, mixed.rfind(got[-1][0]))\
        + 1


@pytest.mark.parametrize("sweep,dense_line", [(r[1], r[2]) for r in _SWEEPS],
                         ids=_IDS)
def test_dense_import_file_parses_within_budget(sweep, dense_line) -> None:
    """A ~2 MB file where every line matches must sweep in linear
    time. Budget is deliberately generous for slow CI (the linear
    implementation finishes in well under a second; the quadratic
    one took tens of seconds on reference hardware and grows 4x per
    doubling)."""
    n_lines = max(1, (1 << 21) // len(dense_line))
    text = dense_line * n_lines
    start = time.monotonic()
    results = list(sweep(text))
    elapsed = time.monotonic() - start
    assert len(results) == n_lines
    # Spot-check the accounting survived the volume.
    assert results[0][1] == 1
    assert results[-1][1] == n_lines
    assert elapsed < 5.0, (
        f"dense-import sweep took {elapsed:.2f}s for {n_lines} lines "
        f"— quadratic line accounting"
    )
