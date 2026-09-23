"""Glob-idiom census: workflow-file globs must accept both extensions.

GitHub Actions runs workflows with EITHER extension (``.yml`` and
``.yaml``), so any gate, script, or path trigger that enumerates
workflow files with a ``*.yml`` glob silently drops the ``.yaml``
half of the platform's grammar out of its universe. This exact
narrow-glob class has now shipped three times on three different
surfaces (source_intel's EXTS suffix gap, the ci-controls
doc-coverage gate's ``glob("*.yml")``, sca-pr-gate.yml's
``.github/workflows/*.yml`` path trigger) — each one a fresh oracle
whose universe was narrower than both the platform and its own
in-file siblings' documented ``*.y*ml`` convention. This census is
the structural end: the fourth recurrence fails CI instead of
waiting for a review wave.

Two arms, both derived mechanically from the tree (never a
hand-typed site list):

* **Python glob sites** — every literal ``glob()``/``rglob()``
  pattern in ``.github/scripts`` + ``.github/tests`` whose target is
  yml-family (ends in ``yml``/``yaml`` with a wildcard) must spell
  the suffix ``.y*ml``, or carry an allowlist row with a rationale.
  Over-inclusive on purpose: a yml glob that genuinely targets a
  single-extension universe (none exists today) gets adjudicated
  into the allowlist instead of escaping the census.
* **Workflow path-trigger globs** — every glob over
  ``.github/workflows/`` inside a workflow file's own text (path
  filters) must use the same idiom.

Declared boundary: only literal string patterns are visible —
a pattern built at runtime (variable, f-string) is outside the
census, as is a hand-rolled ``os.listdir`` + ``endswith`` walk.
Both are un-idiomatic for these trees today; if one appears, the
suffix logic belongs in a shared helper, not a fourth spelling.
Formatting is NOT a boundary: the Python arm matches whole file
text, so a formatter-wrapped call (``.glob(`` + newline + pattern)
is judged identically to the single-line spelling.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Adjudicated exceptions: "<repo-relative-path>::<pattern>" -> reason
# the narrow glob is correct THERE. Every row must name why the
# .yaml half of the grammar is genuinely out of that site's universe.
_ALLOWLISTED_SITES: dict[str, str] = {}

_GLOB_CALL_RE = re.compile(r"\.r?glob\(\s*[rbu]*[\"']([^\"']+)[\"']")

# yml-family glob pattern: wildcard present, names a yml/yaml suffix.
_YML_FAMILY_RE = re.compile(r"ya?\*?ml$")
# The blessed spelling (matches both GHA extensions).
_IDIOM_RE = re.compile(r"\.y\*ml$")

# A path-filter glob over the workflows dir inside workflow text:
# contains the dir prefix and a wildcard in the file part.
_TRIGGER_GLOB_RE = re.compile(
    r"\.github/workflows/[^\s\"']*\*[^\s\"']*"
)


def _python_census_files() -> list[Path]:
    files: list[Path] = []
    for root in (".github/scripts", ".github/tests"):
        files.extend(
            p for p in sorted((REPO / root).rglob("*.py"))
            if "__pycache__" not in p.parts
        )
    return files


def _python_glob_offenders(text: str, rel: str) -> tuple[list[str], int]:
    """(offender rows, compliant count) for one file's text.

    Matched over the WHOLE text, not per line: ruff/format wraps a
    long call as ``.glob(`` + newline + ``"*.yml")`` and a per-line
    scan never saw the pattern — a formatting-shaped escape from the
    census (the call regex's whitespace class already crosses
    newlines). Line
    numbers are recovered from match offsets.
    """
    offenders: list[str] = []
    compliant = 0
    for m in _GLOB_CALL_RE.finditer(text):
        pattern = m.group(1)
        if not _YML_FAMILY_RE.search(pattern):
            continue
        if _IDIOM_RE.search(pattern):
            compliant += 1
            continue
        key = f"{rel}::{pattern}"
        if key in _ALLOWLISTED_SITES:
            continue
        line = text.count("\n", 0, m.start()) + 1
        offenders.append(f"{rel}:{line}: glob({pattern!r})")
    return offenders, compliant


def test_python_workflow_globs_use_both_extension_idiom() -> None:
    offenders: list[str] = []
    compliant = 0
    for path in _python_census_files():
        rel = path.relative_to(REPO).as_posix()
        file_offenders, file_compliant = _python_glob_offenders(
            path.read_text(encoding="utf-8"), rel,
        )
        offenders.extend(file_offenders)
        compliant += file_compliant
    # Vacuousness guard: the compliant sites this census was derived
    # from (test_ci_controls_docs.py x3, test_test_scope.py) must be
    # visible to it — zero means the extraction regressed, not that
    # the tree went clean.
    assert compliant >= 4, (
        f"census extraction found only {compliant} compliant yml-glob "
        "sites — the site derivation itself regressed"
    )
    assert not offenders, (
        "yml-family glob(s) narrower than the GHA workflow grammar "
        "(.yaml files escape these universes) — spell the suffix "
        "*.y*ml, or add an allowlist row with a rationale:\n"
        + "\n".join(offenders)
    )


def test_workflow_trigger_globs_use_both_extension_idiom() -> None:
    offenders: list[str] = []
    checked = 0
    for wf in sorted((REPO / ".github/workflows").glob("*.y*ml")):
        for i, line in enumerate(
            wf.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if line.lstrip().startswith("#"):
                continue
            for m in _TRIGGER_GLOB_RE.finditer(line.split(" #", 1)[0]):
                pattern = m.group(0)
                if not _YML_FAMILY_RE.search(pattern):
                    continue
                checked += 1
                if _IDIOM_RE.search(pattern):
                    continue
                key = f"{wf.relative_to(REPO).as_posix()}::{pattern}"
                if key in _ALLOWLISTED_SITES:
                    continue
                offenders.append(
                    f"{wf.name}:{i}: {pattern}"
                )
    assert checked >= 1, (
        "trigger-glob extraction found no workflows-dir globs — "
        "sca-pr-gate.yml's pin-audit trigger should be visible"
    )
    assert not offenders, (
        "workflow path-trigger glob(s) over .github/workflows/ miss "
        "the .yaml extension — a .yaml workflow change would not "
        "re-fire these workflows; spell the suffix *.y*ml:\n"
        + "\n".join(offenders)
    )


def test_census_sees_wrapped_glob_calls() -> None:
    """Self-check for the formatting escape: the wrapped spelling a
    formatter produces must be judged exactly like the single-line
    one (it silently escaped a per-line scan before), and the
    blessed idiom stays compliant in both layouts."""
    # Plants are spliced ('.gl' + 'ob') so this census file's own
    # text never carries a matchable non-idiom call site.
    wrapped = 'x = d.gl' + 'ob(\n    "*.yml",\n)\n'
    offenders, _ = _python_glob_offenders(wrapped, "probe.py")
    assert offenders == ["probe.py:1: glob('*.yml')"]
    single = 'x = d.gl' + 'ob("*.yml")\n'
    offenders, _ = _python_glob_offenders(single, "probe.py")
    assert offenders == ["probe.py:1: glob('*.yml')"]
    good_wrapped = 'x = d.rgl' + 'ob(\n    "*.y*ml",\n)\n'
    offenders, compliant = _python_glob_offenders(good_wrapped, "probe.py")
    assert not offenders
    assert compliant == 1


def test_allowlist_rows_are_live() -> None:
    """A row for a site that no longer exists (file gone, pattern
    respelled) is stale — remove it so the allowlist stays a set of
    real adjudications."""
    for key in _ALLOWLISTED_SITES:
        rel, pattern = key.split("::", 1)
        path = REPO / rel
        assert path.is_file(), f"allowlist row for missing file: {key}"
        assert pattern in path.read_text(encoding="utf-8"), (
            f"allowlist row for a pattern no longer present: {key}"
        )
