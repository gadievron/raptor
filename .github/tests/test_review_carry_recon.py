"""The carry reconciler must (a) pass on a fully-disposed synthetic carry,
and FAIL loudly on every historical leak shape: (b) a prior finding heading
with no carry row, (c) an unmirrored series-NOTES deferral, (d) a dropped
prior KNOWN-OPEN row, plus double claims, unknown references, P1 ownership
holes, and missing required refs; (e) whitespace-drifted headings and
lowercase deferral spellings must stay in their universes, and table/prose
deferral text must surface as a counted advisory. Hermetic: all universes
are synthetic fixtures under tmp_path; no git, no network."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "review_carry_recon.py"

FINDINGS_U01 = """# U01 findings

### [P1][CONFIRMED] parser drops rows on tab-separated input
- File: pkg/parser.py
### [P3][CONFIRMED] log line interpolates unsanitised name
- File: pkg/log.py
"""

FINDINGS_U02 = """# U02 findings

### [P2][CONFIRMED] cache key ignores namespace
- File: pkg/cache.py
"""

PRIOR_KO = """# KNOWN-OPEN (previous cycle)

## A. Landed fixes (regression-check)

- old fix set alpha — regression-check.
- old fix set beta — regression-check.

## G. Historical

- adjudicated out at prep.
"""

NOTES = """# series NOTES

- FIXED: the parser row drop (diff 01).
- DEFERRED -> elsewhere: sibling stripper keeps its bespoke lexer.
- residual risks: none.
"""

# Line numbers of the universe items above (1-based, in-file):
#   findings: U01:3 [P1], U01:5 [P3], U02:3 [P2]
#   prior rows: A1, A2, G1 (exempt)
#   NOTES deferrals: line 4 (DEFERRED) and line 5 ("residual" spelling —
#   in the default vocabulary)
CLEAN_KO = """# KNOWN-OPEN (new cycle)

## A. Carries

- [src: prev:U01:3] parser drops rows — OPEN — owner U-next.
- [src: KO:A1+KO:A2] both landed sets — regression-check. [p1: 1]
- [src: NOTES:seriesx:4] bespoke lexer kept — OPEN — owner backlog. [p1: 2-3]
- [src: NOTES:seriesx:5] residual risks recorded as none — no carry.
- [src: HF:hotfixa] hotfix landed — regression-check.
- [agg: prev:U01:P3] [agg: prev:U02:P2] remaining headings — OPEN.
"""


def _write_fixture(tmp_path: Path) -> dict[str, Path]:
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "U01.md").write_text(FINDINGS_U01)
    (findings / "U02.md").write_text(FINDINGS_U02)
    prior = tmp_path / "KNOWN-OPEN-prev.md"
    prior.write_text(PRIOR_KO)
    notes = tmp_path / "NOTES.md"
    notes.write_text(NOTES)
    ko = tmp_path / "KNOWN-OPEN.md"
    ko.write_text(CLEAN_KO)
    return {"findings": findings, "prior": prior, "notes": notes, "ko": ko}


def _run(paths: dict[str, Path], *extra: str) -> subprocess.CompletedProcess:
    args = [
        sys.executable, str(SCRIPT),
        "--known-open", str(paths["ko"]),
        "--findings", f"prev={paths['findings']}",
        "--prior-known-open", f"KO={paths['prior']}",
        "--prior-exempt", "KO:G1",
        "--notes", f"seriesx={paths['notes']}",
        "--p1-count", "3",
        "--require-ref", "HF:hotfixa",
        *extra,
    ]
    return subprocess.run(args, capture_output=True, text=True, check=False)


def test_fully_disposed_carry_is_clean(tmp_path):
    res = _run(_write_fixture(tmp_path))
    assert res.returncode == 0, res.stdout + res.stderr
    assert "RECONCILIATION CLEAN" in res.stdout


def test_dropped_finding_heading_fails(tmp_path):
    # Leak shape: a prior unit's findings got no carry row at all.
    paths = _write_fixture(tmp_path)
    paths["ko"].write_text(CLEAN_KO.replace(" [agg: prev:U02:P2]", ""))
    res = _run(paths)
    assert res.returncode == 1
    assert "DROP: finding prev:U02:3 [P2]" in res.stdout


def test_unmirrored_notes_deferral_fails(tmp_path):
    # Leak shape: a series NOTES deferral row never mirrored into the carry.
    paths = _write_fixture(tmp_path)
    paths["ko"].write_text(
        CLEAN_KO.replace("[src: NOTES:seriesx:4] ", "") ,
    )
    res = _run(paths)
    assert res.returncode == 1
    assert "DROP: NOTES deferral seriesx:4 is unmirrored" in res.stdout


def test_dropped_prior_row_fails(tmp_path):
    paths = _write_fixture(tmp_path)
    paths["ko"].write_text(CLEAN_KO.replace("+KO:A2", ""))
    res = _run(paths)
    assert res.returncode == 1
    assert "DROP: KO row A2 has no disposition" in res.stdout


def test_exempt_prior_row_needs_no_claim(tmp_path):
    # G1 is exempt in every case above; dropping the exemption must fail.
    paths = _write_fixture(tmp_path)
    args = [
        sys.executable, str(SCRIPT),
        "--known-open", str(paths["ko"]),
        "--prior-known-open", f"KO={paths['prior']}",
        "--findings", f"prev={paths['findings']}",
        "--notes", f"seriesx={paths['notes']}",
        "--p1-count", "3",
        "--require-ref", "HF:hotfixa",
    ]
    res = subprocess.run(args, capture_output=True, text=True, check=False)
    assert res.returncode == 1
    assert "DROP: KO row G1" in res.stdout


def test_double_claim_fails(tmp_path):
    paths = _write_fixture(tmp_path)
    paths["ko"].write_text(CLEAN_KO + "- [src: prev:U01:3] claimed again.\n")
    res = _run(paths)
    assert res.returncode == 1
    assert "finding prev:U01:3 explicitly claimed 2x" in res.stdout


def test_double_aggregate_fails(tmp_path):
    paths = _write_fixture(tmp_path)
    paths["ko"].write_text(CLEAN_KO + "- [agg: prev:U02:P2] second aggregate.\n")
    res = _run(paths)
    assert res.returncode == 1
    assert "covered by 2 aggregates" in res.stdout


def test_unknown_reference_fails(tmp_path):
    paths = _write_fixture(tmp_path)
    paths["ko"].write_text(CLEAN_KO + "- [src: prev:U99:1] phantom unit.\n")
    res = _run(paths)
    assert res.returncode == 1
    assert "unknown finding prev:U99:1" in res.stdout


def test_p1_ownership_hole_fails(tmp_path):
    paths = _write_fixture(tmp_path)
    paths["ko"].write_text(CLEAN_KO.replace(" [p1: 2-3]", " [p1: 2]"))
    res = _run(paths)
    assert res.returncode == 1
    assert "P1 #3 claimed 0x" in res.stdout


def test_missing_required_ref_fails(tmp_path):
    paths = _write_fixture(tmp_path)
    paths["ko"].write_text(CLEAN_KO.replace("[src: HF:hotfixa] ", ""))
    res = _run(paths)
    assert res.returncode == 1
    assert "required ref 'HF:hotfixa' unreferenced" in res.stdout


def test_claims_outside_bullet_rows_are_inert(tmp_path):
    # Prose documenting the row format must not satisfy (or double) a claim.
    paths = _write_fixture(tmp_path)
    paths["ko"].write_text(
        "Row format doc: [src: prev:U01:3] tokens look like this.\n\n" + CLEAN_KO
    )
    res = _run(paths)
    assert res.returncode == 0, res.stdout + res.stderr


def test_emit_stubs_generates_carry_skeleton(tmp_path):
    # Bootstrap mode: no KNOWN-OPEN yet -> one paste-ready stub per item.
    paths = _write_fixture(tmp_path)
    paths["ko"].unlink()
    res = _run(paths, "--emit-stubs")
    assert res.returncode == 1
    for stub in (
        "- [src: prev:U01:3] [P1] [CONFIRMED] parser drops rows on tab-separated input",
        "- [src: KO:A1]",
        "- [src: NOTES:seriesx:4] DEFERRED -> elsewhere",
        "- [p1: 1]",
        "- [src: HF:hotfixa]",
    ):
        assert stub in res.stdout, res.stdout


def test_whitespace_drifted_headings_still_join_universe(tmp_path):
    # Leak shape: heading whitespace drift (double space, NBSP) must not
    # silently remove a finding from the universe — undisposed, it must DROP.
    paths = _write_fixture(tmp_path)
    (paths["findings"] / "U03.md").write_text(
        "###  [P1][CONFIRMED] double-space heading\n"
        "###\u00a0[P2][CONFIRMED] nbsp heading\n"
    )
    res = _run(paths)
    assert res.returncode == 1
    assert "DROP: finding prev:U03:1 [P1]" in res.stdout
    assert "DROP: finding prev:U03:2 [P2]" in res.stdout


def test_lowercase_deferral_spelling_joins_universe(tmp_path):
    # Leak shape: 'Deferred:' spelling must not escape the case-insensitive
    # default deferral detector — unmirrored, it must DROP.
    paths = _write_fixture(tmp_path)
    paths["notes"].write_text(
        NOTES + "- Deferred: lowercase spelling, sibling lane keeps its parser.\n"
    )
    res = _run(paths)
    assert res.returncode == 1
    assert "DROP: NOTES deferral seriesx:6 is unmirrored" in res.stdout


def test_table_deferral_emits_counted_advisory(tmp_path):
    # Blind spot made loud: deferral-shaped text outside top-level '- ' rows
    # (tables, prose) is not enforced, but must surface as a counted warning
    # — and enforced bullet rows must not inflate the count.
    paths = _write_fixture(tmp_path)
    paths["notes"].write_text(NOTES + "| #9 | DEFERRED to sibling lane | table row |\n")
    res = _run(paths)
    assert res.returncode == 0, res.stdout + res.stderr
    assert (
        "warning: NOTES seriesx: --notes-pattern matched 1 non-bullet line(s)"
        in res.stdout
    )


def test_missing_known_open_without_stub_mode_is_usage_error(tmp_path):
    paths = _write_fixture(tmp_path)
    paths["ko"].unlink()
    res = _run(paths)
    assert res.returncode != 0
    assert "does not exist" in res.stderr


def test_zero_space_heading_joins_universe(tmp_path):
    # Leak shape: a zero-whitespace ###[P1] heading — one char
    # outside the whitespace-drift coverage above — must join the
    # universe; undisposed, it must DROP instead of silently leaving
    # the carry.
    paths = _write_fixture(tmp_path)
    (paths["findings"] / "U04.md").write_text(
        "###[P1][CONFIRMED] zero-space heading with P1 content\n"
    )
    res = _run(paths)
    assert res.returncode == 1
    assert "DROP: finding prev:U04:1 [P1]" in res.stdout


def test_heading_like_lines_emit_counted_advisory(tmp_path):
    # The NEXT drift spelling (wrong hash count, stray chars before
    # the bracket) is not enforced but must surface as a counted
    # warning, never vanish; well-formed headings must not inflate it.
    paths = _write_fixture(tmp_path)
    (paths["findings"] / "U05.md").write_text(
        "## [P1] two-hash heading\n"
        "#### [P2] four-hash sub-heading\n"
        "###x[P3] stray char\n"
        "### [P4][CONFIRMED] well-formed, enforced\n"
    )
    res = _run(paths, "--emit-stubs")
    assert "warning: findings prev:U05: 3 heading-like line(s)" in res.stdout
    # the well-formed one is enforced (undisposed => reported), not advisory
    assert "DROP: finding prev:U05:4 [P4]" in res.stdout


def test_residual_risks_section_rows_join_universe(tmp_path):
    # The program's majority deferral spelling: a "## Residual risks"
    # section whose rows carry NO deferral word. By-placement rows
    # must join the universe — unmirrored, they must DROP — and a
    # later non-residual section must end the by-placement scope.
    paths = _write_fixture(tmp_path)
    paths["notes"].write_text(
        NOTES
        + "\n## Residual risks\n\n"
        + "- extract_imports' string-constant arm stays bespoke.\n"
        + "\n### per-lane\n\n"
        + "- the fnmatch '*' crosses '/' in map globs.\n"
        + "\n## Validation\n\n"
        + "- suite green on the composed tree.\n"
    )
    res = _run(paths)
    assert res.returncode == 1
    assert "DROP: NOTES deferral seriesx:9 is unmirrored" in res.stdout
    assert "DROP: NOTES deferral seriesx:13 is unmirrored" in res.stdout
    # the row under "## Validation" is outside the by-placement scope
    assert "seriesx:17" not in res.stdout


def test_observed_deferral_spellings_join_universe(tmp_path):
    # Real spellings from this program's series NOTES that carry no
    # "defer" token: each must join the default vocabulary.
    paths = _write_fixture(tmp_path)
    paths["notes"].write_text(
        NOTES
        + "- Recorded, not fixed: the Rust token-tree residual.\n"
        + "- Left byte-identical; needs its own fix series.\n"
        + "- Follow-up candidate: the C/Go stripper migration.\n"
        + "- Out of this series' charter: sanitiser unification.\n"
    )
    res = _run(paths)
    assert res.returncode == 1
    for lineno in (6, 7, 8, 9):
        assert f"DROP: NOTES deferral seriesx:{lineno} is unmirrored" in res.stdout, (
            lineno, res.stdout)


def test_zero_contribution_notes_warns(tmp_path):
    # A NOTES file yielding no universe rows is a visible vocabulary
    # gap, not a silent pass.
    paths = _write_fixture(tmp_path)
    paths["notes"].write_text("# series NOTES\n\n- FIXED: everything.\n")
    paths["ko"].write_text(
        CLEAN_KO
        .replace("- [src: NOTES:seriesx:4] bespoke lexer kept — OPEN — "
                 "owner backlog. [p1: 2-3]\n",
                 "- direct ownership rows kept. [p1: 2-3]\n")
        .replace("- [src: NOTES:seriesx:5] residual risks recorded as "
                 "none — no carry.\n", "")
    )
    res = _run(paths)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "warning: NOTES seriesx: contributed ZERO deferral rows" in res.stdout
