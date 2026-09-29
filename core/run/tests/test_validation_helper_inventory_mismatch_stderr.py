"""Stage-A inventory-mismatch stderr warnings are escaped and bounded.

``_assemble_a`` cross-checks the assembled id set against the
``findings.json`` inventory and reports mismatches on stderr. Both id
sets are producer-derived (the inventory rides in from imports; part
rows are LLM-written), so a raw id on that channel is a
terminal-injection / log-splitting primitive. These tests pin:

  * an inventory id carrying ESC + a 100KB tail reaches stderr escaped
    (``\\x1b`` literal, never the raw byte) and bounded with an
    explicit elision marker;
  * a part whose finding id carries a trailing newline is refused at
    the stage-A lint (fullmatch), so the raw newline can never split a
    mismatch warning line — and the id never reaches ``stage-a.json``;
  * mismatch reporting survives mixed-type inventory ids (a non-string
    id must not crash the sort that orders the warnings);
  * VALID ids print byte-exact in the warning text — the mismatch
    report is only useful if an honest id can be grepped verbatim
    (escape-never-rewrite applies to invalid bytes, not valid ids).

The helper module is loaded lazily (fixture) so this file still
collects on a tree without the fix (failing-first discipline).
"""

import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
HELPER = REPO_ROOT / "libexec" / "raptor-validation-helper"

sys.path.insert(0, str(REPO_ROOT))

from core.json import load_json, save_json  # noqa: E402

FIND_1: dict[str, Any] = {
    "id": "FIND-1", "file": "src/a.c", "function": "f", "line": 1,
    "vuln_type": "buffer_overflow", "status": "not_disproven",
}

# Drill-shaped hostile inventory id: ANSI colour ESC then a 100KB
# printable tail (terminal flood + escape injection in one value).
HOSTILE_INV_ID = "FIND-2\x1b[31m" + "A" * 100_000


@pytest.fixture(scope="module")
def helper():
    script = str(HELPER)
    loader = SourceFileLoader(
        "raptor_validation_helper_inv_mismatch", script)
    spec = importlib.util.spec_from_loader(
        "raptor_validation_helper_inv_mismatch", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _setup(tmp_path: Path, inventory_rows: list[dict[str, Any]],
           parts_rows: list[list[dict[str, Any]]]) -> Path:
    parts_dir = tmp_path / "stage-a-parts"
    parts_dir.mkdir()
    save_json(tmp_path / "findings.json", {"findings": inventory_rows})
    for i, rows in enumerate(parts_rows):
        save_json(parts_dir / f"part-{i:03d}.json",
                  {"stage": "A", "findings": rows})
    return parts_dir


class TestHostileInventoryIdNetted:
    def test_control_byte_inventory_id_escaped_and_bounded(
            self, helper, tmp_path, capsys) -> None:
        # Pre-fix RED: the mismatch print interpolated the raw id —
        # the ESC byte and the full 100KB tail hit stderr verbatim.
        hostile_row = dict(FIND_1, id=HOSTILE_INV_ID, file="src/b.c")
        _setup(tmp_path, [FIND_1, hostile_row], [[FIND_1]])

        assert helper.assemble_parts("A", tmp_path) is True
        err = capsys.readouterr().err

        assert "missing from assembled findings" in err
        assert "\x1b" not in err, "raw ESC reached stderr"
        assert "\\x1b" in err, "escaped form absent from the warning"
        assert "...[+" in err, "no elision marker — value unbounded"
        # The 100KB tail must not flood the channel.
        assert len(err) < 2_000

    def test_mixed_type_inventory_ids_do_not_crash_the_report(
            self, helper, tmp_path, capsys) -> None:
        # Pre-fix RED: sorted() over a mixed {int, str} id set raised
        # TypeError before any warning printed, killing the whole
        # assembly on a malformed-but-loadable inventory.
        int_row = dict(FIND_1, id=123, file="src/c.c")
        str_row = dict(FIND_1, id="FIND-9", file="src/d.c")
        _setup(tmp_path, [FIND_1, int_row, str_row], [[FIND_1]])

        assert helper.assemble_parts("A", tmp_path) is True
        err = capsys.readouterr().err
        assert "inventory id 123 missing" in err
        assert "inventory id FIND-9 missing" in err


class TestNewlineIdCannotSplitTheChannel:
    def test_trailing_newline_part_id_refused_at_stage_a(
            self, helper, tmp_path) -> None:
        # Pre-fix RED: the stage-A lint used re.match, so "FIND-1\n"
        # passed, assembled into stage-a.json, and (as the got-side of
        # the mismatch check) rode its raw newline into a stderr
        # warning — a log-splitting primitive. Post-fix the part is
        # quarantined whole; with no valid sibling the assembly
        # refuses loudly.
        parts_dir = _setup(
            tmp_path, [FIND_1],
            [[dict(FIND_1, id="FIND-1\n", file="src/b.c")]])

        assert helper.assemble_parts("A", tmp_path) is False
        assert not (tmp_path / "stage-a.json").exists()
        qpath = (parts_dir / "quarantine" / "part-000.json.reason.json")
        record = load_json(qpath)
        assert record is not None
        assert any("does not match pattern" in r for r in record["reasons"])
        # The reason record embeds the id escaped: no raw newline
        # inside any reason string.
        assert all("\n" not in r for r in record["reasons"])

    def test_valid_sibling_still_assembles_newline_part_dropped(
            self, helper, tmp_path) -> None:
        _setup(tmp_path, [FIND_1],
               [[FIND_1],
                [dict(FIND_1, id="FIND-1\n", file="src/b.c")]])

        assert helper.assemble_parts("A", tmp_path) is True
        stage_a = load_json(tmp_path / "stage-a.json")
        assert [f["id"] for f in stage_a["findings"]] == ["FIND-1"]
        raw = (tmp_path / "stage-a.json").read_bytes()
        assert b'"FIND-1\\n"' not in raw


class TestValidIdsPrintVerbatim:
    def test_honest_mismatch_id_is_grep_able(
            self, helper, tmp_path, capsys) -> None:
        # The other direction: escaping must never mangle a VALID id —
        # the operator greps the warning text for the exact id.
        str_row = dict(FIND_1, id="FIND-9", file="src/d.c")
        _setup(tmp_path, [FIND_1, str_row], [[FIND_1]])

        assert helper.assemble_parts("A", tmp_path) is True
        err = capsys.readouterr().err
        assert ("WARNING: inventory id FIND-9 missing from assembled "
                "findings") in err
