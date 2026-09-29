"""Non-dict promotion candidates are refused with a loud skip.

``_promote_checklist`` re-stamps whatever it elects at the project
level via ``save_checklist``. A run-local ``checklist.json`` holding
valid JSON that is NOT an object (a list, a string, a number) is
corrupt for every consumer — ``read_checklist`` already returns ``{}``
for one — so promotion must skip it to the next-newest sibling (same
degrade direction as a tampered frame, loud warning naming the file)
instead of installing it as the project checklist or crashing the
carry-forward merge on the older-siblings path.
"""

import json
import logging
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


def _doc(name: str = "f1", checked_by: list[str] | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"name": name, "line_start": 1, "line_end": 9}
    if checked_by:
        item["checked_by"] = checked_by
    return {"files": [{"path": "a.c", "lines": 9, "items": [item]}]}


class _CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class NonDictCandidateSkippedTest(unittest.TestCase):
    """List/scalar-shaped run-local checklists never reach the project
    slot and never feed the carry-forward merge."""

    # Promotion's shape refusal logs from core.run.metadata, which
    # get_logger namespaces under the framework root.
    _LOGGER = "raptor.core.run.metadata"

    def _promote_capturing(self, proj: Path) -> str:
        from core.run.metadata import _promote_checklist
        handler = _CaptureHandler()
        logging.getLogger(self._LOGGER).addHandler(handler)
        try:
            _promote_checklist(proj)
        finally:
            logging.getLogger(self._LOGGER).removeHandler(handler)
        return " ".join(r.getMessage() for r in handler.records)

    def test_list_newest_skipped_next_dict_promotes(self) -> None:
        from core.inventory import read_checklist, save_checklist
        with TemporaryDirectory() as d:
            proj = Path(d)
            old_run = proj / "run_001"
            old_run.mkdir()
            save_checklist(old_run, _doc("honest"))
            new_run = proj / "run_002"
            new_run.mkdir()
            (new_run / "checklist.json").write_text(
                json.dumps([{"files": []}, "junk"]))
            # Pin the ordering AFTER all writes: the list-shaped run is
            # the newest candidate, the honest dict next.
            os.utime(old_run, (1_700_000_000, 1_700_000_000))
            os.utime(new_run, (1_700_000_100, 1_700_000_100))

            warned = self._promote_capturing(proj)

            promoted = read_checklist(proj)
            names = [i["name"] for f in promoted["files"]
                     for i in f["items"]]
            self.assertEqual(names, ["honest"])  # next-newest won
            # Project slot ends healthy: a JSON object on disk.
            on_disk = json.loads((proj / "checklist.json").read_text())
            self.assertIsInstance(on_disk, dict)
            # Loud skip names the refused file.
            self.assertIn(str(new_run / "checklist.json"), warned)
            # Pin the type-name rendering — a bare "list" would match
            # inside the word "checklist" and assert nothing.
            self.assertIn("(list)", warned)

    def test_list_only_candidate_promotes_nothing(self) -> None:
        from core.inventory import read_checklist
        with TemporaryDirectory() as d:
            proj = Path(d)
            run = proj / "run_001"
            run.mkdir()
            (run / "checklist.json").write_text(json.dumps(["junk"]))

            self._promote_capturing(proj)

            # Fail-closed: nothing promoted, the project slot stays
            # empty rather than holding a document every reader
            # refuses as non-dict.
            self.assertFalse((proj / "checklist.json").exists())
            self.assertEqual(read_checklist(proj), {})

    def test_scalar_shapes_skipped(self) -> None:
        from core.inventory import read_checklist
        for payload in ('"just a string"', "42", "true"):
            with TemporaryDirectory() as d:
                proj = Path(d)
                run = proj / "run_001"
                run.mkdir()
                (run / "checklist.json").write_text(payload)

                self._promote_capturing(proj)

                self.assertFalse(
                    (proj / "checklist.json").exists(),
                    f"payload {payload!r} reached the project slot")
                self.assertEqual(read_checklist(proj), {})

    def test_non_dict_older_sibling_does_not_corrupt_carry_forward(
            self) -> None:
        from core.inventory import read_checklist, save_checklist
        with TemporaryDirectory() as d:
            proj = Path(d)
            oldest = proj / "run_001"
            oldest.mkdir()
            save_checklist(oldest, _doc("f1", checked_by=["semgrep"]))
            middle = proj / "run_002"
            middle.mkdir()
            (middle / "checklist.json").write_text(json.dumps(["junk"]))
            newest = proj / "run_003"
            newest.mkdir()
            save_checklist(newest, _doc("f1"))
            os.utime(oldest, (1_700_000_000, 1_700_000_000))
            os.utime(middle, (1_700_000_100, 1_700_000_100))
            os.utime(newest, (1_700_000_200, 1_700_000_200))

            self._promote_capturing(proj)

            promoted = read_checklist(proj)
            names = [i["name"] for f in promoted["files"]
                     for i in f["items"]]
            self.assertEqual(names, ["f1"])
            # Carry-forward still folded the OLDEST sibling's marks in
            # across the skipped middle one.
            got = promoted["files"][0]["items"][0].get("checked_by", [])
            self.assertIn("semgrep", got)


if __name__ == "__main__":
    unittest.main()
