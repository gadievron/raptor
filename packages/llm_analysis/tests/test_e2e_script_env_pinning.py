"""The e2e scripts spawn child-process trees that re-import RAPTOR;
each must hard-pin RAPTOR_DIR to THIS checkout so a stale env export
for another checkout can't make the children validate the wrong tree.
Mechanical parity check across the sibling scripts — the deepest
child-spawner (execute-witness) is exactly the one where an unpinned
env does the most damage."""

from __future__ import annotations

from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"


@pytest.mark.parametrize("script", [
    "e2e_execute_witness.py",
    "e2e_verify_exploit.py",
    "e2e_intent_match.py",
])
def test_e2e_script_pins_raptor_dir(script: str) -> None:
    source = (_SCRIPTS_DIR / script).read_text(encoding="utf-8")
    assert "pin_raptor_dir_in_environ()" in source, script
