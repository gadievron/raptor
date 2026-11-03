"""RE database streaming retains extension data and atomic failure behavior."""
import json
from types import SimpleNamespace

import pytest

from packages.ghidra.bridge import GhidraBridge
from packages.ghidra.model import REDatabase, REFunction


def database():
    return REDatabase(source_tool="ghidra", architecture="x86:LE:64",
                      functions=[REFunction(name="café_处理", address=4096, size=32,
                                            decompilation="int f() { return 1; }\n" * 5000)],
                      metadata={"custom": {"unknown": ["😀", "quote\"newline\n", 2**90]}})


def test_large_unicode_database_round_trip_preserves_all_fields(tmp_path):
    db = database()
    bridge = SimpleNamespace(gpr_path=tmp_path / "project.gpr")
    GhidraBridge._write_re_database(bridge, db, tmp_path)
    result = json.loads((tmp_path / "re-database.json").read_bytes())
    assert result == db.to_dict()
    assert result["functions"][0]["decompilation"] == db.functions[0].decompilation


def test_late_invalid_metadata_keeps_existing_database(tmp_path):
    db = database()
    db.metadata["late_invalid"] = float("nan")
    target = tmp_path / "re-database.json"
    target.write_text('{"previous":true}\n')
    bridge = SimpleNamespace(gpr_path=tmp_path / "project.gpr")
    with pytest.raises(ValueError):
        GhidraBridge._write_re_database(bridge, db, tmp_path)
    assert target.read_text() == '{"previous":true}\n'
    assert not list(tmp_path.glob('.~savejson-*'))
