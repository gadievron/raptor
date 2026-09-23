"""_write_re_database's binary hash is containment-gated.

``binary_path`` comes from ``program.getExecutablePath()`` inside the
attacker-supplied project. Hashing it unconstrained made the writer a
same-user file-existence + sha256 oracle: any local path the project
author named got its digest stamped into the long-lived
re-database.json deliverable. The write side now applies the same
containment rule ``import_and_enrich`` already enforces for the same
field, omitting the hash on refusal.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from packages.ghidra.bridge import GhidraBridge
from packages.ghidra.model import REDatabase


def _bridge_at(project_dir: Path) -> SimpleNamespace:
    # _write_re_database consults only self.gpr_path — a namespace
    # stand-in avoids the project validation a full construct runs.
    return SimpleNamespace(gpr_path=project_dir / "p.gpr")


def _written_metadata(tmp_path: Path, db: REDatabase,
                      project_dir: Path) -> dict:
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    GhidraBridge._write_re_database(_bridge_at(project_dir), db, out)
    return json.loads(
        (out / "re-database.json").read_text(),
    ).get("metadata", {})


def test_outside_project_path_is_not_hashed(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    secret = tmp_path / "secret-outside-project.txt"
    secret.write_text("s3cret token contents\n")
    db = REDatabase(source_tool="ghidra", binary_path=str(secret))
    meta = _written_metadata(tmp_path, db, project)
    assert "binary_sha256" not in meta


def test_traversal_relative_path_is_not_hashed(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    secret = tmp_path / "secret.bin"
    secret.write_bytes(b"x")
    db = REDatabase(source_tool="ghidra",
                    binary_path="../secret.bin")
    meta = _written_metadata(tmp_path, db, project)
    assert "binary_sha256" not in meta


def test_bundled_sibling_binary_is_hashed(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    binary = project / "target.bin"
    binary.write_bytes(b"legit binary bytes")
    expected = hashlib.sha256(binary.read_bytes()).hexdigest()
    for path in ("target.bin", str(binary)):
        db = REDatabase(source_tool="ghidra", binary_path=path)
        meta = _written_metadata(tmp_path, db, project)
        assert meta.get("binary_sha256") == expected


def test_empty_binary_path_omits_hash(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    db = REDatabase(source_tool="ghidra", binary_path=None)
    meta = _written_metadata(tmp_path, db, project)
    assert "binary_sha256" not in meta
