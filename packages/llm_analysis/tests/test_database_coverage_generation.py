"""Coverage caches follow replaced database source generations."""

import zipfile

from packages.hypothesis_validation.adapters import CodeQLAdapter
from packages.hypothesis_validation.adapters.base import ToolEvidence
from packages.llm_analysis import dataflow_validation as dv
from packages.llm_analysis.tests.test_dataflow_validation import (
    _owned_database_memos as _owned_database_memos,
)


def test_replaced_archive_refreshes_index_text_and_callable_inventory(tmp_path, monkeypatch):
    db = tmp_path / "db"
    db.mkdir()
    marker = db / "codeql-database.yml"
    marker.write_text("owned-generation: one\n")
    archive_path = db / "src.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("repo/A.java", "void handle() {}\n")
    finding = {"file_path": "A.java", "function_name": "handle"}
    state = {"matches": [{"file": "repo/A.java", "message": "RAPTOR_CALLABLE:handle"}]}
    calls = []
    monkeypatch.setattr(dv, "_layer3_probe_path", lambda language: tmp_path / "owned.ql")
    monkeypatch.setattr(CodeQLAdapter, "is_available", lambda self: True)

    def run_prebuilt(self, query, target):
        calls.append((query, target))
        return ToolEvidence(tool="codeql", rule="owned", success=True,
                            matches=state["matches"])

    monkeypatch.setattr(CodeQLAdapter, "run_prebuilt_query", run_prebuilt)
    assert dv._finding_file_in_db(finding, db)
    assert dv._read_db_source(db, "repo/A.java") == "void handle() {}\n"
    assert dv._function_in_codeql_inventory(finding, db, "java") is True
    # Ordinary query scratch directories do not invalidate a database generation.
    scratch = db / "owned-query-scratch"
    scratch.mkdir()
    scratch.rmdir()
    assert dv._function_in_codeql_inventory(finding, db, "java") is True
    assert len(calls) == 1
    replacement = db / "replacement.zip"
    with zipfile.ZipFile(replacement, "w") as archive:
        archive.writestr("repo/B.java", "void other() {}\n")
    replacement.replace(archive_path)
    state["matches"] = []
    observed = (
        dv._finding_file_in_db(finding, db),
        dv._read_db_source(db, "repo/A.java"),
        dv._function_in_codeql_inventory(finding, db, "java"),
    )
    assert observed == (False, None, False)
    assert len(calls) == 2
    assert len(dv._db_source_cache) == 1
    assert dv._db_source_cache_chars == 0
    # Replacing database metadata also refreshes a previously empty inventory.
    new_marker = db / "new-marker.yml"
    new_marker.write_text("owned-generation: two\n")
    new_marker.replace(marker)
    state["matches"] = [{"file": "repo/A.java", "message": "RAPTOR_CALLABLE:handle"}]
    assert dv._function_in_codeql_inventory(finding, db, "java") is True
    assert len(calls) == 3
