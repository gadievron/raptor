"""Runtime boundaries retained by the supplied SCA type-contract corrections."""
from contextlib import closing
import hashlib
import json
import sys
from types import ModuleType

import pytest

from core.testing.module_bindings import patch_module_attribute
from packages.sca.finding_stream import FindingsFile
from packages.sca.osv_offline import OsvOfflineDB
from packages.sca.reporting import build_sca_document
from packages.sca.resolvers import _cache
from packages.sca.resolvers.gomod import GoResolver


def test_reporting_stream_counts_all_rows_without_sizing_or_restarting(tmp_path, monkeypatch):
    from packages.sca import reporting
    monkeypatch.setattr(reporting, "MAX_FINDINGS", 1)
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([
        {"finding_id": "one", "vuln_type": "sca:vulnerable_dependency", "severity": "high",
         "sca": {"name": "one", "version": "1", "ecosystem": "npm"}},
        {"finding_id": "two", "vuln_type": "sca:vulnerable_dependency", "severity": "high",
         "sca": {"name": "two", "version": "1", "ecosystem": "npm", "in_kev": True}},
        {"vuln_type": "sca:scan_health:advisory_lookup_unavailable", "description": "offline evidence unavailable"},
        False,
    ]))

    class OnePassFindings(FindingsFile):
        iterations = 0

        def __iter__(self):
            self.iterations += 1
            assert self.iterations == 1, "The input must not be decoded again"
            yield from super().__iter__()

        def __len__(self):
            raise AssertionError("The complete findings stream must not be sized/materialised")

        def __getitem__(self, key):
            raise AssertionError("Only the bounded captured rows may be indexed")

    rows = OnePassFindings(path)
    context, document = build_sca_document(rows=rows, target=tmp_path, output_dir=tmp_path, deps_analysed=2)
    assert rows.iterations == 1
    assert context.extensions["raptor.accounting"] == {"recorded_rows": 3, "captured_rows": 1}
    assert len(context.findings) == 1 and document.summary["KEV matches"] == 1
    assert context.state == "partial"
    assert any("1 non-object" in note for note in context.diagnostics)
    assert "offline evidence unavailable" in context.diagnostics
    classes = next(block for block in document.blocks if block.title == "Finding classes")
    assert sum(row[1] for row in classes.rows) == 3


@pytest.mark.parametrize("module_file", [None, "", "present"])
def test_resolver_cache_handles_absent_module_filename_without_changing_identity(tmp_path, monkeypatch, module_file):
    source = tmp_path / "resolver.py"
    source.write_bytes(b"owned resolver source")
    module = ModuleType(GoResolver.__module__)
    module.__file__ = str(source) if module_file == "present" else module_file
    borrowed_modules = sys.modules
    patch_module_attribute(monkeypatch, _cache, "sys", "modules", {**sys.modules, GoResolver.__module__: module})
    monkeypatch.setattr(_cache, "_OVERRIDE_CONFIG_PATH", tmp_path / "absent-hosts.json")
    raw = _cache._resolution_context(GoResolver())
    assert raw is not None
    expected = source.read_bytes() if module_file == "present" else b""
    assert json.loads(raw)["resolver"] == hashlib.sha256(expected).hexdigest()
    assert sys.modules is borrowed_modules and sys.modules[GoResolver.__module__] is not module


def test_offline_metadata_initialises_and_reopens_the_local_connection(tmp_path):
    # No HTTP client is supplied: reading local receipts must never refresh OSV.
    with closing(OsvOfflineDB(tmp_path / "offline.sqlite")) as db:
        assert db.snapshot_metadata() == {}
        assert db._conn is not None
        db._conn.execute("INSERT INTO ingest_meta VALUES (?, ?)", ("PyPI", 123))
        db._conn.commit()
        db.close()
        assert db._conn is None
        assert db.snapshot_metadata() == {"PyPI": 123}
