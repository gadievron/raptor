"""SARIF ingestion goes through the canonical bounded loader.

``SarifCache`` ingestion used a raw ``read_text()`` + ``json.loads``
with no byte cap, bypassing ``core.sarif.parser.load_sarif``'s 100 MiB
size guard — a hostile or runaway SARIF artifact could balloon the
orchestrator's memory before the parse even started.
"""

from __future__ import annotations

import json


class TestBoundedSarifIngestion:
    """Ingestion routes through the canonical bounded SARIF loader."""

    def test_oversized_sarif_is_rejected(self, tmp_path, monkeypatch):
        from core.audit import sweep as sweep_mod
        from core.audit.sweep import SarifCache

        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        sarif = scan_dir / "big.sarif"
        sarif.write_text(json.dumps({
            "runs": [{
                "tool": {"driver": {"name": "test-scanner"}},
                "results": [{
                    "ruleId": "r1",
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/a.c"},
                            "region": {"startLine": 3},
                        },
                    }],
                }],
            }],
        }))
        # Force the canonical loader's size guard to trip without
        # writing 100 MiB to disk.
        real_stat = type(sarif).stat

        class _FakeStat:
            st_size = 101 * 1024 * 1024
            st_mtime = 0.0

        def fake_stat(self, **kwargs):
            if self.name == "big.sarif":
                return _FakeStat()
            return real_stat(self, **kwargs)

        monkeypatch.setattr(type(sarif), "stat", fake_stat)
        cache = SarifCache()
        ingested = sweep_mod._ingest_sarif_file(cache, sarif)
        assert ingested == 0
        assert not cache._by_file

    def test_normal_sarif_still_ingests(self, tmp_path):
        from core.audit import sweep as sweep_mod
        from core.audit.sweep import SarifCache

        sarif = tmp_path / "ok.sarif"
        sarif.write_text(json.dumps({
            "runs": [{
                "tool": {"driver": {"name": "test-scanner"}},
                "results": [{
                    "ruleId": "r1",
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/a.c"},
                            "region": {"startLine": 3},
                        },
                    }],
                }],
            }],
        }))
        cache = SarifCache()
        assert sweep_mod._ingest_sarif_file(cache, sarif) == 1
        assert "src/a.c" in cache._by_file
