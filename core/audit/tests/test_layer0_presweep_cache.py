"""Prep-cache reload seam for the Layer 0 source pre-sweep.

Incident regression (resume wall cost): the pre-sweep re-read every
function's file and re-ran the full pattern battery on every resumed
segment even though its inputs (the pinned checklist's spans + the
target sources) were unchanged. The prep cache reloads the
per-function findings on a fingerprint match and re-scans when it
does not.
"""

from __future__ import annotations

from pathlib import Path

from core.evidence import EvidenceRecord

import core.audit.binary_layer0 as bl0
from core.audit.binary_layer0 import run_source_presweep

_SOURCE = """\
int tty_flag = 0;

static int
check_and_open(const char *path)
{
\tif (access(path, R_OK) != 0)
\t\treturn -1;
\treturn open(path, 0);
}

static int
unrelated(int x)
{
\treturn x + 1;
}
"""


def _target(tmp_path: Path) -> Path:
    root = tmp_path / "target"
    root.mkdir()
    (root / "f.c").write_text(_SOURCE, encoding="utf-8")
    return root


def _index() -> dict[str, EvidenceRecord]:
    return {
        "f.c:check_and_open": EvidenceRecord(
            file="f.c", function="check_and_open",
            line_start=3, line_end=9, kind="function",
        ),
        "f.c:unrelated": EvidenceRecord(
            file="f.c", function="unrelated",
            line_start=11, line_end=15, kind="function",
        ),
        "f.c:tty_flag": EvidenceRecord(
            file="f.c", function="tty_flag",
            line_start=1, line_end=1, kind="global",
        ),
    }


def _findings_view(index):
    return {
        key: [f.to_dict() for f in rec.binary_layer0_findings]
        for key, rec in index.items()
    }


class TestLayer0PresweepCache:
    def test_second_run_reloads_and_skips_the_scan(
        self, tmp_path, monkeypatch,
    ):
        target = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        idx1 = _index()
        r1 = run_source_presweep(idx1, target, out_dir=out)
        assert r1.functions_scanned == 2
        assert r1.findings, "the TOCTOU pair must produce a finding"
        assert (
            out / "prep-cache" / "layer0-presweep-cache.json"
        ).is_file()

        calls = []
        real = bl0.scan_function

        def spy(*a, **kw):
            calls.append(1)
            return real(*a, **kw)

        monkeypatch.setattr(bl0, "scan_function", spy)
        idx2 = _index()
        r2 = run_source_presweep(idx2, target, out_dir=out)
        assert calls == [], "cache hit must skip the pattern battery"
        assert r2.functions_scanned == r1.functions_scanned
        assert [f.to_dict() for f in r2.findings] == [
            f.to_dict() for f in r1.findings
        ]
        assert _findings_view(idx2) == _findings_view(idx1)
        # The globals record stays finding-free either way.
        assert not idx2["f.c:tty_flag"].binary_layer0_findings

    def test_changed_source_rebuilds(self, tmp_path, monkeypatch):
        target = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        run_source_presweep(_index(), target, out_dir=out)

        calls = []
        real = bl0.scan_function

        def spy(*a, **kw):
            calls.append(1)
            return real(*a, **kw)

        monkeypatch.setattr(bl0, "scan_function", spy)
        (target / "f.c").write_text(
            _SOURCE + "\nstatic int extra(void)\n{\n\treturn 0;\n}\n",
            encoding="utf-8",
        )
        run_source_presweep(_index(), target, out_dir=out)
        assert calls, "fingerprint mismatch must re-scan"

    def test_changed_span_rebuilds(self, tmp_path, monkeypatch):
        target = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        run_source_presweep(_index(), target, out_dir=out)

        calls = []
        real = bl0.scan_function

        def spy(*a, **kw):
            calls.append(1)
            return real(*a, **kw)

        monkeypatch.setattr(bl0, "scan_function", spy)
        idx = _index()
        idx["f.c:check_and_open"].line_end = 8
        run_source_presweep(idx, target, out_dir=out)
        assert calls, "span change must re-scan"

    def test_corrupt_cache_rebuilds(self, tmp_path):
        target = _target(tmp_path)
        out = tmp_path / "out"
        (out / "prep-cache").mkdir(parents=True)
        (out / "prep-cache" / "layer0-presweep-cache.json").write_text(
            "{nope",
        )
        idx = _index()
        result = run_source_presweep(idx, target, out_dir=out)
        assert result.functions_scanned == 2
        assert idx["f.c:check_and_open"].binary_layer0_findings

    def test_no_out_dir_means_no_cache(self, tmp_path):
        target = _target(tmp_path)
        idx = _index()
        result = run_source_presweep(idx, target)
        assert result.functions_scanned == 2
        assert not list(tmp_path.rglob("layer0-presweep-cache.json"))

    def test_gates_match_the_inline_sweep(self, tmp_path):
        # kind + span gates: globals and span-less records never scan.
        target = _target(tmp_path)
        idx = {
            "f.c:tty_flag": EvidenceRecord(
                file="f.c", function="tty_flag",
                line_start=1, line_end=1, kind="global",
            ),
            "f.c:spanless": EvidenceRecord(
                file="f.c", function="check_and_open", kind="function",
            ),
        }
        result = run_source_presweep(idx, target)
        assert result.functions_scanned == 0
        assert result.findings == []

    def test_broken_shape_cache_rebuilds(self, tmp_path):
        import json as _json

        from core.audit.binary_layer0 import _presweep_fingerprint

        target = _target(tmp_path)
        out = tmp_path / "out"
        (out / "prep-cache").mkdir(parents=True)
        idx = _index()
        gated = [
            (k, r) for k, r in idx.items() if r.kind == "function"
        ]
        fp = _presweep_fingerprint(gated, target)
        # json-valid, fingerprint-matching, but a row from_dict chokes
        # on — must degrade to the re-scan, not raise, and must leave
        # no partial findings on the records.
        (out / "prep-cache" / "layer0-presweep-cache.json").write_text(
            _json.dumps({
                "fingerprint": fp,
                "payload": {
                    "functions_scanned": 2,
                    "findings_by_key": {
                        "f.c:check_and_open": [{"line": "not-a-number"}],
                    },
                },
            }),
        )
        result = run_source_presweep(idx, target, out_dir=out)
        assert result.functions_scanned == 2
        assert idx["f.c:check_and_open"].binary_layer0_findings
        assert all(
            isinstance(f.line, int)
            for f in idx["f.c:check_and_open"].binary_layer0_findings
        )
