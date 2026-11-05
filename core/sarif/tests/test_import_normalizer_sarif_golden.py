"""Byte-level golden test for the import-normalizer SARIF emitter.

The golden was captured from ``findings_to_sarif`` BEFORE it moved
onto ``core.sarif.emit``. The document is written with
``save_json(sort_keys=False)``, so member order is the on-disk byte
order — including this emitter's historical ``version``-before-
``$schema`` envelope — hence serialized comparison. The normalized metadata
round-trip fix deliberately moves conflicting catalog CWEs onto their own
results so a row without a CWE does not inherit another row's classification.

Input coverage: one run per tool (two tools + the ``external``
default), rule dedup with and without CWE properties, region member
omission (endLine / snippet absent), internal dataflow dict →
codeFlows (primary + alternatives, degenerate alternative dropped),
list-shaped dataflow passthrough (non-dict entries dropped), the
legacy fingerprint guard (``finding_id == rule_id`` NOT stamped),
and ``None`` message/file/level coercion.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.sarif.import_normalizer import findings_to_sarif

_GOLDEN = (
    Path(__file__).parent / "data" / "import_normalizer_sarif_golden.json"
)


def _inputs() -> list[dict]:
    return [
        {"tool": "semgrep", "rule_id": "py.flask.xss", "file": "app/views.py",
         "startLine": 10, "endLine": 12, "snippet": "return render(x)",
         "level": "error", "message": "reflected XSS",
         "cwe_id": "CWE-79", "finding_id": "abc123",
         "has_dataflow": True,
         "dataflow_path": {
             "source": {"file": "app/views.py", "line": 4, "column": 2,
                        "label": "request.args",
                        "snippet": "x = request.args"},
             "steps": [{"file": "app/views.py", "line": 7}],
             "sink": {"file": "app/views.py", "line": 10, "column": 0,
                      "snippet": "return render(x)"},
             "alternative_paths": [
                 {"source": {"file": "app/other.py", "line": 1},
                  "sink": {"file": "app/views.py", "line": 10}},
                 {"source": None, "sink": None},
             ],
         }},
        {"tool": "semgrep", "rule_id": "py.flask.xss", "file": "app/admin.py",
         "startLine": 5, "message": "same rule, deduped",
         "finding_id": "py.flask.xss"},
        {"rule_id": "外部-rule", "message": "no tool -> external run",
         "has_dataflow": True,
         "dataflow_path": [{"threadFlows": []}, "not-a-dict"]},
        {"tool": "codeql", "message": None, "file": None,
         "level": None},
    ]


def test_sarif_document_is_byte_identical_to_golden():
    doc = findings_to_sarif(_inputs())
    got = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    assert got == _GOLDEN.read_text(encoding="utf-8")


def test_envelope_member_order_version_first():
    """This emitter historically wrote ``version`` ahead of
    ``$schema``; the consolidation preserves that byte order."""
    doc = findings_to_sarif(_inputs())
    assert list(doc) == ["version", "$schema", "runs"]
