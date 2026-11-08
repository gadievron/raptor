"""Byte-level golden test for the coccinelle SARIF emitter.

The SARIF document is written with ``save_json(sort_keys=False)``, so
dict insertion order is the on-disk byte order. The golden file was
captured from the emitter BEFORE it moved onto ``core.sarif.emit``;
this test pins that the shared-skeleton emitter reproduces the same
bytes (member order included — hence serialized comparison, not dict
equality).

Input coverage: rule-id dedup (first ``rule_path`` wins), full and
minimal regions (falsy column/line_end omitted), absolute path under
the repo (relativized), absolute path outside it (left as-is), empty
rule name (``(unnamed)``), empty message (default text), spatch
errors (>500 chars, truncated into an invocation notification), and
a match-less rule that still appears in the rule catalog.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if __name__ == "__main__":
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)

from packages.coccinelle.models import SpatchMatch, SpatchResult  # noqa: E402
from packages.coccinelle.sarif import results_to_sarif  # noqa: E402

_GOLDEN = Path(__file__).parent / "data" / "sarif_emit_golden.json"


def _inputs() -> list[SpatchResult]:
    return [
        SpatchResult(
            rule="null_check",
            rule_path="rules/null_check.cocci",
            matches=[
                SpatchMatch(
                    file="/raptor-golden-repo/src/a.c", line=10, column=4,
                    line_end=12, column_end=9, rule="null_check",
                    message="deref before check",
                ),
                SpatchMatch(file="src/b.c", line=7, rule="null_check"),
            ],
            errors=["spatch: parse error in a.c" + "x" * 600],
        ),
        SpatchResult(rule="null_check", matches=[
            SpatchMatch(file="src/c.c", line=1, rule="null_check",
                        message="dup rule id"),
        ]),
        SpatchResult(rule="", rule_path="", matches=[
            SpatchMatch(file="/elsewhere/d.c", line=3),
        ]),
        SpatchResult(rule="clean_rule", rule_path="rules/clean_rule.cocci"),
    ]


def test_sarif_document_is_byte_identical_to_golden():
    doc = results_to_sarif(_inputs(), Path("/raptor-golden-repo"))
    got = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    assert got == _GOLDEN.read_text(encoding="utf-8")
