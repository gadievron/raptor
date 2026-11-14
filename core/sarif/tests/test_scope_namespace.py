"""Direct finding identity namespace controls; file import is fenced."""

from copy import deepcopy
import hashlib

import pytest

from core.json import dumps_canonical
from core.sarif import parser


@pytest.fixture(autouse=True)
def no_file_import(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("direct dedup test entered file import/merge")

    for name in ("parse_sarif_findings", "merge_sarif", "load_sarif"):
        monkeypatch.setattr(parser, name, forbidden)


def finding(tool, **extra):
    return {
        "tool": tool, "finding_id": "owned-native", "file": "owned.c",
        "startLine": 7, "endLine": 7, "rule_id": "owned/rule", **extra,
    }


def test_raw_tool_does_not_alias_encoded_rule_scope():
    origin = hashlib.sha256(b"owned rule scope").hexdigest()
    raw_name = dumps_canonical(["owned scanner", origin])
    rows = [finding("owned scanner", rule_scope=origin), finding(raw_name)]
    before = deepcopy(rows)
    retained = parser.deduplicate_findings(rows)
    assert len(retained) == 2
    assert {row["tool"] for row in retained} == {"owned scanner", raw_name}
    assert len({row["finding_id"] for row in retained}) == 2
    assert {row["source_finding_id"] for row in retained} == {"owned-native"}
    assert rows == before


def test_escape_prefix_keeps_unscoped_tool_names_distinct():
    first = dumps_canonical(["owned scanner", "owned origin"])
    rows = [finding(first), finding("\\" + first)]
    retained = parser.deduplicate_findings(rows)
    assert len(retained) == 2
    assert len({row["finding_id"] for row in retained}) == 2


def test_ordinary_cross_tool_qualified_ids_remain_exact():
    rows = [finding("semgrep"), finding("codeql")]
    retained = parser.deduplicate_findings(rows)
    assert {row["tool"]: row["finding_id"] for row in retained} == {'codeql': '5dab34f9b4a4d71953af4876c2f321a9c72175e5d88df75e89f294332ff11389', 'semgrep': '8f077096302df7ace9a2a3284c78720df9f8875d76326e57110e91d9b72f0fdb'}


def test_legacy_duplicate_still_collapses_without_qualification():
    row = finding("semgrep")
    assert parser.deduplicate_findings([row, dict(row)]) == [row]
    assert row["finding_id"] == "owned-native"
