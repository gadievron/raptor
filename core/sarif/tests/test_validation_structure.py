"""Basic report validation remains effective without an optional JSON schema."""
import json

import pytest

from core.sarif.parser import validate_sarif


@pytest.mark.parametrize("runs", [None, {}, "bad", [None], [{"results": {}}],
                                  [{"results": [None]}]])
def test_malformed_containers_fail_before_optional_schema(tmp_path, runs):
    report = tmp_path / 'report.sarif'
    report.write_text(json.dumps({'version': '2.1.0', 'runs': runs}))
    assert validate_sarif(report, schema_path=tmp_path / 'missing-schema.json') is False


def test_valid_basic_report_can_still_be_unverified(tmp_path):
    report = tmp_path / 'report.sarif'
    report.write_text(json.dumps({'version': '2.1.0', 'runs': [{'results': []}]}))
    assert validate_sarif(report, schema_path=tmp_path / 'missing-schema.json') is None
