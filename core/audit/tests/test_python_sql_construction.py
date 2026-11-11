"""Construction matches remain visible without independently verifying SQL injection."""


import pytest

from core.audit import sweep
from core.detectors import python_sql
from core.testing.module_views import scoped_function_imports
from packages.semgrep import runner
from packages.semgrep.models import SemgrepFinding, SemgrepResult


_CONCAT = "raptor.injection.sql.concatenation"
_FORMAT = "raptor.injection.sql.concatenation.format"
_TAINT = "raptor.injection.sql.taint.python"


def _run(tmp_path, identifiers, *, prefix="", raw=False, scope="curated",
         source=None, lines=None, hypothesis=""):
    extension = ".c" if scope == "non-python" else ".py"
    target = tmp_path / ("subject" + extension)
    source = source or 'def subject(cursor):\n    query = "SELECT " + str(int(input()))\n'
    target.write_text(source)
    config = python_sql.RULE_SOURCE
    if scope == "directory":
        config = config.parent
    elif scope == "operator":
        config = tmp_path / "operator.yaml"
        config.write_bytes(python_sql.RULE_SOURCE.read_bytes())
    rows = []
    for index, identifier in enumerate(identifiers):
        line = lines[index] if lines else 2
        identifier = prefix + identifier
        if raw:
            key = "check_id" if raw == "check_id" else "rule_id"
            rows.append({key: identifier, "start": {"line": line}, "message": "lead"})
        else:
            rows.append(SemgrepFinding(file=str(target), line=line,
                                       rule_id=identifier, message="lead"))
    calls = []
    def transport(path, selected, **kwargs):
        assert path == target and selected == str(config)
        calls.append(path)
        return SemgrepResult(findings=rows, files_examined=[str(path)])
    with scoped_function_imports(sweep, ["run_semgrep_sweep"], {
        "packages.semgrep.runner": runner,
    }) as owned:
        native = getattr(owned, "packages.semgrep.runner")
        native.is_available = lambda: True
        native.run_rule = transport
        result = sweep.run_semgrep_sweep(target_path=tmp_path, file_path=target.name,
            function_name="subject", rule_config=str(config), line_start=1,
            line_end=len(source.splitlines()), hypothesis=hypothesis)
    assert calls == [target]
    assert not result.errors
    return result


@pytest.mark.parametrize("identifier", [_CONCAT, _FORMAT])
@pytest.mark.parametrize("prefix", ["", "engine.semgrep.rules.injection."])
@pytest.mark.parametrize("raw", [False, True, "check_id"],
                         ids=["model", "mapping-rule-id", "mapping-check-id"])
def test_construction_only_keeps_matches_as_inconclusive(tmp_path, identifier, prefix, raw):
    result = _run(tmp_path, [identifier], prefix=prefix, raw=raw)
    assert result.outcome == "inconclusive"
    assert len(result.matches) == 1
    assert "construction-only SQL" in result.details["reason"]


@pytest.mark.parametrize("prefix", ["", "engine.semgrep.rules.injection."])
def test_genuine_taint_with_search_match_remains_confirmed(tmp_path, prefix):
    result = _run(tmp_path, [_CONCAT, _TAINT], prefix=prefix)
    assert result.outcome == "confirmed"
    assert len(result.matches) == 2


def test_containing_shipped_directory_keeps_construction_cap(tmp_path):
    result = _run(tmp_path, [_CONCAT], scope="directory")
    assert result.outcome == "inconclusive" and len(result.matches) == 1


@pytest.mark.parametrize("scope", ["operator", "non-python"])
def test_cap_does_not_classify_unrelated_config_or_language(tmp_path, scope):
    result = _run(tmp_path, [_CONCAT], scope=scope)
    assert result.outcome == "confirmed"


@pytest.mark.parametrize("identifier", [
    _CONCAT + ".php", _FORMAT + "_extra", "not" + _CONCAT, _TAINT, "other.rule",
])
def test_suffix_lookalikes_and_unknown_ids_are_not_reclassified(tmp_path, identifier):
    result = _run(tmp_path, [identifier])
    assert result.outcome == "confirmed"


def test_identifier_filter_leaving_only_construction_cannot_verify(tmp_path):
    source = ('def subject(cursor):\n'
              '    query = "SELECT " + str(int(input()))\n'
              '    a = 0\n    b = 0\n    c = 0\n    d = 0\n    e = 0\n    f = 0\n'
              '    cursor.execute(input())\n')
    result = _run(tmp_path, [_CONCAT, _TAINT], source=source, lines=[2, 9], hypothesis="`query`")
    assert result.outcome == "inconclusive" and len(result.matches) == 1
    assert result.matches[0]["rule_id"] == _CONCAT
    assert "construction-only SQL" in result.details["reason"]


@pytest.mark.parametrize("identifier", [None, 7, [], {}])
def test_malformed_ids_remain_unclassified(identifier):
    assert not python_sql.construction_only_matches([{"rule_id": identifier}])


def test_empty_match_set_is_not_construction_evidence():
    assert not python_sql.construction_only_matches([])
