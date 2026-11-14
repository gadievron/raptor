"""Pure prerequisite finding-file admission controls, with no live-tool prerequisites."""

import pytest

from packages.coccinelle.prereqs import PrereqFacts, evaluate_finding


@pytest.mark.parametrize('file_fields', [{}, {'file': None}, {'file': ''}, {'file': ' \t'}])
@pytest.mark.parametrize('known_function', [False, True])
def test_missing_finding_file_cannot_supply_structural_absence(file_fields, known_function):
    from core.audit.feedback import _cocci_absence_witness

    finding = {'function': 'owned', **file_fields}
    facts = PrereqFacts(defs={'owned': {('owned.c', 1)}} if known_function else {})
    result = evaluate_finding(finding, facts)
    assert result['applicable'] is False
    assert result['skipped_reason'] == 'finding_missing_file'
    assert result['checks'] == {'function_exists': None, 'function_has_callers': None}
    assert not _cocci_absence_witness(result)
