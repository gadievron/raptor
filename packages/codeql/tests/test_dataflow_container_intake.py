"""Malformed sibling containers cannot erase usable captured SARIF paths."""
from __future__ import annotations

from copy import deepcopy
import logging

import pytest

from packages.codeql.dataflow_validator import DataflowValidator
from packages.codeql.tests.test_dataflow_validator import _sarif_two_flows


@pytest.mark.parametrize('malformed', [
    pytest.param(None, id='null-flow'),
    pytest.param([], id='array-flow'),
    pytest.param('unknown', id='text-flow'),
    pytest.param(7, id='numeric-flow'),
    pytest.param({'threadFlows': [None]}, id='null-thread-flow'),
    pytest.param({'threadFlows': 'unknown'}, id='text-thread-container'),
])
def test_malformed_sibling_retains_primary_and_alternative(malformed):
    result = _sarif_two_flows()
    result['codeFlows'].insert(1, malformed)
    original = deepcopy(result)
    validator = object.__new__(DataflowValidator)
    validator.logger = logging.getLogger('owned-container-control')

    path = validator.extract_dataflow_from_sarif(result)

    assert path is not None
    assert path.source.file_path == 'a.c'
    assert path.sink.file_path == 'a.c'
    assert [p.source.file_path for p in path.alternatives] == ['b.c']
    assert all(not p.alternatives for p in path.alternatives)
    assert result == original


def test_malformed_thread_sibling_keeps_existing_primary_order():
    result = _sarif_two_flows()
    second = result['codeFlows'].pop()['threadFlows'][0]
    result['codeFlows'][0]['threadFlows'].extend([None, second])
    validator = object.__new__(DataflowValidator)
    validator.logger = logging.getLogger('owned-thread-control')

    path = validator.extract_dataflow_from_sarif(result)

    assert path is not None
    assert path.source.file_path == 'a.c'
    assert [p.source.file_path for p in path.alternatives] == ['b.c']


def test_only_malformed_containers_do_not_invent_a_path():
    validator = object.__new__(DataflowValidator)
    validator.logger = logging.getLogger('owned-no-path-control')
    assert validator.extract_dataflow_from_sarif({'codeFlows': [None, {'threadFlows': [None]}]}) is None
