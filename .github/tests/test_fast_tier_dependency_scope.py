"""The grammar-enabled fast tier does not consume the base venv warmer."""

from itertools import product
from pathlib import Path
import re

import pytest


WORKFLOW = Path(__file__).resolve().parents[1] / 'workflows/tests.yml'
_OUTPUTS = ('python', 'sandbox', 'sca', 'exploit_feasibility')


def _job(name):
    match = re.search(
        r'^  ' + re.escape(name) + r':\n(.*?)(?=^  [\w-]+:\n|\Z)',
        WORKFLOW.read_text(), re.M | re.S,
    )
    assert match, name
    return match[1]


def _base_dependencies_selected(outputs):
    match = re.search(r'^    if: \|\n((?:      [^\n]*\n)+)', _job('deps'), re.M)
    assert match, 'dependency selection must remain explicit'
    condition = match[1].strip().removeprefix('(').removesuffix(')')
    fields = []
    for term in condition.split('||'):
        comparison = re.fullmatch(r"needs\.changes\.outputs\.(\w+) == 'true'", term.strip())
        assert comparison and comparison[1] in _OUTPUTS, term
        fields.append(comparison[1])
    return any(outputs[field] for field in fields)


@pytest.mark.parametrize('flags', [
    pytest.param(flags, id=''.join('1' if flag else '0' for flag in flags))
    for flags in product((False, True), repeat=4)
])
def test_base_warmer_follows_actual_consumers(flags):
    outputs = dict(zip(_OUTPUTS, flags))
    assert _base_dependencies_selected(outputs) == any(
        outputs[field] for field in ('sandbox', 'sca', 'exploit_feasibility')
    )


def test_fast_tier_owns_its_grammar_venv():
    fast = _job('python-unit-tests-fast')
    assert re.search(r'^    needs: \[changes\]$', fast, re.M)
    assert 'needs.deps.' not in fast
    profile = fast.split('        id: fast_venv\n', 1)[1].split('      - name:', 1)[0]
    assert 'uses: ./.github/actions/setup-venv' in profile
    assert 'cache-key-prefix: venv-grammars' in profile
    assert 'uv-export-extra-args: --extra grammars' in profile
    assert "save-on-rebuild: 'true'" in profile


def test_base_consumers_and_required_status_keep_dependencies():
    for job in ('python-unit-tests-sandbox', 'python-unit-tests-sca',
                'python-unit-tests-exploit-feasibility'):
        needs = re.search(r'^    needs: \[([^\n]+)\]$', _job(job), re.M)
        assert needs and {'changes', 'deps'} <= {name.strip() for name in needs[1].split(',')}
    barrier = _job('tests-passed')
    assert '      - deps\n' in barrier
    assert '"deps":' in barrier and "needs['deps'].result" in barrier
    assert re.search(r'^    if: always\(\)$', barrier, re.M)
