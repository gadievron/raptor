"""Explicit RHS writes precede conditional reads and later tuple elements."""
import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'


def query(tmp_path, statement, *, snapshot=False):
    pytest.importorskip('z3')
    source = 'import re\ndef consume(argument): pass\ndef handle(value, raw, flag):\n'
    source += GUARD + '\n'
    if snapshot:
        source += ' snapshot = value\n'
    source += ' ' + statement + '\n consume(alias)\n'
    # Only source analysis runs; the application is never imported/executed.
    (tmp_path / 'app.py').write_text(source)
    return sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                        sink_uri='app.py', sink_line=len(source.splitlines()), sink_class='xss')


@pytest.mark.parametrize('statement', [
    'alias = value if (value := raw) else value',
    'alias = (value if (value := raw) else value) or value',
    'other, alias = (value := raw), value',
    'alias, spare = (value if (value := raw) else value), 0',
    'alias = value if (lambda argument=(value := raw): True) else value',
], ids=['condition', 'bool-continuation', 'tuple-sibling', 'tuple-condition', 'lambda-default'])
def test_rhs_rebinding_cannot_seed_a_new_certificate(tmp_path, statement):
    result = query(tmp_path, statement)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


@pytest.mark.parametrize('statement', [
    'alias = snapshot if (value := raw) else snapshot',
    'other, alias = (value := raw), snapshot',
])
def test_earlier_snapshot_remains_transferable(tmp_path, statement):
    result = query(tmp_path, statement, snapshot=True)
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize('statement', [
    'alias = value',
    'alias = value if flag else value',
    'alias = value if (other := raw) else value',
    'alias = value if (lambda: (value := raw)) else value',
    'other, alias = (spare := raw), value',
])
def test_unrelated_or_lambda_local_write_preserves_transfer(tmp_path, statement):
    result = query(tmp_path, statement)
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_whole_rhs_filter_conservatively_declines_earlier_tuple_capture(tmp_path):
    result = query(tmp_path, 'alias, other = value, (value := raw)')
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
