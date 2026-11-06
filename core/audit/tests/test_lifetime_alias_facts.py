"""Alias syntax is collected once without changing fixpoint order or caps."""

import pytest

from core.audit import defassign, lifetime_witness as lifetime


@pytest.fixture(autouse=True)
def grammar():
    if defassign._c_parser() is None:
        pytest.skip('requires tree-sitter C grammar')


def analysis(source):
    result = lifetime._Analysis.__new__(lifetime._Analysis)
    result.fn_node = defassign._parse_function(source)
    result.pointer_set = frozenset({'p'})
    return result


def chain(last):
    return (
        'void f(void *p){'
        + ''.join(f'void *a{i}=a{i-1};' for i in range(last, 0, -1))
        + 'void *a0=p; consume(a0, observer);}'
    )


def test_reverse_chain_and_retainer_closure():
    value = analysis(chain(12))
    value._compute_sets()
    assert value.aliases == frozenset({'p'} | {f'a{i}' for i in range(13)})
    assert value.derived == frozenset()
    assert value.retainers == frozenset({'observer'})


@pytest.mark.parametrize('statements,aliases,derived', [
    pytest.param('q = r; r = q;', {'p'}, set(), id='unseeded-cycle'),
    pytest.param('q = p; q = 0; r = q;', {'p', 'q', 'r'}, set(), id='literal-does-not-kill-alias'),
    pytest.param('q = p; r = q + 1;', {'p', 'q'}, {'r'}, id='derived-carrier'),
    pytest.param('q |= p; r = q;', {'p'}, {'q', 'r'}, id='compound-carrier'),
    pytest.param('q = (r = p);', {'p', 'r'}, {'q'}, id='nested-assignment-order'),
    pytest.param('q = p + 1; q = p;', {'p', 'q'}, {'q'}, id='derived-then-alias'),
])
def test_assignment_order_and_classification(statements, aliases, derived):
    value = analysis('void f(void *p, void *q, void *r){' + statements + '}')
    value._compute_sets()
    assert value.aliases == frozenset(aliases)
    assert value.derived == frozenset(derived)


def test_unresolved_initializer_refuses_after_later_alias_growth():
    value = analysis('void f(void *p, void *q){void *slots[1]={q}; q=p;}')
    with pytest.raises(defassign.ProofRefusal) as exc:
        value._compute_sets()
    assert exc.value.reason == (
        "tracked pointer stored through a non-identifier declarator's initializer"
    )


def test_unrelated_unresolved_initializer_stays_harmless():
    value = analysis('void f(void *p, void *q){void *slots[1]={q};}')
    value._compute_sets()
    assert value.aliases == frozenset({'p'})
    assert value.derived == value.retainers == frozenset()


@pytest.mark.parametrize('converges', [True, False], ids=['last-round-converges', 'last-round-grows'])
def test_existing_round_cap_is_unchanged(converges):
    last = lifetime._MAX_TRACK_ROUNDS - (2 if converges else 1)
    value = analysis(chain(last))
    if converges:
        value._compute_sets()
        assert f'a{last}' in value.aliases
    else:
        with pytest.raises(defassign.ProofRefusal) as exc:
            value._compute_sets()
        assert exc.value.reason == 'alias fixpoint did not converge'


def test_multiple_rounds_walk_whole_body_only_twice(monkeypatch):
    value = analysis(chain(12))
    body = value.fn_node.child_by_field_name('body')
    visits = []
    original = lifetime._walk_nodes

    def walk(node):
        if node.id == body.id:
            visits.append(node.id)
        yield from original(node)

    monkeypatch.setattr(lifetime, '_walk_nodes', walk)
    value._compute_sets()
    # One syntax collection and one retainer scan, independent of rounds.
    assert len(visits) == 2
    assert 'a12' in value.aliases
