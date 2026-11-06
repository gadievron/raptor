"""Token alias rounds preserve textual ranges, ordering and convergence caps."""

import pytest

from core.audit import defassign, lifetime_witness as lifetime


def tracked(source):
    return lifetime._token_tracked_superset(defassign._tokenize(source), frozenset({'p'}))


@pytest.mark.parametrize('source,expected', [
    pytest.param('a = p;', {'p', 'a'}, id='direct'),
    pytest.param('a = b; b = p;', {'p', 'a', 'b'}, id='reverse-dependency'),
    pytest.param('a = b; b = a;', {'p'}, id='unseeded-cycle'),
    pytest.param('a = b = p;', {'p', 'a'}, id='nested-assignment-range'),
    pytest.param('a = p, b = q;', {'p', 'a'}, id='comma-range'),
    pytest.param('struct s *q = p;', {'p'}, id='pointer-declarator-guard'),
    pytest.param('*q = p;', {'p'}, id='indirect-assignment-guard'),
    pytest.param('a == p;', {'p'}, id='comparison'),
    pytest.param('a = = p;', {'p'}, id='split-equality-guard'),
    pytest.param('a = p', {'p', 'a'}, id='missing-semicolon'),
    pytest.param('a = ;', {'p'}, id='empty-rhs'),
    pytest.param('a = call("p");', {'p'}, id='literal-not-identifier'),
    pytest.param('obj.x = p;', {'p', 'x'}, id='textual-member-overapproximation'),
    pytest.param('a = p; a = 0; b = a;', {'p', 'a', 'b'}, id='monotone-closure'),
    pytest.param('', {'p'}, id='empty'),
])
def test_exact_token_closures(source, expected):
    assert tracked(source) == frozenset(expected)


def chain(last):
    return ''.join(f'a{i}=a{i-1};' for i in range(last, 0, -1)) + 'a0=p;'


@pytest.mark.parametrize('converges', [True, False], ids=['last-round-converges', 'last-round-grows'])
def test_existing_round_limit(converges):
    last = lifetime._MAX_TRACK_ROUNDS - (2 if converges else 1)
    if converges:
        assert tracked(chain(last)) == frozenset({'p'} | {f'a{i}' for i in range(last + 1)})
    else:
        with pytest.raises(defassign.ProofRefusal) as exc:
            tracked(chain(last))
        assert exc.value.reason == 'tracked-superset fixpoint did not converge'


def test_token_reads_are_bounded_independently_of_rounds():
    class CountingTokens(list):
        reads = 0

        def __getitem__(self, index):
            self.reads += 1
            return super().__getitem__(index)

    tokens = CountingTokens(defassign._tokenize(chain(24)))
    seeds = frozenset({'p'})
    result = lifetime._token_tracked_superset(tokens, seeds)
    assert result == frozenset({'p'} | {f'a{i}' for i in range(25)})
    assert seeds == frozenset({'p'})
    assert tokens.reads <= 8 * len(tokens)
