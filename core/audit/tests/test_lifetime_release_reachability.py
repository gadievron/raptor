"""Release-path checks retain diagnostics with one graph traversal per site."""

import pytest

from core.audit import defassign, lifetime_witness as lifetime


@pytest.fixture
def analyse(monkeypatch, tmp_path):
    if defassign._c_parser() is None:
        pytest.skip('requires tree-sitter C grammar')
    monkeypatch.setattr(defassign, '_TABLE_CACHE', {})
    monkeypatch.setattr(lifetime, '_LT_TABLE_CACHE', {})
    serial = 0

    def build(source):
        nonlocal serial
        serial += 1
        name = f'function{serial}.c'
        (tmp_path / name).write_text(source)
        return lifetime._Analysis(
            source, frozenset({'p'}), target_path=tmp_path, rel_file=name,
        )

    return build


def exclusive_source(count):
    return (
        'void f(void *p, int flag){switch(flag){'
        + ''.join(f'case {i}: kfree(p); break;' for i in range(count))
        + '} consume(flag);}'
    )


@pytest.mark.parametrize('count', [2, 8, 24], ids=['two', 'eight', 'many'])
def test_exclusive_sites_use_one_traversal_each(analyse, monkeypatch, count):
    value = analyse(exclusive_source(count))
    sites = value.release_sites('free')
    calls = []
    original = value.after

    def after(site):
        calls.append(site)
        return original(site)

    monkeypatch.setattr(value, 'after', after)
    result = lifetime._arm_freepath(value, 'p')
    assert result.arm == 'freepath'
    assert result.pointer == 'p'
    assert result.cwes == frozenset({'CWE-415'})
    assert result.reason == (
        f'the {count} release sites of p are pairwise path-exclusive on the '
        'goto-resolved CFG and none is loop-enclosed — no execution frees '
        'it twice at the claimed sites'
    )
    assert len(sites) == count
    assert calls == sites


def test_shared_path_still_refuses(analyse):
    value = analyse('void f(void *p){kfree(p); kfree(p);}')
    with pytest.raises(defassign.ProofRefusal) as exc:
        lifetime._arm_freepath(value, 'p')
    assert exc.value.reason == 'two release sites lie on one path'


def test_loop_diagnostic_precedes_earlier_shared_path(analyse):
    value = analyse(
        'void f(void *p,int flag){'
        'if(flag){kfree(p); kfree(p);}'
        'else {while(flag){kfree(p);}}}'
    )
    with pytest.raises(defassign.ProofRefusal) as exc:
        lifetime._arm_freepath(value, 'p')
    assert exc.value.reason == 'a release site is inside a loop'


def test_too_few_sites_refuses_before_reachability(analyse, monkeypatch):
    value = analyse('void f(void *p){kfree(p);}')

    def after(site):
        pytest.fail('reachability queried before the release-site count guard')

    monkeypatch.setattr(value, 'after', after)
    with pytest.raises(defassign.ProofRefusal) as exc:
        lifetime._arm_freepath(value, 'p')
    assert exc.value.reason == 'fewer than two visible release sites of p'


def test_each_invocation_observes_the_current_graph(analyse):
    value = analyse(exclusive_source(2))
    assert lifetime._arm_freepath(value, 'p').arm == 'freepath'
    sites = value.release_sites('free')
    value.cfg.edge(sites[0], sites[1])
    with pytest.raises(defassign.ProofRefusal) as exc:
        lifetime._arm_freepath(value, 'p')
    assert exc.value.reason == 'two release sites lie on one path'
