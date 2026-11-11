"""Fixture tests for the lock_imbalance rule, seed and vocab-rendered.

The mutex leg's acquire alternation carried a ``lock_acquires`` marker
while its release guard had no ``lock_releases`` marker, so a learned
acquire wrapper minted "return with lock held" verdicts on perfectly
balanced wrapper-locked code. The rendered-rule tests pin the two
sides extending together.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

from engine.coccinelle.vocab_renderer import render

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "lock_imbalance.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


@dataclass
class _FakeVocab:
    allocators: frozenset = field(default_factory=frozenset)
    deallocators: frozenset = field(default_factory=frozenset)
    lock_acquires: frozenset = field(default_factory=frozenset)
    lock_releases: frozenset = field(default_factory=frozenset)
    refcount_gets: frozenset = field(default_factory=frozenset)
    refcount_puts: frozenset = field(default_factory=frozenset)
    callback_cancels: frozenset = field(default_factory=frozenset)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestSeedRule:
    def test_mutex_error_return_with_lock_held_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(struct dev *d)
            {
                mutex_lock(&d->m);
                if (d->bad)
                    return -22;
                mutex_unlock(&d->m);
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "lock_imbalance"
        assert "mutex_lock" in results[0]["message"]

    def test_balanced_mutex_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(struct dev *d)
            {
                mutex_lock(&d->m);
                d->count++;
                mutex_unlock(&d->m);
                return 0;
            }
        """)
        assert results == []


class TestVocabRendered:
    """Learned acquire/release wrappers must extend acquire AND guard."""

    _VOCAB = _FakeVocab(
        lock_acquires=frozenset({"foo_lock"}),
        lock_releases=frozenset({"foo_unlock"}),
    )

    def test_balanced_wrapper_locking_does_not_fire(self, tmp_path):
        rendered = render(_RULE, self._VOCAB)
        assert rendered is not None
        try:
            results = _run_rule(tmp_path, """\
                int ok(struct dev *d)
                {
                    foo_lock(&d->l);
                    d->count++;
                    foo_unlock(&d->l);
                    return 0;
                }
            """, rule=rendered)
            assert results == []
        finally:
            rendered.unlink()

    def test_wrapper_error_return_with_lock_held_fires(self, tmp_path):
        rendered = render(_RULE, self._VOCAB)
        assert rendered is not None
        try:
            results = _run_rule(tmp_path, """\
                int bug(struct dev *d)
                {
                    foo_lock(&d->l);
                    if (d->bad)
                        return -22;
                    foo_unlock(&d->l);
                    return 0;
                }
            """, rule=rendered)
            # The learned acquire is spliced into both the spin and
            # mutex legs, so the same imbalance can report per leg —
            # what matters is that it reports at all and only on the
            # unbalanced return.
            assert results
            assert all(r["line"] == 5 for r in results)
        finally:
            rendered.unlink()


@pytest.mark.slow
@pytest.mark.parametrize('variant,expected', [('direct', 1), ('indirect_release', 1), ('interruptible', 1), ('killable', 1), ('pointer', 0)])
def test_acquisition_and_release_context_remains_required(tmp_path, monkeypatch, variant, expected):
    from core.audit.sweep import (
        is_confirm_only_coccinelle_rule, run_coccinelle_file_sweep, scope_coccinelle_result,
    )
    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig
    from packages.coccinelle import runner
    from packages.coccinelle.models import SpatchMatch, SpatchResult
    rule = _RULE
    bodies = {
        'direct': 'mutex_lock(&d->m); return -22;',
        'indirect_release': 'mutex_lock(&d->m); release(d); return -22;',
        'interruptible': 'mutex_lock_interruptible(&d->m); return -4;',
        'killable': 'mutex_lock_killable(&d->m); return -4;',
        'pointer': 'mutex_lock(m); return -22;',
    }
    source = ('struct lock { int value; }; struct dev { struct lock m; };\n'
              'static void release(struct dev *d) { mutex_unlock(&d->m); }\n'
              'int candidate(struct dev *d, struct lock *m) {\n '+bodies[variant]+'\n}\nvoid untouched(void) {}\n')
    target = tmp_path / 'owned.c'
    target.write_text(source)
    proc = run_pinned_subprocess(
        ['spatch', '--sp-file', str(rule), str(target), '--no-show-diff', '--no-includes'],
        timeout=45, context='Owned lock acquisition and release syntax classification',
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line.removeprefix('COCCIRESULT:'))
            for stream in (proc.stdout, proc.stderr) for line in stream.splitlines()
            if line.startswith('COCCIRESULT:')]
    assert len(rows) == expected
    assert all(row['rule'] == 'lock_imbalance' and 'review acquisition success' in row['message'] for row in rows)
    native = SpatchResult(rule=rule.stem, rule_path=str(rule),
        matches=[SpatchMatch.from_dict(row) for row in rows], files_examined=[str(target)])
    calls = []
    def replay(file_path, rule_path, **kwargs):
        assert file_path == target and rule_path == rule
        calls.append((str(file_path), str(rule_path)))
        return native
    monkeypatch.setattr(runner, 'is_available', lambda: True)
    monkeypatch.setattr(runner, 'run_rule', replay)
    result = run_coccinelle_file_sweep(target_path=tmp_path, file_path=target.name,
        cocci_rule=str(rule), language='c')
    assert len(calls) == 1
    assert is_confirm_only_coccinelle_rule(str(rule))
    assert result.details['confirm_only']
    assert result.outcome == ('confirmed' if expected else 'inconclusive')
    last = len(source.splitlines())
    scoped = scope_coccinelle_result(result, target_path=tmp_path, function_name='untouched',
        line_start=last, line_end=last, language='c')
    assert scoped.matches == [] and scoped.outcome == 'inconclusive'
    assert scoped.details['confirm_only']
    assert len(result.matches) == expected
