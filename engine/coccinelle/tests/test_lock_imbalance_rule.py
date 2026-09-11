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
import subprocess
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

import pytest

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
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(rule), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


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
