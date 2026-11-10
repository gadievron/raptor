"""Fixture tests for the signal_sigkill_sigstop rule.

Detection-role rule surfaces disposition attempts for review. Literal action
queries are distinct from installation, and return-value handling or an
intentional failure probe requires context beyond call syntax.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "signal_sigkill_sigstop.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_signal_sigkill_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void install(void (*handler)(int))
            {
                signal(SIGKILL, handler);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "signal_sigkill_sigstop"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_signal_sigterm_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void install(void (*handler)(int))
            {
                signal(SIGTERM, handler);
            }
        """)
        assert results == []


@pytest.mark.slow
def test_action_queries_and_checked_failure_candidates(tmp_path):
    import json

    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig

    lines = ['#include <signal.h>', '#include <errno.h>', '#include <stddef.h>']
    expected = set()
    for signal in ['SIGKILL', 'SIGSTOP']:
        for operation in ['install_signal', 'checked_signal', 'install_action', 'query_null', 'query_zero']:
            body = {
                'install_signal': f'signal({signal}, handler); return 0;',
                'checked_signal': f'if (signal({signal}, handler) == SIG_ERR) return errno == EINVAL; return 0;',
                'install_action': f'return sigaction({signal}, action, old);',
                'query_null': f'return sigaction({signal}, NULL, old);',
                'query_zero': f'return sigaction({signal}, 0, old);',
            }[operation]
            lines += [f'int case_{signal}_{operation}(void (*handler)(int), struct sigaction *action, struct sigaction *old) {{', body, '}']
            if not operation.startswith('query_'):
                expected.add(len(lines) - 1)
    lines += ['int catchable(struct sigaction *action, struct sigaction *old) {',
              'return sigaction(SIGTERM, action, old);', '}']
    target = tmp_path / 'owned.c'
    target.write_text('\n'.join(lines) + '\n')
    proc = run_pinned_subprocess(
        ['spatch', '--sp-file', str(_RULE), str(target), '--no-show-diff', '--no-includes'],
        timeout=45, context='Owned uncatchable signal action/query syntax',
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line.removeprefix('COCCIRESULT:'))
            for stream in (proc.stdout, proc.stderr) for line in stream.splitlines()
            if line.startswith('COCCIRESULT:')]
    assert {row['line'] for row in rows} == expected
    assert len(rows) == len(expected) == 6
    assert {row['rule'] for row in rows} == {'signal_sigkill_sigstop'}
    assert all(row['message'].startswith('Candidate:')
               and 'handling' in row['message'] for row in rows)
