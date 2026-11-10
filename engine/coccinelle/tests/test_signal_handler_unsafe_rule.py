"""Fixture tests for the signal_handler_unsafe rule.

Detection-role rule reports calls for signal-context review. Registration,
interrupted operations and nonlocal-jump restrictions require independent
evidence; a direct call is not a confirmed CWE-364 verdict.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "signal_handler_unsafe.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_printf_in_handler_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void on_term(int sig)
            {
                printf("terminating: %d\n", sig);
            }

            void install(void)
            {
                signal(15, on_term);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "signal_handler_unsafe"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_flag_only_handler_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static volatile int got_signal;

            void on_term(int sig)
            {
                got_signal = sig;
            }

            void install(void)
            {
                signal(15, on_term);
            }
        """)
        assert results == []


@pytest.mark.slow
def test_nonlocal_jump_calls_are_review_candidates(tmp_path):
    import json

    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig

    lines = ['#include <signal.h>', '#include <setjmp.h>', '#include <stdio.h>',
             '#include <unistd.h>', 'jmp_buf plain_env;', 'sigjmp_buf saved_env;']
    expected = set()
    for registration in ['signal', 'sa_handler', 'sa_sigaction']:
        for operation in ['longjmp', 'siglongjmp', 'printf', '_exit']:
            name = registration + '_' + operation
            args = 'int sig, siginfo_t *info, void *context' if registration == 'sa_sigaction' else 'int sig'
            call = {'longjmp': 'longjmp(plain_env, 1);',
                    'siglongjmp': 'siglongjmp(saved_env, 1);',
                    'printf': 'printf("caught");', '_exit': '_exit(0);'}[operation]
            lines += [f'void handler_{name}({args}) {{', '    ' + call, '}']
            if operation != '_exit':
                expected.add(len(lines) - 1)
            if registration == 'signal':
                lines += [f'void install_{name}(void) {{ signal(SIGUSR1, handler_{name}); }}']
            else:
                lines += [f'void install_{name}(void) {{ struct sigaction sa; sa.{registration} = handler_{name}; sigaction(SIGUSR1, &sa, 0); }}']
    for registration in ['sa_handler', 'sa_sigaction']:
        name = 'uninstalled_' + registration
        args = 'int sig, siginfo_t *info, void *context' if registration == 'sa_sigaction' else 'int sig'
        lines += [f'void handler_{name}({args}) {{', '    malloc(8);', '}']
        expected.add(len(lines) - 1)
        lines += [f'void prepare_{name}(void) {{ struct sigaction sa; sa.{registration} = handler_{name}; }}']
    target = tmp_path / 'owned.c'
    target.write_text('\n'.join(lines) + '\n')
    proc = run_pinned_subprocess(
        ['spatch', '--sp-file', str(_RULE), str(target), '--no-show-diff', '--no-includes'],
        timeout=45, context='Owned signal-handler candidate classification',
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line.removeprefix('COCCIRESULT:'))
            for stream in (proc.stdout, proc.stderr) for line in stream.splitlines()
            if line.startswith('COCCIRESULT:')]
    assert {row['line'] for row in rows} == expected
    assert len(rows) == len(expected) == 11
    assert {row['rule'] for row in rows} == {'signal_handler_unsafe'}
    assert all(row['message'].startswith('Candidate:')
               and 'interrupted operations' in row['message']
               and 'subsequent calls' in row['message'] for row in rows)
