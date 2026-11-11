"""Fixture tests for the socket_no_cloexec rule.

Existing post-call and text-based exclusions are coverage filters, not
proof that a descriptor is protected. Reports need lifetime/exec review,
and quiet results remain inconclusive.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "socket_no_cloexec.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_socket_without_cloexec_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(void)
            {
                int fd = socket(2, SOCK_STREAM, 0);
                return fd;
            }
        """)
        assert [r["rule"] for r in results] == ["socket_no_cloexec"]

    def test_accept_without_cloexec_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(int s)
            {
                int c = accept(s, 0, 0);
                return c;
            }
        """)
        assert [r["rule"] for r in results] == ["accept_no_cloexec"]


class TestNegatives:
    def test_sock_cloexec_flag_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(void)
            {
                int fd = socket(2, SOCK_STREAM | SOCK_CLOEXEC, 0);
                return fd;
            }
        """)
        assert results == []

    def test_socket_then_fcntl_setfd_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(void)
            {
                int fd = socket(2, SOCK_STREAM, 0);
                fcntl(fd, F_SETFD, FD_CLOEXEC);
                return fd;
            }
        """)
        assert results == []

    def test_accept_then_fcntl_setfd_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(int s)
            {
                int c = accept(s, 0, 0);
                fcntl(c, F_SETFD, FD_CLOEXEC);
                return c;
            }
        """)
        assert results == []

    def test_accept4_with_cloexec_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(int s)
            {
                int c = accept4(s, 0, 0, SOCK_CLOEXEC);
                return c;
            }
        """)
        assert results == []

    def test_plain_assignment_form_fcntl_does_not_fire(self, tmp_path):
        # Safe set must also cover the assignment (non-declaration)
        # binding of the descriptor.
        results = _run_rule(tmp_path, """\
            int ok(int s)
            {
                int c;
                c = accept(s, 0, 0);
                fcntl(c, F_SETFD, FD_CLOEXEC);
                return c;
            }
        """)
        assert results == []

    def test_struct_field_fd_fcntl_does_not_fire(self, tmp_path):
        # The common daemon idiom stores the descriptor in a struct
        # field (srv->listen_fd = socket(...)); an identifier-only
        # safe set could not bind it, so the correct
        # fcntl(c->fd, F_SETFD, ...) sequence was reported at
        # verification grade.
        results = _run_rule(tmp_path, """\
            int ok(struct conn *c)
            {
                c->fd = socket(2, 1, 0);
                fcntl(c->fd, F_SETFD, FD_CLOEXEC);
                return 0;
            }
        """)
        assert results == []

    def test_struct_field_accept_fcntl_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(struct conn *c, int s)
            {
                c->fd = accept(s, 0, 0);
                fcntl(c->fd, F_SETFD, FD_CLOEXEC);
                return 0;
            }
        """)
        assert results == []

    def test_struct_field_fd_without_fcntl_still_fires(self, tmp_path):
        # Recall guard for the expression-shaped safe arm: the field
        # binding alone must not suppress anything.
        results = _run_rule(tmp_path, """\
            int bug(struct conn *c)
            {
                c->fd = socket(2, 1, 0);
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "socket_no_cloexec"


@pytest.mark.parametrize('api,variant,expected', [('socket', 'closed', 1), ('socket', 'cleared', 0), ('socket', 'substring', 1), ('accept', 'closed', 1), ('accept', 'cleared', 0)])
def test_socket_inheritance_requires_context_and_coverage(tmp_path, monkeypatch, api, variant, expected):
    from core.audit.sweep import (
        is_confirm_only_coccinelle_rule, run_coccinelle_file_sweep, scope_coccinelle_result,
    )
    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig
    from packages.coccinelle import runner
    from packages.coccinelle.models import SpatchMatch, SpatchResult
    rule = _RULE
    flags = 'SOCK_STREAM | MY_SOCK_CLOEXEC' if variant == 'substring' else 'SOCK_STREAM'
    tail = 'fcntl(fd, F_SETFD, 0);' if variant == 'cleared' else ''
    if variant == 'closed':
        tail = 'close(fd);'
    creation = f'socket(AF_INET, {flags}, 0)' if api == 'socket' else 'accept(0, 0, 0)'
    source = ('int candidate(void) {\n'
              f' int fd = {creation};\n'
              f' {tail}\n return 0;\n}}\nvoid untouched(void) {{}}\n')
    target = tmp_path / 'owned.c'
    target.write_text(source)
    proc = run_pinned_subprocess(
        ['spatch', '--sp-file', str(rule), str(target), '--no-show-diff', '--no-includes'],
        timeout=45, context='Owned socket inheritance syntax classification',
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line.removeprefix('COCCIRESULT:'))
            for stream in (proc.stdout, proc.stderr) for line in stream.splitlines()
            if line.startswith('COCCIRESULT:')]
    assert len(rows) == expected
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
    assert all('review descriptor lifetime' in row['message'] for row in rows)
    assert result.outcome == ('confirmed' if expected else 'inconclusive')
    last = len(source.splitlines())
    scoped = scope_coccinelle_result(result, target_path=tmp_path, function_name='untouched',
        line_start=last, line_end=last, language='c')
    assert scoped.matches == [] and scoped.outcome == 'inconclusive'
    assert scoped.details['confirm_only']
    assert len(result.matches) == expected


def test_socket_flags_require_exact_surviving_symbol(tmp_path):
    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig

    cases = [
        ('SOCK_STREAM | SOCK_CLOEXEC', False),
        ('SOCK_CLOEXEC | SOCK_STREAM', False),
        ('(SOCK_CLOEXEC | flags) & SOCK_CLOEXEC', False),
        ('SOCK_CLOEXEC & SOCK_CLOEXEC', False),
        ('SOCK_CLOEXEC | 0UL', False),
        ('SOCK_CLOEXEC | 010U', False),
        ('SOCK_CLOEXEC | 0x0UL', False),
        ('SOCK_STREAM', True),
        ('SOCK_STREAM | MY_SOCK_CLOEXEC', True),
        ('SOCK_CLOEXEC_BACKUP', True),
        ('SOCK_CLOEXEC & 0', True),
        ('flags & SOCK_CLOEXEC', True),
        ('flags & ~SOCK_CLOEXEC', True),
        ('SOCK_CLOEXEC ^ SOCK_CLOEXEC', True),
        ('SOCK_CLOEXEC && flags', True),
        ('contains(SOCK_CLOEXEC)', True),
        ('(int)SOCK_CLOEXEC', True),
        ('SOCK_CLOEXEC | ' + '0 | ' * 160 + '0', True),
    ]
    lines, expected = [], []
    for flags, report in cases:
        lines += [f'int flag_{len(lines)}(int flags) {{',
                  f' return socket(AF_INET, {flags}, 0);', '}']
        if report:
            expected.append(len(lines) - 1)
    for index in range(120):
        lines += [f'int repeated_{index}(void) {{',
                  ' return socket(AF_INET, SOCK_STREAM | MY_SOCK_CLOEXEC, 0);', '}']
        expected.append(len(lines) - 1)
    source = tmp_path / 'flags.c'
    source.write_text('\n'.join(lines) + '\n')
    proc = run_pinned_subprocess(
        ['spatch', '--sp-file', str(_RULE), str(source), '--no-show-diff', '--no-includes'],
        timeout=45, context='Exact socket close-on-exec flag syntax',
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line.removeprefix('COCCIRESULT:'))
            for stream in (proc.stdout, proc.stderr) for line in stream.splitlines()
            if line.startswith('COCCIRESULT:')]
    assert sorted(row['line'] for row in rows) == expected
    assert all(row['rule'] == 'socket_no_cloexec' for row in rows)


def test_socket_flag_filter_keeps_production_batching(tmp_path):
    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig
    from packages.coccinelle import runner

    source = tmp_path / 'batch.c'
    source.write_text(
        'int missing(void) { return socket(AF_INET, MY_SOCK_CLOEXEC, 0); }\n'
        'int present(void) { return socket(AF_INET, SOCK_CLOEXEC, 0); }\n'
        'int mode(char *p) { return open(p, O_CREAT); }\n'
    )
    calls = []
    def _socket_batch_execute(argv, **options):
        calls.append(tuple(argv))
        return run_pinned_subprocess(
            argv, timeout=45, context='Socket and open symbolic filters production batch',
            env=RaptorConfig.get_safe_env(), skip_signals=(9,),
        )
    results = runner.run_rules_batched(
        source, [_RULE, _RULE.with_name('open_creat_no_mode.cocci')],
        subprocess_runner=_socket_batch_execute, allow_scripting=True,
        no_includes=True, timeout=45, env=RaptorConfig.get_safe_env(),
    )
    assert len(calls) == 1, calls
    assert set(results) == {'socket_no_cloexec', 'open_creat_no_mode'}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results['socket_no_cloexec'].matches) == 1
    assert len(results['open_creat_no_mode'].matches) == 1
