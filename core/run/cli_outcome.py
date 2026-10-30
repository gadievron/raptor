"""RAPTOR-owned exit receipts; never rewrite a Codex command or approve a tool.

Receipts describe the Python dispatch outcome, not arbitrary shell stdout.
PostToolUse consumes only a single simple invocation with matching argv. This
is same-user bookkeeping, not isolation against code running as the operator.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sys

from core.hash import sha256_string
from core.run.literal_command import _literal_words
from core.startup import codex_environment as environment

_ID = re.compile(r'[A-Za-z0-9_-]{1,256}')


def _address(sid):
    # POSIX broker imports stay off ordinary Claude / non-Codex startup paths.
    from core.startup.codex_broker import _address as broker_address
    return broker_address(sid)


def _digest(value):
    from core.json import dumps_canonical
    return sha256_string(dumps_canonical(value))


def _generation(context):
    return _digest([context['pid'], context['identity'], context['token_digest']])


def _argv(argv):
    return [str(Path(argv[0]).resolve()), *argv[1:]]


def _prefix(sid, call):
    if not isinstance(call, str) or not _ID.fullmatch(call):
        raise ValueError('invalid native tool call identifier')
    return 'outcome-' + _digest([sid, call]) + '-'


def _record(status, argv):
    sid = os.environ.get('RAPTOR_CODEX_CONTEXT_ID') or os.environ['CODEX_THREAD_ID']
    call = os.environ['CODEX_TOOL_CALL_ID']
    context = environment.read_context(sid)
    token = os.environ.get('RAPTOR_SESSION_TOKEN', '')
    if (os.environ.get('RAPTOR_SESSION_PID') != str(context['pid'])
            or sha256_string(token) != context['token_digest']):
        raise ValueError('outcome has no matching restored credential')
    from core.sandbox.summary import get_active_run_dir
    active = get_active_run_dir()
    value = {'generation': _generation(context), 'argv': _digest(argv),
             'status': status, 'run': str(active.resolve()) if active is not None else None}
    with environment._directory(_address(sid)) as directory:
        environment._atomic(directory, _prefix(sid, call) + str(os.getpid()) + '.json', json.dumps(value))


@contextmanager
def cli_outcome():
    """Preserve return/exception/exit semantics; report only opted-in Codex calls."""
    enabled = (os.environ.get('RAPTOR_CODEX_ENVIRONMENT') == '1'
               and os.environ.get('CODEX_THREAD_ID') and os.environ.get('CODEX_TOOL_CALL_ID')
               and not os.environ.get('CLAUDECODE') and os.environ.get('RAPTOR_CODEX_HOOK') != '1')
    argv = _argv(sys.argv) if enabled else None
    status = 0
    try:
        yield
    except BaseException as error:
        if isinstance(error, SystemExit):
            status = (error.code & 255 if isinstance(error.code, int)
                      else 0 if error.code is None else 1)
        else:
            status = 130 if isinstance(error, KeyboardInterrupt) else 1
        raise
    finally:
        if enabled:
            try:
                _record(status, argv)
            except Exception:  # noqa: BLE001 — outcome recording must never replace the original exit
                # Diagnostics never echo argv, environment values or credentials.
                sys.stderr.write('RAPTOR: could not record Codex command outcome\n')


def _expected(command):
    """Only standalone literal RAPTOR calls; shell expansions remain unknown."""
    # The read-coverage path uses the same conservative POSIX literal parser:
    # quoted metacharacters are argv data; active expansion is never evaluated.
    words = _literal_words(command)
    if not words:
        return None
    first = Path(words[0])
    if not first.is_absolute():
        first = environment.ROOT / first
    if first.parent == environment.ROOT / 'libexec' and re.fullmatch(r'raptor-[A-Za-z0-9._-]+', first.name):
        if first.name in ('raptor-agentic', 'raptor-openant'):
            return [str(environment.ROOT / 'raptor.py'), first.name.removeprefix('raptor-'), *words[1:]]
        return [str(first.resolve()), *words[1:]]
    if (words[0] in ('python3', sys.executable) and len(words) >= 2
            and (environment.ROOT / words[1]).resolve() == environment.ROOT / 'raptor.py'):
        return [str(environment.ROOT / 'raptor.py'), *words[2:]]
    return None


def consume(payload):
    """Return a proven failure's command; successes/unknowns do not mark runs."""
    if (not isinstance(payload, dict) or payload.get('hook_event_name') != 'PostToolUse'
            or payload.get('tool_name') != 'Bash'):
        return None
    tool_input = payload.get('tool_input')
    command = tool_input.get('command') if isinstance(tool_input, dict) else None
    expected = _expected(command)
    if expected is None:
        return None
    # Native hooks can identify a child thread. Authenticate its alias first,
    # then use the restored root for both IPC addressing and receipt hashing,
    # exactly as _record does. Never select a root from inherited hook env.
    restored = environment.restore(payload.get('session_id'))
    sid = restored['RAPTOR_CODEX_CONTEXT_ID']
    prefix = _prefix(sid, payload.get('tool_use_id'))
    context = environment.read_context(sid)
    statuses = []
    with environment._directory(_address(sid)) as directory:
        names = [n for n in os.listdir(directory) if n.startswith(prefix) and n.endswith('.json')]
        if len(names) > 128:
            return None
        for name in names:
            if not re.fullmatch(re.escape(prefix) + r'[0-9]+\.json', name):
                continue
            try:
                value = json.loads(environment._read(directory, name))
                if (isinstance(value, dict) and set(value) == {'generation', 'argv', 'status', 'run'}
                        and value['generation'] == _generation(context)
                        and value['argv'] == _digest(expected)
                        and type(value['status']) is int and 0 <= value['status'] <= 255
                        and (value['run'] is None or isinstance(value['run'], str)
                             and value['run'].startswith('/') and '\0' not in value['run'])):
                    statuses.append((value['status'], value['run']))
            finally:
                os.unlink(name, dir_fd=directory)
    return (command, statuses[0][1], expected[1:]) if len(statuses) == 1 and statuses[0][0] != 0 else None
