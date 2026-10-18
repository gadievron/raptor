"""Codex source reads with content-bound, single-use post-tool receipts.

The native Bash event omits exit status and workdir. Never infer a file read
from shell syntax or stdout. The sandboxed reader emits content and records
its own canonical path/run; the host hook accepts only a matching literal
invocation, native call ID, live generation and exact returned content.
Like cli_outcome, this is same-user bookkeeping, not an OS security boundary.
"""
from __future__ import annotations

import argparse
import io
from itertools import islice
import os
from pathlib import Path
import re
import sys

from core.coverage import track_read
from core.hash import sha256_string
from core.json import dumps_canonical, loads_bounded
from core.run import cli_outcome as outcome
from core.source import open_regular_beneath
from core.startup import codex_environment as environment

_MAX_SOURCE_BYTES = 8 * 1024 * 1024
_MAX_OUTPUT_BYTES = 32 * 1024
_MAX_RECEIPT_BYTES = 64 * 1024


def _prefix(sid, call):
    return outcome._prefix(sid, call).replace('outcome-', 'read-', 1)


def _record(path, selected, content, argv):
    sid = os.environ['RAPTOR_CODEX_CONTEXT_ID']
    call = os.environ['CODEX_TOOL_CALL_ID']
    context = environment.read_context(sid)
    if (os.environ.get('RAPTOR_SESSION_PID') != str(context['pid'])
            or sha256_string(os.environ.get('RAPTOR_SESSION_TOKEN', '')) != context['token_digest']):
        raise ValueError('read has no matching restored credential')
    value = {'generation': outcome._generation(context),
             'argv': outcome._digest(outcome._argv(argv)),
             'content': sha256_string(content), 'path': path,
             'run': selected[0], 'target': selected[1]}
    encoded = dumps_canonical(value)
    if len(encoded.encode('utf-8')) > _MAX_RECEIPT_BYTES:
        raise ValueError('read receipt exceeds IPC budget')
    with environment._directory(outcome._address(sid)) as directory:
        environment._atomic(directory, _prefix(sid, call) + str(os.getpid()) + '.json',
                            encoded)


def read_main(argv=None, *, output=None):
    parser = argparse.ArgumentParser(description='Read source with Codex file-access coverage.')
    parser.add_argument('path')
    parser.add_argument('--start-line', type=int, default=1)
    parser.add_argument('--end-line', type=int)
    words = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(words)
    end = args.end_line if args.end_line is not None else args.start_line + 199
    if (args.start_line < 1 or end < args.start_line or end > sys.maxsize
            or end - args.start_line >= 2000):
        parser.error('select 1 to 2000 lines using positive line numbers')
    if any(c in args.path for c in ('\0', '\n', '\r')):
        parser.error('path contains a manifest delimiter')
    # Pin the run before reading or emitting bytes. Claude never consults this
    # new route; it retains its native Read hook and existing consumer.
    enabled = (os.environ.get('RAPTOR_CODEX_ENVIRONMENT') == '1'
               and os.environ.get('RAPTOR_CODEX_CONTEXT_ID')
               and os.environ.get('CODEX_TOOL_CALL_ID') and not os.environ.get('CLAUDECODE')
               and os.environ.get('RAPTOR_CODEX_HOOK') != '1')
    selected = track_read._find_active_run() if enabled else (None, None)
    try:
        path = str(Path(args.path).resolve(strict=True))
        # Resolve in the sandbox, then use the standard anchored no-link walk:
        # a later directory/symlink swap refuses rather than escaping the path.
        anchor = Path(path).anchor
        stream = open_regular_beneath(anchor, Path(path).relative_to(anchor), 'rb')
        if stream is None:
            raw = None
        else:
            with stream:
                raw = stream.read(_MAX_SOURCE_BYTES + 1)
    except (OSError, ValueError, RuntimeError):
        raw = None
    if raw is None or len(raw) > _MAX_SOURCE_BYTES or b'\0' in raw:
        print('raptor-read: unreadable, unsafe, binary or oversized source', file=sys.stderr)
        return 1
    # Iterate instead of materializing millions of tiny lines from an 8 MiB
    # newline-heavy file. Preserve CR/LF spelling in the emitted selection.
    with io.TextIOWrapper(io.BytesIO(raw), encoding='utf-8', errors='replace', newline='') as text:
        content = ''.join(islice(text, args.start_line - 1, end))
    if len(content.encode('utf-8')) > _MAX_OUTPUT_BYTES:
        print('raptor-read: output exceeds 32 KiB; request fewer lines', file=sys.stderr)
        return 1
    stream = sys.stdout if output is None else output
    try:
        stream.write(content)
        stream.flush()
    except (OSError, ValueError):
        return 1
    if content and selected[0]:
        try:
            _record(path, selected, content, [str(environment.ROOT / 'libexec/raptor-read'), *words])
        except (OSError, ValueError, KeyError, TypeError):
            # Coverage is observational. Failed telemetry must not replace the
            # read result or claim success; absent receipt means no coverage.
            print('raptor-read: coverage receipt unavailable', file=sys.stderr)
    return 0


def consume(payload):
    """Consume at most one receipt; no output or command is ever executed."""
    if (not isinstance(payload, dict) or payload.get('hook_event_name') != 'PostToolUse'
            or payload.get('tool_name') != 'Bash'):
        return
    inputs = payload.get('tool_input')
    expected = outcome._expected(inputs.get('command') if isinstance(inputs, dict) else None)
    if not expected or expected[0] != str(environment.ROOT / 'libexec/raptor-read'):
        return
    # The restored root can differ from native child thread IDs. Namespace by
    # the authenticated root, exactly as the existing outcome transport does.
    environment.restore(payload.get('session_id'))
    sid = os.environ['RAPTOR_CODEX_CONTEXT_ID']
    context = environment.read_context(sid)
    prefix = _prefix(sid, payload.get('tool_use_id'))
    accepted = []
    with environment._directory(outcome._address(sid)) as directory:
        names = [name for name in os.listdir(directory)
                 if re.fullmatch(re.escape(prefix) + r'[0-9]+\.json', name)]
        if len(names) > 128:
            return
        for name in names:
            try:
                value = loads_bounded(environment._read(directory, name), max_bytes=_MAX_RECEIPT_BYTES)
                if (isinstance(value, dict)
                        and set(value) == {'generation', 'argv', 'content', 'path', 'run', 'target'}
                        and value['generation'] == outcome._generation(context)
                        and value['argv'] == outcome._digest(expected)
                        and isinstance(payload.get('tool_response'), str)
                        and value['content'] == sha256_string(payload['tool_response'])
                        and all(isinstance(value[k], str) for k in ('path', 'run', 'target'))
                        and os.path.isabs(value['path']) and os.path.isabs(value['run'])):
                    accepted.append(value)
            finally:
                os.unlink(name, dir_fd=directory)
    if len(names) != 1 or len(accepted) != 1:
        return
    value = accepted[0]
    if track_read._find_active_run() == (value['run'], value['target']):
        track_read.record_read(value['path'], value['run'], value['target'], canonical=True)
