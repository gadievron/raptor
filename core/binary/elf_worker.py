"""Bounded pwntools ELF facts from a disposable sandbox worker."""
from __future__ import annotations

from dataclasses import dataclass, fields
import json
import logging
import os
from pathlib import Path
import re
import site
import subprocess
import sys

from core.run.scratch import scratch_dir
from core.security.log_sanitisation import escape_nonprintable
from core.source.contained import open_regular

# Large debug ELFs retain the readelf fallback. Two GiB accommodates the
# interpreter, mapped input and parser state without an unbounded multiplier.
MAX_ELF_INPUT_BYTES = 512 * 1024 * 1024
_MEMORY_MB = 2048
_CPU_SECONDS = 10
_TIMEOUT_SECONDS = 20
_MAX_REPLY_BYTES = 128 * 1024
_MAX_CHECKSEC_CHARS = 16 * 1024
_logger = logging.getLogger(__name__)
_WORKER = Path(__file__).with_name('_elf_worker_child.py').resolve()


@dataclass(frozen=True)
class ElfFacts:
    arch: str
    bits: int
    endian: str
    os_abi: str
    relro: str | None
    pie: bool
    nx: bool | None
    canary: bool
    fortify: bool
    has_gnu_stack: bool
    checksec: str


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate result field')
        result[key] = value
    return result


def _decode_facts(payload: bytes) -> ElfFacts | None:
    if not isinstance(payload, bytes) or len(payload) > _MAX_REPLY_BYTES:
        return None
    try:
        obj = json.loads(payload, object_pairs_hook=_unique_object)  # json-budget: worker bytes checked against 128 KiB above.
        if not isinstance(obj, dict) or set(obj) != {field.name for field in fields(ElfFacts)}:
            return None
        if not isinstance(obj['arch'], str) or not re.fullmatch(r'[A-Za-z0-9_.:+ -]{1,64}', obj['arch']):
            return None
        if type(obj['bits']) is not int or obj['bits'] not in (32, 64):
            return None
        if obj['endian'] not in ('little', 'big') or obj['relro'] not in (None, 'Full', 'Partial'):
            return None
        if not isinstance(obj['os_abi'], str) or len(obj['os_abi']) > 128 or not all(c.isprintable() for c in obj['os_abi']):
            return None
        if any(type(obj[name]) is not bool for name in ('pie', 'canary', 'fortify', 'has_gnu_stack')):
            return None
        if obj['nx'] is not None and type(obj['nx']) is not bool:
            return None
        if not isinstance(obj['checksec'], str) or len(obj['checksec']) > _MAX_CHECKSEC_CHARS:
            return None
        obj['checksec'] = escape_nonprintable(obj['checksec'], preserve_newlines=True)
        return ElfFacts(**obj)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return None


def inspect_elf(binary: str | Path) -> ElfFacts | None:
    """Return complete scalar facts, or None for parser/transport failure.

    Isolation refusals propagate. The parent never imports pwntools or
    deserializes worker objects. Input regularity and size are checked on an
    opened descriptor; the worker repeats that check after confinement.
    """
    from core.binary._inspection_policy import inspection_command, inspection_options
    from core.sandbox import SandboxSetupError, run
    from core.sandbox.python_paths import _home_roots, python_runtime_tool_paths
    from core.security.env_sanitisation import subprocess_tmpdir
    selected = Path(binary).resolve()
    stream = open_regular(selected, 'rb')
    if stream is None:
        return None
    with stream:
        if os.fstat(stream.fileno()).st_size > MAX_ELF_INPUT_BYTES:
            return None
    worker = _WORKER
    runtime = python_runtime_tool_paths()
    user_site = site.getusersitepackages()
    if not isinstance(user_site, str) or not Path(user_site).is_dir():
        user_site = ''
    elif any(Path(user_site).resolve() == home or Path(user_site).resolve() in home.parents for home in _home_roots()):
        raise SandboxSetupError('ELF worker dependencies require a dedicated Python package directory, not HOME')
    if user_site:
        runtime.append(str(Path(user_site).resolve()))
    try:
        with scratch_dir('raptor-elf-facts-', dir=subprocess_tmpdir(), keepalive=True) as scratch_path:
            scratch = str(scratch_path)
            options = inspection_options(selected, sys.executable, scratch)
            options['tool_paths'] = list(dict.fromkeys([*options['tool_paths'], *runtime, str(worker)]))
            command = inspection_command([sys.executable, '-I', '-B', str(worker),
                                          str(selected), user_site, str(MAX_ELF_INPUT_BYTES)], scratch)
            result = run(command, **options, stdin=subprocess.DEVNULL,
                         capture_output=True, max_capture_bytes=_MAX_REPLY_BYTES + 1,
                         timeout=_TIMEOUT_SECONDS, start_new_session=True,
                         limits=dict(memory_mb=_MEMORY_MB, cpu_seconds=_CPU_SECONDS, max_file_mb=16))
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        detail = (result.stderr or b'')[-2048:].decode('utf-8', errors='replace')
        _logger.debug('ELF worker exited %s; discarding facts (stderr=%s)',
                      result.returncode, escape_nonprintable(detail))
        return None
    facts = _decode_facts(result.stdout)
    if facts is None:
        _logger.debug('ELF worker returned an invalid or incomplete fact record')
    return facts
