"""Keep CodeQL scratch usable when an outer Linux mount makes /tmp read-only."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile


# Trusted constant code, not an interpolation of target data. Execute after the
# sandbox has chosen its mount-tree or mountless TMPDIR. Isolated system Python
# needs no site packages and does not load the operator's Python configuration.
_TEMP_EXEC = r'''
import os, sys
value = os.environ.get('TMPDIR') or sys.argv[1]
if not os.path.isabs(value) or os.statvfs(value).f_flag & os.ST_RDONLY:
    raise OSError('CodeQL requires a writable temporary directory')
os.environ['TMPDIR'] = value
if any(character.isspace() or character in "\"'" for character in value):
    value = '"' + value.replace('"', '"' + "'\"'" + '"') + '"'
os.environ['_JAVA_OPTIONS'] = '-Djava.io.tmpdir=' + value
os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
'''


def temporary_command(command: list) -> list:
    # Ordinary environments keep their existing argv and startup cost.
    if sys.platform != 'linux' or not os.statvfs('/tmp').f_flag & os.ST_RDONLY:
        return command
    from core.config import RaptorConfig
    directory = RaptorConfig.get_safe_env().get('TMPDIR') or tempfile.gettempdir()
    if not directory or not os.path.isabs(directory) or os.statvfs(directory).f_flag & os.ST_RDONLY:
        raise OSError('CodeQL requires a writable TMPDIR when /tmp is read-only')
    python = '/usr/bin/python3' if Path('/usr/bin/python3').is_file() else sys.executable
    # The fallback is an argv value. An inner sandbox's trusted TMPDIR takes
    # precedence, so no host-only path is reintroduced after a pivot_root.
    return [python, '-I', '-S', '-c', _TEMP_EXEC, directory, *command]
