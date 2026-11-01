"""Negative errno is not a byte count; signed and deliberate sentinel APIs differ."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

_RULE = Path(__file__).resolve().parents[1] / "rules/negative_errno_unsigned_return.cocci"
pytestmark = pytest.mark.skipif(shutil.which("spatch") is None, reason="coccinelle not installed")


def test_unsigned_errno_contract(tmp_path):
    source = '''typedef unsigned long size_t;
typedef long ssize_t;
size_t unmap(int present) { if (!present) return -ENOENT; return 4096; } /* unsafe */
size_t count(int ready) { if (ready) return 1; return -EINVAL; } /* unsafe */
size_t bytes(void) { return -ENOMEM; } /* unsafe */
size_t wide(void) { return -EIO; } /* unsafe */
unsigned long encoded_syscall(void) { return -EINVAL; }
unsigned int encoded_status(void) { return -ENOENT; }
ssize_t signed_size(void) { return -ENOENT; }
int signed_error(void) { return -EINVAL; }
size_t count_failure(void) { return 0; }
size_t sentinel(void) { return -1; }
size_t explicit_sentinel(void) { return SIZE_MAX; }
size_t explicit_cast(void) { return (size_t)-EIO; }
size_t unrelated(void) { return -entry_count; }
'''
    target = tmp_path / "counts.c"
    target.write_text(source)
    result = subprocess.run(["spatch", "--sp-file", str(_RULE), str(target), "--no-show-diff"],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    actual = set()
    for line in (result.stdout + result.stderr).splitlines():
        if line.startswith("COCCIRESULT:"):
            hit = json.loads(line.removeprefix("COCCIRESULT:"))
            assert hit["rule"] == "negative_errno_unsigned_return"
            actual.add(hit["line"])
    expected = {i for i, line in enumerate(source.splitlines(), 1) if "/* unsafe */" in line}
    assert actual == expected
