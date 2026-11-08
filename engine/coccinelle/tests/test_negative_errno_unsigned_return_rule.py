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
static inline size_t wrapped(void) { return (-ENOENT); } /* unsafe */
size_t nested_parens(void) { return (((-ENOMEM))); } /* unsafe */
size_t operand_parens(void) { return -(EINVAL); } /* unsafe */
size_t wrapped_operand(void) { return (-(EIO)); } /* unsafe */
size_t digit_errno(void) { return -E2BIG; } /* unsafe */
size_t multiline(void) { return ( /* unsafe */
    -
    (
        EINVAL
    )
); }
unsigned long encoded_syscall(void) { return -EINVAL; }
unsigned int encoded_status(void) { return -ENOENT; }
ssize_t signed_size(void) { return -ENOENT; }
int signed_error(void) { return -EINVAL; }
size_t count_failure(void) { return 0; }
size_t sentinel(void) { return -1; }
size_t explicit_sentinel(void) { return SIZE_MAX; }
size_t explicit_cast(void) { return (size_t)-EIO; }
size_t unrelated(void) { return -entry_count; }
size_t positive_again(void) { return -(-EINVAL); }
size_t arithmetic(void) { return (-EINVAL + 1); }
size_t composite_operand(void) { return -(EINVAL - 1); }
size_t call_argument(void) { return handle(-EINVAL); }
size_t paren_sentinel(void) { return (((-1))); }
size_t paren_cast(void) { return (((size_t)-EINVAL)); }
size_t comment_spacing(void) { return ( /* comment */ - /* comment */ EIO); } /* unsafe */
'''
    target = tmp_path / "counts.c"
    target.write_text(source)
    result = subprocess.run(["spatch", "--sp-file", str(_RULE), str(target), "--no-show-diff"],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    actual = []
    for line in (result.stdout + result.stderr).splitlines():
        if line.startswith("COCCIRESULT:"):
            hit = json.loads(line.removeprefix("COCCIRESULT:"))
            assert hit["rule"] == "negative_errno_unsigned_return"
            actual.append(hit["line"])
    expected = {i for i, line in enumerate(source.splitlines(), 1) if "/* unsafe */" in line}
    assert set(actual) == expected
    assert len(actual) == len(expected), "one diagnostic per return expression"


@pytest.mark.integration
@pytest.mark.parametrize("other_hit", [False, True], ids=["file-empty", "other-function-hit"])
def test_partial_arithmetic_silence_is_inconclusive(tmp_path, other_hit):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    prefix = 'typedef unsigned long size_t;\n'
    source = prefix + 'size_t partial(int failed) { return failed ? -EINVAL : 0; }' + "\n"
    partial_line = 1 + prefix.count("\n")
    if other_hit:
        source += 'size_t other(void) { return -EINVAL; }' + "\n"
    (tmp_path / "partial.c").write_text(source)
    result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path="partial.c", cocci_rule=str(_RULE), language="c",
    )
    assert result.outcome == ("confirmed" if other_hit else "inconclusive"), result.errors
    assert len(result.matches) == int(other_hit)
    if other_hit:
        assert result.matches[0]["rule"] == 'negative_errno_unsigned_return'
    assert result.details["confirm_only"]
    scoped = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="partial",
        line_start=partial_line, line_end=partial_line, language="c",
    )
    assert scoped.outcome == "inconclusive"
    assert scoped.details["confirm_only"]
    assert not scoped.matches
    assert len(result.matches) == int(other_hit)
