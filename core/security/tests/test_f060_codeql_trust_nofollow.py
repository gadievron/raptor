"""Regression test for F060.

`core/security/codeql_trust.py._read_capped` opened files with the
default flags (`open(path, "rb")`) — no O_NOFOLLOW, no O_NONBLOCK,
no fstat-S_ISREG check.

Risks closed by porting the cc_trust._read_capped hardening
(commit eb18aa6, "fix(security): cc_trust._read_capped opens with
O_NOFOLLOW"):

  * **Symlink redirect (TOCTOU).** The caller's pack-file walk
    inspects `is_symlink()` separately and records a blocking
    finding when one is seen. But a target repo can race between
    that check and the open inside `_read_capped` — swap a regular
    file for a symlink and the open silently follows it. With
    O_NOFOLLOW the open fails with ELOOP and we fail-closed (return
    None).
  * **FIFO DoS.** `path.is_file()` returns False for FIFOs so the
    current code is technically safe today, but the explicit
    O_NONBLOCK + S_ISREG check is the sibling's pattern and
    survives future is_file() shape changes.
  * **stat-vs-open TOCTOU.** Same as above: a stat-then-open with
    no FD-level guard could read a different inode than the one
    statted.

This test asserts `_read_capped(symlink)` returns None — the
behaviour the O_NOFOLLOW port guarantees. Today (pre-fix) it
returns the symlink target's bytes.
"""

from __future__ import annotations


def test_read_capped_returns_none_on_symlink(tmp_path):
    """`_read_capped` must NOT follow a symlink to read its target."""
    from core.security.codeql_trust import _read_capped

    target = tmp_path / "real.yml"
    target.write_text("name: real-pack\n")

    link = tmp_path / "qlpack.yml"
    link.symlink_to(target)

    result = _read_capped(link)
    assert result is None, (
        "_read_capped followed a symlink and returned the target's "
        f"content: {result!r}. Expected None (fail-closed) per the "
        "cc_trust._read_capped pattern (O_NOFOLLOW → ELOOP → None)."
    )
