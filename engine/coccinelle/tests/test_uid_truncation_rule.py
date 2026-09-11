"""Fixture tests for the uid_truncation verification-grade rule.

The negatives pin the provenance regression: the generic 16-bit casts
((unsigned short) / (__u16)) matched EVERY narrowing cast in a
codebase (ports, lengths, counters) because the operand was an
unconstrained expression metavariable. The operand must now carry
UID/GID provenance — a uid_t/gid_t/kuid_t/kgid_t static type or a
direct accessor call — while the __old_*/__kernel_old_* destination
casts stay operand-unconstrained (the destination type itself is
UID/GID).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "uid_truncation.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(_RULE), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


class TestPositives:
    def test_uid_typed_operand_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct legacy { unsigned short uid16; unsigned short gid16; };

            void store_ids(struct legacy *l, uid_t uid, gid_t gid)
            {
                l->uid16 = (unsigned short)uid;
                l->gid16 = (__u16)gid;
            }
        """)
        assert len(results) == 2
        assert all(r["rule"] == "uid_truncation" for r in results)
        assert sorted(r["line"] for r in results) == [5, 6]

    def test_accessor_call_operand_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct legacy { unsigned short uid16; };

            void store_current(struct legacy *l)
            {
                l->uid16 = (unsigned short)getuid();
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 5

    def test_old_kernel_type_cast_fires(self, tmp_path):
        # Casting to the legacy 16-bit uid types is UID context by the
        # destination type alone — no operand constraint needed.
        results = _run_rule(tmp_path, """\
            struct oldcred { __kernel_old_uid_t uid; };

            void store_old(struct oldcred *c, unsigned int wide)
            {
                c->uid = (__kernel_old_uid_t)wide;
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 5


class TestNegatives:
    def test_benign_narrowing_casts_do_not_fire(self, tmp_path):
        # Ports, lengths, counters: narrowing casts with no UID/GID
        # provenance are the overwhelmingly common benign shape.
        results = _run_rule(tmp_path, """\
            struct pkt { unsigned short len16; };

            void store_port(unsigned short *out, int port)
            {
                *out = (unsigned short)port;
            }

            void store_len(struct pkt *p, unsigned long len)
            {
                p->len16 = (unsigned short)len;
            }
        """)
        assert results == []
