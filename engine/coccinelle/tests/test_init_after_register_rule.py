"""Fixture tests for the init_after_register rule's chrdev leg.

U12-F205 regression: the chrdev sub-rule attached its position
metavariable to the argument dots (``(...@p_reg)``), which never
binds — the leg parsed cleanly but was silently dead. The position
now binds to the first argument expression (mirroring the platform
leg), so the exact target shape from the rule header fires.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "init_after_register.cocci"
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


class TestChrdevLeg:
    def test_field_init_after_register_chrdev_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static struct dev d;
            static struct file_operations fops;

            int init_bad(void)
            {
                register_chrdev(10, "x", &fops);
                d.owner = 0;
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "init_after_register"

    def test_init_before_register_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static struct dev d;
            static struct file_operations fops;

            int init_ok(void)
            {
                d.owner = 0;
                register_chrdev(10, "x", &fops);
                return 0;
            }
        """)
        assert results == []


class TestNetdevLegControl:
    def test_netdev_leg_still_fires(self, tmp_path):
        # Control: the position-binding change on the chrdev leg must
        # not disturb the working legs.
        results = _run_rule(tmp_path, """\
            int probe(struct net_device *ndev)
            {
                register_netdev(ndev);
                ndev->mtu = 1500;
                return 0;
            }
        """)
        assert len(results) == 1
