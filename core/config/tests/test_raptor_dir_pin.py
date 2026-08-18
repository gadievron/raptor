"""RAPTOR_DIR pinning — cross-checkout env-skew defence (A2).

The final comparison audit ran with the launching shell exporting
``RAPTOR_DIR`` for a DIFFERENT development checkout. Every code path
that ``setdefault``'d the variable kept the poison, and the SMT probe
children (``sys.path.insert(0, os.environ['RAPTOR_DIR'])``) imported
the other tree's ``core.audit.sweep`` — all 11 probes exited 1 with a
``TypeError`` on a kwarg the stale tree lacked.

These tests pin the fix: RAPTOR's own child-env construction SETS
``RAPTOR_DIR`` to the invoking tree's root (never ``setdefault``), a
one-line notice fires when a differing ambient value is overridden,
and a child spawned from tree A with ambient ``RAPTOR_DIR`` = tree B
imports tree A's modules.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from unittest import mock

from core.config import (
    _RAPTOR_DIR_OVERRIDE_NOTICED,
    RaptorConfig,
    pin_raptor_dir,
    pin_raptor_dir_in_environ,
)

_OWN = str(RaptorConfig.REPO_ROOT)


class TestPinRaptorDir:
    def test_ambient_other_checkout_is_overridden(self, tmp_path):
        env = {"RAPTOR_DIR": str(tmp_path)}
        out = pin_raptor_dir(env)
        assert out["RAPTOR_DIR"] == _OWN
        assert env["RAPTOR_DIR"] == _OWN  # in-place

    def test_absent_value_is_set(self):
        assert pin_raptor_dir({})["RAPTOR_DIR"] == _OWN

    def test_matching_value_kept_without_notice(self, caplog):
        with caplog.at_level(logging.INFO, logger="core.config"):
            out = pin_raptor_dir({"RAPTOR_DIR": _OWN})
        assert out["RAPTOR_DIR"] == _OWN
        assert "RAPTOR_DIR override" not in caplog.text

    def test_override_notice_once_per_ambient_value(self, tmp_path, caplog):
        other = str(tmp_path / "other-checkout")
        _RAPTOR_DIR_OVERRIDE_NOTICED.discard(other)
        with caplog.at_level(logging.INFO, logger="core.config"):
            pin_raptor_dir({"RAPTOR_DIR": other})
            pin_raptor_dir({"RAPTOR_DIR": other})
        notices = [
            r for r in caplog.records if "RAPTOR_DIR override" in r.message
        ]
        assert len(notices) == 1
        assert other in notices[0].getMessage()
        assert _OWN in notices[0].getMessage()

    def test_get_safe_env_pins_raptor_dir(self, tmp_path):
        poisoned = {
            "PATH": "/usr/bin", "HOME": "/home/x",
            "RAPTOR_DIR": str(tmp_path / "stale-tree"),
        }
        with mock.patch.dict("os.environ", poisoned, clear=True):
            env = RaptorConfig.get_safe_env()
        assert env["RAPTOR_DIR"] == _OWN

    def test_pin_in_environ_overrides_ambient(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path / "stale-tree"))
        pin_raptor_dir_in_environ()
        import os
        assert os.environ["RAPTOR_DIR"] == _OWN


def _make_poisoned_tree(root) -> str:
    """A fake checkout whose ``core.audit.sweep`` mimics the observed
    cross-checkout skew: ``_run_smt_verb_inner`` rejects the kwargs the
    real tree sends (the run's TypeError shape)."""
    pkg = root / "core" / "audit"
    pkg.mkdir(parents=True)
    (root / "core" / "__init__.py").write_text("")
    (pkg / "__init__.py").write_text("")
    (pkg / "sweep.py").write_text(
        "def _run_smt_verb_inner(**kwargs):\n"
        "    raise TypeError(\n"
        "        \"_run_smt_verb_inner() got an unexpected keyword \"\n"
        "        \"argument 'target_path'\"\n"
        "    )\n"
    )
    return str(root)


class TestSmtChildTwoTreeLayout:
    """Child spawned from tree A with ambient RAPTOR_DIR=tree B must
    import tree A's modules."""

    def test_poisoned_env_breaks_the_bare_child(self, tmp_path):
        """Fixture validity: WITHOUT the pin, the poisoned env really
        does route the child into the fake tree (the pre-fix failure
        shape — child exits nonzero)."""
        from core.audit.sweep import _SMT_VERB_CHILD_SCRIPT

        poisoned = _make_poisoned_tree(tmp_path / "tree-b")
        import pickle
        payload = pickle.dumps({
            "file_path": "f.c", "function_name": "f",
            "verb": "check-negative-bypass", "source": "int x;",
            "hypothesis": "nothing", "target_path": None,
        })
        proc = subprocess.run(
            [sys.executable, "-c", _SMT_VERB_CHILD_SCRIPT],
            input=payload, capture_output=True, timeout=30,
            check=False, env={"RAPTOR_DIR": poisoned},
        )
        assert proc.returncode != 0
        assert b"TypeError" in proc.stderr

    def test_smt_child_env_pins_own_tree(self, tmp_path, monkeypatch):
        from core.audit.sweep import smt_child_env

        poisoned = _make_poisoned_tree(tmp_path / "tree-b")
        monkeypatch.setenv("RAPTOR_DIR", poisoned)
        assert smt_child_env()["RAPTOR_DIR"] == _OWN

    def test_run_smt_verb_direct_survives_ambient_poison(
        self, tmp_path, monkeypatch,
    ):
        """End-to-end: the real spawn path returns a genuine child
        result (no 'Z3 subprocess crashed' error) despite the ambient
        poison, because RAPTOR_DIR is pinned at the spawn chokepoint."""
        from core.audit.sweep import run_smt_verb_direct

        poisoned = _make_poisoned_tree(tmp_path / "tree-b")
        monkeypatch.setenv("RAPTOR_DIR", poisoned)
        result = run_smt_verb_direct(
            file_path="f.c", function_name="f",
            verb="check-negative-bypass",
            source="int x;", hypothesis="nothing",
        )
        # Pre-fix this came back as the crashed-subprocess sentinel
        # ("Z3 subprocess crashed or timed out"); pinned, the child
        # imports THIS tree and reports a clean inconclusive (no
        # operands extractable from the hypothesis).
        assert result.outcome == "inconclusive"
        assert result.errors == []

    def test_z3_child_env_pins_own_tree(self, tmp_path, monkeypatch):
        from core.audit.condition_smt import _z3_child_env

        poisoned = _make_poisoned_tree(tmp_path / "tree-b")
        monkeypatch.setenv("RAPTOR_DIR", poisoned)
        assert _z3_child_env()["RAPTOR_DIR"] == _OWN
