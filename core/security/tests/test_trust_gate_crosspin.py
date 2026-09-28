"""
core/security/tests/test_trust_gate_crosspin.py

Divergence tripwire for the two repo trust gates.

cc_trust and codeql_trust share one helper layer
(core/security/_trust_common.py). Before the extraction each gate
carried a private, hand-synced copy, and the same fix repeatedly had
to land twice. These pins red the moment the gates diverge again:

  1. identity — each gate's helper names must BE the shared objects,
     not equal-looking copies;
  2. no re-derivation — neither gate's source may re-define a helper
     the shared layer owns;
  3. behavior — both gates give the SAME fail-closed verdict on the
     same unexaminable-target probe set, and the same trust-override
     downgrade.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import core.security._trust_common as common
import core.security.cc_trust as cc
import core.security.codeql_trust as ql

# (attribute name on both gate modules, name on the shared module)
_SHARED_NAMES = [
    ("_safe", "safe_text"),
    ("_truncate", "truncate"),
    ("_mask", "mask"),
    ("_read_capped", "read_trust_config"),
    ("Finding", "Finding"),
    ("FileScan", "FileScan"),
    ("_RAPTOR_DIR", "RAPTOR_DIR"),
]


class TestSharedLayerIdentity:

    @pytest.mark.parametrize(("gate_name", "common_name"), _SHARED_NAMES)
    def test_helpers_are_the_shared_objects(self, gate_name, common_name):
        shared = getattr(common, common_name)
        assert getattr(cc, gate_name) is shared, (
            f"cc_trust.{gate_name} is no longer "
            f"_trust_common.{common_name} — the gates' helper layers "
            "are diverging again")
        assert getattr(ql, gate_name) is shared, (
            f"codeql_trust.{gate_name} is no longer "
            f"_trust_common.{common_name} — the gates' helper layers "
            "are diverging again")

    def test_result_shapes_are_one_type(self):
        assert cc.Finding is ql.Finding
        assert cc.FileScan is ql.FileScan


class TestNoPrivateReDerivation:
    """A helper re-defined inside a gate module silently shadows the
    shared layer and restarts the hand-sync treadmill. Ban the
    definitions at source level."""

    _BANNED_DEFS = (
        "def _safe(",
        "def _truncate(",
        "def _mask(",
        "def _read_capped(",
        "def _render_scan_report(",
        "class Finding",
        "class FileScan",
        "_EXTRA_STRIP =",
        "_MAX_CONFIG_BYTES =",
        "_RAPTOR_DIR = Path(",
    )

    @pytest.mark.parametrize("mod", [cc, ql], ids=["cc_trust", "codeql_trust"])
    def test_gate_does_not_redefine_shared_helpers(self, mod):
        src = Path(mod.__file__).read_text(encoding="utf-8")
        for banned in self._BANNED_DEFS:
            assert banned not in src, (
                f"{Path(mod.__file__).name} re-defines {banned!r} — "
                "that helper lives in core/security/_trust_common.py; "
                "fix it there so BOTH gates get the fix")


_GATES = [
    pytest.param(cc.check_repo_claude_trust, "Claude Code config",
                 id="cc_trust"),
    pytest.param(ql.check_repo_codeql_trust, "CodeQL pack config",
                 id="codeql_trust"),
]


class TestFailClosedBehaviorParity:
    """Same probe set through both gates (explicit trust_override args,
    so neither module's process-wide flag is touched). Every probe is
    an unexaminable target: both gates must refuse, with the same
    wording modulo their subject string, and both must downgrade to
    warn-and-proceed under the override."""

    @pytest.mark.parametrize(("check", "subject"), _GATES)
    def test_nonexistent_refuses(self, check, subject, tmp_path, capsys):
        assert check(str(tmp_path / "gone"), trust_override=False) is True
        out = capsys.readouterr().out
        assert "cannot examine" in out
        assert "treating as dangerous" in out
        assert subject in out

    @pytest.mark.parametrize(("check", "subject"), _GATES)
    def test_nonexistent_override_proceeds(self, check, subject,
                                           tmp_path, capsys):
        assert check(str(tmp_path / "gone"), trust_override=True) is False
        out = capsys.readouterr().out
        assert "cannot examine" in out
        assert "trust override active" in out
        assert subject in out

    @pytest.mark.parametrize(("check", "subject"), _GATES)
    def test_null_byte_path_refuses(self, check, subject):
        assert check("./weird\x00path", trust_override=False) is True

    @pytest.mark.parametrize(("check", "subject"), _GATES)
    def test_pathological_long_path_refuses(self, check, subject):
        assert check("/" + "a" * 10_000, trust_override=False) is True

    @pytest.mark.parametrize(("check", "subject"), _GATES)
    def test_empty_path_is_a_noop(self, check, subject, capsys):
        # Documented contract on both gates: empty repo_path returns
        # False silently (nothing was supplied, nothing to gate).
        assert check("", trust_override=False) is False
        assert capsys.readouterr().out == ""

    @pytest.mark.parametrize(("check", "subject"), _GATES)
    def test_hostile_path_output_escaped_and_bounded(self, check, subject,
                                                     tmp_path, capsys):
        hostile = str(tmp_path / ("evil\x1b]0;pwned\x07" + "x" * 400))
        assert check(hostile, trust_override=False) is True
        out = capsys.readouterr().out
        assert "\x1b" not in out and "\x07" not in out
        assert "..." in out

    def test_verdicts_agree_probe_by_probe(self, tmp_path):
        """Belt over the per-gate pins: identical probe, identical
        verdict from both gates."""
        probes = [
            str(tmp_path / "gone"),
            "./weird\x00path",
            "/" + "a" * 10_000,
            "",
        ]
        for probe in probes:
            cc_v = cc.check_repo_claude_trust(probe, trust_override=False)
            ql_v = ql.check_repo_codeql_trust(probe, trust_override=False)
            assert cc_v == ql_v, (
                f"gates disagree on probe {probe[:40]!r}: "
                f"cc={cc_v} codeql={ql_v}")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
