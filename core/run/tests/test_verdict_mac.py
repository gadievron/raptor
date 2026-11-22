"""Tests for core/run/verdict_mac.py — HMAC provenance for the
``manual_override`` operator claim and the consumer chokepoint
(``verified_manual_override``) the suppression/refutation gates use."""

import json
from pathlib import Path

import pytest

from core.run import verdict_mac as vm


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _finding(**over):
    base = {
        "id": "FIND-0001",
        "file": "src/a.c",
        "function": "parse",
        "line": 12,
        "vuln_type": "buffer_overflow",
        "manual_override": True,
        "manual_override_reason": "exposed via debug endpoint",
    }
    base.update(over)
    return base


class TestStampAndVerify:
    def test_round_trip(self):
        f = _finding()
        assert vm.stamp_manual_override(f)
        assert vm.TOKEN_KEY in f
        assert vm.verify_manual_override(f)

    def test_survives_json_round_trip(self):
        f = _finding()
        vm.stamp_manual_override(f)
        again = json.loads(json.dumps(f))
        assert vm.verify_manual_override(again)

    def test_unstamped_never_verifies(self):
        assert not vm.verify_manual_override(_finding())

    def test_splice_onto_other_finding_fails(self):
        f = _finding()
        vm.stamp_manual_override(f)
        other = _finding(id="FIND-0002", function="lookalike")
        other[vm.TOKEN_KEY] = f[vm.TOKEN_KEY]
        assert not vm.verify_manual_override(other)

    def test_reason_tamper_fails(self):
        f = _finding()
        vm.stamp_manual_override(f)
        f["manual_override_reason"] = "attacker-chosen rationale"
        assert not vm.verify_manual_override(f)

    def test_file_tamper_fails(self):
        f = _finding()
        vm.stamp_manual_override(f)
        f["file"] = "src/other.c"
        assert not vm.verify_manual_override(f)

    def test_line_not_bound(self):
        # Line numbers shift under re-scans while the operator's
        # decision stands — deliberately outside the claim.
        f = _finding()
        vm.stamp_manual_override(f)
        f["line"] = 99
        assert vm.verify_manual_override(f)

    def test_token_from_other_key_fails(self, tmp_path, monkeypatch):
        f = _finding()
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-a"))
        vm.stamp_manual_override(f)
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-b"))
        assert not vm.verify_manual_override(f)

    def test_unusable_key_mints_nothing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-bad"))
        key = tmp_path / "xdg-bad" / "raptor" / "verdict-mac.key"
        key.parent.mkdir(parents=True)
        key.write_bytes(b"short")  # wrong length — refused
        f = _finding()
        assert not vm.stamp_manual_override(f)
        assert vm.TOKEN_KEY not in f
        assert vm.mint_override_token(f) is None

    def test_key_created_private(self, tmp_path):
        vm.stamp_manual_override(_finding())
        key = Path(tmp_path / "xdg" / "raptor" / "verdict-mac.key")
        assert key.is_file()
        assert len(key.read_bytes()) == 32
        assert (key.stat().st_mode & 0o077) == 0


class TestVerifiedManualOverride:
    def test_stamped_flag_grants(self):
        f = _finding()
        vm.stamp_manual_override(f)
        assert vm.verified_manual_override(f)

    def test_planted_flag_demotes(self):
        assert not vm.verified_manual_override(_finding())

    def test_truthy_junk_without_token_demotes(self):
        # Pre-fix the guard-dominance gate took bare truthiness — any
        # non-empty string (even "false" there) read as an override.
        assert not vm.verified_manual_override(
            _finding(manual_override="yes"))

    def test_absent_and_string_false_are_silent_false(self):
        f = _finding()
        del f["manual_override"]
        assert not vm.verified_manual_override(f)
        assert not vm.verified_manual_override(
            _finding(manual_override="false"))

    def test_non_mapping_tolerated(self):
        assert not vm.verified_manual_override(None)  # type: ignore[arg-type]
        assert not vm.verified_manual_override("junk")  # type: ignore[arg-type]

    def test_demotion_warns_with_reapply_hint(self, caplog):
        import logging
        f = _finding(id="FIND-WARN-01")
        with caplog.at_level(logging.WARNING):
            vm.verified_manual_override(f)
        text = caplog.text
        assert "FIND-WARN-01" in text
        assert "raptor-review verdict" in text

    def test_idless_findings_warn_per_coordinates(self, caplog):
        # Keying the warn-once on a literal "?" collapsed every
        # id-less finding into one warning — the second planted flag
        # demoted silently. Fall back to file:function coordinates.
        import logging
        a = _finding(file="src/warn-a.c", function="alpha")
        b = _finding(file="src/warn-b.c", function="beta")
        del a["id"], b["id"]
        with caplog.at_level(logging.WARNING):
            assert not vm.verified_manual_override(a)
            assert not vm.verified_manual_override(b)
        assert "src/warn-a.c:alpha" in caplog.text
        assert "src/warn-b.c:beta" in caplog.text
