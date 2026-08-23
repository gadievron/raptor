"""Operator-described (no-CVE) build mode: ``cve-env build --describe``.

The operator chooses the setup, so the description enters the run with
operator provenance (first-class instruction) rather than as untrusted
scan output. Everything a CVE id normally keys — audit dir, spec-store
replay, container labels — keys on a deterministic ``DESC-<hash>``
synthetic id, and outcomes carry an explicit ``operator_described``
label so downstream consumers weigh the (weaker, non-CVE-pinned)
oracle accordingly.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from cve_env.agent.prompts import render_user_prompt
from cve_env.cli import _build_argparser, _describe_record
from cve_env.models import CveRecord, HostInfo


def _args(**over):
    base = dict(describe="nginx 1.18.0 with a vulnerable upload module",
                product=None, version=None)
    base.update(over)
    return SimpleNamespace(**base)


def _host() -> HostInfo:
    return HostInfo(arch="x86_64", os="linux")


class TestDescribeRecord:
    def test_synthetic_id_is_deterministic(self):
        a = _describe_record(_args())
        b = _describe_record(_args())
        assert a.cve_id == b.cve_id
        assert a.cve_id.startswith("DESC-")
        assert a.operator_described is True

    def test_id_varies_with_description_and_pins(self):
        base = _describe_record(_args())
        other_text = _describe_record(_args(describe="something else"))
        pinned = _describe_record(_args(version="1.18.0"))
        assert base.cve_id != other_text.cve_id
        assert base.cve_id != pinned.cve_id

    def test_file_value_reads_the_file(self, tmp_path):
        f = tmp_path / "notes.txt"
        f.write_text("redis 5.0.7 with default config\n")
        rec = _describe_record(_args(describe=str(f)))
        assert rec.description == "redis 5.0.7 with default config"

    def test_empty_description_refused(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("   \n")
        with pytest.raises(SystemExit):
            _describe_record(_args(describe=str(f)))


class TestArgparseSurface:
    def test_cve_id_now_optional_with_describe(self):
        parser = _build_argparser()
        ns = parser.parse_args(["build", "--describe", "nginx 1.18"])
        assert ns.cve_id is None
        assert ns.describe == "nginx 1.18"

    def test_plain_cve_invocation_unchanged(self):
        parser = _build_argparser()
        ns = parser.parse_args(["build", "CVE-2018-7600"])
        assert ns.cve_id == "CVE-2018-7600"
        assert ns.describe is None

    def test_invalid_cve_id_still_rejected(self):
        parser = _build_argparser()
        with pytest.raises(SystemExit):
            parser.parse_args(["build", "not-a-cve"])


class TestCmdBuildGate:
    """Exactly one of (cve_id, --describe): both and neither refuse
    before any lock, probe, or LLM work."""

    def _ns(self, cve_id, describe):
        return SimpleNamespace(cve_id=cve_id, describe=describe,
                               product=None, version=None,
                               description=None)

    def test_both_refused_with_usage_exit_code(self, capsys):
        from cve_env.cli import _cmd_build
        with pytest.raises(SystemExit) as exc:
            _cmd_build(self._ns("CVE-2018-7600", "nginx 1.18"))
        assert exc.value.code == 2
        assert "not both" in capsys.readouterr().err

    def test_neither_refused_with_usage_exit_code(self, capsys):
        from cve_env.cli import _cmd_build
        with pytest.raises(SystemExit) as exc:
            _cmd_build(self._ns(None, None))
        assert exc.value.code == 2
        assert "--describe is required" in capsys.readouterr().err


class TestDescribedPrompt:
    def _rec(self, **over):
        base = dict(cve_id="DESC-abc123def456",
                    product="nginx", version="1.18.0",
                    description="nginx 1.18.0 with a vulnerable module",
                    operator_described=True)
        base.update(over)
        return CveRecord(**base)

    def test_described_block_replaces_cve_block(self):
        out = render_user_prompt(self._rec(), _host())
        assert "# Operator-described target (no CVE)" in out
        assert "operator-asserted" in out
        assert "do not call `nvd_lookup`" in out
        assert "# CVE\n" not in out
        assert "(research via nvd_lookup)" not in out

    def test_version_assertion_demanded_when_pinned(self):
        out = render_user_prompt(self._rec(), _host())
        assert "version assertions" in out
        assert "1.18.0" in out

    def test_description_is_sanitized(self):
        # exploit-disclosure phrasing must not reach the prompt verbatim
        rec = self._rec(description=(
            "nginx 1.18.0. The exploit has been disclosed to the public "
            "and may be used; manipulation leads to remote code "
            "execution."))
        out = render_user_prompt(rec, _host())
        from cve_env.utils.exploit_text_sanitizer import (
            sanitize_exploit_text,
        )
        assert rec.description not in out
        assert sanitize_exploit_text(
            rec.description, max_chars=4000, preserve_layout=True) in out

    def test_cve_prompt_unchanged_for_normal_records(self):
        rec = CveRecord(cve_id="CVE-2014-0160", product="OpenSSL",
                        version="1.0.1f", description="heartbeat")
        out = render_user_prompt(rec, _host())
        assert "# CVE" in out
        assert "Operator-described" not in out


class TestRecordCompat:
    def test_default_records_are_not_described(self):
        rec = CveRecord(cve_id="CVE-2018-7600")
        assert rec.operator_described is False


class TestFileModeVisibility:
    """Review remediations: file-vs-text mode is announced on stderr;
    an existing-but-unreadable file refuses instead of silently
    becoming literal text."""

    def test_file_mode_announced(self, tmp_path, capsys):
        f = tmp_path / "notes.txt"
        f.write_text("redis 5.0.7\n")
        _describe_record(_args(describe=str(f)))
        assert f"read {len('redis 5.0.7' + chr(10))} chars from file" \
            in capsys.readouterr().err

    def test_literal_mode_announced(self, capsys):
        _describe_record(_args(describe="nginx 1.18"))
        assert "literal text" in capsys.readouterr().err

    def test_unreadable_existing_file_refused(self, tmp_path, capsys):
        f = tmp_path / "secret.txt"
        f.write_text("x")
        f.chmod(0o000)
        try:
            with pytest.raises(SystemExit) as exc:
                _describe_record(_args(describe=str(f)))
        finally:
            f.chmod(0o644)
        assert exc.value.code == 2
        assert "cannot be read" in capsys.readouterr().err

    def test_hash_boundary_unambiguous(self):
        a = _describe_record(_args(describe="x\ny", product=None))
        b = _describe_record(_args(describe="x", product="y"))
        assert a.cve_id != b.cve_id


class TestLayoutPreservation:
    """Operator descriptions legitimately carry config sketches whose
    indentation is meaning — the sanitizer's phrase rewriting applies,
    but the whitespace collapse (cosmetic) does not."""

    def test_described_prompt_keeps_structure(self):
        sketch = ("nginx 1.18.0 with:\n"
                  "    location /upload {\n"
                  "        dav_methods PUT;\n"
                  "    }\n")
        rec = CveRecord(cve_id="DESC-aaaabbbbcccc", product="nginx",
                        version="1.18.0", description=sketch,
                        operator_described=True)
        out = render_user_prompt(rec, _host())
        assert "    location /upload {" in out
        assert "        dav_methods PUT;" in out

    def test_phrase_rewriting_still_applies_with_layout(self):
        from cve_env.utils.exploit_text_sanitizer import (
            sanitize_exploit_text,
        )
        text = ("line one\n    indented\n"
                "The exploit has been disclosed to the public.")
        out = sanitize_exploit_text(text, preserve_layout=True)
        assert "\n    indented" in out
        assert "exploit has been disclosed" not in out

    def test_cve_hint_path_unchanged(self):
        from cve_env.utils.exploit_text_sanitizer import (
            sanitize_exploit_text,
        )
        assert sanitize_exploit_text("a  \n  b") == "a b"


class TestVerifiedOutcomeLabel:
    def test_operator_described_reaches_evidence(self, tmp_path):
        from cve_env.infra.verified_outcomes import write_build_outcome
        ok = write_build_outcome(tmp_path, {
            "cve_id": "DESC-aaaabbbbcccc", "status": "success",
            "verify_passed": True, "operator_described": True,
        })
        assert ok
        import json
        rec = json.loads(
            next(tmp_path.glob("*.jsonl")).read_text().splitlines()[0])
        assert rec["evidence"]["operator_described"] is True

    def test_cve_run_labelled_false(self, tmp_path):
        from cve_env.infra.verified_outcomes import write_build_outcome
        ok = write_build_outcome(tmp_path, {
            "cve_id": "CVE-2018-7600", "status": "success",
            "verify_passed": True,
        })
        assert ok
        import json
        rec = json.loads(
            next(tmp_path.glob("*.jsonl")).read_text().splitlines()[0])
        assert rec["evidence"]["operator_described"] is False
