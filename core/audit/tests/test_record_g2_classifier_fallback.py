"""`record` G2 gate: receipt grading when a channel classifier is unavailable.

The G2 TOOL-GROUNDED gate grades sweep receipts through the channel's
own ``is_detection_rule_id`` classifier. When the channel module cannot
be imported (partial upgrade, missing optional dep) the gate used to
grade the receipt as verification-grade — so on exactly the install
whose toolchain is least healthy, a detection-only receipt (bare
``joern:live`` reachability, a sanwit probe) could ground
``--status finding`` alone. The gate now delegates to core's
``_is_detection_variant``, whose classifier-unavailable fallback is the
string heuristics for the KNOWN detection spellings, and an exception
out of the grading fails closed (not verification-grade).
"""

from __future__ import annotations

import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_g2_fallback", str(_SCRIPT))
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_g2_fallback", loader)
    mod = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        loader.exec_module(mod)
    return mod


def _record_args(out_dir: Path, target: Path, **overrides) -> SimpleNamespace:
    base = dict(
        out=str(out_dir),
        target=str(target),
        file="src/a.c",
        function="foo",
        status="finding",
        body="joern dataflow output",
        line_start=None,
        line_end=None,
        cwe=None,
        strategies=None,
        evidence_tool="joern",
        hypothesis="if input reaches memcpy without bound check, CWE-787",
        vuln_type="buffer_overflow",
        related_to=None,
        reach_via="exported API",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _seed_run(tmp_path: Path, *, sweep_rule_id: str):
    """Minimal run dir: context breadcrumb + confirmed joern receipt."""
    from core.audit.record import append_audit_log

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "a.c").write_text(
        "int foo(char *p) { return p[0]; }\n"
    )
    append_audit_log(out_dir, {
        "action": "context", "key": "src/a.c:foo",
        "file": "src/a.c", "function": "foo",
    })
    append_audit_log(out_dir, {
        "action": "sweep", "key": "src/a.c:foo",
        "file": "src/a.c", "function": "foo",
        "tool": "joern", "outcome": "confirmed",
        "rule_id": sweep_rule_id,
    })
    return out_dir, target


@pytest.fixture
def joern_classifier_unavailable(monkeypatch):
    """Block the joern channel module so its classifier cannot load."""
    from core.audit.evidence_grade import _channel_detection_classifier

    # None in sys.modules makes `import core.audit.joern_verify` raise
    # ImportError — the degraded-install shape (module unimportable).
    monkeypatch.setitem(sys.modules, "core.audit.joern_verify", None)
    _channel_detection_classifier.cache_clear()
    yield
    # Drop any classifier cached while the module was blocked.
    _channel_detection_classifier.cache_clear()


def test_detection_receipt_rejected_when_classifier_unavailable(
        tmp_path, capsys, joern_classifier_unavailable):
    # joern:live is a KNOWN detection-grade spelling (guard-blind
    # reachability). With the channel classifier unimportable the gate
    # must fall back to the string heuristics, not auto-grade the
    # receipt as verification.
    mod = _load_cli()
    out_dir, target = _seed_run(tmp_path, sweep_rule_id="joern:live")
    rc = mod.cmd_record(_record_args(out_dir, target))
    captured = capsys.readouterr()
    assert rc == 1, captured.out + captured.err
    assert "detection-grade" in captured.err


def test_verification_receipt_still_records_when_classifier_unavailable(
        tmp_path, capsys, joern_classifier_unavailable):
    # The fallback must not over-close: joern:flow keeps verification
    # role in the string heuristics, so a degraded install can still
    # record genuinely tool-grounded findings.
    mod = _load_cli()
    out_dir, target = _seed_run(tmp_path, sweep_rule_id="joern:flow")
    rc = mod.cmd_record(_record_args(out_dir, target))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert "recorded: src/a.c:foo" in captured.out


def test_detection_receipt_rejected_with_classifier_available(
        tmp_path, capsys):
    # Healthy-install behavior is unchanged: the channel classifier
    # itself demotes joern:live.
    from core.audit.evidence_grade import _channel_detection_classifier

    _channel_detection_classifier.cache_clear()
    mod = _load_cli()
    out_dir, target = _seed_run(tmp_path, sweep_rule_id="joern:live")
    rc = mod.cmd_record(_record_args(out_dir, target))
    captured = capsys.readouterr()
    assert rc == 1, captured.out + captured.err
    assert "detection-grade" in captured.err
