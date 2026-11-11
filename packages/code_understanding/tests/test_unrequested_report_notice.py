"""Native-only completion identifies retained portable Understand receipts."""
import copy
import json
from pathlib import Path

import pytest

from core.testing.state_isolation import pin_user_state_dirs
from packages.code_understanding import reporting
from packages.code_understanding.tests.test_reporting import _args, _payload


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path)


@pytest.mark.parametrize("disabled", [False, True])
def test_native_only_completion_preserves_prior_receipt_and_warns_once(
    tmp_path, monkeypatch, capsys, disabled,
):
    native = tmp_path / "run" / "hunt-result.json"
    native.parent.mkdir()
    args = _args(tmp_path)
    payload = _payload()
    native.write_text(json.dumps(payload), encoding="utf-8")
    reporting.prepare_understand_report(args, native.parent, Path(args.target))
    result = reporting.complete_understand_report(args, payload, native)
    assert result is not None and not result.errors
    portable = native.parent / "portable-reports"
    before = {p.relative_to(portable): p.read_bytes() for p in portable.rglob("*") if p.is_file()}
    current = {**payload, "items": [{"private": "PRIVATE_CURRENT_ITEM_825"}], "total_cost_usd": 3.0}
    native.write_text(json.dumps(current), encoding="utf-8")
    native_bytes = native.read_bytes()
    captured = copy.deepcopy(current)
    next_args = _args(tmp_path, report_format=None, no_report=disabled)
    reporting.prepare_understand_report(next_args, native.parent, Path(next_args.target))

    def forbidden(*args, **kwargs):
        pytest.fail("native-only completion must not build a portable result")

    monkeypatch.setattr(reporting, "NativeResult", forbidden)
    capsys.readouterr()
    assert reporting.complete_understand_report(next_args, current, native) is None
    streams = capsys.readouterr()
    (tmp_path / "captured-stderr.txt").write_text(streams.err, encoding="utf-8")
    assert streams.err.count("prior report artifacts were not refreshed") == 1
    assert "Summary" not in streams.err and "PRIVATE_CURRENT_ITEM_825" not in streams.err
    assert native.read_bytes() == native_bytes and current == captured
    for name, contents in before.items():
        assert (portable / name).read_bytes() == contents


def test_fresh_native_only_completion_stays_silent(tmp_path, monkeypatch, capsys):
    native = tmp_path / "run" / "hunt-result.json"
    native.parent.mkdir()
    payload = _payload()
    native.write_text(json.dumps(payload), encoding="utf-8")
    before = native.read_bytes()
    args = _args(tmp_path, report_format=None)

    def forbidden(*args, **kwargs):
        pytest.fail("native-only completion must not construct a result")

    monkeypatch.setattr(reporting, "NativeResult", forbidden)
    reporting.prepare_understand_report(args, native.parent, Path(args.target))
    assert reporting.complete_understand_report(args, payload, native) is None
    assert capsys.readouterr().err == ""
    assert native.read_bytes() == before
    assert not (native.parent / "portable-reports").exists()
