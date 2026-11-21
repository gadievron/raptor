"""The ``events_output=`` kwarg must ride through both untrusted
helpers to ``run()``.

Anonymous-workspace callers pass a throwaway scratch dir as ``output=``
and the durable run dir as ``events_output=`` so the egress audit
stream (``proxy-events.jsonl`` + its MAC'd count sidecar) outlives the
workspace. Both helpers filter ``**kwargs`` through an explicit
allowlist, so without these pins a future allowlist edit would turn the
kwarg into a TypeError — and the caller's audit stream would silently
go back to dying with the scratch dir once someone "fixed" the caller
by dropping the kwarg.

The persistence routing itself (events land in ``events_output``, not
``output``) is covered end-to-end in
``test_proxy_events_cm_block.py``.
"""

import pytest

from core.sandbox import context as _ctx
from core.sandbox.tests.capability import requires_userns


@pytest.fixture
def fake_run(monkeypatch):
    captured = {}

    def _fake(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs

        class _Stub:
            returncode = 0
        return _Stub()

    monkeypatch.setattr(_ctx, "run", _fake)
    # The darwin arm of the entry gate smoke-tests the REAL host's
    # sandbox-exec; pretend it holds so the forwarding under test is
    # reached on every platform (test_run_untrusted_networked_strict_env
    # precedent).
    monkeypatch.setattr(_ctx, "check_seatbelt_available", lambda: True)
    return captured


@requires_userns
def test_run_untrusted_forwards_events_output(fake_run, tmp_path):
    _ctx.run_untrusted(
        ["echo", "ok"],
        target=str(tmp_path / "target"),
        output=str(tmp_path / "workspace"),
        events_output=str(tmp_path / "run"),
    )
    assert fake_run["kwargs"].get("events_output") == str(tmp_path / "run")


@requires_userns
def test_run_untrusted_networked_forwards_events_output(fake_run, tmp_path):
    _ctx.run_untrusted_networked(
        ["echo", "ok"],
        target=str(tmp_path / "target"),
        output=str(tmp_path / "workspace"),
        events_output=str(tmp_path / "run"),
        proxy_hosts=["api.example.com"],
    )
    assert fake_run["kwargs"].get("events_output") == str(tmp_path / "run")
