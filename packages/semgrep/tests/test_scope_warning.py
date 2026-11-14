"""A compatibility notice must not invent version evidence or probe again."""

from unittest.mock import Mock

from packages.semgrep import runner


def test_unverified_scope_notice_neither_probes_nor_orders_versions(monkeypatch):
    diagnostic = Mock(return_value="99.0.0")
    log = Mock()
    monkeypatch.setattr(runner, "version", diagnostic)
    monkeypatch.setattr(runner, "_scope_upgrade_warned", False)

    runner._warn_scope_isolation_once(log)
    runner._warn_scope_isolation_once(log)

    diagnostic.assert_not_called()
    log.warning.assert_called_once()
    template, *arguments = log.warning.call_args.args
    message = template % tuple(arguments)
    assert "unverified" in message
    assert "--x-ignore-semgrepignore-files unavailable" in message
    assert ".semgrepignore" in message
    assert "99.0.0" not in message
    assert " < " not in message
