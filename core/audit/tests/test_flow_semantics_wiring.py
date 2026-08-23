"""install_flow_semantics — learned sanitisers reach the Joern server."""

from __future__ import annotations

from pathlib import Path

import core.audit.joern_backend as jb


class _FakeServer:
    def __init__(self):
        self.calls = []

    def set_flow_semantics(self, rows):
        self.calls.append(list(rows))
        return len(rows)


class _NoSemanticsServer:
    """Server predating set_flow_semantics."""


class TestInstallFlowSemantics:
    def test_no_learned_sanitisers_leaves_server_untouched(self, monkeypatch):
        monkeypatch.setattr(
            "core.iris.api.get_project_sanitisers",
            lambda **kw: frozenset(),
        )
        srv = _FakeServer()
        assert jb.install_flow_semantics(srv, "/tmp/t") == 0
        assert srv.calls == []

    def test_learned_sanitisers_installed_sorted(self, monkeypatch):
        monkeypatch.setattr(
            "core.iris.api.get_project_sanitisers",
            lambda **kw: frozenset({"zap_clean", "validate_len"}),
        )
        srv = _FakeServer()
        assert jb.install_flow_semantics(srv, "/tmp/t") == 2
        assert srv.calls == [["validate_len", "zap_clean"]]

    def test_out_dir_and_target_forwarded(self, monkeypatch):
        seen = {}

        def fake(out_dir=None, target_path=None):
            seen["out_dir"] = out_dir
            seen["target_path"] = target_path
            return frozenset({"clean"})

        monkeypatch.setattr("core.iris.api.get_project_sanitisers", fake)
        jb.install_flow_semantics(_FakeServer(), "/tmp/t", out_dir="/tmp/o")
        assert seen["out_dir"] == Path("/tmp/o")
        assert seen["target_path"] == Path("/tmp/t")

    def test_store_failure_degrades_to_zero(self, monkeypatch):
        def boom(**kw):
            raise RuntimeError("store unreadable")

        monkeypatch.setattr("core.iris.api.get_project_sanitisers", boom)
        srv = _FakeServer()
        assert jb.install_flow_semantics(srv, "/tmp/t") == 0
        assert srv.calls == []

    def test_install_failure_degrades_to_zero(self, monkeypatch):
        monkeypatch.setattr(
            "core.iris.api.get_project_sanitisers",
            lambda **kw: frozenset({"clean"}),
        )

        class _Boom:
            def set_flow_semantics(self, rows):
                raise RuntimeError("REPL down")

        assert jb.install_flow_semantics(_Boom(), "/tmp/t") == 0

    def test_server_without_semantics_support(self, monkeypatch):
        monkeypatch.setattr(
            "core.iris.api.get_project_sanitisers",
            lambda **kw: frozenset({"clean"}),
        )
        assert jb.install_flow_semantics(_NoSemanticsServer(), "/tmp/t") == 0

    def test_none_server(self):
        assert jb.install_flow_semantics(None, "/tmp/t") == 0


class TestStartServerWiring:
    def test_start_joern_server_installs_semantics(self, monkeypatch, tmp_path):
        (tmp_path / "a.c").write_text("int main(void) { return 0; }\n")
        srv = _FakeServer()
        monkeypatch.setattr(jb, "joern_available", lambda overrides=None: True)
        monkeypatch.setattr(jb, "_ensure_cpg_loaded",
                            lambda s, t, tun=None, exclude_dirs=(): True)
        import packages.joern.lifecycle as lifecycle
        monkeypatch.setattr(lifecycle, "joern_acquire", lambda tun: srv)
        monkeypatch.setattr(
            "core.iris.api.get_project_sanitisers",
            lambda **kw: frozenset({"scrub"}),
        )
        out = jb.start_joern_server(tmp_path, out_dir="/tmp/run")
        assert out is srv
        assert srv.calls == [["scrub"]]
