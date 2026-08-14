"""Tests for core.iris.api — consumer-facing spec API."""

from core.evidence import EvidenceTier
from core.iris.specs import _parse_one_spec, _specs_from_list
from core.iris.api import (
    _resolve_out_dir,
    get_project_propagators,
    get_project_sanitisers,
    get_project_sinks,
    get_project_sources,
    load_project_specs,
    promote_spec_on_annotation,
)
from core.iris.specs import TaintSpec
from core.iris.store import load_specs, save_specs


def _make_spec(fn="check_input", file="src/auth.py", role="sanitiser", **kw):
    return TaintSpec(function=fn, file=file, role=role, **kw)


class TestLoadProjectSpecs:
    def test_empty_when_no_store(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        assert load_project_specs(out_dir=run_dir) == []

    def test_loads_from_store(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="sanitize_html", role="sanitiser"),
            _make_spec(fn="exec_cmd", role="sink"),
        ])
        specs = load_project_specs(out_dir=run_dir)
        assert len(specs) == 2

    def test_filter_by_role(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="sanitize_html", role="sanitiser"),
            _make_spec(fn="exec_cmd", role="sink"),
            _make_spec(fn="read_input", role="source"),
        ])
        sinks = load_project_specs(out_dir=run_dir, roles={"sink"})
        assert len(sinks) == 1
        assert sinks[0].function == "exec_cmd"

    def test_filter_by_min_tier(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="heuristic_fn", evidence_tier=EvidenceTier.HEURISTIC),
            _make_spec(fn="confirmed_fn", evidence_tier=EvidenceTier.XREF_BACKED),
        ])
        high = load_project_specs(
            out_dir=run_dir, min_tier=EvidenceTier.XREF_BACKED,
        )
        assert len(high) == 1
        assert high[0].function == "confirmed_fn"

    def test_none_out_dir(self):
        assert load_project_specs(out_dir=None) == []


class TestGetProjectSinks:
    def test_returns_frozenset(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="exec_cmd", role="sink"),
            _make_spec(fn="system_call", role="sink"),
            _make_spec(fn="sanitize_html", role="sanitiser"),
        ])
        sinks = get_project_sinks(out_dir=run_dir)
        assert isinstance(sinks, frozenset)
        assert sinks == {"exec_cmd", "system_call"}

    def test_empty_when_no_sinks(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [_make_spec(role="sanitiser")])
        assert get_project_sinks(out_dir=run_dir) == frozenset()


class TestGetProjectSanitisers:
    def test_returns_frozenset(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="sanitize_html", role="sanitiser"),
            _make_spec(fn="exec_cmd", role="sink"),
        ])
        sani = get_project_sanitisers(out_dir=run_dir)
        assert sani == {"sanitize_html"}


class TestGetProjectSources:
    def test_returns_frozenset(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="read_input", role="source"),
            _make_spec(fn="recv_data", role="source"),
            _make_spec(fn="exec_cmd", role="sink"),
        ])
        sources = get_project_sources(out_dir=run_dir)
        assert isinstance(sources, frozenset)
        assert sources == {"read_input", "recv_data"}

    def test_empty_when_no_sources(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [_make_spec(role="sink")])
        assert get_project_sources(out_dir=run_dir) == frozenset()


class TestGetProjectPropagators:
    def test_returns_frozenset(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="wrap_query", role="propagator"),
            _make_spec(fn="pass_through", role="propagator"),
            _make_spec(fn="exec_cmd", role="sink"),
        ])
        props = get_project_propagators(out_dir=run_dir)
        assert isinstance(props, frozenset)
        assert props == {"wrap_query", "pass_through"}

    def test_empty_when_no_propagators(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [_make_spec(role="sink")])
        assert get_project_propagators(out_dir=run_dir) == frozenset()


class TestPromoteSpecOnAnnotation:
    def test_promotes_matching_sink(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="exec_cmd", file="src/cmd.py", role="sink",
                       evidence_tier=EvidenceTier.HEURISTIC),
        ])
        result = promote_spec_on_annotation(
            "src/cmd.py", "exec_cmd", "sink", out_dir=run_dir,
        )
        assert result is True
        reloaded = load_specs(run_dir)
        assert reloaded[0].evidence_tier == EvidenceTier.XREF_BACKED
        assert reloaded[0].source == "operator_confirmed"

    def test_entry_point_maps_to_source(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="read_input", file="src/io.py", role="source",
                       evidence_tier=EvidenceTier.HEURISTIC),
        ])
        result = promote_spec_on_annotation(
            "src/io.py", "read_input", "entry_point", out_dir=run_dir,
        )
        assert result is True
        reloaded = load_specs(run_dir)
        assert reloaded[0].evidence_tier == EvidenceTier.XREF_BACKED

    def test_no_match_returns_false(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="exec_cmd", file="src/cmd.py", role="sink"),
        ])
        result = promote_spec_on_annotation(
            "src/cmd.py", "unrelated_fn", "sink", out_dir=run_dir,
        )
        assert result is False

    def test_irrelevant_status_returns_false(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="exec_cmd", file="src/cmd.py", role="sink"),
        ])
        result = promote_spec_on_annotation(
            "src/cmd.py", "exec_cmd", "clean", out_dir=run_dir,
        )
        assert result is False

    def test_already_high_tier_not_re_promoted(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="exec_cmd", file="src/cmd.py", role="sink",
                       evidence_tier=EvidenceTier.XREF_BACKED),
        ])
        result = promote_spec_on_annotation(
            "src/cmd.py", "exec_cmd", "sink", out_dir=run_dir,
        )
        assert result is False

    def test_no_store_returns_false(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        result = promote_spec_on_annotation(
            "src/cmd.py", "exec_cmd", "sink", out_dir=run_dir,
        )
        assert result is False

    def test_finding_status_maps_to_sink(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="exec_cmd", file="src/cmd.py", role="sink",
                       evidence_tier=EvidenceTier.HEURISTIC),
        ])
        result = promote_spec_on_annotation(
            "src/cmd.py", "exec_cmd", "finding", out_dir=run_dir,
        )
        assert result is True
        reloaded = load_specs(run_dir)
        assert reloaded[0].evidence_tier == EvidenceTier.XREF_BACKED

    def test_endswith_boundary_check(self, tmp_path):
        """test_auth.py must NOT match auth.py (M1 fix)."""
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="check_pw", file="auth.py", role="sink",
                       evidence_tier=EvidenceTier.HEURISTIC),
        ])
        result = promote_spec_on_annotation(
            "test_auth.py", "check_pw", "sink", out_dir=run_dir,
        )
        assert result is False

    def test_path_prefix_matches(self, tmp_path):
        """src/auth.py should match spec with file=auth.py."""
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="check_pw", file="auth.py", role="sink",
                       evidence_tier=EvidenceTier.HEURISTIC),
        ])
        result = promote_spec_on_annotation(
            "src/auth.py", "check_pw", "sink", out_dir=run_dir,
        )
        assert result is True


class TestResolveOutDir:
    def test_explicit_out_dir(self, tmp_path):
        result = _resolve_out_dir(tmp_path)
        assert result == tmp_path

    def test_none_returns_none_when_no_project(self, monkeypatch):
        monkeypatch.setattr(
            "core.run.output._resolve_active_project", lambda: None,
        )
        result = _resolve_out_dir(None)
        assert result is None

    def test_active_project_child_path(self, monkeypatch):
        """C1 fix: active project dir goes through .parent correctly."""
        from pathlib import Path
        from core.iris.store import _project_dir

        fake_project_dir = Path("/fake/project/output")

        def mock_resolve():
            return (str(fake_project_dir), "myproject", "/target")

        monkeypatch.setattr(
            "core.run.output._resolve_active_project",
            mock_resolve,
        )

        resolved = _resolve_out_dir(None)
        assert resolved is not None
        project = _project_dir(resolved)
        assert project == fake_project_dir


class TestTaintSpecParamsCoercion:
    def test_parse_one_spec_coerces_string_params(self):
        spec = _parse_one_spec({
            "function": "f", "role": "source",
            "params_affected": ["0", "1"],
        })
        assert spec is not None
        assert spec.params_affected == [0, 1]
        assert all(isinstance(p, int) for p in spec.params_affected)

    def test_parse_one_spec_skips_bad_params(self):
        spec = _parse_one_spec({
            "function": "f", "role": "source",
            "params_affected": ["0", "abc", "2"],
        })
        assert spec is not None
        assert spec.params_affected == [0, 2]

    def test_specs_from_list_coerces_list_params(self):
        specs = _specs_from_list([
            {"function": "exec", "params_affected": ["0", "1"],
             "taint_classes": ["cmdi"], "role": "sink"},
        ])
        assert specs[0].params_affected == [0, 1]
