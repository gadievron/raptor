"""Validation fixtures are owned through engine execution and teardown."""

from contextlib import contextmanager

import pytest

from core.run import scratch
from packages.checker_synthesis import synthesise as synth
from packages.checker_synthesis.models import Match, SeedBug, SynthesisedRule


@pytest.fixture(params=["dual", "fixture", "mutant"])
def control(request, tmp_path, monkeypatch):
    roots = []
    source = tmp_path / "seed.c"
    source.write_text("original();\n")
    seed = SeedBug("seed.c", "f", 1, 1, "CWE-476", "test")
    rule = SynthesisedRule("semgrep", "test", "rule", test_positive="positive", test_negative="negative", fix_patch="guarded();")

    @contextmanager
    def workspace(prefix):
        with scratch.scratch_dir(prefix, dir=tmp_path / "scratch", keepalive=True) as root:
            roots.append(root)
            yield root

    def invoke():
        if request.param == "dual":
            return synth._dual_control(rule, tmp_path / "rule", "semgrep", ".c")
        if request.param == "fixture":
            return synth._run_on_fixture_text(tmp_path / "rule", "semgrep", "fixture", ".c")
        return synth._fix_mutant_control(seed, rule, tmp_path / "rule", tmp_path, "semgrep")

    monkeypatch.setattr(synth, "scratch_dir", workspace)
    return invoke, roots, source


def engine(roots, error=None):
    def run(rule, rule_path, target):
        assert target.parent == roots[-1]
        assert str(target.parent) in scratch._keepalive_paths
        assert target.read_text()
        nested = target.parent / (target.stem + "-debris")
        nested.mkdir()
        (nested / "partial").write_bytes(b"partial")
        nested.chmod(0)
        if error is not None:
            raise error
        return ([Match(str(target), 1)] if target.stem == "test_positive" else []), []
    return run


@pytest.mark.parametrize("error_type", [None, OSError, ValueError, KeyboardInterrupt, SystemExit])
def test_controls_release_private_fixtures(control, monkeypatch, error_type):
    invoke, roots, source = control
    primary = error_type("engine failed") if error_type else None
    monkeypatch.setattr(synth, "_run_engine", engine(roots, primary))
    if primary is None:
        invoke()
    else:
        with pytest.raises(error_type) as caught:
            invoke()
        assert caught.value is primary
    assert roots and all(not root.exists() for root in roots)
    assert all(str(root) not in scratch._keepalive_paths for root in roots)
    assert source.read_text() == "original();\n"


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt])
def test_controls_preserve_engine_error(control, monkeypatch, error_type, cleanup_type):
    invoke, roots, source = control
    primary = error_type("engine failed")
    remove = scratch.rmtree_hardened

    def cleanup(root):
        assert remove(root)
        raise cleanup_type("cleanup failed")

    monkeypatch.setattr(synth, "_run_engine", engine(roots, primary))
    monkeypatch.setattr(scratch, "rmtree_hardened", cleanup)
    with pytest.raises(error_type) as caught:
        invoke()
    assert caught.value is primary
    assert all(not root.exists() for root in roots)
    assert not scratch._keepalive_paths
    assert source.read_text() == "original();\n"
