"""Corpus Git recorders preserve unrelated process calls and borrowed bindings."""
from contextlib import nullcontext
import subprocess

import pytest

from core.audit.tests import test_corpus_fetch_git_safety as native


@pytest.mark.parametrize("name", ["test_rev_parse_uses_strict_readonly_pins", "test_fetch_and_checkout_use_safe_pins"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_git_recorder_restores_consumer_binding(tmp_path, name, failure):
    namespace = native.run_corpus.subprocess
    runner = subprocess.run
    fixtures = native.run_corpus.FIXTURES_DIR
    calls = []
    token = object()

    def unrelated(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return token

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(subprocess, "run", unrelated)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                getattr(native, name)(tmp_path, patch)
                assert subprocess.run is unrelated
                assert native.run_corpus.subprocess is not namespace
                assert isinstance(native.run_corpus.subprocess.run, native._Recorder)
                assert native.run_corpus.subprocess.CalledProcessError is subprocess.CalledProcessError
                assert subprocess.run(["owned-unrelated"], timeout=7) is token
                assert calls == [(["owned-unrelated"], {"timeout": 7})]
                if failure:
                    raise failure("owned body failure")
        assert native.run_corpus.subprocess is namespace
        assert subprocess.run is unrelated
        assert native.run_corpus.FIXTURES_DIR is fixtures
    assert subprocess.run is runner
