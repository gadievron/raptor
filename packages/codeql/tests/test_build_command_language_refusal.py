"""`--build-command` with zero or multiple languages is refused with a
message that names the fix (`--languages <lang>`). No codeql CLI, no
network — the refusal fires during argument validation.
"""

import argparse
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# packages/codeql/tests/test_build_command_language_refusal.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))


class TestAgentMainRefusal:
    def _main_argv(self, tmp_path, languages):
        argv = ["agent.py", "--repo", str(tmp_path),
                "--build-command", "make"]
        if languages:
            argv += ["--languages", languages]
        return argv

    def test_multi_language_refused_with_languages_hint(self, tmp_path, capsys):
        from packages.codeql import agent as agent_mod
        with patch.object(sys, "argv",
                          self._main_argv(tmp_path, "java,python")):
            with pytest.raises(SystemExit) as exc:
                agent_mod.main()
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert "--build-command requires exactly one language" in err
        assert "--languages <lang>" in err

    def test_no_language_refused_with_languages_hint(self, tmp_path, capsys):
        from packages.codeql import agent as agent_mod
        with patch.object(sys, "argv", self._main_argv(tmp_path, None)):
            with pytest.raises(SystemExit) as exc:
                agent_mod.main()
        assert exc.value.code == 1
        assert "--languages <lang>" in capsys.readouterr().err


class TestWorkflowRefusal:
    def test_multi_language_refused_with_languages_hint(self, tmp_path):
        import raptor_codeql
        args = argparse.Namespace(
            languages="java,python", build_command="make",
        )
        with patch.object(raptor_codeql, "logger", MagicMock()) as mock_log:
            with pytest.raises(SystemExit) as exc:
                raptor_codeql.run_autonomous_workflow(args)
        assert exc.value.code == 1
        logged = " ".join(
            str(a) for call in mock_log.error.call_args_list
            for a in call.args
        )
        assert "--build-command requires exactly one language" in logged
        assert "--languages <lang>" in logged
