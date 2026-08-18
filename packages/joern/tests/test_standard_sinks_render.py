"""Drift guard: standard_sinks.sc renders from the lang_config authority.

The script used to hardcode its own copy of the sweep sink list; the
list now lives in ``lang_config.STANDARD_SWEEP_SINKS`` and is rendered
into the ``__SINK_NAMES__`` template slot by the sweep caller.
"""

from pathlib import Path

from packages.joern.lang_config import STANDARD_SWEEP_SINKS, scala_string_list

_SC = Path(__file__).resolve().parents[1] / "queries" / "standard_sinks.sc"


class TestStandardSinksRender:
    def test_template_has_slot_and_no_hardcoded_names(self):
        body = _SC.read_text(encoding="utf-8")
        assert "__SINK_NAMES__" in body
        # No leftover quoted sink names in the template file.
        for name in STANDARD_SWEEP_SINKS:
            assert f'"{name}"' not in body, name

    def test_rendered_list_matches_pre_split_literal(self):
        # Exact vocabulary the script carried before single-sourcing.
        assert STANDARD_SWEEP_SINKS == (
            "system", "popen", "exec", "execve", "execvp", "execl",
            "execlp", "execle", "fexecve", "posix_spawn", "posix_spawnp",
            "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat",
            "strncat", "sprintf", "snprintf", "vsprintf", "vsnprintf",
            "printf", "fprintf", "syslog",
            "fopen", "freopen", "open",
            "query", "execute", "raw",
            "loads", "load", "unserialize", "pickle",
        )
        rendered = _SC.read_text(encoding="utf-8").replace(
            "__SINK_NAMES__", scala_string_list(STANDARD_SWEEP_SINKS),
        )
        assert 'val dangerousSinks = List("system", "popen", "exec"' in rendered
        assert '"unserialize", "pickle")' in rendered

    def test_run_query_applies_substitutions(self):
        from packages.joern.runner import run_query

        captured = {}

        def fake_runner(cmd, **kwargs):
            # Grab the wrapper script content run_query wrote.
            script = Path(cmd[-1]).read_text(encoding="utf-8")
            captured["script"] = script

            class P:
                returncode = 0
                stdout = ""
                stderr = ""

            return P()

        class FakeCPG:
            path = _SC  # any existing file; importCpg line is inert here
            target = _SC.parent

            def exists(self):
                return True

        run_query(
            FakeCPG(), str(_SC),
            subprocess_runner=fake_runner, validate=False,
            substitutions={
                "__SINK_NAMES__": scala_string_list(STANDARD_SWEEP_SINKS),
            },
        )
        assert "__SINK_NAMES__" not in captured["script"]
        assert '"posix_spawnp"' in captured["script"]
