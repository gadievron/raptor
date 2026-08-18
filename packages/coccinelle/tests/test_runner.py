"""Tests for Coccinelle runner."""

import json
import os
import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.coccinelle import runner as runner_mod
from packages.coccinelle.models import SpatchMatch
from packages.coccinelle.runner import (
    MIN_SPATCH_VERSION,
    RESULT_PREFIX,
    _collect_files_examined,
    _dedup_matches,
    _inject_harness,
    _parse_errors,
    _parse_results,
    contains_script_block,
    is_available,
    meets_min_version,
    run_rule,
    run_rules,
    run_rules_batched,
    version,
    version_tuple,
)


class TestAvailability:
    def test_is_available_found(self):
        with patch("shutil.which", return_value="/usr/bin/spatch"):
            assert is_available()

    def test_is_available_missing(self):
        with patch("shutil.which", return_value=None):
            assert not is_available()

    def test_version_returns_string(self):
        with patch("shutil.which", return_value="/usr/bin/spatch"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="spatch version 1.3 compiled with OCaml\n",
                returncode=0,
            )
            v = version()
            assert v is not None
            assert "1.3" in v

    def test_version_unavailable(self):
        with patch("shutil.which", return_value=None):
            assert version() is None

    def test_version_tuple_parses_major_minor(self):
        with patch("shutil.which", return_value="/usr/bin/spatch"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="spatch version 1.3 compiled with OCaml version 5.4.0\n",
                returncode=0,
            )
            assert version_tuple() == (1, 3)

    def test_version_tuple_handles_three_component(self):
        with patch("shutil.which", return_value="/usr/bin/spatch"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="spatch version 1.1.1 compiled with OCaml version 4.14.1\n",
                returncode=0,
            )
            # Only major.minor is significant for the floor check.
            assert version_tuple() == (1, 1)

    def test_version_tuple_none_when_unavailable(self):
        with patch("shutil.which", return_value=None):
            assert version_tuple() is None

    def test_meets_min_version_true_at_floor(self):
        with patch("packages.coccinelle.runner.version_tuple",
                   return_value=MIN_SPATCH_VERSION):
            assert meets_min_version() is True

    def test_meets_min_version_false_below_floor(self):
        with patch("packages.coccinelle.runner.version_tuple",
                   return_value=(1, 1)):
            assert meets_min_version() is False

    def test_meets_min_version_false_when_unknown(self):
        with patch("packages.coccinelle.runner.version_tuple",
                   return_value=None):
            assert meets_min_version() is False


class TestParseResults:
    def test_parse_single_result(self):
        data = {"file": "./a.c", "line": 10, "col": 5}
        output = f"{RESULT_PREFIX}{json.dumps(data)}\n"
        matches = _parse_results(output, "test_rule")
        assert len(matches) == 1
        assert matches[0].file == "./a.c"
        assert matches[0].line == 10
        assert matches[0].rule == "test_rule"

    def test_parse_multiple_results(self):
        lines = []
        for i in range(3):
            d = {"file": f"f{i}.c", "line": i + 1}
            lines.append(f"{RESULT_PREFIX}{json.dumps(d)}")
        output = "\n".join(lines)
        matches = _parse_results(output, "r")
        assert len(matches) == 3

    def test_parse_ignores_non_result_lines(self):
        output = "init_defs_builtins: /usr/lib/coccinelle/standard.h\n"
        output += "HANDLING: ./test.c\n"
        output += f'{RESULT_PREFIX}{{"file":"a.c","line":1}}\n'
        matches = _parse_results(output, "r")
        assert len(matches) == 1

    def test_parse_handles_malformed_json(self):
        output = f"{RESULT_PREFIX}not-json\n"
        output += f'{RESULT_PREFIX}{{"file":"a.c","line":1}}\n'
        matches = _parse_results(output, "r")
        assert len(matches) == 1

    def test_parse_empty(self):
        assert _parse_results("", "r") == []


class TestParseErrors:
    def test_ignores_info_lines(self):
        stderr = (
            "init_defs_builtins: /usr/lib/coccinelle/standard.h\n"
            "HANDLING: ./test.c\n"
        )
        assert _parse_errors(stderr) == []

    def test_captures_parse_error(self):
        stderr = 'minus: parse error:\n  File "test.cocci", line 6\n'
        errors = _parse_errors(stderr)
        assert len(errors) >= 1
        assert "parse error" in errors[0].lower()

    def test_ignores_result_prefix(self):
        stderr = f"{RESULT_PREFIX}{{\"file\":\"a.c\"}}\n"
        assert _parse_errors(stderr) == []

    def test_ignores_generic_error_substring(self):
        stderr = "warning: some informational message about error recovery\n"
        assert _parse_errors(stderr) == []

    def test_captures_semantic_error(self):
        stderr = "Semantic error: bad use of ...\n"
        errors = _parse_errors(stderr)
        assert len(errors) == 1


class TestCollectFilesExamined:
    def test_single_file_always_included(self, tmp_path):
        target = tmp_path / "test.c"
        target.write_text("int main() {}\n")
        result = _collect_files_examined(target, set())
        assert str(target) in result

    def test_single_file_with_matches(self, tmp_path):
        target = tmp_path / "test.c"
        target.write_text("int main() {}\n")
        result = _collect_files_examined(target, {"other.c"})
        assert str(target) in result
        assert "other.c" in result

    def test_directory_enumerates_c_files(self, tmp_path):
        (tmp_path / "a.c").write_text("")
        (tmp_path / "b.c").write_text("")
        (tmp_path / "skip.txt").write_text("")
        result = _collect_files_examined(tmp_path, set())
        assert len(result) == 2
        assert any("a.c" in f for f in result)
        assert any("b.c" in f for f in result)
        assert not any("skip.txt" in f for f in result)

    def test_nonexistent_target(self, tmp_path):
        result = _collect_files_examined(tmp_path / "gone", {"a.c"})
        assert result == ["a.c"]


class TestDedupMatches:
    def test_removes_duplicates(self):
        matches = [
            SpatchMatch(file="a.c", line=10, column=5, rule="r1"),
            SpatchMatch(file="a.c", line=10, column=5, rule="r1"),
            SpatchMatch(file="a.c", line=20, column=1, rule="r1"),
        ]
        result = _dedup_matches(matches)
        assert len(result) == 2

    def test_preserves_order(self):
        matches = [
            SpatchMatch(file="b.c", line=1, rule="r1"),
            SpatchMatch(file="a.c", line=1, rule="r1"),
            SpatchMatch(file="b.c", line=1, rule="r1"),
        ]
        result = _dedup_matches(matches)
        assert result[0].file == "b.c"
        assert result[1].file == "a.c"

    def test_different_rules_not_deduped(self):
        matches = [
            SpatchMatch(file="a.c", line=10, column=5, rule="r1"),
            SpatchMatch(file="a.c", line=10, column=5, rule="r2"),
        ]
        result = _dedup_matches(matches)
        assert len(result) == 2

    def test_empty(self):
        assert _dedup_matches([]) == []


class TestInjectHarness:
    def test_injects_for_position_rule(self):
        rule = textwrap.dedent("""\
            @r@
            expression E;
            position p;
            @@

            E@p = malloc(...);
        """)
        result = _inject_harness(rule, "test_rule")
        assert "script:python" in result
        assert RESULT_PREFIX in result
        assert "test_rule" in result

    def test_no_inject_without_position(self):
        rule = textwrap.dedent("""\
            @@
            expression E;
            @@

            E = malloc(...);
        """)
        result = _inject_harness(rule, "test_rule")
        assert result == rule

    def test_sanitizes_rule_name(self):
        rule = textwrap.dedent("""\
            @r@
            expression E;
            position p;
            @@

            E@p = malloc(...);
        """)
        result = _inject_harness(rule, 'evil", "extra": "injected')
        assert '"extra"' not in result
        assert "evil____extra____injected" in result

    def test_harness_contains_valid_python(self):
        rule = textwrap.dedent("""\
            @r@
            expression E;
            position p;
            @@

            E@p = malloc(...);
        """)
        result = _inject_harness(rule, "test_rule")
        python_block = result.split("@script:python@")[1].split("@@")[1]
        compile(python_block.strip(), "<harness>", "exec")

    def test_no_inject_if_already_scripted(self):
        rule = textwrap.dedent("""\
            @r@
            position p;
            @@

            malloc@p(...)

            @script:python@
            p << r.p;
            @@
            print("already has script")
        """)
        # _inject_harness checks for script:python presence
        # But it's called only when RESULT_PREFIX not in text AND script:python not in text
        # So this case is handled by the caller (runner.run_rule)
        assert "script:python" in rule


class TestRunRule:
    def test_not_installed(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text("@@\nexpression E;\n@@\nE = malloc(...);\n")
        with patch("packages.coccinelle.runner.is_available", return_value=False):
            result = run_rule(tmp_path, rule)
        assert not result.ok
        assert "not installed" in result.errors[0].lower()
        assert result.returncode == -1

    def test_missing_rule_file(self, tmp_path):
        with patch("packages.coccinelle.runner.is_available", return_value=True):
            result = run_rule(tmp_path, tmp_path / "nonexistent.cocci")
        assert not result.ok
        assert result.errors
        assert "not found" in result.errors[0].lower()

    def test_run_with_mock(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(textwrap.dedent("""\
            @r@
            position p;
            @@

            malloc@p(...)

            @script:python@
            p << r.p;
            @@

            import json, sys
            for _p in p:
                sys.stderr.write("COCCIRESULT:" + json.dumps({"file": _p.file, "line": int(_p.line)}) + "\\n")
        """))
        target = tmp_path / "test.c"
        target.write_text("void f() { void *p = malloc(10); }\n")

        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = (
            'COCCIRESULT:{"file":"test.c","line":1}\n'
        )
        mock_proc.returncode = 0

        with patch("packages.coccinelle.runner.is_available", return_value=True), \
             patch("packages.coccinelle.runner._sandboxed_run", return_value=mock_proc):
            # Rule carries its own @script:python — trusted-caller flag.
            result = run_rule(target, rule, env=dict(os.environ),
                              allow_scripting=True)

        assert result.rule == "test"
        assert result.match_count == 1

    def test_timeout(self, tmp_path):
        import subprocess as sp

        rule = tmp_path / "test.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        target = tmp_path / "test.c"
        target.write_text("void f() {}\n")

        with patch("packages.coccinelle.runner.is_available", return_value=True), \
             patch("packages.coccinelle.runner._sandboxed_run",
                   side_effect=sp.TimeoutExpired("spatch", 5)):
            result = run_rule(target, rule, timeout=5, env=dict(os.environ))

        assert not result.ok
        assert "timeout" in result.errors[0].lower()


class TestHarnessTempfilePath:
    """Pin the post-fix invocation: harnessed rules go through a
    tempfile path, NOT ``--sp-file -`` (which spatch 1.3 rejects).

    Bug recap: pre-fix, when a rule needed harness injection the
    runner emitted ``[spatch, --sp-file, -]`` and fed the modified
    text via ``input=`` to subprocess.run. spatch 1.3 errors on
    ``-`` as a file argument with ``Sys_error("-: No such file or
    directory")``. The hypothesis_validation adapter dodged this
    by pre-injecting its own script:python so the runner never
    took the ``-`` path; nothing else exercised it.
    """

    def test_harnessed_rule_routes_via_tempfile_not_stdin(
        self, tmp_path,
    ):
        """A rule without ``script:python`` triggers harness
        injection. The runner must invoke spatch with a real file
        path (not ``-``) and must NOT pass ``input=``."""
        rule = tmp_path / "needs_harness.cocci"
        rule.write_text(
            "@r@\nexpression e1, e2;\nposition p;\n@@\nstrcpy@p(e1, e2)\n"
        )
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        captured = {}

        def _capture(cmd, **kwargs):
            captured["cmd"] = list(cmd)
            captured["input"] = kwargs.get("input")
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ), patch("packages.coccinelle.runner._sandboxed_run",
                 side_effect=_capture):
            run_rule(target, rule, env=dict(os.environ))

        cmd = captured["cmd"]
        # ``cmd`` must NOT include the broken ``-`` stdin marker.
        assert "-" not in cmd, (
            f"runner regressed to ``--sp-file -`` (stdin); cmd={cmd!r}"
        )
        # The --sp-file argument must point at a real file. It will
        # NOT be the original rule (the original lacks the
        # COCCIRESULT-emitting script); it should be a tempfile.
        sp_idx = cmd.index("--sp-file")
        sp_path = Path(cmd[sp_idx + 1])
        assert sp_path.exists() is False, (
            "tempfile should be cleaned up by the time subprocess.run "
            "returns to the caller (we're inside the patched runner, "
            "which captured the path; runner's finally cleans up)"
        )
        # Fed via input= would be a regression — passing a path to
        # an existing file means input= must NOT be set.
        assert captured["input"] is None, (
            f"runner still passes input= to subprocess.run "
            f"(input={captured['input']!r}); the harness must travel "
            f"via the tempfile path"
        )

    def test_pre_injected_rule_bypasses_tempfile(self, tmp_path):
        """If the operator's rule already has ``script:python``
        (e.g. the hypothesis_validation adapter's pattern), the
        runner skips harness injection and uses the original
        rule path directly — no tempfile, no path rewrite."""
        rule = tmp_path / "self_emitting.cocci"
        rule.write_text(textwrap.dedent("""\
            @r@
            position p;
            @@
            malloc@p(...)

            @script:python@
            p << r.p;
            @@

            import json, sys
            sys.stderr.write("COCCIRESULT:" + json.dumps({"file":"x","line":1}) + "\\n")
        """))
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        captured = {}

        def _capture(cmd, **kwargs):
            captured["cmd"] = list(cmd)
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ), patch("packages.coccinelle.runner._sandboxed_run",
                 side_effect=_capture):
            # Rule carries its own @script:python — trusted-caller flag.
            run_rule(target, rule, env=dict(os.environ),
                     allow_scripting=True)

        cmd = captured["cmd"]
        sp_idx = cmd.index("--sp-file")
        sp_path = Path(cmd[sp_idx + 1])
        # No harness injection → pass-through to the original rule.
        assert sp_path == rule, (
            f"runner unnecessarily wrote a harnessed tempfile when "
            f"the rule already has script:python; got path={sp_path}"
        )

    def test_tempfile_cleaned_up_after_success(self, tmp_path):
        """Tempfile should be removed when spatch succeeds."""
        rule = tmp_path / "needs_harness.cocci"
        rule.write_text(
            "@r@\nposition p;\n@@\nstrcpy@p(...)\n"
        )
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        captured_paths = []

        def _capture(cmd, **kwargs):
            sp_idx = cmd.index("--sp-file")
            captured_paths.append(Path(cmd[sp_idx + 1]))
            # Simulate spatch — file exists at this point.
            assert captured_paths[-1].exists()
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ), patch("packages.coccinelle.runner._sandboxed_run",
                 side_effect=_capture):
            run_rule(target, rule, env=dict(os.environ))

        # Post-call: tempfile gone.
        assert captured_paths
        assert not captured_paths[0].exists(), (
            f"tempfile leaked: {captured_paths[0]} still exists"
        )

    def test_tempfile_cleaned_up_after_timeout(self, tmp_path):
        """Tempfile cleanup must run even when subprocess.run raises
        TimeoutExpired. ``finally`` covers this; pin it so a future
        refactor doesn't put the cleanup outside the try-block."""
        import subprocess as sp

        rule = tmp_path / "needs_harness.cocci"
        rule.write_text(
            "@r@\nposition p;\n@@\nstrcpy@p(...)\n"
        )
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        captured = {}

        def _capture_then_timeout(cmd, **kwargs):
            sp_idx = cmd.index("--sp-file")
            captured["path"] = Path(cmd[sp_idx + 1])
            assert captured["path"].exists(), (
                "tempfile not present at spatch-invocation time"
            )
            raise sp.TimeoutExpired("spatch", 5)

        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ), patch("packages.coccinelle.runner._sandboxed_run",
                 side_effect=_capture_then_timeout):
            result = run_rule(target, rule, timeout=5,
                              env=dict(os.environ))

        assert not result.ok
        assert "timeout" in result.errors[0].lower()
        # Tempfile cleaned up despite the early-return path.
        assert "path" in captured
        assert not captured["path"].exists(), (
            f"tempfile leaked on timeout: {captured['path']}"
        )

    def test_tempfile_cleaned_up_after_oserror(self, tmp_path):
        """Same cleanup guarantee when subprocess.run raises
        OSError (e.g. spatch binary went missing mid-call)."""
        rule = tmp_path / "needs_harness.cocci"
        rule.write_text(
            "@r@\nposition p;\n@@\nstrcpy@p(...)\n"
        )
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        captured = {}

        def _capture_then_oserror(cmd, **kwargs):
            sp_idx = cmd.index("--sp-file")
            captured["path"] = Path(cmd[sp_idx + 1])
            raise OSError("spatch went missing")

        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ), patch("packages.coccinelle.runner._sandboxed_run",
                 side_effect=_capture_then_oserror):
            result = run_rule(target, rule, env=dict(os.environ))

        assert not result.ok
        assert "path" in captured
        assert not captured["path"].exists(), (
            f"tempfile leaked on OSError: {captured['path']}"
        )


class TestRunRules:
    def test_not_installed(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.cocci").write_text("@@\n@@\nmalloc(...);\n")
        (rules_dir / "b.cocci").write_text("@@\n@@\nfree(...);\n")
        with patch("packages.coccinelle.runner.is_available", return_value=False):
            results = run_rules(tmp_path, rules_dir)
        assert len(results) == 1
        assert not results[0].ok
        assert "not installed" in results[0].errors[0].lower()

    def test_empty_dir(self, tmp_path):
        assert run_rules(tmp_path / "nonexistent", tmp_path) == []

    def test_runs_all_cocci_files(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        for name in ["a.cocci", "b.cocci"]:
            (rules_dir / name).write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        target = tmp_path / "test.c"
        target.write_text("void f() {}\n")

        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0

        with patch("packages.coccinelle.runner.is_available", return_value=True), \
             patch("packages.coccinelle.runner._sandboxed_run",
                   return_value=mock_proc):
            results = run_rules(target, rules_dir, env=dict(os.environ))

        assert len(results) == 2
        assert results[0].rule == "a"
        assert results[1].rule == "b"


class TestRunRulesBatched:
    def test_empty_list(self):
        assert run_rules_batched(Path("/tmp"), []) == {}

    def test_single_rule_delegates(self, tmp_path):
        rule = tmp_path / "a.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        target = tmp_path / "test.c"
        target.write_text("void f() {}\n")
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        with patch(
            "packages.coccinelle.runner.is_available",
            return_value=True,
        ), patch("packages.coccinelle.runner._sandboxed_run",
                 return_value=mock_proc):
            results = run_rules_batched(
                target, [rule], env=dict(os.environ),
            )
        assert "a" in results
        assert results["a"].rule == "a"

    def test_batched_demultiplexes(self, tmp_path):
        r1 = tmp_path / "rule_x.cocci"
        r1.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        r2 = tmp_path / "rule_y.cocci"
        r2.write_text("@s@\nposition p;\n@@\nfree@p(...)\n")
        target = tmp_path / "test.c"
        target.write_text("void f() { malloc(1); free(0); }\n")
        line1 = json.dumps({
            "file": "test.c", "line": 1, "col": 1,
            "line_end": 1, "col_end": 10,
            "rule": "rule_x", "message": "hit x",
        })
        line2 = json.dumps({
            "file": "test.c", "line": 1, "col": 20,
            "line_end": 1, "col_end": 30,
            "rule": "rule_y", "message": "hit y",
        })
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = (
            f"COCCIRESULT:{line1}\nCOCCIRESULT:{line2}\n"
        )
        mock_proc.returncode = 0
        with patch(
            "packages.coccinelle.runner.is_available",
            return_value=True,
        ), patch("packages.coccinelle.runner._sandboxed_run",
                 return_value=mock_proc):
            results = run_rules_batched(
                target, [r1, r2], env=dict(os.environ),
            )
        assert set(results.keys()) == {"rule_x", "rule_y"}
        assert len(results["rule_x"].matches) == 1
        assert len(results["rule_y"].matches) == 1
        assert results["rule_x"].matches[0].message == "hit x"

    def test_not_installed(self, tmp_path):
        r1 = tmp_path / "a.cocci"
        r1.write_text("@@\n@@\nmalloc(...);\n")
        r2 = tmp_path / "b.cocci"
        r2.write_text("@@\n@@\nfree(...);\n")
        with patch(
            "packages.coccinelle.runner.is_available",
            return_value=False,
        ):
            results = run_rules_batched(
                tmp_path, [r1, r2],
            )
        assert len(results) == 2
        for r in results.values():
            assert not r.ok
            assert "not installed" in r.errors[0].lower()


@pytest.mark.skipif(
    not is_available(),
    reason="spatch not installed",
)
class TestRunRuleIntegration:
    """Integration tests that actually run spatch."""

    def test_basic_match(self, tmp_path):
        target = tmp_path / "test.c"
        target.write_text(textwrap.dedent("""\
            int get_value(int x);

            int good(void) {
                int r = get_value(42);
                if (r < 0) return -1;
                return r;
            }

            int bad(void) {
                return get_value(42) + 1;
            }
        """))

        rule = tmp_path / "find_calls.cocci"
        rule.write_text(textwrap.dedent("""\
            @r@
            position p;
            @@

            get_value@p(...)

            @script:python@
            p << r.p;
            @@

            import json, sys
            for _p in p:
                _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": "find_calls"}
                sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\\n")
        """))

        # Rule carries its own @script:python — trusted-caller flag.
        result = run_rule(target, rule, allow_scripting=True)
        assert result.ok or result.returncode == 0
        assert result.match_count == 2

    def test_no_match(self, tmp_path):
        target = tmp_path / "test.c"
        target.write_text("int main(void) { return 0; }\n")

        rule = tmp_path / "find_calls.cocci"
        rule.write_text(textwrap.dedent("""\
            @r@
            position p;
            @@

            nonexistent_function@p(...)

            @script:python@
            p << r.p;
            @@

            import json, sys
            for _p in p:
                sys.stderr.write("COCCIRESULT:" + json.dumps({"file": _p.file, "line": int(_p.line)}) + "\\n")
        """))

        result = run_rule(target, rule, allow_scripting=True)
        assert result.match_count == 0

    def test_files_examined_includes_clean_file(self, tmp_path):
        target = tmp_path / "clean.c"
        target.write_text("int main(void) { return 0; }\n")

        rule = tmp_path / "find_calls.cocci"
        rule.write_text(textwrap.dedent("""\
            @r@
            position p;
            @@

            nonexistent@p(...)

            @script:python@
            p << r.p;
            @@

            import json, sys
            for _p in p:
                sys.stderr.write("COCCIRESULT:" + json.dumps({"file": _p.file, "line": int(_p.line)}) + "\\n")
        """))

        result = run_rule(target, rule, allow_scripting=True)
        assert result.match_count == 0
        assert str(target) in result.files_examined


@pytest.mark.skipif(
    not is_available(),
    reason="spatch not installed",
)
class TestShippedRulesIntegration:
    """Integration tests for the .cocci rules shipped in rules/."""

    # parents[1] = packages/coccinelle, parents[3] = repo root
    RULES_DIR = Path(__file__).resolve().parents[3] / "engine" / "coccinelle" / "rules"

    def test_missing_null_check_catches_deref(self, tmp_path):
        target = tmp_path / "test.c"
        target.write_text(textwrap.dedent("""\
            #include <stdlib.h>
            void f(void) {
                int *p = malloc(sizeof(int));
                *p = 42;
            }
        """))
        result = run_rule(target, self.RULES_DIR / "missing_null_check.cocci",
                          allow_scripting=True)
        assert result.returncode == 0
        assert result.match_count >= 1

    def test_missing_null_check_clean(self, tmp_path):
        target = tmp_path / "test.c"
        target.write_text(textwrap.dedent("""\
            #include <stdlib.h>
            void f(void) {
                int *p = malloc(sizeof(int));
                if (!p) return;
                *p = 42;
            }
        """))
        result = run_rule(target, self.RULES_DIR / "missing_null_check.cocci",
                          allow_scripting=True)
        assert result.returncode == 0
        assert result.match_count == 0

    def test_lock_imbalance_catches_missing_unlock(self, tmp_path):
        target = tmp_path / "test.c"
        target.write_text(textwrap.dedent("""\
            struct spinlock_t {};
            void spin_lock(struct spinlock_t *l);
            void spin_unlock(struct spinlock_t *l);
            struct spinlock_t lock;

            int f(int cond) {
                spin_lock(&lock);
                if (cond)
                    return -1;
                spin_unlock(&lock);
                return 0;
            }
        """))
        result = run_rule(target, self.RULES_DIR / "lock_imbalance.cocci",
                          allow_scripting=True)
        assert result.returncode == 0
        assert result.match_count >= 1

    def test_lock_imbalance_clean(self, tmp_path):
        target = tmp_path / "test.c"
        target.write_text(textwrap.dedent("""\
            struct spinlock_t {};
            void spin_lock(struct spinlock_t *l);
            void spin_unlock(struct spinlock_t *l);
            struct spinlock_t lock;

            int f(int cond) {
                spin_lock(&lock);
                if (cond) {
                    spin_unlock(&lock);
                    return -1;
                }
                spin_unlock(&lock);
                return 0;
            }
        """))
        result = run_rule(target, self.RULES_DIR / "lock_imbalance.cocci",
                          allow_scripting=True)
        assert result.returncode == 0
        assert result.match_count == 0

    def test_lock_imbalance_irqsave(self, tmp_path):
        target = tmp_path / "test.c"
        target.write_text(textwrap.dedent("""\
            typedef unsigned long spinlock_t;
            void spin_lock_irqsave(spinlock_t *l, unsigned long f);
            void spin_unlock_irqrestore(spinlock_t *l, unsigned long f);
            spinlock_t lock;

            int f(int cond) {
                unsigned long flags;
                spin_lock_irqsave(&lock, flags);
                if (cond)
                    return -1;
                spin_unlock_irqrestore(&lock, flags);
                return 0;
            }
        """))
        result = run_rule(target, self.RULES_DIR / "lock_imbalance.cocci",
                          allow_scripting=True)
        assert result.returncode == 0
        assert result.match_count >= 1

    def test_unchecked_return_finds_unchecked_call(self, tmp_path):
        target = tmp_path / "test.c"
        target.write_text(textwrap.dedent("""\
            int do_io(int fd);

            int good(int fd) {
                int r = do_io(fd);
                if (r < 0) return -1;
                return r;
            }

            void bad(int fd) {
                do_io(fd);
            }
        """))
        result = run_rule(
            target,
            self.RULES_DIR / "unchecked_return.cocci",
            defines={"func": "do_io"},
            allow_scripting=True,
        )
        assert result.returncode == 0
        assert result.match_count >= 1
        assert any(m.line >= 10 for m in result.matches)

    def test_unchecked_return_clean(self, tmp_path):
        target = tmp_path / "test.c"
        target.write_text(textwrap.dedent("""\
            int do_io(int fd);

            int caller(int fd) {
                int r = do_io(fd);
                if (r < 0) return -1;
                return r;
            }
        """))
        result = run_rule(
            target,
            self.RULES_DIR / "unchecked_return.cocci",
            defines={"func": "do_io"},
            allow_scripting=True,
        )
        assert result.returncode == 0
        assert result.match_count == 0


class TestSpatchScratchTmpdir:
    """spatch materialises per-file working copies (cocci-output-*,
    cocci_small_output-*) in TMPDIR and only removes them on clean
    exit — a timeout kill stranded ~200 of them per interrupted sweep.
    The runner gives every invocation a private scratch TMPDIR and
    removes it unconditionally."""

    def _run_and_capture_env(self, tmp_path, *, boom=False):
        import subprocess as _sp
        rule = tmp_path / "r.cocci"
        rule.write_text(
            "@r@\nexpression e1, e2;\nposition p;\n@@\nstrcpy@p(e1, e2)\n"
        )
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")
        captured = {}

        def _fake(cmd, **kwargs):
            captured["env"] = kwargs.get("env") or {}
            # Simulate spatch stranding a working copy in TMPDIR.
            scratch = captured["env"].get("TMPDIR")
            if scratch:
                (Path(scratch) / "cocci-output-1-abc-x.c").write_text("x")
            if boom:
                raise _sp.TimeoutExpired(cmd, 1)
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ), patch("subprocess.run", side_effect=_fake):
            run_rule(target, rule, env=dict(os.environ))
        return captured

    def test_private_tmpdir_passed_and_removed(self, tmp_path):
        captured = self._run_and_capture_env(tmp_path)
        scratch = captured["env"].get("TMPDIR", "")
        assert "raptor-cocci-tmp-" in scratch, (
            "spatch not given a private scratch TMPDIR"
        )
        assert not Path(scratch).exists(), (
            "scratch dir (with spatch's stranded working copy) survived"
        )

    def test_scratch_removed_even_on_timeout(self, tmp_path):
        captured = self._run_and_capture_env(tmp_path, boom=True)
        scratch = captured["env"].get("TMPDIR", "")
        assert scratch and not Path(scratch).exists(), (
            "timeout path leaked the scratch dir"
        )


# ---------------------------------------------------------------------------
# Scripting gate — allow_scripting=False (default) refuses rules that
# declare SmPL scripting blocks BEFORE any spatch invocation.
# ---------------------------------------------------------------------------


HOSTILE_SCRIPTED_RULE = textwrap.dedent("""\
    @r@
    position p;
    @@
    malloc@p(...)

    @script:python@
    p << r.p;
    @@
    import os
    os.system("touch /tmp/pwned")
""")

PLAIN_RULE = "@r@\nposition p;\n@@\nmalloc@p(...)\n"


def _mock_proc():
    return MagicMock(stdout="", stderr="", returncode=0)


class TestScriptingGate:
    """LLM-synthesised (untrusted) rules must never smuggle a
    @script:/@initialize:/@finalize: block into spatch. The refusal is
    a structured error result, not an exception, and it fires before
    tempfile write / runner invocation. RAPTOR's own injected harness
    is added after the gate and is exempt by construction."""

    def test_default_refuses_scripted_rule_runner_not_invoked(
        self, tmp_path,
    ):
        rule = tmp_path / "hostile.cocci"
        rule.write_text(HOSTILE_SCRIPTED_RULE)
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        spy = MagicMock()
        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ):
            result = run_rule(target, rule, subprocess_runner=spy)

        assert not result.ok
        assert result.returncode == -1
        assert "scripting block" in result.errors[0]
        spy.assert_not_called()

    @pytest.mark.parametrize("header", [
        "@script:python@",
        "@script:ocaml@",
        "@initialize:python@",
        "@finalize:python@",
        "@ script:python @",  # header whitespace tolerated by spatch
    ])
    def test_all_scripting_headers_refused(self, tmp_path, header):
        rule = tmp_path / "hostile.cocci"
        rule.write_text(f"{PLAIN_RULE}\n{header}\n@@\nprint(1)\n")
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        spy = MagicMock()
        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ):
            result = run_rule(target, rule, subprocess_runner=spy)

        assert not result.ok
        assert "scripting block" in result.errors[0]
        spy.assert_not_called()

    def test_comment_mentioning_script_does_not_trip_gate(self, tmp_path):
        """The matcher anchors on rule-header syntax; a comment that
        merely mentions "@script:" must not refuse the rule."""
        rule = tmp_path / "commented.cocci"
        rule.write_text(
            "// do NOT add @script: blocks here — see runner docs\n"
            + PLAIN_RULE
        )
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        spy = MagicMock(return_value=_mock_proc())
        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ):
            result = run_rule(target, rule, subprocess_runner=spy)

        assert spy.called
        assert result.returncode == 0

    def test_allow_scripting_true_passes_rule_through_unmodified(
        self, tmp_path,
    ):
        """Shipped-rule path: with allow_scripting=True the scripted
        rule still executes, and the text handed to spatch is the
        original rule file, byte-for-byte."""
        rule = tmp_path / "shipped.cocci"
        rule.write_text(HOSTILE_SCRIPTED_RULE)
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        captured = {}

        def _capture(cmd, **kwargs):
            sp_idx = cmd.index("--sp-file")
            captured["path"] = Path(cmd[sp_idx + 1])
            captured["text"] = captured["path"].read_text(encoding="utf-8")
            return _mock_proc()

        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ):
            result = run_rule(
                target, rule,
                subprocess_runner=_capture,
                allow_scripting=True,
            )

        assert result.returncode == 0
        assert captured["path"] == rule
        assert captured["text"] == HOSTILE_SCRIPTED_RULE

    def test_plain_rule_still_gets_harness_and_runs(self, tmp_path):
        """The gate must not break RAPTOR's own harness injection:
        a plain SmPL rule is wrapped with the @script:python
        COCCIRESULT harness and executed."""
        rule = tmp_path / "plain.cocci"
        rule.write_text(PLAIN_RULE)
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        captured = {}

        def _capture(cmd, **kwargs):
            sp_idx = cmd.index("--sp-file")
            captured["text"] = Path(cmd[sp_idx + 1]).read_text(
                encoding="utf-8",
            )
            return _mock_proc()

        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ):
            result = run_rule(target, rule, subprocess_runner=_capture)

        assert result.returncode == 0
        assert "@script:python@" in captured["text"]
        assert RESULT_PREFIX in captured["text"]

    def test_contains_script_block_predicate(self):
        assert contains_script_block(HOSTILE_SCRIPTED_RULE)
        assert contains_script_block("@initialize:python@\n@@\nx=1\n")
        assert contains_script_block("@finalize:ocaml@\n@@\n")
        assert not contains_script_block(PLAIN_RULE)
        assert not contains_script_block(
            "// commented @script:python mention\n" + PLAIN_RULE
        )


class TestScriptingGateBatched:
    def test_scripted_rule_refused_plain_rule_still_batched(
        self, tmp_path,
    ):
        hostile = tmp_path / "hostile.cocci"
        hostile.write_text(HOSTILE_SCRIPTED_RULE)
        plain = tmp_path / "plain.cocci"
        plain.write_text(PLAIN_RULE)
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        captured = {}

        def _capture(cmd, **kwargs):
            sp_idx = cmd.index("--sp-file")
            captured["text"] = Path(cmd[sp_idx + 1]).read_text(
                encoding="utf-8",
            )
            captured["calls"] = captured.get("calls", 0) + 1
            return _mock_proc()

        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ):
            results = run_rules_batched(
                target, [hostile, plain, tmp_path / "plain2.cocci"],
                subprocess_runner=_capture,
            )

        # plain2 doesn't exist → dropped by the existence filter;
        # hostile refused; plain batched alone... but a 2-element
        # surviving list still takes the batch path only when >1 rule
        # remains AFTER the existence filter. Here [hostile, plain]
        # survive, so the batch path runs with hostile refused.
        assert "hostile" in results
        assert not results["hostile"].ok
        assert "scripting block" in results["hostile"].errors[0]
        # The hostile payload never reached the batch file.
        assert "os.system" not in captured["text"]
        assert "malloc@p" in captured["text"]
        assert captured["calls"] == 1
        assert results["plain"].returncode == 0

    def test_all_scripted_rules_refused_runner_not_invoked(self, tmp_path):
        r1 = tmp_path / "h1.cocci"
        r1.write_text(HOSTILE_SCRIPTED_RULE)
        r2 = tmp_path / "h2.cocci"
        r2.write_text(PLAIN_RULE + "\n@initialize:python@\n@@\nx=1\n")
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        spy = MagicMock()
        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ):
            results = run_rules_batched(
                target, [r1, r2], subprocess_runner=spy,
            )

        assert set(results) == {"h1", "h2"}
        for r in results.values():
            assert not r.ok
            assert "scripting block" in r.errors[0]
        spy.assert_not_called()

    def test_single_rule_delegation_forwards_gate(self, tmp_path):
        rule = tmp_path / "hostile.cocci"
        rule.write_text(HOSTILE_SCRIPTED_RULE)
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        spy = MagicMock()
        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ):
            results = run_rules_batched(
                target, [rule], subprocess_runner=spy,
            )

        assert not results["hostile"].ok
        assert "scripting block" in results["hostile"].errors[0]
        spy.assert_not_called()

    def test_allow_scripting_true_keeps_scripted_rule_in_batch(
        self, tmp_path,
    ):
        r1 = tmp_path / "shipped.cocci"
        r1.write_text(HOSTILE_SCRIPTED_RULE)
        r2 = tmp_path / "plain.cocci"
        r2.write_text(PLAIN_RULE)
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        captured = {}

        def _capture(cmd, **kwargs):
            sp_idx = cmd.index("--sp-file")
            captured["text"] = Path(cmd[sp_idx + 1]).read_text(
                encoding="utf-8",
            )
            return _mock_proc()

        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ):
            results = run_rules_batched(
                target, [r1, r2],
                subprocess_runner=_capture,
                allow_scripting=True,
            )

        assert "@script:python@" in captured["text"]
        assert results["shipped"].returncode == 0
        assert results["plain"].returncode == 0


# ---------------------------------------------------------------------------
# Default runner — sandboxed, network blocked.
# ---------------------------------------------------------------------------


class TestDefaultRunnerSandboxed:
    """When no subprocess_runner is passed, the runner routes spatch
    through core.sandbox (network blocked) rather than bare
    subprocess.run. Explicit subprocess_runner always wins."""

    def test_run_rule_default_routes_through_sandboxed_run(
        self, tmp_path, monkeypatch,
    ):
        rule = tmp_path / "plain.cocci"
        rule.write_text(PLAIN_RULE)
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        spy = MagicMock(return_value=_mock_proc())
        monkeypatch.setattr(runner_mod, "_sandboxed_run", spy)
        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ):
            result = run_rule(target, rule, env=dict(os.environ))

        assert spy.called
        assert result.returncode == 0

    def test_run_rules_batched_default_routes_through_sandboxed_run(
        self, tmp_path, monkeypatch,
    ):
        r1 = tmp_path / "a.cocci"
        r1.write_text(PLAIN_RULE)
        r2 = tmp_path / "b.cocci"
        r2.write_text("@s@\nposition p;\n@@\nfree@p(...)\n")
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        spy = MagicMock(return_value=_mock_proc())
        monkeypatch.setattr(runner_mod, "_sandboxed_run", spy)
        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ):
            run_rules_batched(target, [r1, r2], env=dict(os.environ))

        assert spy.called

    def test_sandboxed_run_blocks_network(self, monkeypatch):
        """_sandboxed_run wires core.sandbox.run with
        block_network=True; subprocess-style kwargs pass through."""
        import core.sandbox as sandbox_pkg

        captured = {}

        def fake_sandbox_run(cmd, **kwargs):
            captured["cmd"] = list(cmd)
            captured["kwargs"] = kwargs
            return _mock_proc()

        monkeypatch.setattr(sandbox_pkg, "run", fake_sandbox_run)
        proc = runner_mod._sandboxed_run(
            ["spatch", "--version"],
            capture_output=True, text=True, timeout=5,
        )

        assert proc.returncode == 0
        assert captured["cmd"] == ["spatch", "--version"]
        assert captured["kwargs"]["block_network"] is True
        assert captured["kwargs"]["caller_label"] == "coccinelle-runner"
        assert captured["kwargs"]["capture_output"] is True
        assert captured["kwargs"]["timeout"] == 5

    def test_explicit_subprocess_runner_wins(self, tmp_path, monkeypatch):
        rule = tmp_path / "plain.cocci"
        rule.write_text(PLAIN_RULE)
        target = tmp_path / "x.c"
        target.write_text("void f() {}\n")

        def _boom(cmd, **kwargs):
            raise AssertionError(
                "default sandbox runner used despite explicit "
                "subprocess_runner"
            )

        monkeypatch.setattr(runner_mod, "_sandboxed_run", _boom)
        stub = MagicMock(return_value=_mock_proc())
        with patch(
            "packages.coccinelle.runner.is_available", return_value=True,
        ):
            result = run_rule(target, rule, subprocess_runner=stub)

        assert stub.called
        assert result.returncode == 0

class TestSpatchPathRealpath:
    """_spatch_path caches the REAL path: a symlink shim on PATH
    otherwise fails the sandbox's mount-ns visibility check and
    silently downgrades rule runs to Landlock-only."""

    def test_resolves_symlink(self, tmp_path, monkeypatch):
        from packages.coccinelle import runner as runner_mod
        real = tmp_path / "coccinelle" / "bin" / "spatch"
        real.parent.mkdir(parents=True)
        real.write_text("#!/bin/sh\n")
        link = tmp_path / "shim" / "spatch"
        link.parent.mkdir()
        link.symlink_to(real)
        monkeypatch.setattr(runner_mod.shutil, "which",
                            lambda _name: str(link))
        monkeypatch.setattr(runner_mod, "_spatch_resolved", False)
        monkeypatch.setattr(runner_mod, "_resolved_spatch", None)
        assert runner_mod._spatch_path() == str(real.resolve())
        # Cache invalidation hygiene for later tests.
        monkeypatch.setattr(runner_mod, "_spatch_resolved", False)
        monkeypatch.setattr(runner_mod, "_resolved_spatch", None)
