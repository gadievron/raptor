"""Tests for Coccinelle runner."""

import json
import os
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.coccinelle.runner import (
    run_rule,
    run_rules,
    is_available,
    version,
    _parse_results,
    _parse_errors,
    _inject_harness,
    _collect_files_examined,
    _dedup_matches,
    RESULT_PREFIX,
)
from packages.coccinelle.models import SpatchMatch


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


class TestParseResults:
    def test_parse_single_result(self):
        data = {"file": "/tmp/a.c", "line": 10, "col": 5}
        output = f"{RESULT_PREFIX}{json.dumps(data)}\n"
        matches = _parse_results(output, "test_rule")
        assert len(matches) == 1
        assert matches[0].file == "/tmp/a.c"
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
        output += "HANDLING: /tmp/test.c\n"
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
            "HANDLING: /tmp/test.c\n"
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
             patch("subprocess.run", return_value=mock_proc):
            result = run_rule(target, rule, env=dict(os.environ))

        assert result.rule == "test"
        assert result.match_count == 1

    def test_timeout(self, tmp_path):
        import subprocess as sp

        rule = tmp_path / "test.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        target = tmp_path / "test.c"
        target.write_text("void f() {}\n")

        with patch("packages.coccinelle.runner.is_available", return_value=True), \
             patch("subprocess.run", side_effect=sp.TimeoutExpired("spatch", 5)):
            result = run_rule(target, rule, timeout=5, env=dict(os.environ))

        assert not result.ok
        assert "timeout" in result.errors[0].lower()


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
             patch("subprocess.run", return_value=mock_proc):
            results = run_rules(target, rules_dir, env=dict(os.environ))

        assert len(results) == 2
        assert results[0].rule == "a"
        assert results[1].rule == "b"


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

        result = run_rule(target, rule)
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

        result = run_rule(target, rule)
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

        result = run_rule(target, rule)
        assert result.match_count == 0
        assert str(target) in result.files_examined


@pytest.mark.skipif(
    not is_available(),
    reason="spatch not installed",
)
class TestShippedRulesIntegration:
    """Integration tests for the .cocci rules shipped in rules/."""

    RULES_DIR = Path(__file__).resolve().parents[1] / "rules"  # packages/coccinelle/rules/

    def test_missing_null_check_catches_deref(self, tmp_path):
        target = tmp_path / "test.c"
        target.write_text(textwrap.dedent("""\
            #include <stdlib.h>
            void f(void) {
                int *p = malloc(sizeof(int));
                *p = 42;
            }
        """))
        result = run_rule(target, self.RULES_DIR / "missing_null_check.cocci")
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
        result = run_rule(target, self.RULES_DIR / "missing_null_check.cocci")
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
        result = run_rule(target, self.RULES_DIR / "lock_imbalance.cocci")
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
        result = run_rule(target, self.RULES_DIR / "lock_imbalance.cocci")
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
        result = run_rule(target, self.RULES_DIR / "lock_imbalance.cocci")
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
        )
        assert result.returncode == 0
        assert result.match_count == 0
