"""Tests for core.audit.framework_model."""

from __future__ import annotations

from core.audit.framework_model import (
    FrameworkGuarantee,
    format_framework_context,
    framework_negates_cwe,
)


class TestFrameworkNegatesCwe:
    def test_django_orm_negates_sqli(self):
        source = "from django.db import models\nqs = MyModel.objects.filter(name=user_input)"
        result = framework_negates_cwe("views.py", source, "CWE-89")
        assert result is not None
        assert result.framework == "django"
        assert "CWE-89" in result.negates_cwe

    def test_django_template_negates_xss(self):
        source = "from django.template import loader\nrender_to_string('t.html', ctx)"
        result = framework_negates_cwe("views.py", source, "CWE-79")
        assert result is not None
        assert "CWE-79" in result.negates_cwe

    def test_django_template_with_mark_safe_does_not_negate(self):
        source = "from django.template import loader\nmark_safe(user_input)"
        result = framework_negates_cwe("views.py", source, "CWE-79")
        assert result is None

    def test_spring_jdbc_negates_sqli(self):
        source = "JdbcTemplate tmpl = new JdbcTemplate(ds);\ntmpl.query(sql, ?);"
        result = framework_negates_cwe("Dao.java", source, "CWE-89")
        assert result is not None
        assert result.framework == "spring"

    def test_go_html_template_negates_xss(self):
        source = 'import "html/template"\nt := template.Must(template.New("").Parse(tmpl))'
        result = framework_negates_cwe("handler.go", source, "CWE-79")
        assert result is not None
        assert result.framework == "go"

    def test_django_mark_safe_before_render_does_not_negate(self) -> None:
        # The escape hatch voids the guarantee regardless of where it
        # appears relative to the rendering call.
        source = (
            "from django.shortcuts import render\n"
            "safe_body = mark_safe(user_html)\n"
            "return render(request, 't.html', {'body': safe_body})\n"
        )
        result = framework_negates_cwe("views.py", source, "CWE-79")
        assert result is None

    def test_rails_html_safe_alone_does_not_negate(self) -> None:
        # .html_safe disables escaping; it must never count as evidence
        # that escaping is in force.
        source = "raw_output = params[:name].html_safe\n"
        result = framework_negates_cwe("show.html.erb", source, "CWE-79")
        assert result is None

    def test_rails_erb_with_html_safe_does_not_negate(self) -> None:
        source = "<%= comment.body.html_safe %>\n"
        result = framework_negates_cwe("show.html.erb", source, "CWE-79")
        assert result is None

    def test_rails_erb_without_escape_hatch_negates_xss(self) -> None:
        source = "<%= user.name %>\n<%= @post.title %>\n"
        result = framework_negates_cwe("show.html.erb", source, "CWE-79")
        assert result is not None
        assert result.framework == "rails"
        assert "CWE-79" in result.negates_cwe

    def test_bare_filter_without_sqlalchemy_import_does_not_negate(self) -> None:
        # .filter( is a generic method name; without framework import
        # evidence it says nothing about SQL parameterisation.
        source = "results = queryset.filter(name=user_input)\n"
        result = framework_negates_cwe("query.py", source, "CWE-89")
        assert result is None

    def test_sqlalchemy_filter_with_import_negates_sqli(self) -> None:
        source = (
            "from sqlalchemy import select\n"
            "q = session.query(User).filter(User.name == name)\n"
        )
        result = framework_negates_cwe("query.py", source, "CWE-89")
        assert result is not None
        assert result.framework == "flask"
        assert "CWE-89" in result.negates_cwe

    def test_flask_render_template_negates_xss(self) -> None:
        source = (
            "from flask import render_template\n"
            "return render_template('index.html', name=name)\n"
        )
        result = framework_negates_cwe("app.py", source, "CWE-79")
        assert result is not None
        assert result.framework == "flask"

    def test_flask_safe_filter_does_not_negate(self) -> None:
        source = (
            "from flask import render_template_string\n"
            "return render_template_string('{{ body|safe }}', body=body)\n"
        )
        result = framework_negates_cwe("app.py", source, "CWE-79")
        assert result is None

    def test_no_framework_returns_none(self):
        source = "int main() { return 0; }"
        result = framework_negates_cwe("main.c", source, "CWE-89")
        assert result is None

    def test_unrelated_cwe_returns_none(self):
        source = "from django.db import models"
        result = framework_negates_cwe("views.py", source, "CWE-22")
        assert result is None


class TestFormatFrameworkContext:
    def test_empty_list(self):
        assert format_framework_context([]) == ""

    def test_single_guarantee(self):
        g = FrameworkGuarantee(
            framework="django",
            pattern="ORM .filter()",
            guarantees="parameterises queries",
            negates_cwe=["CWE-89"],
        )
        text = format_framework_context([g])
        assert "Django" in text
        assert "CWE-89" in text
        assert "Framework conventions:" in text


class TestBoundedDetectorWindows:
    """The parameterised-query detectors must not span the whole file:
    with DOTALL `.*`, a concatenated-SQL call plus a `?` ANYWHERE
    later in the file (comment, URL, string) minted the "framework
    negates CWE-89" hint — steering review away from exactly the
    unparameterised sites the hint claims are safe."""

    def test_go_distant_question_mark_does_not_negate(self):
        source = (
            'db.Exec(fmt.Sprintf("SELECT * FROM t WHERE n = %s", user))\n'
            + "x := 1\n" * 30
            + "// see https://example.com/docs?page=1\n"
        )
        assert framework_negates_cwe("q.go", source, "CWE-89") is None

    def test_go_parameterised_call_still_negates(self):
        source = 'db.Exec("SELECT * FROM t WHERE n = ?", user)\n'
        result = framework_negates_cwe("q.go", source, "CWE-89")
        assert result is not None
        assert result.framework == "go"

    def test_spring_distant_question_mark_does_not_negate(self):
        source = (
            'tmpl.query(sql + userInput);\n'
            + "int x = 1;\n" * 30
            + "// what? nothing.\n"
        )
        assert framework_negates_cwe("Dao.java", source, "CWE-89") is None

    def test_spring_multiline_parameterised_call_still_negates(self):
        source = (
            'tmpl.query(\n    "SELECT * FROM t WHERE n = ?",\n    name);\n'
        )
        result = framework_negates_cwe("Dao.java", source, "CWE-89")
        assert result is not None
        assert result.framework == "spring"

    def test_rails_distant_question_mark_does_not_negate(self):
        source = (
            'User.where("name = " + params[:n])\n'
            + "y = 1\n" * 30
            + "# huh?\n"
        )
        assert framework_negates_cwe("user.rb", source, "CWE-89") is None

    def test_rails_parameterised_where_still_negates(self):
        source = 'User.where("name = ?", params[:n])\n'
        result = framework_negates_cwe("user.rb", source, "CWE-89")
        assert result is not None
        assert result.framework == "rails"


class TestDetectorWindowsLinearOnHostileRuns:
    """The bounded argument windows must be a single character CLASS.

    The previous spelling (?:[^()]|\n){0,200}? put a branch whose
    arms OVERLAP on newline ([^()] already matches \n) under the
    repeat: two derivations per newline hand the backtracking engine
    a split search the {0,200} bound only caps at 2^199, so a planted
    newline run after a call opener — scanned-repo file content is
    attacker-shaped — pinned a CPU (~x2 per newline; ~0.2s CPU at 22
    newlines and doubling).  The single-class spelling denotes the
    same window with one parse per input; each probe below completes
    in microseconds where the overlapping-arms spelling needs
    seconds, so re-introducing the ambiguity fails the budget in
    finite time.  Match-set preservation is pinned by the multiline
    positives in TestBoundedDetectorWindows.
    """

    # 26 unterminated newlines: far past where the overlapping-arms
    # spelling crosses ~1s CPU, trivially inside any real budget for
    # the single-class spelling.
    _HOSTILE_RUNS = [
        ("Dao.java", "tmpl.query(" + "\n" * 26),
        ("q.go", "db.Exec(" + "\n" * 26),
        ("q.go", "db.Query(" + "\n" * 26),
        ("q.go", "db.QueryRow(" + "\n" * 26),
        ("user.rb", "User.where(" + "\n" * 26),
    ]

    def test_hostile_newline_runs_complete_within_budget(self):
        import time

        for filename, source in self._HOSTILE_RUNS:
            start = time.process_time()
            result = framework_negates_cwe(filename, source, "CWE-89")
            elapsed = time.process_time() - start
            assert result is None, (filename, source[:20])
            assert elapsed < 0.25, (
                f"{filename}: hostile newline-run probe took "
                f"{elapsed:.3f}s CPU — the argument window is "
                f"backtracking superlinearly again (keep it a single "
                f"character class, never an alternation with "
                f"newline-overlapping arms)"
            )
