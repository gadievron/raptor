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
