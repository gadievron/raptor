"""Tests for core.audit.typestate."""

from __future__ import annotations

from core.analysis.typestate import (
    TypeStateViolation,
    build_builtin_models,
    check_typestate_violations,
    extract_typestate_models,
    format_typestate_for_context,
)


class TestBuildBuiltinModels:
    def test_has_malloc_free(self):
        models = build_builtin_models()
        assert "malloc/free" in models

    def test_has_fopen_fclose(self):
        models = build_builtin_models()
        assert "fopen/fclose" in models

    def test_has_lock_unlock(self):
        models = build_builtin_models()
        assert "pthread_mutex_lock/pthread_mutex_unlock" in models

    def test_has_ssl(self):
        models = build_builtin_models()
        assert "SSL_new/SSL_free" in models

    def test_malloc_model_structure(self):
        models = build_builtin_models()
        m = models["malloc/free"]
        assert "allocated" in m.states
        assert "freed" in m.states
        assert len(m.transitions) >= 2
        assert len(m.forbidden) >= 1

    def test_lock_model_structure(self):
        models = build_builtin_models()
        m = models["pthread_mutex_lock/pthread_mutex_unlock"]
        assert "locked" in m.states
        assert "unlocked" in m.states


class TestExtractTypestateModels:
    def test_no_checklist(self):
        models = extract_typestate_models()
        assert len(models) > 0

    def test_discovers_lifecycle_pairs(self):
        checklist = {
            "items": [
                {"name": "ctx_init"},
                {"name": "ctx_destroy"},
                {"name": "unrelated"},
            ],
        }
        models = extract_typestate_models(checklist)
        assert "ctx_init/ctx_destroy" in models

    def test_discovers_alloc_free(self):
        checklist = {
            "items": [
                {"name": "session_alloc"},
                {"name": "session_free"},
            ],
        }
        models = extract_typestate_models(checklist)
        assert "session_alloc/session_free" in models

    def test_discovers_open_close(self):
        checklist = {
            "items": [
                {"name": "conn_open"},
                {"name": "conn_close"},
            ],
        }
        models = extract_typestate_models(checklist)
        assert "conn_open/conn_close" in models

    def test_no_false_pairs(self):
        checklist = {
            "items": [
                {"name": "foo_init"},
                {"name": "bar_destroy"},
            ],
        }
        models = extract_typestate_models(checklist)
        assert "foo_init/bar_destroy" not in models

    def test_empty_checklist(self):
        models = extract_typestate_models({"items": []})
        assert len(models) == len(build_builtin_models())


class TestCheckTypestateViolations:
    def test_double_free(self):
        source = (
            "void f(void) {\n"
            "    char *p = malloc(64);\n"
            "    free(p);\n"
            "    free(p);\n"
            "}\n"
        )
        models = build_builtin_models()
        violations = check_typestate_violations(source, models)
        double_frees = [v for v in violations if v.violation_kind == "double_free"]
        assert len(double_frees) >= 1
        assert double_frees[0].type_name == "malloc/free"

    def test_use_after_free(self):
        source = (
            "void f(void) {\n"
            "    char *buf = malloc(64);\n"
            "    free(buf);\n"
            "    buf[0] = 'a';\n"
            "}\n"
        )
        models = build_builtin_models()
        violations = check_typestate_violations(source, models)
        uafs = [v for v in violations if v.violation_kind == "use_after_free"]
        assert len(uafs) >= 1

    def test_clean_usage(self):
        source = (
            "void f(void) {\n"
            "    char *p = malloc(64);\n"
            "    p[0] = 'x';\n"
            "    free(p);\n"
            "}\n"
        )
        models = build_builtin_models()
        violations = check_typestate_violations(source, models)
        uafs = [v for v in violations if v.violation_kind in ("double_free", "use_after_free")]
        assert len(uafs) == 0

    def test_null_assignment_not_use(self):
        source = (
            "void f(void) {\n"
            "    char *p = malloc(64);\n"
            "    free(p);\n"
            "    p = NULL;\n"
            "}\n"
        )
        models = build_builtin_models()
        violations = check_typestate_violations(source, models)
        uafs = [v for v in violations if v.violation_kind == "use_after_free"]
        assert len(uafs) == 0

    def test_lock_not_released(self):
        source = (
            "void f(void) {\n"
            "    pthread_mutex_lock(&mtx);\n"
            "    do_work();\n"
            "}\n"
        )
        models = build_builtin_models()
        violations = check_typestate_violations(source, models)
        lock_violations = [v for v in violations if v.violation_kind == "lock_not_released"]
        assert len(lock_violations) >= 1

    def test_lock_properly_released(self):
        source = (
            "void f(void) {\n"
            "    pthread_mutex_lock(&mtx);\n"
            "    do_work();\n"
            "    pthread_mutex_unlock(&mtx);\n"
            "}\n"
        )
        models = build_builtin_models()
        violations = check_typestate_violations(source, models)
        lock_violations = [v for v in violations if v.violation_kind == "lock_not_released"]
        assert len(lock_violations) == 0

    def test_fopen_fclose(self):
        source = (
            "void f(void) {\n"
            "    FILE *fp = fopen(\"test\", \"r\");\n"
            "    fclose(fp);\n"
            "    fclose(fp);\n"
            "}\n"
        )
        models = build_builtin_models()
        violations = check_typestate_violations(source, models)
        df = [v for v in violations if v.violation_kind == "double_free"]
        assert len(df) >= 1

    def test_empty_source(self):
        models = build_builtin_models()
        assert check_typestate_violations("", models) == []

    def test_no_models(self):
        assert check_typestate_violations("free(p);", {}) == []

    def test_error_path_missing_cleanup(self):
        source = (
            "int f(void) {\n"
            "    char *p = malloc(64);\n"
            "    if (err < 0)\n"
            "        goto fail;\n"
            "    use(p);\n"
            "fail:\n"
            "    return -1;\n"
            "}\n"
        )
        models = build_builtin_models()
        violations = check_typestate_violations(source, models)
        cleanup = [v for v in violations if v.violation_kind == "missing_cleanup"]
        assert len(cleanup) >= 1


class TestFormatTypestateForContext:
    def test_renders_violations(self):
        violations = [
            TypeStateViolation(
                type_name="malloc/free",
                operation="free",
                current_state="freed",
                required_states={"allocated"},
                location="line 10",
                path_description="`p` freed at line 5, freed again at line 10",
                violation_kind="double_free",
            ),
        ]
        text = format_typestate_for_context(violations)
        assert "double_free" in text
        assert "malloc/free" in text
        assert "line 10" in text

    def test_empty_violations(self):
        assert format_typestate_for_context([]) == ""

    def test_limits_output(self):
        violations = [
            TypeStateViolation(
                type_name=f"type_{i}",
                operation="op",
                current_state="freed",
                required_states={"allocated"},
                location=f"line {i}",
                path_description=f"violation {i}",
                violation_kind="double_free",
            )
            for i in range(20)
        ]
        text = format_typestate_for_context(violations)
        assert text.count("double_free") <= 8
