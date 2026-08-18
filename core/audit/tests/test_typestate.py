"""Tests for core.audit.typestate."""

from __future__ import annotations

from typing import ClassVar

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

    def test_openssl_pairs_removed_from_builtins(self):
        # OpenSSL pairs follow the _new/_free convention and are
        # covered by pattern discovery — no longer hardcoded.
        models = build_builtin_models()
        assert not any(k.startswith("SSL_new/") for k in models)
        assert not any(k.startswith("EVP_") for k in models)

    def test_malloc_model_structure(self):
        models = build_builtin_models()
        m = models["malloc/free"]
        assert "allocated" in m.states
        assert "freed" in m.states
        assert m.alloc_methods == ["malloc"]
        assert m.free_methods == ["free"]

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
        # The machine-checked state evidence is part of the rendered
        # bullet — the LLM shouldn't have to re-infer it from prose.
        assert "state: freed" in text
        assert "requires: allocated" in text

    def test_renders_multiple_required_states_sorted(self):
        violations = [
            TypeStateViolation(
                type_name="lock",
                operation="unlock",
                current_state="unlocked",
                required_states={"locked", "armed"},
                location="line 3",
                path_description="unlock without lock",
                violation_kind="lock_not_held",
            ),
        ]
        text = format_typestate_for_context(violations)
        assert "requires: armed/locked" in text

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


class TestConventionDiscoveryCoversOpenSSL:
    """The deleted OpenSSL builtin pairs stay covered mechanically.

    _INIT_DESTROY_PATTERNS' `_new`/`_free` rule matches every pair the
    builtin table used to hardcode; discovery now also runs over (a)
    Joern callee names at model-extraction time and (b) the analyzed
    source's own call names at check time, so OpenSSL *consumers*
    (which never define SSL_new in their checklist) keep coverage.
    """

    _DELETED_PAIRS: ClassVar[list] = [
        ("SSL_new", "SSL_free"),
        ("SSL_CTX_new", "SSL_CTX_free"),
        ("EVP_CIPHER_CTX_new", "EVP_CIPHER_CTX_free"),
        ("EVP_MD_CTX_new", "EVP_MD_CTX_free"),
        ("BIO_new", "BIO_free"),
        ("BN_new", "BN_free"),
        ("X509_new", "X509_free"),
        ("RSA_new", "RSA_free"),
        ("EC_KEY_new", "EC_KEY_free"),
        ("HMAC_CTX_new", "HMAC_CTX_free"),
    ]

    def test_patterns_pair_every_deleted_builtin(self):
        from core.analysis.typestate import _discover_lifecycle_pairs

        names = [n for pair in self._DELETED_PAIRS for n in pair]
        discovered = {
            (alloc, free)
            for alloc, free, _ in _discover_lifecycle_pairs(names)
        }
        for pair in self._DELETED_PAIRS:
            assert pair in discovered, pair

    def test_double_ssl_free_flagged_without_builtin_model(self):
        # An OpenSSL *consumer*: SSL_new is not in its checklist, so
        # only check-time source discovery can supply the model.
        src = (
            "void handler(void) {\n"
            "    SSL *s = SSL_new(ctx);\n"
            "    SSL_free(s);\n"
            "    SSL_free(s);\n"
            "}\n"
        )
        violations = check_typestate_violations(src, build_builtin_models())
        assert any(
            v.violation_kind == "double_free"
            and v.type_name == "SSL_new/SSL_free"
            for v in violations
        )

    def test_use_after_evp_ctx_free_flagged(self):
        src = (
            "int digest(void) {\n"
            "    EVP_MD_CTX *c = EVP_MD_CTX_new();\n"
            "    EVP_MD_CTX_free(c);\n"
            "    return EVP_MD_CTX_new_id(c);\n"
            "}\n"
        )
        violations = check_typestate_violations(src, build_builtin_models())
        assert any(
            v.violation_kind == "use_after_free" for v in violations
        )

    def test_joern_callees_feed_extraction_discovery(self):
        from core.analysis.typestate import extract_typestate_models

        checklist = {"items": [{"name": "handler"}]}
        summaries = {
            "src/tls.c:handler": {
                "callees": ["SSL_new", "SSL_free", "memcpy"],
            },
        }
        models = extract_typestate_models(
            checklist, joern_summaries=summaries,
        )
        assert "SSL_new/SSL_free" in models

    def test_caller_models_dict_not_mutated(self):
        models = build_builtin_models()
        before = set(models)
        src = "void f(void) { SSL *s = SSL_new(c); SSL_free(s); }\n"
        check_typestate_violations(src, models)
        assert set(models) == before
