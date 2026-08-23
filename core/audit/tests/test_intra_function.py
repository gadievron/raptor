"""Tests for core.audit.intra_function."""

from __future__ import annotations

from core.audit.intra_function import (
    analyse_intra_function,
    check_cleanup_consistency,
    check_operator_consistency,
    format_intra_function_context,
)


class TestCleanupConsistency:

    def test_missing_kfree_on_one_path(self):
        src = (
            "int f(void) {\n"
            "    buf = kmalloc(128);\n"
            "    if (error1) {\n"
            "        kfree(buf);\n"
            "        return -EINVAL;\n"
            "    }\n"
            "    if (error2) {\n"
            "        return -ENOMEM;\n"  # missing kfree
            "    }\n"
            "    if (error3) {\n"
            "        kfree(buf);\n"
            "        return -EFAULT;\n"
            "    }\n"
            "    kfree(buf);\n"
            "    return 0;\n"
            "}\n"
        )
        results = check_cleanup_consistency(src)
        assert len(results) >= 1
        assert any(r.kind == "cleanup" and "kfree" in r.description for r in results)

    def test_all_paths_consistent(self):
        src = (
            "int f(void) {\n"
            "    buf = kmalloc(128);\n"
            "    if (error) {\n"
            "        kfree(buf);\n"
            "        return -1;\n"
            "    }\n"
            "    kfree(buf);\n"
            "    return 0;\n"
            "}\n"
        )
        results = check_cleanup_consistency(src)
        assert len(results) == 0

    def test_too_few_paths_skipped(self):
        src = (
            "int f(void) {\n"
            "    return 0;\n"
            "}\n"
        )
        assert check_cleanup_consistency(src) == []

    def test_mutex_unlock_missing(self):
        src = (
            "int f(struct mutex *lock) {\n"
            "    mutex_lock(lock);\n"
            "    if (check1()) {\n"
            "        mutex_unlock(lock);\n"
            "        return 0;\n"
            "    }\n"
            "    if (check2()) {\n"
            "        return -1;\n"  # missing unlock
            "    }\n"
            "    mutex_unlock(lock);\n"
            "    return 0;\n"
            "}\n"
        )
        results = check_cleanup_consistency(src)
        assert any("mutex_unlock" in r.description for r in results)

    def test_fclose_missing(self):
        src = (
            "int process(FILE *fp) {\n"
            "    if (bad1) {\n"
            "        fclose(fp);\n"
            "        return -1;\n"
            "    }\n"
            "    if (bad2) {\n"
            "        fclose(fp);\n"
            "        return -1;\n"
            "    }\n"
            "    if (bad3) {\n"
            "        return -1;\n"  # missing fclose
            "    }\n"
            "    fclose(fp);\n"
            "    return 0;\n"
            "}\n"
        )
        results = check_cleanup_consistency(src, min_paths=2)
        assert any("fclose" in r.description for r in results)

    def test_multiple_cleanups_tracked_independently(self):
        src = (
            "int f(void) {\n"
            "    buf = malloc(64);\n"
            "    fp = fopen(path);\n"
            "    if (err1) {\n"
            "        free(buf);\n"
            "        fclose(fp);\n"
            "        return -1;\n"
            "    }\n"
            "    if (err2) {\n"
            "        free(buf);\n"
            "        return -1;\n"  # missing fclose
            "    }\n"
            "    free(buf);\n"
            "    fclose(fp);\n"
            "    return 0;\n"
            "}\n"
        )
        results = check_cleanup_consistency(src, min_paths=2)
        assert any("fclose" in r.description for r in results)
        assert not any("free" in r.description and "missing" in r.description
                       for r in results)


class TestOperatorConsistency:

    def test_deviant_operator_detected(self):
        src = (
            "int f(int idx, int len) {\n"
            "    if (idx < len) do_a();\n"
            "    if (idx < len) do_b();\n"
            "    if (idx < len) do_c();\n"
            "    if (idx <= len) do_d();\n"  # deviant
            "    return 0;\n"
            "}\n"
        )
        results = check_operator_consistency(src)
        assert len(results) == 1
        assert results[0].kind == "operator"
        assert "`<`" in results[0].description
        assert "`<=`" in results[0].description

    def test_all_same_operator_no_finding(self):
        src = (
            "int f(int x) {\n"
            "    if (x < 10) a();\n"
            "    if (x < 20) b();\n"
            "    if (x < 30) c();\n"
            "    return 0;\n"
            "}\n"
        )
        assert check_operator_consistency(src) == []

    def test_too_few_comparisons_skipped(self):
        src = (
            "int f(int x) {\n"
            "    if (x < 10) a();\n"
            "    if (x <= 20) b();\n"
            "    return 0;\n"
            "}\n"
        )
        assert check_operator_consistency(src) == []

    def test_different_variables_not_grouped(self):
        src = (
            "int f(int a, int b) {\n"
            "    if (a < 10) x();\n"
            "    if (a < 20) y();\n"
            "    if (a < 30) z();\n"
            "    if (b <= 10) w();\n"
            "    return 0;\n"
            "}\n"
        )
        assert check_operator_consistency(src) == []

    def test_comment_lines_skipped(self):
        src = (
            "int f(int x) {\n"
            "    if (x < 10) a();\n"
            "    if (x < 20) b();\n"
            "    if (x < 30) c();\n"
            "    // if (x <= 40) d();\n"
            "    return 0;\n"
            "}\n"
        )
        assert check_operator_consistency(src) == []

    def test_equality_vs_inequality_detected(self):
        src = (
            "int f(int status) {\n"
            "    if (status == OK) handle_ok();\n"
            "    if (status == ERR) handle_err();\n"
            "    if (status == WARN) handle_warn();\n"
            "    if (status != FATAL) handle_nonfatal();\n"  # deviant
            "    return 0;\n"
            "}\n"
        )
        results = check_operator_consistency(src)
        assert len(results) == 1
        assert "`!=`" in results[0].description


class TestAnalyseIntraFunction:

    def test_empty_source(self):
        assert analyse_intra_function("") == []

    def test_combines_cleanup_and_operator(self):
        src = (
            "int f(int idx, int len) {\n"
            "    buf = malloc(64);\n"
            "    if (idx < len) {\n"
            "        free(buf);\n"
            "        return 0;\n"
            "    }\n"
            "    if (idx < len) {\n"
            "        free(buf);\n"
            "        return 0;\n"
            "    }\n"
            "    if (idx <= len) {\n"  # deviant operator
            "        return -1;\n"  # missing free
            "    }\n"
            "    free(buf);\n"
            "    return 0;\n"
            "}\n"
        )
        results = analyse_intra_function(src, min_branches=2)
        kinds = {r.kind for r in results}
        assert "cleanup" in kinds


class TestFormatContext:

    def test_none_when_empty(self):
        assert format_intra_function_context([]) is None

    def test_formats_asymmetries(self):
        from core.audit.intra_function import IntraFunctionAsymmetry
        asym = [
            IntraFunctionAsymmetry(
                kind="cleanup",
                description="3/4 return paths call kfree(), but line 8 does not",
                line=8,
            ),
        ]
        result = format_intra_function_context(asym)
        assert result is not None
        assert "[cleanup]" in result
        assert "kfree" in result


class TestCleanupVocabulary:
    """Seed-capped cleanup vocabulary with pack + study hooks (the
    resource_bounds channel-local pattern): the kernel bulk lives in
    the linux_kernel vocab pack, project verbs arrive via
    study-learned paired_operations release verbs."""

    def test_seed_set_capped(self):
        from core.audit.intra_function import _SEED_CLEANUP_NAMES
        assert len(_SEED_CLEANUP_NAMES) <= 9

    def test_learned_release_verb_extends_matcher(self):
        from core.audit.intra_function import check_cleanup_consistency

        src = (
            "int handle(struct conn *c) {\n"
            "    if (setup(c) < 0) { conn_teardown(c); return -1; }\n"
            "    if (bind(c) < 0) { conn_teardown(c); return -1; }\n"
            "    if (send(c) < 0) { return -1; }\n"
            "    conn_teardown(c);\n"
            "    return 0;\n"
            "}\n"
        )
        dm = {"paired_operations": [{
            "acquire": "conn_setup", "release": "conn_teardown",
            "provenance": "verbatim",
        }]}
        # Without vocabulary: conn_teardown is unknown, no asymmetry.
        assert check_cleanup_consistency(src) == []
        # With the learned release verb the missing-cleanup path fires.
        res = check_cleanup_consistency(src, domain_model=dm)
        assert res and res[0].kind == "cleanup"
        assert "conn_teardown" in res[0].description

    def test_llm_prior_provenance_excluded(self):
        from core.audit.intra_function import _learned_cleanup_names
        dm = {"paired_operations": [
            {"acquire": "a", "release": "hallucinated_free",
             "provenance": "llm_prior"},
            {"acquire": "b", "release": "real_free",
             "provenance": "verbatim"},
        ]}
        names = _learned_cleanup_names(dm)
        assert "real_free" in names
        assert "hallucinated_free" not in names

    def test_pack_names_gated_on_kernel_tree(self, tmp_path):
        from core.audit.intra_function import _pack_cleanup_names
        # A plain tmp dir is not a kernel tree — pack stays off.
        assert _pack_cleanup_names(tmp_path) == frozenset()
        assert _pack_cleanup_names(None) == frozenset()
