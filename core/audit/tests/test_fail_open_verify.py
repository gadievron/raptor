"""Fail-open verification channel.

The LLM hypothesises "control X fails open on error"; the channel
adjudicates mechanically: role (tiered + learned vocabulary) ×
permissive handler outcome × fallibility. Verdicts follow the
api_boundary discipline — confirmed / refuted /
inconclusive-with-reason, never a guess. Hermetic — no LLM, no
subprocesses, ``tmp_path`` fixture trees throughout.

Fixtures deliberately hardcode target-like and library-like names
(``jwt.decode``, ``EVP_VerifyFinal``, …) — they *simulate targets*,
so the vocabulary policy does not apply to them; each fixture supplies
the learned-vocab artifact (spec / annotation / domain-model stub)
the real pipeline would have produced for that name, except where the
name is Tier-A universal or a documented seed exemplar.
"""

from __future__ import annotations

import json

import pytest

from core.audit.fail_open_lang import (
    c_ignored_return_sites,
    c_tristate_sites,
    go_discard_sites,
    go_function_returns_error,
    go_recover_handlers,
    java_handlers,
    python_handlers,
)
from core.audit.fail_open_roles import (
    GRADE_DETECTION,
    GRADE_REGISTRY,
    SEED_EXEMPLARS,
    SEED_SET_CAP,
    TIER_A_CATEGORY_CAP,
    TIER_A_MODULE_PREFIXES,
    TIER_A_UNIVERSAL,
    TIER_B_FRAMEWORK_HOOKS,
    RoleContext,
    bind_role,
    registry_budget_violations,
)
from core.audit.fail_open_verify import (
    REASON_FALLIBILITY_UNRESOLVED,
    REASON_HANDLER_UNDECIDED,
    REASON_HYPOTHESIS_UNBINDABLE,
    REASON_LANGUAGE_UNSUPPORTED,
    REASON_ROLE_UNBOUND,
    REASON_TYPES_UNRESOLVED,
    RULE_HANDLER_OUTCOME,
    RULE_IGNORED_RETURN,
    RULE_RECOVER_CONTINUE,
    RULE_TRISTATE,
    fail_open_applicable,
    is_detection_rule_id,
    is_fail_open_hypothesis,
    run_fail_open_check,
)
from core.testing import requires_ts

# ── fixture helpers ─────────────────────────────────────────────────


def _write(tmp_path, rel, text):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def _out_dir_with_spec(tmp_path, function, role="sanitiser",
                       tier="xref_backed"):
    """A run dir carrying one IRIS taint spec for *function*."""
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    (out / "iris-taint-specs.json").write_text(json.dumps([{
        "function": function,
        "file": "",
        "role": role,
        "evidence_tier": tier,
    }]))
    return out


def _out_dir_with_domain_model(tmp_path, statement, *, contract=None):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    model = {
        "invariants": [{
            "id": "inv-verify-before-dispatch",
            "statement": statement,
        }],
    }
    if contract:
        model["contracts"] = [contract]
    (out / "domain-model.json").write_text(json.dumps(model))
    return out


def _annotations_dir(tmp_path, source_file, function, status):
    base = tmp_path / "annotations"
    from core.annotations.models import Annotation
    from core.annotations.storage import write_annotation
    write_annotation(base, Annotation(
        file=source_file, function=function,
        body="fixture", metadata={"status": status, "source": "human"},
    ))
    return base


# ── hypothesis classifier ───────────────────────────────────────────


class TestHypothesisShape:
    ACCEPTS = (
        "the token check fails open when jwt.decode raises",
        "handler swallows the exception and proceeds",
        "empty catch around certificate validation",
        "silent except handler hides sanitiser failures",
        "the return value of setuid is ignored; on failure we keep root",
        "unchecked error from EVP_VerifyFinal accepted as success",
        "discarded error from the session store",
        "panic recovered and processing continues",
        "unawaited promise rejection in the CSRF middleware",
        ("verification error is silently ignored and the request "
         "proceeds to the authenticated branch"),
    )
    REJECTS = (
        "unchecked memcpy overflow of the notification buffer",
        "integer overflow when len * size exceeds UINT32_MAX",
        "use-after-free of conn in the handler",
        "",
    )

    def test_accepts_fail_open_shapes(self):
        for text in self.ACCEPTS:
            assert is_fail_open_hypothesis(text), text

    def test_rejects_unrelated_shapes(self):
        for text in self.REJECTS:
            assert not is_fail_open_hypothesis(text), text

    def test_cwe_applicability(self):
        for cwe in ("CWE-703", "CWE-636", "CWE-391", "CWE-390",
                    "CWE-252", "CWE-248"):
            assert fail_open_applicable(cwe), cwe
        assert fail_open_applicable("703")
        assert not fail_open_applicable("CWE-787")
        assert not fail_open_applicable("")

    def test_detection_variant_rule_ids(self):
        assert is_detection_rule_id(RULE_HANDLER_OUTCOME + "-naming")
        assert not is_detection_rule_id(RULE_HANDLER_OUTCOME)
        assert not is_detection_rule_id("semgrep:rule-naming")


# ── leg-1 role binding ──────────────────────────────────────────────


class TestRoleBinding:
    def test_tier_a_posix_binds_registry_grade(self):
        role = bind_role(["setuid"], "", "src/priv.c", language="c")
        assert role is not None
        assert role.source == "universal_registry"
        assert role.grade == GRADE_REGISTRY
        assert role.contract == "zero_ok"
        assert role.provenance.startswith("tier_a:")

    def test_tier_a_module_prefix_binds(self):
        role = bind_role(
            ["hmac.compare_digest"], "", "src/a.py", language="python",
        )
        assert role is not None
        assert role.source == "universal_registry"
        assert role.grade == GRADE_REGISTRY

    def test_tier_b_hook_mechanics_bind_from_source(self):
        segment = "@auth.login_required\ndef view(req):\n    pass\n"
        role = bind_role(
            ["helper"], "view", "src/views.py",
            language="python", enclosing_source=segment,
        )
        assert role is not None
        assert role.source == "framework_registry"
        assert role.grade == GRADE_REGISTRY
        assert role.provenance.startswith("tier_b:")

    def test_seed_exemplar_is_detection_grade(self):
        role = bind_role(
            ["EVP_VerifyFinal"], "", "src/verify.c", language="c",
        )
        assert role is not None
        assert role.source == "seed_exemplar"
        assert role.grade == GRADE_DETECTION
        assert role.contract.startswith("tristate")

    def test_naming_heuristic_is_detection_grade(self):
        role = bind_role(
            ["check_password_v2"], "", "src/a.py", language="python",
        )
        # "check" is not a stem; "password" is not a stem — no bind.
        assert role is None
        role = bind_role(
            ["verify_token"], "", "src/a.py", language="python",
        )
        assert role is not None
        assert role.source == "naming"
        assert role.grade == GRADE_DETECTION

    def test_no_role_returns_none(self):
        assert bind_role(
            ["compute_checksum_helper"], "process_batch", "src/a.py",
            language="python",
        ) is None

    def test_two_detection_sources_upgrade_to_registry(self, tmp_path):
        # heuristic-tier spec (detection) + naming stem (detection)
        # on the same callee → registry-grade upgrade.
        out = _out_dir_with_spec(
            tmp_path, "verify_sig", tier="heuristic",
        )
        role = bind_role(
            ["verify_sig"], "", "src/a.py", language="python",
            context=RoleContext(out_dir=out),
        )
        assert role is not None
        assert role.grade == GRADE_REGISTRY
        assert role.provenance.startswith("upgraded:")


class TestLearnedVocab:
    """Hermetic plumbing proof for every learned-vocab surface, plus
    the no-hidden-list proof: strip the learned inputs and a
    target-specific name no longer binds."""

    def test_annotation_binds_registry_grade(self, tmp_path):
        base = _annotations_dir(
            tmp_path, "src/auth.py", "check_pw", "trust_boundary",
        )
        role = bind_role(
            ["check_pw"], "", "src/auth.py", language="python",
            context=RoleContext(annotations_dir=base),
        )
        assert role is not None
        assert role.source == "annotation"
        assert role.provenance == "annotation"
        assert role.grade == GRADE_REGISTRY

    def test_domain_model_invariant_binds_registry_grade(self, tmp_path):
        out = _out_dir_with_domain_model(
            tmp_path,
            "signature verification via verify_blob must succeed "
            "before dispatch",
        )
        role = bind_role(
            ["verify_blob"], "", "src/dispatch.c", language="c",
            context=RoleContext(out_dir=out),
        )
        assert role is not None
        assert role.source == "domain_model"
        assert role.grade == GRADE_REGISTRY
        assert role.provenance.startswith("domain_model:")

    def test_domain_model_contract_carries_tristate(self, tmp_path):
        out = _out_dir_with_domain_model(
            tmp_path,
            "irrelevant invariant text",
            contract={
                "function": "verify_blob",
                "file": "src/dispatch.c",
                "output_semantics": "returns 1 on success, 0 on "
                                    "failure, -1 on error",
            },
        )
        role = bind_role(
            ["verify_blob"], "", "src/dispatch.c", language="c",
            context=RoleContext(out_dir=out),
        )
        assert role is not None
        assert role.contract == "tristate:1=ok,0=fail,-1=error"
        assert role.grade == GRADE_REGISTRY

    def test_xref_backed_spec_is_registry_grade(self, tmp_path):
        out = _out_dir_with_spec(
            tmp_path, "sanitize_html", tier="xref_backed",
        )
        role = bind_role(
            ["sanitize_html"], "", "src/render.py", language="python",
            context=RoleContext(out_dir=out),
        )
        assert role is not None
        assert role.source == "iris_spec"
        assert role.provenance == "iris_spec:xref_backed"
        assert role.grade == GRADE_REGISTRY

    def test_heuristic_spec_is_detection_grade(self, tmp_path):
        out = _out_dir_with_spec(
            tmp_path, "scrub_output", tier="heuristic",
        )
        role = bind_role(
            ["scrub_output"], "", "src/render.py", language="python",
            context=RoleContext(out_dir=out),
        )
        assert role is not None
        assert role.provenance == "iris_spec:heuristic"
        assert role.grade == GRADE_DETECTION

    def test_discovered_wrapper_sink_is_registry_grade(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        (out / "discovered-sinks.json").write_text(json.dumps({
            "discovered_sinks": [{
                "file": "src/db.py", "function": "run_raw_query",
                "reason": "wrapper", "confidence": "high",
            }],
        }))
        role = bind_role(
            ["run_raw_query"], "", "src/db.py", language="python",
            context=RoleContext(out_dir=out),
        )
        assert role is not None
        assert role.source == "sink_catalog"
        assert role.provenance == "sink_catalog:wrapper"
        assert role.grade == GRADE_REGISTRY

    def test_naming_reason_sink_is_detection_grade(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        (out / "discovered-sinks.json").write_text(json.dumps({
            "discovered_sinks": [{
                "file": "src/db.py", "function": "do_frobnicate",
                "reason": "naming", "confidence": "low",
            }],
        }))
        role = bind_role(
            ["do_frobnicate"], "", "src/db.py", language="python",
            context=RoleContext(out_dir=out),
        )
        assert role is not None
        assert role.grade == GRADE_DETECTION

    def test_no_hidden_list_strip_learned_inputs(self, tmp_path):
        """Removing all learned inputs on a target-specific name yields
        no role — proves no hidden hardcoded list does the work."""
        out = _out_dir_with_spec(tmp_path, "gskit_attach_channel",
                                 tier="xref_backed")
        ctx = RoleContext(out_dir=out)
        bound = bind_role(
            ["gskit_attach_channel"], "", "src/net.c", language="c",
            context=ctx,
        )
        assert bound is not None and bound.source == "iris_spec"
        # Same name, learned inputs stripped → role-unbound.
        stripped = bind_role(
            ["gskit_attach_channel"], "", "src/net.c", language="c",
            context=RoleContext(),
        )
        assert stripped is None


class TestVocabPolicy:
    """CI size-budget lint: 'huge special-case list' is structurally
    impossible, not just discouraged."""

    def test_registry_budgets_hold(self):
        assert registry_budget_violations() == []

    def test_seed_sets_single_digit(self):
        by_cat: dict[str, int] = {}
        for e in SEED_EXEMPLARS:
            assert e.tier == "seed_exemplar"
            by_cat[e.role] = by_cat.get(e.role, 0) + 1
        for cat, count in by_cat.items():
            assert count <= SEED_SET_CAP, cat

    def test_tier_a_caps_hold(self):
        by_cat: dict[str, int] = {}
        for e in TIER_A_UNIVERSAL:
            assert e.tier == "universal"
            by_cat[e.role] = by_cat.get(e.role, 0) + 1
        for cat, count in by_cat.items():
            assert count <= TIER_A_CATEGORY_CAP, cat
        assert len(TIER_A_MODULE_PREFIXES) <= TIER_A_CATEGORY_CAP

    def test_no_library_names_outside_seed_sets(self):
        library_prefixes = ("EVP_", "BIO_", "SSL_", "X509_", "PEM_",
                            "jwt.", "django.", "flask.")
        for e in TIER_A_UNIVERSAL:
            assert not e.name.startswith(library_prefixes), e.name

    def test_tier_b_is_mechanics_not_name_lists(self):
        import re as _re
        for hook in TIER_B_FRAMEWORK_HOOKS:
            _re.compile(hook.pattern)  # must be a pattern, must compile


# ── leg-2 analyzers (direct) ────────────────────────────────────────


class TestPythonHandlerAnalyzer:
    def test_except_pass_classified(self):
        src = (
            "def f(token, key):\n"
            "    claims = {}\n"
            "    try:\n"
            "        claims = jwt.decode(token, key)\n"
            "    except Exception:\n"
            "        pass\n"
            "    return claims\n"
        )
        handlers = python_handlers(src, "a.py")
        assert len(handlers) == 1
        h = handlers[0]
        assert h.outcome_kind == "pass"
        assert h.broad is True
        assert h.enclosing_function == "f"
        assert "jwt.decode" in h.try_calls

    def test_reraise_is_fail_closed(self):
        src = (
            "def f(t):\n"
            "    try:\n"
            "        check(t)\n"
            "    except InvalidTokenError:\n"
            "        raise Unauthorized()\n"
        )
        h = python_handlers(src, "a.py")[0]
        assert h.outcome_kind == "fail_closed"

    def test_return_true_is_permissive(self):
        src = (
            "def user_can(user, obj):\n"
            "    try:\n"
            "        return acl.check(user, obj)\n"
            "    except LookupError:\n"
            "        return True\n"
        )
        h = python_handlers(src, "a.py")[0]
        assert h.outcome_kind == "return_permissive"
        assert h.permissive_value == "True"

    def test_return_false_is_fail_closed(self):
        src = (
            "def user_can(user, obj):\n"
            "    try:\n"
            "        return acl.check(user, obj)\n"
            "    except LookupError:\n"
            "        return False\n"
        )
        h = python_handlers(src, "a.py")[0]
        assert h.outcome_kind == "fail_closed"

    def test_contextlib_suppress_classified(self):
        src = (
            "import contextlib\n"
            "def f(t):\n"
            "    with contextlib.suppress(Exception):\n"
            "        verify_token(t)\n"
        )
        h = python_handlers(src, "a.py")[0]
        assert h.idiom == "contextlib_suppress"
        assert h.broad is True
        assert h.outcome_kind == "pass"
        assert "verify_token" in h.try_calls

    def test_fallback_action_is_undecided(self):
        src = (
            "def f(t):\n"
            "    try:\n"
            "        verify(t)\n"
            "    except Exception:\n"
            "        rebuild_state()\n"
        )
        h = python_handlers(src, "a.py")[0]
        assert h.outcome_kind == "fallback_action"
        assert not h.is_permissive
        assert not h.is_fail_closed


class TestCAnalyzers:
    IGNORED = (
        "int drop_priv(uid_t u) {\n"
        "    setuid(u);\n"
        "    return execve(handler, argv, envp);\n"
        "}\n"
    )
    CHECKED = (
        "int drop_priv(uid_t u) {\n"
        "    if (setuid(u) != 0)\n"
        "        return -1;\n"
        "    return execve(handler, argv, envp);\n"
        "}\n"
    )

    def test_bare_statement_is_unguarded(self):
        sites = c_ignored_return_sites(self.IGNORED, "a.c", "setuid")
        assert [s.verdict for s in sites] == ["unguarded"]

    def test_condition_consumption_is_guarded(self):
        sites = c_ignored_return_sites(self.CHECKED, "a.c", "setuid")
        assert [s.verdict for s in sites] == ["guarded"]

    @pytest.mark.parametrize("tier", ["tree-sitter", "regex-fallback"])
    def test_void_cast_still_unguarded_with_receipt(
        self, tier, monkeypatch,
    ):
        # The C leg HAS a line-regex fallback — pin both tiers: the
        # verdict survives without a tree, only the receipt coarsens
        # (the cast text is a tree-level observation).
        if tier == "tree-sitter":
            from core.testing import ts_parser_available
            if not ts_parser_available("c"):
                pytest.skip("no tree-sitter c grammar installed")
        else:
            import core.audit.fail_open_lang as lang
            monkeypatch.setattr(lang, "_ts_parser", lambda language: None)
        src = "void f(uid_t u) {\n    (void)setuid(u);\n}\n"
        sites = c_ignored_return_sites(src, "a.c", "setuid")
        assert sites[0].verdict == "unguarded"
        if tier == "tree-sitter":
            assert "(void)" in sites[0].evidence
        else:
            assert sites[0].parser == "regex"
            assert "fallback" in sites[0].evidence

    def test_tristate_truth_test_accepts_error(self):
        src = (
            "int check(EVP_MD_CTX *c, unsigned char *s, int n, "
            "EVP_PKEY *k) {\n"
            "    if (EVP_VerifyFinal(c, s, n, k))\n"
            "        return ACCEPT;\n"
            "    return REJECT;\n"
            "}\n"
        )
        sites = c_tristate_sites(src, "a.c", "EVP_VerifyFinal")
        assert sites[0].verdict == "unguarded"
        assert "-1" in sites[0].evidence

    def test_tristate_eq_one_is_guarded(self):
        src = (
            "int check(EVP_MD_CTX *c, unsigned char *s, int n, "
            "EVP_PKEY *k) {\n"
            "    if (EVP_VerifyFinal(c, s, n, k) == 1)\n"
            "        return ACCEPT;\n"
            "    return REJECT;\n"
            "}\n"
        )
        sites = c_tristate_sites(src, "a.c", "EVP_VerifyFinal")
        assert sites[0].verdict == "guarded"

    def test_tristate_ne_zero_accepts_error(self):
        src = (
            "int check(void) {\n"
            "    if (EVP_VerifyFinal(c, s, n, k) != 0)\n"
            "        return ACCEPT;\n"
            "    return REJECT;\n"
            "}\n"
        )
        sites = c_tristate_sites(src, "a.c", "EVP_VerifyFinal")
        assert sites[0].verdict == "unguarded"

    def test_regex_fallback_when_parser_absent(self, monkeypatch):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        sites = c_ignored_return_sites(self.IGNORED, "a.c", "setuid")
        assert sites and sites[0].verdict == "unguarded"
        assert sites[0].parser == "regex"
        tri = c_tristate_sites(
            "int f(void) {\n"
            "    if (EVP_VerifyFinal(c, s, n, k) == 1) return 1;\n"
            "    return 0;\n"
            "}\n",
            "a.c", "EVP_VerifyFinal",
        )
        assert tri and tri[0].verdict == "guarded"
        assert tri[0].parser == "regex"


# ── verdicts end to end (fixture pairs per idiom) ───────────────────


class TestVerdictsPython:
    JWT_VULN = (
        "import jwt\n"
        "def current_user(token, key):\n"
        "    claims = {}\n"
        "    try:\n"
        "        claims = jwt.decode(token, key, algorithms=['RS256'])\n"
        "    except Exception:\n"
        "        pass\n"
        "    return User(claims)\n"
    )
    JWT_SAFE = (
        "import jwt\n"
        "def current_user(token, key):\n"
        "    try:\n"
        "        claims = jwt.decode(token, key, algorithms=['RS256'])\n"
        "    except InvalidTokenError:\n"
        "        raise Unauthorized()\n"
        "    return User(claims)\n"
    )
    HYP = "token verification fails open: the broad except swallows " \
          "jwt.decode signature errors and the request proceeds"

    def _ctx(self, tmp_path):
        # The learned-vocab artifact the real pipeline would have
        # produced for jwt.decode (spec role=sanitiser, corroborated).
        out = _out_dir_with_spec(tmp_path, "decode", tier="xref_backed")
        return RoleContext(out_dir=out)

    def test_vulnerable_form_confirms_with_receipts(self, tmp_path):
        _write(tmp_path, "src/auth.py", self.JWT_VULN)
        res = run_fail_open_check(
            tmp_path, "src/auth.py", "current_user", self.HYP,
            role_context=self._ctx(tmp_path),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_HANDLER_OUTCOME
        assert res.role is not None and res.role["grade"] == "registry"
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "pass"
        assert res.handler["broad"] is True
        assert res.fallible is not None
        assert res.fallible["callee"] == "jwt.decode"
        assert "jwt.decode" in res.reason

    def test_fail_closed_twin_refutes(self, tmp_path):
        _write(tmp_path, "src/auth.py", self.JWT_SAFE)
        res = run_fail_open_check(
            tmp_path, "src/auth.py", "current_user", self.HYP,
            role_context=self._ctx(tmp_path),
        )
        assert res.outcome == "refuted"
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "fail_closed"

    def test_permission_check_returns_true_on_error(self, tmp_path):
        src = (
            "def user_can(user, obj):\n"
            "    try:\n"
            "        return acl.check(user, obj)\n"
            "    except LookupError:\n"
            "        return True\n"
        )
        _write(tmp_path, "src/perm.py", src)
        out = _out_dir_with_spec(tmp_path, "check", tier="xref_backed")
        res = run_fail_open_check(
            tmp_path, "src/perm.py", "user_can",
            "permission check fails open: returns True when the ACL "
            "lookup errors",
            role_context=RoleContext(out_dir=out),
        )
        # acl.check is not broad-caught and raises nothing same-file →
        # the spec-bound role holds but fallibility must gate.
        assert res.outcome == "inconclusive"
        assert REASON_FALLIBILITY_UNRESOLVED in res.reason

    def test_permission_check_confirms_with_raise_evidence(
        self, tmp_path,
    ):
        src = (
            "def lookup_acl(user, obj):\n"
            "    if user is None:\n"
            "        raise LookupError('no user')\n"
            "    return ACL[user]\n"
            "\n"
            "def user_can(user, obj):\n"
            "    try:\n"
            "        return lookup_acl(user, obj)\n"
            "    except LookupError:\n"
            "        return True\n"
        )
        _write(tmp_path, "src/perm.py", src)
        out = _out_dir_with_spec(
            tmp_path, "lookup_acl", tier="xref_backed",
        )
        res = run_fail_open_check(
            tmp_path, "src/perm.py", "user_can",
            "permission check fails open: returns True on error",
            role_context=RoleContext(out_dir=out),
        )
        assert res.outcome == "confirmed"
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "return_permissive"
        assert res.handler["permissive_value"] == "True"
        assert res.fallible is not None
        assert res.fallible["evidence"] == "raises"
        assert "LookupError" in res.fallible["types"]

    def test_naming_only_role_gets_detection_variant(self, tmp_path):
        src = (
            "def gate(req):\n"
            "    try:\n"
            "        verify_token(req)\n"
            "    except Exception:\n"
            "        pass\n"
            "    return handle(req)\n"
        )
        _write(tmp_path, "src/gate.py", src)
        res = run_fail_open_check(
            tmp_path, "src/gate.py", "gate",
            "token verification failure swallowed; request proceeds",
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_HANDLER_OUTCOME + "-naming"
        assert is_detection_rule_id(res.rule_id)
        assert res.role is not None and res.role["grade"] == "detection"


class TestVerdictsC:
    SETUID_VULN = (
        "#include <unistd.h>\n"
        "int handler_main(uid_t unpriv_uid) {\n"
        "    setuid(unpriv_uid);\n"
        "    return execve(handler, argv, envp);\n"
        "}\n"
    )
    SETUID_SAFE = (
        "#include <unistd.h>\n"
        "int handler_main(uid_t unpriv_uid) {\n"
        "    if (setuid(unpriv_uid) != 0)\n"
        "        return -1;\n"
        "    return execve(handler, argv, envp);\n"
        "}\n"
    )
    HYP_SETUID = "the return value of setuid is ignored; on failure " \
                 "the process keeps root"

    def test_ignored_privilege_drop_confirms(self, tmp_path):
        _write(tmp_path, "src/priv.c", self.SETUID_VULN)
        res = run_fail_open_check(
            tmp_path, "src/priv.c", "handler_main", self.HYP_SETUID,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_IGNORED_RETURN
        assert res.role is not None
        assert res.role["source"] == "universal_registry"
        assert res.fallible is not None
        assert res.sites and res.sites[0].verdict == "unguarded"

    def test_span_failure_refuses_whole_file_scan_c(self, tmp_path):
        """Pre-fix the C leg fell back to scanning the whole file when
        the function span could not be resolved — an unguarded setuid
        in handler_main would "confirm" a hypothesis naming a function
        that is not even in the file."""
        _write(tmp_path, "src/priv.c", self.SETUID_VULN)
        res = run_fail_open_check(
            tmp_path, "src/priv.c", "ghost_function", self.HYP_SETUID,
        )
        assert res.outcome == "inconclusive"
        assert "span-unresolved" in res.reason

    def test_checked_privilege_drop_refutes(self, tmp_path):
        _write(tmp_path, "src/priv.c", self.SETUID_SAFE)
        res = run_fail_open_check(
            tmp_path, "src/priv.c", "handler_main", self.HYP_SETUID,
        )
        assert res.outcome == "refuted"
        assert res.sites and all(
            s.verdict == "guarded" for s in res.sites
        )

    EVP_VULN = (
        "int verify_sig(EVP_MD_CTX *ctx, unsigned char *sig, "
        "int siglen, EVP_PKEY *pkey) {\n"
        "    if (EVP_VerifyFinal(ctx, sig, siglen, pkey))\n"
        "        return ACCEPT;\n"
        "    return REJECT;\n"
        "}\n"
    )
    EVP_SAFE = (
        "int verify_sig(EVP_MD_CTX *ctx, unsigned char *sig, "
        "int siglen, EVP_PKEY *pkey) {\n"
        "    if (EVP_VerifyFinal(ctx, sig, siglen, pkey) == 1)\n"
        "        return ACCEPT;\n"
        "    return REJECT;\n"
        "}\n"
    )
    HYP_EVP = "EVP_VerifyFinal error (-1) accepted as a valid " \
              "signature: the truth test ignores the tri-state error " \
              "value"

    def _evp_ctx(self, tmp_path):
        # Seed exemplar alone is detection-grade; the domain model the
        # study loop would have produced makes it registry-grade.
        out = _out_dir_with_domain_model(
            tmp_path,
            "signature verification via EVP_VerifyFinal must succeed "
            "before the payload is dispatched",
        )
        return RoleContext(out_dir=out)

    def test_tristate_truth_test_confirms(self, tmp_path):
        _write(tmp_path, "src/verify.c", self.EVP_VULN)
        res = run_fail_open_check(
            tmp_path, "src/verify.c", "verify_sig", self.HYP_EVP,
            role_context=self._evp_ctx(tmp_path),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_TRISTATE
        assert res.role is not None and res.role["grade"] == "registry"
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "tristate_accepts_error"
        assert res.fallible is not None

    def test_tristate_eq_one_twin_refutes(self, tmp_path):
        _write(tmp_path, "src/verify.c", self.EVP_SAFE)
        res = run_fail_open_check(
            tmp_path, "src/verify.c", "verify_sig", self.HYP_EVP,
            role_context=self._evp_ctx(tmp_path),
        )
        assert res.outcome == "refuted"

    def test_tristate_seed_only_is_detection_variant(self, tmp_path):
        _write(tmp_path, "src/verify.c", self.EVP_VULN)
        res = run_fail_open_check(
            tmp_path, "src/verify.c", "verify_sig", self.HYP_EVP,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_TRISTATE + "-naming"

    def test_wur_fact_supplies_fallibility(self, tmp_path):
        src = (
            "int commit(struct tx *t) {\n"
            "    validate_tx(t);\n"
            "    return apply(t);\n"
            "}\n"
        )
        _write(tmp_path, "src/tx.c", src)
        out = _out_dir_with_spec(
            tmp_path, "validate_tx", tier="header_backed",
        )
        res = run_fail_open_check(
            tmp_path, "src/tx.c", "commit",
            "the return value of validate_tx is ignored and the "
            "transaction is applied anyway",
            role_context=RoleContext(
                out_dir=out, wur_functions=frozenset({"validate_tx"}),
            ),
        )
        assert res.outcome == "confirmed"
        assert res.fallible is not None
        assert res.fallible["evidence"] == "wur:validate_tx"

    def test_tu_declared_wur_supplies_fallibility(self, tmp_path):
        # The target's OWN header attribute is the fallibility witness
        # — no harvested facts passed in.
        src = (
            "__attribute__((warn_unused_result))\n"
            "int validate_tx(struct tx *t);\n"
            "\n"
            "int commit(struct tx *t) {\n"
            "    validate_tx(t);\n"
            "    return apply(t);\n"
            "}\n"
        )
        _write(tmp_path, "src/tx.c", src)
        out = _out_dir_with_spec(
            tmp_path, "validate_tx", tier="header_backed",
        )
        res = run_fail_open_check(
            tmp_path, "src/tx.c", "commit",
            "the return value of validate_tx is ignored and the "
            "transaction is applied anyway",
            role_context=RoleContext(out_dir=out),
        )
        assert res.outcome == "confirmed"
        assert res.fallible is not None
        assert res.fallible["evidence"].startswith("wur:validate_tx")
        assert "TU" in res.fallible["evidence"]




@requires_ts("java")
class TestJavaHandlerAnalyzer:
    def test_empty_catch_classified(self):
        src = (
            "class A {\n"
            "    void f(Request req) {\n"
            "        try { authz.check(req); }\n"
            "        catch (Exception e) { /* TODO */ }\n"
            "    }\n"
            "}\n"
        )
        handlers = java_handlers(src, "A.java")
        assert handlers is not None and len(handlers) == 1
        h = handlers[0]
        assert h.outcome_kind == "pass"
        assert h.broad is True
        assert h.enclosing_function == "f"
        assert "authz.check" in h.try_calls
        assert h.parser == "tree-sitter"

    def test_union_catch_types_resolved(self):
        src = (
            "class A {\n"
            "    void f() {\n"
            "        try { verify(); }\n"
            "        catch (SignatureException | CertificateException e) "
            "{}\n"
            "    }\n"
            "}\n"
        )
        h = java_handlers(src, "A.java")[0]
        assert h.caught == ["SignatureException", "CertificateException"]
        assert h.broad is False

    def test_rethrow_is_fail_closed(self):
        src = (
            "class A {\n"
            "    void f() {\n"
            "        try { check(); }\n"
            "        catch (AccessDeniedException e) "
            "{ throw new SecurityException(e); }\n"
            "    }\n"
            "}\n"
        )
        h = java_handlers(src, "A.java")[0]
        assert h.outcome_kind == "fail_closed"
        assert h.permissive_value == "re-throws"

    def test_return_true_is_permissive(self):
        src = (
            "class A {\n"
            "    boolean f() {\n"
            "        try { return acl.check(); }\n"
            "        catch (LookupException e) { return true; }\n"
            "    }\n"
            "}\n"
        )
        h = java_handlers(src, "A.java")[0]
        assert h.outcome_kind == "return_permissive"
        assert h.permissive_value == "true"

    def test_return_false_is_fail_closed(self):
        src = (
            "class A {\n"
            "    boolean f() {\n"
            "        try { return acl.check(); }\n"
            "        catch (LookupException e) { return false; }\n"
            "    }\n"
            "}\n"
        )
        h = java_handlers(src, "A.java")[0]
        assert h.outcome_kind == "fail_closed"

    def test_quiet_log_only_classified(self):
        src = (
            "class A {\n"
            "    void f() {\n"
            "        try { verifier.verify(chain); }\n"
            "        catch (CertificateException e) "
            "{ LOG.debug(\"failed\", e); }\n"
            "    }\n"
            "}\n"
        )
        h = java_handlers(src, "A.java")[0]
        assert h.outcome_kind == "quiet_log_only"

    def test_loud_log_is_undecided(self):
        src = (
            "class A {\n"
            "    void f() {\n"
            "        try { verifier.verify(chain); }\n"
            "        catch (CertificateException e) "
            "{ LOG.error(\"failed\", e); }\n"
            "    }\n"
            "}\n"
        )
        h = java_handlers(src, "A.java")[0]
        assert h.outcome_kind == "fallback_action"
        assert not h.is_permissive
        assert not h.is_fail_closed

    def test_abort_is_fail_closed(self):
        src = (
            "class A {\n"
            "    void f() {\n"
            "        try { check(); }\n"
            "        catch (Exception e) { System.exit(1); }\n"
            "    }\n"
            "}\n"
        )
        h = java_handlers(src, "A.java")[0]
        assert h.outcome_kind == "fail_closed"
        assert h.permissive_value == "aborts"

    def test_parser_absent_returns_none(self, monkeypatch):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        assert java_handlers("class A {}", "A.java") is None


@requires_ts("java")
class TestVerdictsJava:
    """Fixture pairs 5 (trust-manager) and 6 (filter catch-and-
    continue) from the design, plus the swallowed-checked-exception
    compilability witness."""

    FILTER_VULN = (
        "class AccessDeniedException extends Exception {}\n"
        "public class AuthzFilter implements Filter {\n"
        "    public void doFilter(ServletRequest req, "
        "ServletResponse res, FilterChain chain) {\n"
        "        try { authz.check(req); }\n"
        "        catch (AccessDeniedException e) { /* TODO */ }\n"
        "        chain.doFilter(req, res);\n"
        "    }\n"
        "}\n"
    )
    HYP_FILTER = (
        "authorization failure swallowed by the empty catch; the "
        "filter chain proceeds"
    )

    def test_filter_empty_catch_confirms_via_tier_b(self, tmp_path):
        _write(tmp_path, "src/AuthzFilter.java", self.FILTER_VULN)
        res = run_fail_open_check(
            tmp_path, "src/AuthzFilter.java", "doFilter",
            self.HYP_FILTER,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_HANDLER_OUTCOME
        assert res.role is not None
        assert res.role["source"] == "framework_registry"
        assert res.role["provenance"].startswith("tier_b:jakarta")
        assert res.role["grade"] == "registry"
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "pass"
        # The checked-exception compilability witness: the catch of a
        # same-file `extends Exception` type compiles only when the
        # try body can throw it.
        assert res.fallible is not None
        assert res.fallible["evidence"].startswith(
            "checked-exception-catch:AccessDeniedException",
        )

    def test_filter_rethrow_twin_refutes(self, tmp_path):
        safe = self.FILTER_VULN.replace(
            "{ /* TODO */ }", "{ throw new SecurityException(e); }",
        )
        _write(tmp_path, "src/AuthzFilter.java", safe)
        res = run_fail_open_check(
            tmp_path, "src/AuthzFilter.java", "doFilter",
            self.HYP_FILTER,
        )
        assert res.outcome == "refuted"
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "fail_closed"

    TRUST_VULN = (
        "public class ChainValidator {\n"
        "    public boolean validate(X509Certificate[] chain) {\n"
        "        try { checkValidity(chain); }\n"
        "        catch (CertificateException e) "
        "{ LOG.debug(\"cert check failed\", e); }\n"
        "        return true;\n"
        "    }\n"
        "    void checkValidity(X509Certificate[] c) "
        "throws CertificateException "
        "{ throw new CertificateException(); }\n"
        "}\n"
    )
    HYP_TRUST = (
        "certificate validation fails open: the CertificateException "
        "is swallowed with a debug log and the method returns true"
    )

    def test_trust_manager_quiet_log_confirms(self, tmp_path):
        _write(tmp_path, "src/ChainValidator.java", self.TRUST_VULN)
        out = _out_dir_with_spec(
            tmp_path, "checkValidity", tier="xref_backed",
        )
        res = run_fail_open_check(
            tmp_path, "src/ChainValidator.java", "validate",
            self.HYP_TRUST, role_context=RoleContext(out_dir=out),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_HANDLER_OUTCOME
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "quiet_log_only"
        # Swallowed checked exception: the callee DECLARES the very
        # type the handler catches.
        assert res.fallible is not None
        assert res.fallible["evidence"] == "declared-throws"
        assert "CertificateException" in res.fallible["types"]

    def test_trust_manager_naming_only_is_detection_variant(
        self, tmp_path,
    ):
        _write(tmp_path, "src/ChainValidator.java", self.TRUST_VULN)
        res = run_fail_open_check(
            tmp_path, "src/ChainValidator.java", "validate",
            self.HYP_TRUST,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_HANDLER_OUTCOME + "-naming"
        assert is_detection_rule_id(res.rule_id)

    def test_spring_preauthorize_binds_tier_b(self, tmp_path):
        src = (
            "public class OrderService {\n"
            "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
            "    public void cancel(Order order) {\n"
            "        try { doCancel(order); }\n"
            "        catch (Exception e) { }\n"
            "    }\n"
            "    void doCancel(Order o) throws CancelException "
            "{ throw new CancelException(); }\n"
            "}\n"
        )
        _write(tmp_path, "src/OrderService.java", src)
        res = run_fail_open_check(
            tmp_path, "src/OrderService.java", "cancel",
            "errors during the protected cancel operation are "
            "swallowed by the broad catch and processing continues",
        )
        assert res.outcome == "confirmed"
        assert res.role is not None
        assert res.role["provenance"].startswith("tier_b:spring")

    def test_unresolved_specific_catch_is_types_unresolved(
        self, tmp_path,
    ):
        src = (
            "public class AuthzFilter implements Filter {\n"
            "    public void doFilter(ServletRequest req, "
            "ServletResponse res, FilterChain chain) {\n"
            "        try { authz.check(req); }\n"
            "        catch (AccessDeniedException e) { /* TODO */ }\n"
            "        chain.doFilter(req, res);\n"
            "    }\n"
            "}\n"
        )
        _write(tmp_path, "src/AuthzFilter.java", src)
        res = run_fail_open_check(
            tmp_path, "src/AuthzFilter.java", "doFilter",
            self.HYP_FILTER,
        )
        assert res.outcome == "inconclusive"
        assert REASON_TYPES_UNRESOLVED in res.reason
        assert "AccessDeniedException" in res.reason

    def test_no_catch_in_function_is_unbindable(self, tmp_path):
        src = (
            "class A {\n"
            "    int f(int x) { return x + 1; }\n"
            "}\n"
        )
        _write(tmp_path, "src/A.java", src)
        res = run_fail_open_check(
            tmp_path, "src/A.java", "f",
            "auth check failure swallowed silently",
        )
        assert res.outcome == "inconclusive"
        assert REASON_HYPOTHESIS_UNBINDABLE in res.reason

    def test_parser_absent_is_language_unsupported(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        _write(tmp_path, "src/A.java", "class A {}")
        res = run_fail_open_check(
            tmp_path, "src/A.java", "f",
            "auth check failure swallowed silently",
        )
        assert res.outcome == "inconclusive"
        assert REASON_LANGUAGE_UNSUPPORTED in res.reason



@requires_ts("go")
class TestGoAnalyzers:
    DISCARD = (
        "package main\n"
        "\n"
        "func getSession(r *Request, n string) (*Session, error) "
        "{ return load(r, n) }\n"
        "\n"
        "func serveAdmin(w W, r *Request) {\n"
        "    sess, _ := getSession(r, \"admin-session\")\n"
        "    if sess.Values[\"admin\"] == true { doServe(w, r) }\n"
        "}\n"
    )

    def test_blank_discard_is_unguarded(self):
        sites = go_discard_sites(self.DISCARD, "m.go", "getSession")
        admin = [s for s in sites if s.shape == "blank-discard"]
        assert admin and admin[0].verdict == "unguarded"
        assert "blank identifier" in admin[0].evidence

    def test_err_checked_is_guarded(self):
        src = self.DISCARD.replace(
            "sess, _ := getSession(r, \"admin-session\")\n"
            "    if sess.Values",
            "sess, err := getSession(r, \"admin-session\")\n"
            "    if err != nil { return }\n"
            "    if sess.Values",
        )
        sites = go_discard_sites(src, "m.go", "getSession")
        outer = [s for s in sites if s.line > 4]
        assert outer and outer[0].verdict == "guarded"
        assert outer[0].shape == "tested"

    def test_err_never_read_is_unguarded(self):
        src = (
            "package main\n"
            "func f(r *Request) {\n"
            "    v, err := validate(r)\n"
            "    use(v)\n"
            "}\n"
        )
        sites = go_discard_sites(src, "m.go", "validate")
        assert sites[0].verdict == "unguarded"
        assert sites[0].shape == "err-never-checked"

    def test_err_overwritten_before_check_is_unguarded(self):
        src = (
            "package main\n"
            "func f(r *Request) {\n"
            "    a, err := validate(r)\n"
            "    b, err := parse(r)\n"
            "    if err != nil { return }\n"
            "    use(a, b)\n"
            "}\n"
        )
        sites = go_discard_sites(src, "m.go", "validate")
        assert sites[0].verdict == "unguarded"
        assert sites[0].shape == "err-overwritten-before-check"

    def test_bare_statement_is_unguarded(self):
        src = (
            "package main\n"
            "func f(r *Request) {\n"
            "    validateToken(r)\n"
            "}\n"
        )
        sites = go_discard_sites(src, "m.go", "validateToken")
        assert sites[0].verdict == "unguarded"
        assert sites[0].shape == "bare-statement"

    def test_propagated_is_guarded(self):
        src = (
            "package main\n"
            "func f(r *Request) error {\n"
            "    return validateToken(r)\n"
            "}\n"
        )
        sites = go_discard_sites(src, "m.go", "validateToken")
        assert sites[0].verdict == "guarded"
        assert sites[0].shape == "propagated"

    def test_returns_error_signature(self):
        assert go_function_returns_error(self.DISCARD, "getSession")
        assert not go_function_returns_error(self.DISCARD, "serveAdmin")

    RECOVER = (
        "package main\n"
        "func mw(next http.Handler) http.Handler {\n"
        "    defer func() { if r := recover(); r != nil "
        "{ log.Println(r) } }()\n"
        "    mustAuthorize(nil)\n"
        "    return next\n"
        "}\n"
    )

    def test_recover_and_log_is_permissive(self):
        handlers = go_recover_handlers(self.RECOVER, "m.go")
        assert handlers is not None and len(handlers) == 1
        h = handlers[0]
        assert h.outcome_kind == "recover_continue"
        assert h.is_permissive
        assert h.broad is True
        assert h.caught == ["<panic>"]
        assert "mustAuthorize" in h.try_calls
        assert h.enclosing_function == "mw"

    def test_repanic_is_fail_closed(self):
        src = self.RECOVER.replace(
            "{ log.Println(r) }", "{ log.Println(r); panic(r) }",
        )
        h = go_recover_handlers(src, "m.go")[0]
        assert h.outcome_kind == "fail_closed"
        assert h.permissive_value == "re-panics"

    def test_os_exit_is_fail_closed(self):
        src = self.RECOVER.replace(
            "{ log.Println(r) }", "{ os.Exit(1) }",
        )
        h = go_recover_handlers(src, "m.go")[0]
        assert h.outcome_kind == "fail_closed"
        assert h.permissive_value == "aborts"

    def test_parser_absent_returns_none(self, monkeypatch):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        assert go_recover_handlers(self.RECOVER, "m.go") is None
        assert go_discard_sites(self.DISCARD, "m.go", "getSession") \
            is None


@requires_ts("go")
class TestVerdictsGo:
    """Fixture pairs 7 (discarded session-store error) and 8
    (recover-to-continue in auth middleware) from the design."""

    MW_VULN = (
        "package main\n"
        "\n"
        "func getSession(r *http.Request, name string) "
        "(*Session, error) { return store.load(r, name) }\n"
        "\n"
        "func adminGate(next http.Handler) http.Handler {\n"
        "    return http.HandlerFunc(func(w http.ResponseWriter, "
        "r *http.Request) {\n"
        "        sess, _ := getSession(r, \"admin-session\")\n"
        "        if sess.Values[\"admin\"] == true "
        "{ next.ServeHTTP(w, r) }\n"
        "    })\n"
        "}\n"
    )
    HYP_MW = (
        "the error from getSession is discarded with the blank "
        "identifier; a failed session load still serves the admin page"
    )

    def test_discarded_store_error_confirms_via_tier_b(self, tmp_path):
        _write(tmp_path, "src/mw.go", self.MW_VULN)
        res = run_fail_open_check(
            tmp_path, "src/mw.go", "adminGate", self.HYP_MW,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_IGNORED_RETURN
        assert res.role is not None
        assert res.role["provenance"].startswith("tier_b:go-net/http")
        assert res.role["grade"] == "registry"
        assert res.fallible is not None
        assert res.fallible["evidence"] == \
            "returns-error (same-file signature)"
        assert res.sites
        assert res.sites[0].shape == "blank-discard"

    def test_checked_error_twin_refutes(self, tmp_path):
        safe = self.MW_VULN.replace(
            "sess, _ := getSession(r, \"admin-session\")\n"
            "        if sess.Values",
            "sess, err := getSession(r, \"admin-session\")\n"
            "        if err != nil { http.Error(w, \"no\", 401); "
            "return }\n"
            "        if sess.Values",
        )
        _write(tmp_path, "src/mw.go", safe)
        res = run_fail_open_check(
            tmp_path, "src/mw.go", "adminGate", self.HYP_MW,
        )
        assert res.outcome == "refuted"
        assert res.sites and all(
            s.verdict == "guarded" for s in res.sites
        )

    def test_out_of_tree_callee_uses_inventory_signature(
        self, tmp_path,
    ):
        src = (
            "package main\n"
            "func gate(w W, r *Request) {\n"
            "    sess, _ := fetchSession(r, \"s\")\n"
            "    serve(w, sess)\n"
            "}\n"
        )
        _write(tmp_path, "src/gate.go", src)
        inventory = {"files": [{
            "path": "pkg/store/store.go",
            "functions": [{
                "name": "fetchSession",
                "signature": "func fetchSession(r *Request, "
                             "n string) (*Session, error)",
            }],
        }]}
        res = run_fail_open_check(
            tmp_path, "src/gate.go", "gate",
            "the error from fetchSession is discarded and the "
            "request proceeds",
            inventory=inventory,
        )
        assert res.outcome == "confirmed"
        assert res.fallible is not None
        assert res.fallible["evidence"] == \
            "returns-error (inventory signature)"
        # naming-only role (session stem) -> detection variant.
        assert res.rule_id == RULE_IGNORED_RETURN + "-naming"

    def test_unresolvable_callee_gates_fallibility(self, tmp_path):
        src = (
            "package main\n"
            "func gate(w W, r *Request) {\n"
            "    sess, _ := fetchSession(r, \"s\")\n"
            "    serve(w, sess)\n"
            "}\n"
        )
        _write(tmp_path, "src/gate.go", src)
        res = run_fail_open_check(
            tmp_path, "src/gate.go", "gate",
            "the error from fetchSession is discarded and the "
            "request proceeds",
        )
        assert res.outcome == "inconclusive"
        assert REASON_FALLIBILITY_UNRESOLVED in res.reason

    RECOVER_VULN = (
        "package main\n"
        "\n"
        "func requireAuth(next http.Handler) http.Handler {\n"
        "    return http.HandlerFunc(func(w http.ResponseWriter, "
        "r *http.Request) {\n"
        "        defer func() { if rec := recover(); rec != nil "
        "{ log.Println(rec) } }()\n"
        "        mustAuthorize(r)\n"
        "        next.ServeHTTP(w, r)\n"
        "    })\n"
        "}\n"
    )
    HYP_RECOVER = (
        "a panic from mustAuthorize is recovered and the request "
        "continues to the protected handler"
    )

    def test_recover_to_continue_confirms(self, tmp_path):
        _write(tmp_path, "src/rec.go", self.RECOVER_VULN)
        res = run_fail_open_check(
            tmp_path, "src/rec.go", "requireAuth", self.HYP_RECOVER,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id.startswith(RULE_RECOVER_CONTINUE)
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "recover_continue"
        assert res.fallible is not None
        assert res.fallible["evidence"] == \
            "catchable: any-call-under-recover"

    def test_repanic_twin_refutes(self, tmp_path):
        safe = self.RECOVER_VULN.replace(
            "{ log.Println(rec) }", "{ log.Println(rec); panic(rec) }",
        )
        _write(tmp_path, "src/rec.go", safe)
        res = run_fail_open_check(
            tmp_path, "src/rec.go", "requireAuth", self.HYP_RECOVER,
        )
        assert res.outcome == "refuted"
        assert res.handler is not None
        assert res.handler["permissive_value"] == "re-panics"

    def test_no_recover_handler_is_unbindable(self, tmp_path):
        src = (
            "package main\n"
            "func f(r *Request) { serve(r) }\n"
        )
        _write(tmp_path, "src/f.go", src)
        res = run_fail_open_check(
            tmp_path, "src/f.go", "f",
            "a panic is recovered and processing continues",
        )
        assert res.outcome == "inconclusive"
        assert REASON_HYPOTHESIS_UNBINDABLE in res.reason

    def test_parser_absent_is_language_unsupported(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        _write(tmp_path, "src/mw.go", self.MW_VULN)
        res = run_fail_open_check(
            tmp_path, "src/mw.go", "adminGate", self.HYP_MW,
        )
        assert res.outcome == "inconclusive"
        assert REASON_LANGUAGE_UNSUPPORTED in res.reason

    def test_span_failure_refuses_whole_file_scan_go(self, tmp_path):
        """A function whose span cannot be resolved must yield
        span-unresolved — pre-fix the segment fell back to the WHOLE
        file, so a discarded error in a different function could
        confirm a hypothesis about this one."""
        _write(tmp_path, "src/mw.go", self.MW_VULN)
        res = run_fail_open_check(
            tmp_path, "src/mw.go", "ghostFunction", self.HYP_MW,
        )
        assert res.outcome == "inconclusive"
        assert "span-unresolved" in res.reason

    def test_recover_hypothesis_routes_cwe_703(self):
        from core.audit.cwe_dispatch import infer_cwe_from_hypothesis
        assert infer_cwe_from_hypothesis(
            "panic recovered and processing continues",
        ) == "CWE-703"
        assert infer_cwe_from_hypothesis(self.HYP_RECOVER) == "CWE-703"



class TestCalibrationCases:
    """The two operator calibration shapes: both must confirm."""

    ENV_FALLBACK = (
        "import os\n"
        "def discover_executables(target):\n"
        "    try:\n"
        "        from core.config import RaptorConfig\n"
        "        env = RaptorConfig.get_safe_env()\n"
        "    except Exception:\n"
        "        env = os.environ.copy()\n"
        "    return run_find(target, env)\n"
    )

    def test_validation_helper_env_fallback_confirms(self, tmp_path):
        """The pre-fix validation-helper shape: env sanitisation falls
        back to the ambient environment exactly when it errors."""
        _write(tmp_path, "libexec/helper.py", self.ENV_FALLBACK)
        base = _annotations_dir(
            tmp_path, "libexec/helper.py", "discover_executables",
            "trust_boundary",
        )
        res = run_fail_open_check(
            tmp_path, "libexec/helper.py", "discover_executables",
            "environment sanitisation fails open: when get_safe_env "
            "errors the broad except falls back to the full ambient "
            "environment",
            role_context=RoleContext(annotations_dir=base),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_HANDLER_OUTCOME
        assert res.role is not None
        assert res.role["source"] == "annotation"
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "assign_default"
        assert "os.environ.copy()" in res.handler["permissive_value"]
        assert res.fallible is not None

    AFL_PROBE = (
        "import subprocess\n"
        "def check_afl_shmem(afl_fuzz):\n"
        "    try:\n"
        "        result = subprocess.run([afl_fuzz, '-V', '1'])\n"
        "        return parse_output(result)\n"
        "    except Exception:\n"
        "        return True\n"
    )

    def test_afl_probe_permissive_default_confirms(self, tmp_path):
        """The AFL capability-probe shape the triage pack paired with
        the env fallback: 'if we cannot tell, assume OK'."""
        _write(tmp_path, "pkg/capability.py", self.AFL_PROBE)
        out = _out_dir_with_spec(
            tmp_path, "check_afl_shmem", tier="heuristic",
        )
        res = run_fail_open_check(
            tmp_path, "pkg/capability.py", "check_afl_shmem",
            "the capability probe fails open: any error is swallowed "
            "and the probe reports the capability as OK",
            role_context=RoleContext(out_dir=out),
        )
        assert res.outcome == "confirmed"
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "return_permissive"
        assert res.handler["permissive_value"] == "True"
        # heuristic-tier spec only → detection variant.
        assert is_detection_rule_id(res.rule_id)


# ── undecided gating + inconclusive reasons ─────────────────────────


class TestUndecidedGating:
    def test_fallback_action_gates_to_handler_undecided(self, tmp_path):
        src = (
            "def gate(req):\n"
            "    try:\n"
            "        verify_token(req)\n"
            "    except Exception:\n"
            "        rebuild_from_snapshot(req)\n"
            "    return handle(req)\n"
        )
        _write(tmp_path, "src/gate.py", src)
        res = run_fail_open_check(
            tmp_path, "src/gate.py", "gate",
            "verification errors swallowed and the request proceeds",
        )
        assert res.outcome == "inconclusive"
        assert REASON_HANDLER_UNDECIDED in res.reason

    def test_role_unbound_reason(self, tmp_path):
        src = (
            "def load(path):\n"
            "    try:\n"
            "        data = parse_file(path)\n"
            "    except Exception:\n"
            "        data = {}\n"
            "    return data\n"
        )
        _write(tmp_path, "src/load.py", src)
        res = run_fail_open_check(
            tmp_path, "src/load.py", "load",
            "parse errors swallowed and an empty default proceeds",
        )
        assert res.outcome == "inconclusive"
        assert REASON_ROLE_UNBOUND in res.reason

    def test_language_unsupported_reason(self, tmp_path):
        _write(tmp_path, "src/main.rb", "def main; end\n")
        res = run_fail_open_check(
            tmp_path, "src/main.rb", "main",
            "the session store error is discarded",
        )
        assert res.outcome == "inconclusive"
        assert REASON_LANGUAGE_UNSUPPORTED in res.reason
        assert "ruby" in res.reason

    def test_hypothesis_unbindable_reason(self, tmp_path):
        src = "def clean(x):\n    return x + 1\n"
        _write(tmp_path, "src/clean.py", src)
        res = run_fail_open_check(
            tmp_path, "src/clean.py", "clean",
            "auth check failure swallowed silently",
        )
        assert res.outcome == "inconclusive"
        assert REASON_HYPOTHESIS_UNBINDABLE in res.reason

    def test_c_undecided_comparison_gates(self, tmp_path):
        # Error-only test (< 0): a second failure check may follow —
        # never confirmed, never refuted.
        src = (
            "int verify_sig(EVP_MD_CTX *c, unsigned char *s, int n, "
            "EVP_PKEY *k) {\n"
            "    if (EVP_VerifyFinal(c, s, n, k) < 0)\n"
            "        return ERROR;\n"
            "    return ACCEPT;\n"
            "}\n"
        )
        _write(tmp_path, "src/verify.c", src)
        res = run_fail_open_check(
            tmp_path, "src/verify.c", "verify_sig",
            "EVP_VerifyFinal tri-state error accepted as success",
        )
        assert res.outcome == "inconclusive"
        assert REASON_HANDLER_UNDECIDED in res.reason

    def test_unreadable_file_is_unbindable(self, tmp_path):
        res = run_fail_open_check(
            tmp_path, "src/missing.py", "f",
            "auth error swallowed",
        )
        assert res.outcome == "inconclusive"
        assert REASON_HYPOTHESIS_UNBINDABLE in res.reason


# ── receipts ────────────────────────────────────────────────────────


class TestReceiptShape:
    def test_to_dict_carries_all_receipt_sections(self, tmp_path):
        _write(tmp_path, "src/priv.c", TestVerdictsC.SETUID_VULN)
        res = run_fail_open_check(
            tmp_path, "src/priv.c", "handler_main",
            TestVerdictsC.HYP_SETUID,
        )
        d = res.to_dict()
        assert d["outcome"] == "confirmed"
        assert d["rule_id"] == RULE_IGNORED_RETURN
        assert d["language"] == "c"
        assert d["role"]["source"] == "universal_registry"
        assert d["role"]["grade"] == "registry"
        assert d["fallible"]["callee"] == "setuid"
        assert d["sites"][0]["verdict"] == "unguarded"
        # Optional legs not run → keys absent, not null.
        assert "reachability" not in d
        assert "corroboration" not in d

    def test_corroboration_accepts_stamps_and_peer_evidence_dicts(self):
        from core.audit.fail_open_verify import FailOpenResult

        class _PeerEvidenceStub:
            def to_dict(self):
                return {"dimension": "return-check", "n": 10,
                        "conforming": 9, "ratio": 0.9}

        res = FailOpenResult(
            outcome="confirmed", reason="r",
            corroboration=["compiler:-Wunused-result",
                           _PeerEvidenceStub()],
        )
        d = res.to_dict()
        assert d["corroboration"][0] == "compiler:-Wunused-result"
        assert d["corroboration"][1]["dimension"] == "return-check"

    def test_reachability_escalator_entry_point(self, tmp_path):
        _write(tmp_path, "src/priv.c", TestVerdictsC.SETUID_VULN)
        ctx = RoleContext(context_map={
            "entry_points": [
                {"file": "src/priv.c", "function": "handler_main"},
            ],
        })
        res = run_fail_open_check(
            tmp_path, "src/priv.c", "handler_main",
            TestVerdictsC.HYP_SETUID, role_context=ctx,
        )
        assert res.outcome == "confirmed"
        assert res.reachability is not None
        assert res.reachability["status"] == "entry_reachable"

    def test_reachability_absent_when_no_context_map(self, tmp_path):
        _write(tmp_path, "src/priv.c", TestVerdictsC.SETUID_VULN)
        res = run_fail_open_check(
            tmp_path, "src/priv.c", "handler_main",
            TestVerdictsC.HYP_SETUID,
        )
        assert res.outcome == "confirmed"
        assert res.reachability is None


class TestJoernFlowEscalator:
    """Leg 3, flow form — outcome-gated, hermetic (the flow check is
    monkeypatched; no server, no subprocess)."""

    def _stub(self, monkeypatch, outcome, calls):
        from core.audit.sweep import SweepResult

        def _fake(**kw):
            calls.append(kw)
            return SweepResult(
                tool="joern", file_path=kw["file_path"],
                function_name=kw["function_name"], outcome=outcome,
                matches=[{"steps": []}] if outcome == "confirmed"
                else [],
                rule_id="joern:flow",
                details={"reason": "no dataflow"}
                if outcome == "refuted" else None,
            )

        import core.audit.joern_verify as jv
        monkeypatch.setattr(jv, "run_flow_reachability_check", _fake)

    JWT_HYP = (
        "token verification fails open: the broad except swallows "
        "jwt.decode signature errors for the attacker-controlled "
        "token parameter and the request proceeds"
    )

    def _confirm(self, tmp_path, **kw):
        _write(tmp_path, "src/auth.py", TestVerdictsPython.JWT_VULN)
        out = _out_dir_with_spec(tmp_path, "decode", tier="xref_backed")
        return run_fail_open_check(
            tmp_path, "src/auth.py", "current_user", self.JWT_HYP,
            role_context=RoleContext(out_dir=out), **kw,
        )

    def test_confirmed_flow_stamps_tainted(self, tmp_path, monkeypatch):
        calls = []
        self._stub(monkeypatch, "confirmed", calls)
        res = self._confirm(tmp_path, joern_server=object())
        assert res.outcome == "confirmed"
        assert calls and calls[0]["source_id"] == "token"
        assert calls[0]["sink_call"] == "decode"
        assert res.reachability is not None
        assert res.reachability["status"] == "tainted"
        assert res.reachability["stamp"] == "joern:flow"
        assert res.reachability["source_id"] == "token"
        assert "joern:flow" in res.corroboration
        d = res.to_dict()
        assert d["reachability"]["status"] == "tainted"
        assert "joern:flow" in d["corroboration"]

    def test_refuted_flow_never_blocks_the_verdict(
        self, tmp_path, monkeypatch,
    ):
        calls = []
        self._stub(monkeypatch, "refuted", calls)
        res = self._confirm(tmp_path, joern_server=object())
        assert res.outcome == "confirmed"
        assert calls
        assert "joern:flow" not in res.corroboration
        assert res.reachability is not None
        assert res.reachability["status"] == "unknown"
        assert "joern flow refuted" in res.reachability["detail"]

    def test_zero_budget_skips_the_leg(self, tmp_path, monkeypatch):
        calls = []
        self._stub(monkeypatch, "confirmed", calls)
        res = self._confirm(
            tmp_path, joern_server=object(), budget_s=0,
        )
        assert res.outcome == "confirmed"
        assert calls == []

    def test_no_server_skips_the_leg(self, tmp_path, monkeypatch):
        calls = []
        self._stub(monkeypatch, "confirmed", calls)
        res = self._confirm(tmp_path)
        assert res.outcome == "confirmed"
        assert calls == []
        assert res.reachability is None

    def test_no_parameter_binding_skips_the_leg(
        self, tmp_path, monkeypatch,
    ):
        calls = []
        self._stub(monkeypatch, "confirmed", calls)
        _write(tmp_path, "src/auth.py", TestVerdictsPython.JWT_VULN)
        out = _out_dir_with_spec(tmp_path, "decode", tier="xref_backed")
        res = run_fail_open_check(
            tmp_path, "src/auth.py", "current_user",
            "verification errors are swallowed and the request "
            "proceeds silently",
            role_context=RoleContext(out_dir=out),
            joern_server=object(),
        )
        assert res.outcome == "confirmed"
        assert calls == []

    def test_refuted_verdict_never_escalates(
        self, tmp_path, monkeypatch,
    ):
        calls = []
        self._stub(monkeypatch, "confirmed", calls)
        _write(tmp_path, "src/auth.py", TestVerdictsPython.JWT_SAFE)
        out = _out_dir_with_spec(tmp_path, "decode", tier="xref_backed")
        res = run_fail_open_check(
            tmp_path, "src/auth.py", "current_user", self.JWT_HYP,
            role_context=RoleContext(out_dir=out),
            joern_server=object(),
        )
        assert res.outcome == "refuted"
        assert calls == []

    def test_escalator_error_never_blocks(self, tmp_path, monkeypatch):
        import core.audit.joern_verify as jv

        def _boom(**kw):
            raise RuntimeError("server went away")

        monkeypatch.setattr(jv, "run_flow_reachability_check", _boom)
        res = self._confirm(tmp_path, joern_server=object())
        assert res.outcome == "confirmed"

    def test_run_tool_chain_passes_server_and_persists_stamp(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import (
            TierCounters,
            _run_tool_chain,
        )
        calls = []
        self._stub(monkeypatch, "confirmed", calls)
        _write(tmp_path, "src/auth.py", TestVerdictsPython.JWT_VULN)
        out = tmp_path / "out"
        out.mkdir()
        (out / "iris-taint-specs.json").write_text(json.dumps([{
            "function": "decode", "file": "", "role": "sanitiser",
            "evidence_tier": "xref_backed",
        }]))
        confirmed = _run_tool_chain(
            [{"type": "fail_open", "config": {}}],
            config=_Cfg(tmp_path, out_dir=out),
            file_path="src/auth.py",
            function_name="current_user",
            source="",
            hypothesis=self.JWT_HYP,
            tier_counters={"fail_open": TierCounters()},
            joern_server=object(),
        )
        assert RULE_HANDLER_OUTCOME in confirmed
        assert calls, "escalator did not run through the tool chain"
        record = json.loads(
            (out / ".audit-log.jsonl").read_text().splitlines()[-1],
        )
        assert record["reachability"]["status"] == "tainted"
        assert "joern:flow" in record["corroboration"]



# ── dispatch wiring ─────────────────────────────────────────────────


class _Cfg:
    """Minimal OrchestratorConfig stand-in for _run_tool_chain."""

    def __init__(self, target, out_dir=None):
        self.target_path = target
        self.out_dir = out_dir
        self.codeql_db_path = None
        self.project_sinks = None
        self.annotations_dir = None
        self.inventory = None


class TestDispatchWiring:
    def test_hypothesis_chain_adds_fail_open(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain
        chain = _hypothesis_to_tool_chain(
            "the broad except swallows the exception from "
            "verify_token and the request proceeds",
            "src/auth.py",
        )
        assert {"type": "fail_open", "config": {}} in chain

    def test_unrelated_hypothesis_does_not_dispatch(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain
        chain = _hypothesis_to_tool_chain(
            "unchecked memcpy overflow of the notification buffer",
            "src/a.c",
        )
        assert all(e["type"] != "fail_open" for e in chain)

    def test_cwe_fallback_chain_carries_fail_open(self):
        from core.audit.orchestrator import _cwe_fallback_chain
        for cwe in ("CWE-703", "CWE-636", "CWE-391", "CWE-390",
                    "CWE-252", "CWE-248"):
            types = [e["type"] for e in _cwe_fallback_chain(cwe)]
            assert "fail_open" in types, cwe

    def test_fail_open_family_no_longer_unmapped(self):
        # Regression: CWE-703/636/391/390 used to hit
        # _warn_unmapped_cwe (empty chain) and drain checker-synthesis
        # attempts.
        from core.audit.cwe_dispatch import lookup
        from core.audit.orchestrator import _cwe_fallback_chain
        for cwe in ("CWE-703", "CWE-636", "CWE-391", "CWE-390"):
            assert lookup(cwe) is not None, cwe
            assert _cwe_fallback_chain(cwe), cwe

    def test_hypothesis_cwe_inference_routes_fail_open_family(self):
        from core.audit.cwe_dispatch import infer_cwe_from_hypothesis
        assert infer_cwe_from_hypothesis(
            "the handler swallows the exception silently",
        ) == "CWE-703"
        assert infer_cwe_from_hypothesis(
            "empty catch around the certificate check",
        ) == "CWE-703"
        assert infer_cwe_from_hypothesis(
            "ignored error from the privilege drop",
        ) == "CWE-252"
        # Reversed phrasing (object before verb) must route too — the
        # channel dispatches by keyword either way, but the CWE seeds
        # the corroborating compiler-family chain step.
        assert infer_cwe_from_hypothesis(
            "the return value of setuid is ignored; on failure the "
            "process keeps root",
        ) == "CWE-252"

    def test_no_duplicate_with_cwe_and_keywords(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain
        chain = _hypothesis_to_tool_chain(
            "verification errors are swallowed and processing "
            "continues",
            "src/a.py",
            cwe="CWE-703",
        )
        assert [e["type"] for e in chain].count("fail_open") == 1

    def test_tier_counter_exists(self):
        from core.audit.orchestrator import _make_tier_counters
        assert "fail_open" in _make_tier_counters()

    def test_cheap_lane_membership(self):
        from core.audit.orchestrator import _REFUTED_CHEAP_CHANNELS
        assert "fail_open" in _REFUTED_CHEAP_CHANNELS

    def _run_chain(self, tmp_path, file_path, function, hypothesis,
                   out_dir=None):
        from core.audit.orchestrator import (
            TierCounters,
            _run_tool_chain,
        )
        counters = {"fail_open": TierCounters()}
        confirmed = _run_tool_chain(
            [{"type": "fail_open", "config": {}}],
            config=_Cfg(tmp_path, out_dir=out_dir),
            file_path=file_path,
            function_name=function,
            source="",
            hypothesis=hypothesis,
            tier_counters=counters,
        )
        return confirmed, counters

    def test_run_tool_chain_confirms_and_counts(self, tmp_path):
        _write(tmp_path, "src/priv.c", TestVerdictsC.SETUID_VULN)
        out = tmp_path / "out"
        out.mkdir()
        confirmed, counters = self._run_chain(
            tmp_path, "src/priv.c", "handler_main",
            TestVerdictsC.HYP_SETUID, out_dir=out,
        )
        assert confirmed == [RULE_IGNORED_RETURN]
        assert counters["fail_open"].confirmed == 1
        # Receipt persisted via append_audit_log.
        log = (out / ".audit-log.jsonl").read_text()
        record = json.loads(log.splitlines()[-1])
        assert record["action"] == "fail_open_check"
        assert record["outcome"] == "confirmed"
        assert record["rule_id"] == RULE_IGNORED_RETURN
        assert record["role"]["grade"] == "registry"
        assert record["sites"][0]["verdict"] == "unguarded"

    def test_run_tool_chain_refuted_counts(self, tmp_path):
        _write(tmp_path, "src/priv.c", TestVerdictsC.SETUID_SAFE)
        confirmed, counters = self._run_chain(
            tmp_path, "src/priv.c", "handler_main",
            TestVerdictsC.HYP_SETUID,
        )
        assert confirmed == []
        assert counters["fail_open"].refuted == 1

    def test_run_tool_chain_inconclusive_counts(self, tmp_path):
        _write(tmp_path, "src/main.rs", "fn main() {}\n")
        confirmed, counters = self._run_chain(
            tmp_path, "src/main.rs", "main",
            "session store error discarded",
        )
        assert confirmed == []
        assert counters["fail_open"].inconclusive == 1

    def test_prior_confirmations_ride_as_corroboration(self, tmp_path):
        import core.audit.compiler_sweep as cs
        from core.audit.orchestrator import (
            TierCounters,
            _run_tool_chain,
        )
        from core.audit.sweep import SweepResult

        _write(tmp_path, "src/priv.c", TestVerdictsC.SETUID_VULN)
        out = tmp_path / "out"
        out.mkdir()

        def _fake_compiler(**kw):
            return SweepResult(
                tool="compiler", file_path="src/priv.c",
                function_name="handler_main", outcome="confirmed",
                rule_id="compiler:-Wunused-result",
            )

        original = cs.run_compiler_analyzer_sweep
        cs.run_compiler_analyzer_sweep = _fake_compiler
        try:
            confirmed = _run_tool_chain(
                [
                    {"type": "compiler", "config": {"cwe": "CWE-252"}},
                    {"type": "fail_open", "config": {}},
                ],
                config=_Cfg(tmp_path, out_dir=out),
                file_path="src/priv.c",
                function_name="handler_main",
                source="",
                hypothesis=TestVerdictsC.HYP_SETUID,
                tier_counters={
                    "fail_open": TierCounters(),
                    "compiler": TierCounters(),
                },
            )
        finally:
            cs.run_compiler_analyzer_sweep = original
        assert "compiler:-Wunused-result" in confirmed
        assert RULE_IGNORED_RETURN in confirmed
        record = json.loads(
            (out / ".audit-log.jsonl").read_text().splitlines()[-1],
        )
        assert record["corroboration"] == ["compiler:-Wunused-result"]

    def test_rule_ids_are_tool_evidence(self):
        from core.audit.evidence_grade import is_tool_evidence
        assert is_tool_evidence(RULE_HANDLER_OUTCOME)
        assert is_tool_evidence(RULE_IGNORED_RETURN)
        assert is_tool_evidence(RULE_TRISTATE)
        # The -naming variant is detection-grade by this channel's own
        # is_detection_rule_id contract: it may ride in a composite but
        # is NOT full tool evidence alone.
        assert not is_tool_evidence(RULE_HANDLER_OUTCOME + "-naming")
        assert is_tool_evidence(
            RULE_HANDLER_OUTCOME + "-naming+coccinelle"
        )

    def test_detection_variant_is_detection_only(self):
        from core.audit.orchestrator import _is_detection_only
        assert _is_detection_only(RULE_HANDLER_OUTCOME + "-naming")
        assert not _is_detection_only(RULE_HANDLER_OUTCOME)
        assert not _is_detection_only(RULE_TRISTATE)

    def test_receipt_map_entries_render(self):
        from core.audit.evidence_grade import grade_review_result
        for rule_id, needle in (
            (RULE_HANDLER_OUTCOME, "permissive error handler"),
            (RULE_IGNORED_RETURN, "neither assigned nor compared"),
            (RULE_TRISTATE, "tri-state"),
            # Detection-grade -naming variants render only inside a
            # composite that carries a qualifying receipt.
            (RULE_HANDLER_OUTCOME + "-naming+coccinelle", "fail-open"),
        ):
            items = grade_review_result(
                {"hypothesis": "h"}, evidence_tool=rule_id,
            )
            tool_items = [
                i for i in items
                if i.source.value == "mechanical:tree_sitter"
            ]
            assert tool_items, rule_id
            assert needle in tool_items[0].description, rule_id

    def test_degradation_row_present(self):
        from core.audit.degradation import get_fallback
        fb = get_fallback("tree-sitter")
        assert fb is not None
        assert "fail_open" in fb.impact


if __name__ == "__main__":  # pragma: no cover
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
