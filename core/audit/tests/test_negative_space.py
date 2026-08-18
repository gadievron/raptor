"""Tests for core.audit.negative_space — convention discovery + absence checking."""

from core.audit.negative_space import (
    NegativeSpaceFinding,
    SecurityConvention,
    check_deployment_assumptions,
    check_lock_ordering,
    check_missing_app_features,
    check_multi_process,
    check_negative_space,
    check_protocol_ambiguity,
    check_resource_exhaustion,
    check_side_channels,
    check_signal_safety,
    check_ub_patterns,
    detect_framework,
    discover_conventions,
    format_negative_space_prose,
)


class TestDetectFramework:
    def test_no_source(self):
        assert detect_framework([{"name": "f"}]) == ""

    def test_django(self):
        gaps = [
            {"name": "v1", "source": "from django.views import View"},
            {"name": "v2", "source": "from django.http import HttpResponse"},
        ]
        assert detect_framework(gaps) == "django"

    def test_flask(self):
        gaps = [
            {"name": "v1", "source": "from flask import Flask"},
            {"name": "v2", "source": "from flask import request"},
        ]
        assert detect_framework(gaps) == "flask"

    def test_express(self):
        gaps = [
            {"name": "v1", "source": "const express = require('express')"},
            {"name": "v2", "source": "const app = require('express')()"},
        ]
        assert detect_framework(gaps) == "express"

    def test_spring(self):
        gaps = [
            {"name": "v1", "source": "import org.springframework.web.bind.annotation.RestController;"},
            {"name": "v2", "source": "@SpringBootApplication"},
        ]
        assert detect_framework(gaps) == "spring"

    def test_go(self):
        gaps = [
            {"name": "v1", "source": 'import "net/http"'},
            {"name": "v2", "source": "http.Handle(\"/api\", handler)"},
        ]
        assert detect_framework(gaps) == "go"

    def test_no_framework(self):
        gaps = [
            {"name": "f", "source": "int main() { return 0; }"},
        ]
        assert detect_framework(gaps) == ""

    def test_single_signal_not_enough(self):
        gaps = [
            {"name": "f", "source": "from flask import request"},
        ]
        assert detect_framework(gaps) == ""


class TestDiscoverConventions:
    def _auth_gaps(self, n_with_auth, n_without):
        gaps = []
        for i in range(n_with_auth):
            gaps.append({
                "file": f"views/{i}.py",
                "name": f"handle_view_{i}",
                "source": "@login_required\ndef handle_view():\n    pass",
                "strategies": ["auth"],
            })
        for i in range(n_without):
            gaps.append({
                "file": f"views/no_{i}.py",
                "name": f"handle_other_{i}",
                "source": "def handle_other():\n    pass",
                "strategies": ["auth"],
            })
        return gaps

    def test_finds_auth_convention(self):
        gaps = self._auth_gaps(5, 2)
        convs = discover_conventions(gaps, framework="django")
        auth_convs = [c for c in convs if c.concern == "auth"]
        assert len(auth_convs) >= 1
        assert auth_convs[0].occurrences >= 5

    def test_minimum_occurrences(self):
        gaps = self._auth_gaps(2, 5)
        convs = discover_conventions(gaps, framework="django")
        auth_convs = [c for c in convs if c.concern == "auth"]
        assert len(auth_convs) == 0

    def test_empty_gaps(self):
        assert discover_conventions([]) == []

    def test_no_source(self):
        gaps = [{"file": "a.py", "name": "f"}]
        assert discover_conventions(gaps) == []

    def test_generic_patterns_without_framework(self):
        gaps = []
        for i in range(5):
            gaps.append({
                "file": f"auth/{i}.py",
                "name": f"check_{i}",
                "source": "def handler():\n    check_auth(user)\n    do_stuff()",
                "strategies": ["auth"],
            })
        convs = discover_conventions(gaps, framework="")
        assert len(convs) >= 1

    def test_error_handling_go(self):
        gaps = []
        for i in range(4):
            gaps.append({
                "file": f"pkg/{i}.go",
                "name": f"func_{i}",
                "source": "if err != nil {\n    return err\n}",
                "strategies": ["general"],
            })
        convs = discover_conventions(gaps, framework="go")
        err_convs = [c for c in convs if c.concern == "error_handling"]
        assert len(err_convs) >= 1

    def test_confidence_reflects_adoption(self):
        gaps = self._auth_gaps(8, 2)
        convs = discover_conventions(gaps, framework="django")
        auth_convs = [c for c in convs if c.concern == "auth"]
        assert len(auth_convs) >= 1
        assert auth_convs[0].confidence >= 0.7

    def test_convention_locations_populated(self):
        gaps = self._auth_gaps(4, 0)
        convs = discover_conventions(gaps, framework="django")
        auth_convs = [c for c in convs if c.concern == "auth"]
        assert len(auth_convs) >= 1
        assert len(auth_convs[0].locations) == 4


class TestCheckNegativeSpace:
    def _make_convention(self, concern="auth", pattern="check_auth", occurrences=10,
                         confidence=0.9, locations=None):
        return SecurityConvention(
            concern=concern,
            pattern=pattern,
            occurrences=occurrences,
            locations=locations or [],
            framework="",
            confidence=confidence,
        )

    def test_missing_auth_in_handler(self):
        conv = self._make_convention()
        gap = {
            "file": "views/api.py",
            "name": "handle_create",
            "source": "def handle_create(request):\n    db.save(request.data)",
            "sloc": 10,
            "is_entry_point": True,
        }
        findings = check_negative_space(gap, [conv], "auth")
        assert len(findings) == 1
        assert findings[0].check_type == "missing_auth"
        assert findings[0].cwe == "CWE-306"

    def test_present_check_no_finding(self):
        conv = self._make_convention()
        gap = {
            "file": "views/api.py",
            "name": "handle_create",
            "source": "def handle_create(request):\n    check_auth(request)\n    db.save()",
            "sloc": 10,
            "is_entry_point": True,
        }
        findings = check_negative_space(gap, [conv], "auth")
        assert len(findings) == 0

    def test_already_in_convention_locations(self):
        conv = self._make_convention(locations=["views/api.py:handle_create"])
        gap = {
            "file": "views/api.py",
            "name": "handle_create",
            "source": "def handle_create(request):\n    pass",
            "sloc": 10,
            "is_entry_point": True,
        }
        findings = check_negative_space(gap, [conv], "auth")
        assert len(findings) == 0

    def test_non_handler_skipped_for_auth(self):
        conv = self._make_convention()
        gap = {
            "file": "utils/helpers.py",
            "name": "format_date",
            "source": "def format_date(d):\n    return d.isoformat()",
            "sloc": 3,
        }
        findings = check_negative_space(gap, [conv], "auth")
        assert len(findings) == 0

    def test_small_function_skipped(self):
        conv = self._make_convention(concern="validation", pattern="validate_")
        gap = {
            "file": "util.py",
            "name": "get_name",
            "source": "def get_name(): return name",
            "sloc": 1,
        }
        findings = check_negative_space(gap, [conv], "input_handling")
        assert len(findings) == 0

    def test_test_function_skipped(self):
        conv = self._make_convention()
        gap = {
            "file": "tests/test_auth.py",
            "name": "test_login",
            "source": "def test_login():\n    pass",
            "sloc": 10,
            "is_entry_point": True,
        }
        findings = check_negative_space(gap, [conv], "auth")
        assert len(findings) == 0

    def test_wrong_strategy_ignored(self):
        conv = self._make_convention(concern="auth")
        gap = {
            "file": "views/api.py",
            "name": "handle_create",
            "source": "def handle_create(request):\n    pass",
            "sloc": 10,
            "is_entry_point": True,
        }
        findings = check_negative_space(gap, [conv], "memory")
        assert len(findings) == 0

    def test_high_confidence_finding(self):
        conv = self._make_convention(confidence=0.9)
        gap = {
            "file": "views/api.py",
            "name": "handle_update",
            "source": "def handle_update(request):\n    db.update(request.data)",
            "sloc": 10,
            "is_entry_point": True,
        }
        findings = check_negative_space(gap, [conv], "auth")
        assert findings[0].confidence == "high"

    def test_medium_confidence_finding(self):
        conv = self._make_convention(confidence=0.5)
        gap = {
            "file": "views/api.py",
            "name": "handle_update",
            "source": "def handle_update(request):\n    db.update(request.data)",
            "sloc": 10,
            "is_entry_point": True,
        }
        findings = check_negative_space(gap, [conv], "auth")
        assert findings[0].confidence == "medium"

    def test_bounds_check_missing(self):
        conv = self._make_convention(
            concern="bounds", pattern=r"check_bounds", confidence=0.85,
        )
        gap = {
            "file": "parser.c",
            "name": "handle_packet",
            "source": "void handle_packet(char *buf, int len) {\n    memcpy(dst, buf, len);\n}",
            "sloc": 15,
        }
        findings = check_negative_space(gap, [conv], "input_handling")
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-120"

    def test_null_check_present(self):
        conv = self._make_convention(
            concern="null_check",
            pattern=r"if\s*\(\s*!\s*\w+\s*\)",
            confidence=0.9,
        )
        gap = {
            "file": "alloc.c",
            "name": "handle_alloc",
            "source": "void *p = malloc(n);\n    if (!p) return NULL;",
            "sloc": 10,
        }
        findings = check_negative_space(gap, [conv], "memory")
        assert len(findings) == 0


class TestNegativeSpaceFindingDict:
    def test_to_dict(self):
        f = NegativeSpaceFinding(
            check_type="missing_auth",
            expected="check_auth (10 functions)",
            evidence="no auth check",
            cwe="CWE-306",
            confidence="high",
            convention="check_auth",
            strategy="auth",
        )
        d = f.to_dict()
        assert d["check_type"] == "missing_auth"
        assert d["cwe"] == "CWE-306"
        assert d["confidence"] == "high"


class TestFormatNegativeSpaceProse:
    def test_empty(self):
        assert format_negative_space_prose([]) == ""

    def test_high_confidence_tag(self):
        f = NegativeSpaceFinding(
            check_type="missing_auth",
            expected="check_auth (10 functions, ~90% adoption)",
            evidence="no auth check found",
            cwe="CWE-306",
            confidence="high",
            convention="check_auth",
            strategy="auth",
        )
        result = format_negative_space_prose([f])
        assert "[high]" in result
        assert "CWE-306" in result
        assert "missing_auth" in result
        assert "Convention deviations" in result

    def test_medium_confidence_no_tag(self):
        f = NegativeSpaceFinding(
            check_type="missing_validation",
            expected="validate_ (5 functions, ~50% adoption)",
            evidence="no validation found",
            cwe="CWE-20",
            confidence="medium",
            convention="validate_",
            strategy="input_handling",
        )
        result = format_negative_space_prose([f])
        assert "[high]" not in result
        assert "CWE-20" in result

    def test_multiple_findings(self):
        findings = [
            NegativeSpaceFinding(
                check_type="missing_auth", expected="a", evidence="b",
                cwe="CWE-306", confidence="high", convention="c", strategy="auth",
            ),
            NegativeSpaceFinding(
                check_type="missing_validation", expected="d", evidence="e",
                cwe="CWE-20", confidence="medium", convention="f", strategy="input_handling",
            ),
        ]
        result = format_negative_space_prose(findings)
        assert "CWE-306" in result
        assert "CWE-20" in result
        assert result.count("- (") == 2


class TestSiblingNegativeSpace:
    def test_detects_sibling_missing_convention(self):
        from core.audit.negative_space import check_sibling_negative_space

        gaps = [
            {
                "name": "handle_login",
                "file": "auth.py",
                "source": "def handle_login(req): check_auth(req); ...",
                "strategies": {"auth"},
            },
            {
                "name": "handle_logout",
                "file": "auth.py",
                "source": "def handle_logout(req): check_auth(req); ...",
                "strategies": {"auth"},
            },
            {
                "name": "handle_register",
                "file": "auth.py",
                "source": "def handle_register(req): do_register(req); ...",
                "strategies": {"auth"},
            },
        ]
        conventions = [
            SecurityConvention(
                concern="auth",
                pattern="check_auth",
                occurrences=5,
                locations=["auth.py:handle_login", "auth.py:handle_logout"],
                confidence=0.8,
            ),
        ]
        findings = check_sibling_negative_space(gaps, conventions)
        assert len(findings) >= 1
        assert any("handle_register" in f.evidence for f in findings)
        assert all(f.strategy == "sibling_asymmetry" for f in findings)

    def test_no_findings_when_all_follow(self):
        from core.audit.negative_space import check_sibling_negative_space

        gaps = [
            {
                "name": "render_html",
                "file": "views.py",
                "source": "def render_html(data): escape(data)",
            },
            {
                "name": "render_json",
                "file": "views.py",
                "source": "def render_json(data): escape(data)",
            },
        ]
        conventions = [
            SecurityConvention(
                concern="validation",
                pattern="escape",
                occurrences=5,
                locations=["views.py:render_html", "views.py:render_json"],
                confidence=0.9,
            ),
        ]
        findings = check_sibling_negative_space(gaps, conventions)
        assert len(findings) == 0

    def test_no_peer_groups_returns_empty(self):
        from core.audit.negative_space import check_sibling_negative_space

        gaps = [
            {"name": "unrelated_func", "file": "a.py", "source": "def f(): pass"},
        ]
        conventions = [
            SecurityConvention(
                concern="auth", pattern="check", occurrences=5,
                locations=[], confidence=0.8,
            ),
        ]
        assert check_sibling_negative_space(gaps, conventions) == []

    def test_sibling_finding_has_correct_check_type(self):
        from core.audit.negative_space import check_sibling_negative_space

        gaps = [
            {
                "name": "validate_email",
                "file": "v.py",
                "source": "def validate_email(x): sanitize_(x)",
            },
            {
                "name": "validate_phone",
                "file": "v.py",
                "source": "def validate_phone(x): just_return(x)",
            },
            {
                "name": "validate_url",
                "file": "v.py",
                "source": "def validate_url(x): sanitize_(x)",
            },
        ]
        conventions = [
            SecurityConvention(
                concern="validation",
                pattern=r"sanitize_",
                occurrences=5,
                locations=["v.py:validate_email", "v.py:validate_url"],
                confidence=0.9,
            ),
        ]
        findings = check_sibling_negative_space(gaps, conventions)
        assert len(findings) >= 1
        assert findings[0].check_type == "sibling_missing_validation"
        assert findings[0].cwe == "CWE-20"


# ── Post-loop pattern checks ─────────────────────────────────────────


class TestResourceExhaustion:
    def test_detects_suspicious_regex(self):
        gaps = [
            {
                "name": "validate",
                "file": "v.py",
                "source": "pat = re.compile(r'^(a+)+$')",
            },
        ]
        findings = check_resource_exhaustion(gaps)
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-1333"

    def test_detects_unbounded_alloc(self):
        gaps = [
            {
                "name": "alloc_buf",
                "file": "buf.c",
                "source": "char *p = malloc(user_size + HEADER);",
            },
        ]
        findings = check_resource_exhaustion(gaps)
        assert any(f.cwe == "CWE-190" for f in findings)

    def test_alloc_with_check_no_finding(self):
        gaps = [
            {
                "name": "safe_alloc",
                "file": "buf.c",
                "source": "if (size > MAX_SIZE) return NULL; char *p = malloc(size + 16);",
            },
        ]
        findings = check_resource_exhaustion(gaps)
        alloc_findings = [f for f in findings if f.cwe == "CWE-190"]
        assert len(alloc_findings) == 0

    def test_empty_source(self):
        assert check_resource_exhaustion([{"name": "f", "source": ""}]) == []


class TestProtocolAmbiguity:
    def test_detects_http_cl_te(self):
        gaps = [
            {
                "name": "parse_headers",
                "file": "http.py",
                "source": "if 'Content-Length' in headers and 'Transfer-Encoding' in headers:",
            },
        ]
        findings = check_protocol_ambiguity(gaps)
        assert any("CL vs TE" in f.title for f in findings)

    def test_detects_jwt(self):
        gaps = [
            {
                "name": "verify",
                "file": "auth.py",
                "source": "import jwt; token = jwt.decode(raw)",
            },
        ]
        findings = check_protocol_ambiguity(gaps)
        assert any("JWT" in f.title for f in findings)

    def test_detects_xml_xxe(self):
        gaps = [
            {
                "name": "parse",
                "file": "xml_handler.py",
                "source": "from xml.etree import ElementTree; tree = ElementTree.parse(f)",
            },
        ]
        findings = check_protocol_ambiguity(gaps)
        assert any("XXE" in f.title for f in findings)

    def test_deduplicates_per_file_protocol(self):
        gaps = [
            {
                "name": "f1",
                "file": "http.py",
                "source": "Content-Length header",
            },
            {
                "name": "f2",
                "file": "http.py",
                "source": "Content-Length handling",
            },
        ]
        findings = check_protocol_ambiguity(gaps)
        cl_te_findings = [f for f in findings if "CL vs TE" in f.title]
        assert len(cl_te_findings) <= 1


class TestMissingAppFeatures:
    def test_detects_missing_rate_limit(self):
        # Framework evidence present (flask import): the checklist runs.
        gaps = [
            {
                "name": "login",
                "file": "auth.py",
                "source": "from flask import Flask\ndef login(user, pw): ...",
            },
        ]
        findings = check_missing_app_features(gaps)
        assert any("Rate limiting" in f.title for f in findings)

    def test_no_finding_when_present(self):
        gaps = [
            {
                "name": "app",
                "file": "config.py",
                "source": "from flask_limiter import RateLimit\nrate_limit = RateLimit()",
            },
        ]
        findings = check_missing_app_features(gaps)
        rate_findings = [f for f in findings if "Rate limiting" in f.title]
        assert len(rate_findings) == 0

    def test_detects_missing_csrf(self):
        gaps = [
            {
                "name": "form",
                "file": "forms.py",
                "source": "import django\ndef submit(): pass",
            },
        ]
        findings = check_missing_app_features(gaps)
        assert any("CSRF" in f.title for f in findings)

    def test_gated_off_for_pure_c_target(self):
        # A C crypto library has no web-application obligations: the
        # checklist previously emitted all six "Missing: …" findings
        # against pure C (observed on a real run).
        gaps = [
            {"name": "bio_ctrl", "file": "crypto/bio/bss_file.c",
             "source": "static long file_ctrl(BIO *b) { return 0; }"},
            {"name": "xsyslog", "file": "crypto/bio/bss_log.c",
             "source": "static void xsyslog(BIO *bp) {}"},
        ]
        findings = check_missing_app_features(gaps)
        assert findings == []

    def test_gated_off_without_framework_evidence(self):
        # Web-capable language but no framework/HTTP-server marker
        # (e.g. a Python CLI tool): still no CSRF surface.
        gaps = [
            {"name": "main", "file": "cli.py",
             "source": "def main():\n    print('hello')"},
        ]
        findings = check_missing_app_features(gaps)
        assert findings == []


class TestUBPatterns:
    def test_detects_signed_overflow_check(self):
        gaps = [
            {
                "name": "check_overflow",
                "file": "math.c",
                "source": "if (a + b < a) return 1;",
            },
        ]
        findings = check_ub_patterns(gaps)
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-190"

    def test_skips_non_c_files(self):
        gaps = [
            {
                "name": "check",
                "file": "math.py",
                "source": "if (a + b < a): return True",
            },
        ]
        assert check_ub_patterns(gaps) == []

    def test_language_filter(self):
        gaps = [
            {
                "name": "f",
                "file": "f.c",
                "source": "if (a + b < a) return 1;",
            },
        ]
        assert check_ub_patterns(gaps, languages={"python"}) == []
        assert len(check_ub_patterns(gaps, languages={"c"})) == 1

    def test_detects_type_punning(self):
        gaps = [
            {
                "name": "read_int",
                "file": "io.c",
                "source": "int val = *(int *)buf;",
            },
        ]
        findings = check_ub_patterns(gaps)
        assert any("Type-punning" in f.title for f in findings)


class TestSignalSafety:
    def test_detects_unsafe_signal_handler(self):
        gaps = [
            {
                "name": "setup",
                "file": "main.c",
                "source": "signal(SIGINT, handler);",
                "callees": ["handler"],
            },
            {
                "name": "handler",
                "file": "main.c",
                "source": "void handler(int sig) { printf(\"caught\\n\"); }",
                "callees": ["printf"],
            },
        ]
        findings = check_signal_safety(gaps)
        assert len(findings) == 1
        assert "printf" in findings[0].evidence
        assert findings[0].confidence == "high"

    def test_safe_handler_no_finding(self):
        gaps = [
            {
                "name": "setup",
                "file": "main.c",
                "source": "signal(SIGINT, handler);",
                "callees": ["handler"],
            },
            {
                "name": "handler",
                "file": "main.c",
                "source": "void handler(int sig) { flag = 1; }",
                "callees": ["write"],
            },
        ]
        assert check_signal_safety(gaps) == []


class TestCheckSideChannels:
    def test_detects_early_return_auth(self):
        gaps = [{"name": "verify_pw", "file": "auth.py", "source": (
            "for i in range(len(password)):\n"
            "    if password[i] != stored[i]: return False"
        )}]
        results = check_side_channels(gaps)
        assert len(results) == 1
        assert results[0].cwe == "CWE-208"

    def test_detects_non_constant_time(self):
        gaps = [{"name": "check", "file": "a.c",
                 "source": "if (strcmp(password, stored) == 0)"}]
        results = check_side_channels(gaps)
        assert any(f.title == "Non-constant-time comparison of secrets" for f in results)

    def test_empty_source_skipped(self):
        assert check_side_channels([{"name": "f", "file": "a.c", "source": ""}]) == []

    def test_no_source_key_skipped(self):
        assert check_side_channels([{"name": "f", "file": "a.c"}]) == []


class TestCheckMultiProcess:
    def test_detects_pickle_load(self):
        gaps = [{"name": "handle", "file": "ipc.py",
                 "source": "data = pickle.loads(sock.recv(4096))"}]
        results = check_multi_process(gaps)
        assert len(results) >= 1
        assert results[0].cwe == "CWE-502"

    def test_detects_subprocess_shell(self):
        gaps = [{"name": "run", "file": "cmd.py",
                 "source": "subprocess.call(user_input, shell=True)"}]
        results = check_multi_process(gaps)
        assert any(f.cwe == "CWE-78" for f in results)


class TestCheckDeploymentAssumptions:
    def test_detects_debug_bypass(self):
        gaps = [{"name": "check", "file": "app.py",
                 "source": "if DEBUG: skip_auth_check()"}]
        results = check_deployment_assumptions(gaps)
        assert len(results) >= 1

    def test_clean_source_no_findings(self):
        gaps = [{"name": "f", "file": "a.py",
                 "source": "x = 1 + 2\nreturn x"}]
        assert check_deployment_assumptions(gaps) == []


class TestCheckLockOrdering:
    def test_detects_multiple_locks(self):
        gaps = [{"name": "transfer", "file": "bank.c", "source": (
            "lock_a.acquire()\nlock_b.acquire()\n"
            "# do work\nlock_b.release()\nlock_a.release()"
        )}]
        results = check_lock_ordering(gaps)
        assert any(f.cwe == "CWE-764" for f in results)

    def test_no_findings_clean(self):
        gaps = [{"name": "f", "file": "a.c", "source": "return 0;"}]
        assert check_lock_ordering(gaps) == []

    def test_domain_vocab_lock_names_captured(self):
        from dataclasses import dataclass, field

        @dataclass
        class _Vocab:
            lock_acquires: frozenset = field(default_factory=frozenset)
            lock_releases: frozenset = field(default_factory=frozenset)

        vocab = _Vocab(
            lock_acquires=frozenset({"spin_lock", "rw_lock"}),
            lock_releases=frozenset({"spin_unlock", "rw_unlock"}),
        )
        gaps = [{"name": "work", "file": "drv.c", "source": (
            "spin_lock(a);\nrw_lock(b);\n"
            "do_work();\n"
            "rw_unlock(b);\nspin_unlock(a);\n"
        )}]
        results = check_lock_ordering(gaps, domain_vocab=vocab)
        assert any(f.cwe == "CWE-764" for f in results)


class TestDeadGapExclusion:
    """Dead gaps must not pollute convention baselines or sibling votes."""

    def _live_gaps(self):
        return [
            {"name": "render_a", "file": "v.py", "source": "html_escape(x)"},
            {"name": "render_b", "file": "v.py", "source": "html_escape(y)"},
            {"name": "render_c", "file": "v.py", "source": "html_escape(z)"},
        ]

    def test_discover_conventions_excludes_dead(self):
        gaps = self._live_gaps() + [
            {"name": "render_dead", "file": "v.py",
             "source": "html_escape(w)", "dead": True},
        ]
        convs = discover_conventions(gaps)
        for conv in convs:
            assert "v.py:render_dead" not in conv.locations

    def test_detect_framework_excludes_dead(self):
        gaps = [
            {"name": "a", "source": "from django.views import View"},
            {"name": "b", "source": "from django.http import HttpResponse"},
            {"name": "c", "source": "from django.db import models", "dead": True},
        ]
        fw = detect_framework(gaps)
        assert fw == "django"

    def test_detect_framework_dead_only_no_framework(self):
        gaps = [
            {"name": "a", "source": "from django.views import View", "dead": True},
            {"name": "b", "source": "from django.http import HttpResponse", "dead": True},
        ]
        fw = detect_framework(gaps)
        assert fw == ""


class TestPostLoopHydration:
    """Post-loop pattern-scan functions read source from disk via target_path."""

    @staticmethod
    def _gap(file, name, ls, le, source=""):
        g = {"file": file, "name": name, "line_start": ls, "line_end": le}
        if source:
            g["source"] = source
        return g

    def test_resource_exhaustion_from_disk(self, tmp_path):
        body = "parser = XMLParser(target)\n"
        (tmp_path / "srv.py").write_text(body)
        gap = self._gap("srv.py", "handle", 1, 1)
        findings = check_resource_exhaustion([gap], target_path=tmp_path)
        assert any(f.check_type == "resource_exhaustion" for f in findings)

    def test_deployment_assumptions_from_disk(self, tmp_path):
        body = "if '127.0.0.1' in trusted_allow_list:\n    skip_auth()\n"
        (tmp_path / "cfg.py").write_text(body)
        gap = self._gap("cfg.py", "check", 1, 2)
        findings = check_deployment_assumptions([gap], target_path=tmp_path)
        assert any(f.check_type == "deployment_assumption" for f in findings)

    def test_lock_ordering_from_disk(self, tmp_path):
        body = (
            "pthread_mutex_lock(&mutex_a);\n"
            "pthread_mutex_lock(&mutex_b);\n"
            "do_work();\n"
            "pthread_mutex_unlock(&mutex_b);\n"
            "pthread_mutex_unlock(&mutex_a);\n"
        )
        (tmp_path / "locks.c").write_text(body)
        gap = self._gap("locks.c", "work", 1, 5)
        findings = check_lock_ordering([gap], target_path=tmp_path)
        assert any(f.check_type == "lock_ordering" for f in findings)

    def test_missing_app_features_from_disk(self, tmp_path):
        body = (
            "@app.route('/')\n"
            "def index(req):\n    return render(req, 'index.html')\n"
        )
        (tmp_path / "views.py").write_text(body)
        gap = self._gap("views.py", "index", 1, 3)
        findings = check_missing_app_features([gap], target_path=tmp_path)
        assert len(findings) > 0

    def test_no_target_path_still_works(self):
        gap = self._gap("x.py", "f", 1, 2)
        findings = check_resource_exhaustion([gap])
        assert findings == []

    def test_gap_source_preferred_over_disk(self, tmp_path):
        (tmp_path / "a.py").write_text("clean code\n")
        body = "parser = XMLParser(target)\n"
        gap = self._gap("a.py", "handle", 1, 1, source=body)
        findings = check_resource_exhaustion([gap], target_path=tmp_path)
        assert any(f.check_type == "resource_exhaustion" for f in findings)

    def test_missing_app_features_early_exit(self, tmp_path):
        """Once all features found, stops reading further gaps."""
        from core.audit.negative_space import _APP_FEATURE_CHECKS

        if not _APP_FEATURE_CHECKS:
            return
        body = "\n".join(
            p.pattern
            for check in _APP_FEATURE_CHECKS
            for p in check.search_patterns[:1]
        )
        (tmp_path / "all.py").write_text(body)
        gap = self._gap("all.py", "f", 1, body.count("\n") + 1)
        findings = check_missing_app_features([gap], target_path=tmp_path)
        assert findings == []


class TestVocabAuthConventionDiscovery:
    """Study-learned auth predicates extend convention discovery.

    Coverage gain: a project whose auth gate is a bespoke predicate
    (``foo_may_access``) has no convention discoverable from the
    framework/generic seed patterns; the learned vocabulary makes the
    convention (and therefore the missing-auth negative-space check)
    visible. No vocab → behaviour unchanged.
    """

    def _project_gaps(self):
        gaps = []
        for i in range(4):
            gaps.append({
                "file": f"srv/handler_{i}.c",
                "name": f"handle_req_{i}",
                "source": (
                    "int handle_req(struct req *r) {\n"
                    "    if (!foo_may_access(r->ctx))\n"
                    "        return -EPERM;\n"
                    "    return do_work(r);\n"
                    "}\n"
                ),
                "strategies": ["auth"],
            })
        gaps.append({
            "file": "srv/handler_missing.c",
            "name": "handle_req_missing",
            "source": (
                "int handle_req_missing(struct req *r) {\n"
                "    return do_work(r);\n"
                "}\n"
            ),
            "strategies": ["auth"],
        })
        return gaps

    def _vocab(self):
        from core.audit.condition_smt import DomainVocabulary

        return DomainVocabulary.from_domain_model({
            "auth_predicates": [
                {"name": "foo_may_access", "kind": "permission"},
            ],
        })

    def test_without_vocab_no_auth_convention(self):
        convs = discover_conventions(self._project_gaps())
        assert [c for c in convs if c.concern == "auth"] == []

    def test_learned_predicate_discovers_convention(self):
        convs = discover_conventions(
            self._project_gaps(), domain_vocab=self._vocab(),
        )
        auth_convs = [c for c in convs if c.concern == "auth"]
        assert len(auth_convs) == 1
        assert auth_convs[0].occurrences == 4
        assert "foo_may_access" in auth_convs[0].pattern

    def test_discovered_convention_flags_the_outlier(self):
        convs = discover_conventions(
            self._project_gaps(), domain_vocab=self._vocab(),
        )
        outlier = {
            "file": "srv/handler_missing.c",
            "name": "handle_req_missing",
            "source": (
                "int handle_req_missing(struct req *r) {\n"
                "    return do_work(r);\n"
                "}\n"
            ),
            "sloc": 10,
            "is_entry_point": True,
            "callers": [],
        }
        findings = check_negative_space(outlier, convs, "auth")
        assert any(f.check_type == "missing_auth" for f in findings)

    def test_none_vocab_is_equivalent_to_omitting_it(self):
        gaps = self._project_gaps()
        assert (
            discover_conventions(gaps)
            == discover_conventions(gaps, domain_vocab=None)
        )


class TestProtocolEvidenceGate:
    """v4 misfire: TLS session-cache C code was flagged with an HTTP
    CRLF-injection question purely on the word "session". HTTP checks
    now require actual HTTP evidence in the source (the
    check_missing_app_features gating precedent)."""

    def test_tls_session_code_not_flagged_as_http(self):
        gaps = [{
            "name": "ssl_get_prev_session",
            "file": "ssl/ssl_sess.c",
            "source": (
                "int ssl_get_prev_session(SSL_CONNECTION *s) {\n"
                "    SSL_SESSION *ret = lookup_sess_in_cache(s, sess_id,"
                " sess_id_len);\n"
                "    if (ret->session_id_length == 0) return 0;\n"
                "    ssl_session_calculate_timeout(ret);\n"
                "}\n"
            ),
        }]
        findings = check_protocol_ambiguity(gaps)
        assert not any(f.protocol == "HTTP" if hasattr(f, "protocol")
                       else "HTTP" in f.title for f in findings)

    def test_real_http_response_code_still_flagged(self):
        gaps = [{
            "name": "write_session_cookie",
            "file": "web/session.py",
            "source": (
                "def write_session_cookie(response, session_id):\n"
                "    response.headers['Set-Cookie'] = "
                "'session=' + session_id\n"
            ),
        }]
        findings = check_protocol_ambiguity(gaps)
        assert any("CRLF" in f.title for f in findings)

    def test_cl_te_literals_are_their_own_evidence(self):
        # The CL/TE check's trigger literals ARE HTTP evidence — the
        # gate must not suppress it.
        gaps = [{
            "name": "parse_headers",
            "file": "http.c",
            "source": "if (has_content_length && strstr(h, "
                      "\"Transfer-Encoding\")) reject();",
        }]
        findings = check_protocol_ambiguity(gaps)
        assert any("CL vs TE" in f.title for f in findings)
