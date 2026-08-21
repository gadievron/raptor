"""Tests for the live-finding string-theory injection prescreen.

Soundness bar: a false "refuted" suppresses a real bug, so every
tricky liftability fixture (partial anchors, re.search, flags/count
arguments, Ruby line anchors, the re.match trailing-newline quirk)
must yield NO signal — only the exact whole-string charset shapes may
refute, and only when every path is neutralised.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

pytest.importorskip("z3")

from core.dataflow import injection_prescreen as ip
from core.dataflow.smt_barrier import ValidatorSpec
from core.dataflow.injection_prescreen import (
    PrescreenVerdict,
    prescreen_finding,
    sink_classes_for_rule,
    snapshot_stats,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

# Line numbers (1-based) are load-bearing for the AST dominance checks.
# The refuting charset is DOTLESS: '.' is a pathtrav danger char ('.'
# builds '..' segments), so dot-admitting charsets must decline.
GUARD_APP = """\
import os
import re


def handler(request):
    name = request.args.get('name')
    if not re.match(r'^[A-Za-z0-9_+-]+$', name):
        return None
    cfg = os.path.join('/etc/app', name)
    open(cfg)
"""
GUARD_SOURCE_LINE = 6
GUARD_VALIDATOR_LINE = 7
GUARD_SINK_LINE = 10

# The historical whoogle shape admits '.' — sound for the join-shape
# seen there, but the charset proof has no join-shape model, so the
# prescreen must not refute pathtrav on it.
GUARD_APP_WHOOGLE = GUARD_APP.replace("[A-Za-z0-9_+-]", "[A-Za-z0-9_.+-]")


SUB_APP = """\
import os
import re


def handler(request):
    name = request.args.get('name')
    name = re.sub(r'[/\\\\.]+', '', name)
    open('/etc/app/' + name)
"""
SUB_SOURCE_LINE = 6
SUB_VALIDATOR_LINE = 7
SUB_SINK_LINE = 8


def _step(file_path: str, line: int, label: str = "step"):
    return SimpleNamespace(
        file_path=file_path, line=line, column=1, snippet="", label=label,
    )


def _path(file_name: str, source_line: int, step_lines: list,
          sink_line: int):
    return SimpleNamespace(
        source=_step(file_name, source_line, "source"),
        sink=_step(file_name, sink_line, "sink"),
        intermediate_steps=[_step(file_name, ln) for ln in step_lines],
    )


@pytest.fixture
def guard_repo(tmp_path):
    (tmp_path / "app.py").write_text(GUARD_APP, encoding="utf-8")
    return tmp_path


@pytest.fixture
def sub_repo(tmp_path):
    (tmp_path / "app.py").write_text(SUB_APP, encoding="utf-8")
    return tmp_path


def _guard_path():
    return _path("app.py", GUARD_SOURCE_LINE,
                 [GUARD_VALIDATOR_LINE], GUARD_SINK_LINE)


def _sub_path():
    return _path("app.py", SUB_SOURCE_LINE,
                 [SUB_VALIDATOR_LINE], SUB_SINK_LINE)


def _write_app(tmp_path, body: str, name: str = "app.py"):
    (tmp_path / name).write_text(body, encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# Rule-id → sink-class mapping
# ---------------------------------------------------------------------------


class TestSinkClassMapping:
    @pytest.mark.parametrize("rule_id,expected", [
        ("py/path-injection", {"pathtrav"}),
        ("py/command-line-injection", {"cmdi"}),
        ("js/xss", {"xss"}),
        ("js/reflected-xss", {"xss"}),
        ("java/sql-injection", {"sqli"}),
        ("raptor.injection.command-shell", set()),
        ("semgrep.python.path-traversal.open", {"pathtrav"}),
    ])
    def test_rule_patterns(self, rule_id, expected):
        assert set(sink_classes_for_rule(rule_id)) == expected

    def test_non_injection_rules_map_to_nothing(self):
        for rule_id in ("cpp/integer-overflow", "py/weak-crypto",
                        "js/prototype-pollution", ""):
            assert sink_classes_for_rule(rule_id) == frozenset()

    def test_explicit_cwe_fallback(self):
        assert "pathtrav" in sink_classes_for_rule("custom/rule-1",
                                                   cwe="CWE-22")
        assert "sqli" in sink_classes_for_rule("custom/rule-1", cwe="CWE-89")


# ---------------------------------------------------------------------------
# End-to-end refutations
# ---------------------------------------------------------------------------


class TestGuardFormRefutation:
    def test_dotless_charset_shape_refutes(self, guard_repo):
        verdict = prescreen_finding(
            paths=[_guard_path()], repo_root=guard_repo,
            rule_id="py/path-injection",
        )
        assert isinstance(verdict, PrescreenVerdict)
        assert verdict.refuted is True
        assert verdict.paths_checked == 1
        (ev,) = verdict.evidence
        assert ev["validator_file"] == "app.py"
        assert ev["validator_line"] == GUARD_VALIDATOR_LINE
        assert ev["kind"] == "charset"
        assert ev["sink_classes"] == ["pathtrav"]
        assert verdict.solver_ms >= 0

    def test_whoogle_dot_charset_declines_pathtrav(self, tmp_path):
        # '.' is in the pathtrav danger model ('..' segments) and the
        # charset proof carries no join-shape model — a dot-admitting
        # charset must not refute a pathtrav finding.
        repo = _write_app(tmp_path, GUARD_APP_WHOOGLE)
        assert prescreen_finding(
            paths=[_guard_path()], repo_root=repo,
            rule_id="py/path-injection",
        ) is None

    def test_insufficient_charset_no_refutation(self, tmp_path):
        # Charset PERMITS '/' — the danger char survives; the Z3 proof
        # comes back sat and the prescreen must not refute.
        app = GUARD_APP.replace("[A-Za-z0-9_+-]", "[A-Za-z0-9_/+-]")
        repo = _write_app(tmp_path, app)
        assert prescreen_finding(
            paths=[_guard_path()], repo_root=repo,
            rule_id="py/path-injection",
        ) is None

    def test_sub_form_refutes(self, sub_repo):
        verdict = prescreen_finding(
            paths=[_sub_path()], repo_root=sub_repo,
            rule_id="py/path-injection",
        )
        assert verdict is not None and verdict.refuted is True
        (ev,) = verdict.evidence
        assert ev["kind"] == "charset_sub"

    def test_fullmatch_refutes_cmdi(self, tmp_path):
        # fullmatch has no trailing-newline quirk, so a charset
        # excluding every cmdi danger char may refute a cmdi finding.
        app = GUARD_APP.replace(
            "re.match(r'^[A-Za-z0-9_+-]+$', name)",
            "re.fullmatch(r'[A-Za-z0-9_+-]+', name)",
        ).replace("os.path.join('/etc/app', name)", "'ls ' + name")
        repo = _write_app(tmp_path, app)
        verdict = prescreen_finding(
            paths=[_guard_path()], repo_root=repo,
            rule_id="py/command-line-injection",
        )
        assert verdict is not None and verdict.refuted is True


# ---------------------------------------------------------------------------
# Liftability: every tricky shape must yield NO signal
# ---------------------------------------------------------------------------


class TestLiftabilityConservatism:
    @pytest.mark.parametrize("validator_line", [
        # re.search constrains nothing about the whole string.
        "    if not re.search(r'^[A-Za-z0-9_+-]+$', name):",
        # Unanchored re.match — suffix unconstrained.
        "    if not re.match(r'[A-Za-z0-9_+-]+', name):",
        # Partial anchor (no $) — suffix unconstrained.
        "    if not re.match(r'^[A-Za-z0-9_+-]+', name):",
        # Flags argument changes matching semantics (e.g. MULTILINE
        # turns $ into a line anchor) — call must close after the var.
        "    if not re.match(r'^[A-Za-z0-9_+-]+$', name, re.MULTILINE):",
        "    if not re.match(r'^[A-Za-z0-9_+-]+$', name, re.I):",
        # Negated class inverts the language.
        "    if not re.match(r'^[^/\\\\]+$', name):",
        # Shorthand classes are not literal charsets.
        "    if not re.match(r'^[\\w.+-]+$', name):",
    ])
    def test_unliftable_python_guards(self, tmp_path, validator_line):
        lines = GUARD_APP.splitlines()
        lines[GUARD_VALIDATOR_LINE - 1] = validator_line
        repo = _write_app(tmp_path, "\n".join(lines) + "\n")
        assert prescreen_finding(
            paths=[_guard_path()], repo_root=repo,
            rule_id="py/path-injection",
        ) is None

    def test_sub_with_count_arg_unliftable(self, tmp_path):
        # count=1 strips only the first occurrence — later danger
        # chars survive, so the strip claim is false.
        app = SUB_APP.replace(
            "re.sub(r'[/\\\\.]+', '', name)",
            "re.sub(r'[/\\\\.]+', '', name, 1)",
        )
        repo = _write_app(tmp_path, app)
        assert prescreen_finding(
            paths=[_sub_path()], repo_root=repo,
            rule_id="py/path-injection",
        ) is None

    def test_match_dollar_refused_for_cmdi(self, tmp_path):
        # Python's $ under re.match tolerates one trailing newline and
        # "\n" is a cmdi danger char — the same guard that soundly
        # refutes pathtrav must NOT refute cmdi.
        app = GUARD_APP.replace("os.path.join('/etc/app', name)",
                                "'ls ' + name")
        repo = _write_app(tmp_path, app)
        assert prescreen_finding(
            paths=[_guard_path()], repo_root=repo,
            rule_id="py/command-line-injection",
        ) is None

    def test_ruby_guards_refused(self, tmp_path):
        # Ruby ^/$ are always line anchors — the whole-string charset
        # claim never holds, whatever the pattern.
        app = (
            "def handler(request)\n"
            "  name = params[:name]\n"
            "  return nil unless name =~ /^[A-Za-z0-9_+-]+$/\n"
            "  File.open('/etc/app/' + name)\n"
            "end\n"
        )
        repo = _write_app(tmp_path, app, name="app.rb")
        path = _path("app.rb", 2, [3], 4)
        assert prescreen_finding(
            paths=[path], repo_root=repo, rule_id="rb/path-injection",
        ) is None


# ---------------------------------------------------------------------------
# Dominance / value-chain conservatism
# ---------------------------------------------------------------------------


class TestDominanceConservatism:
    def test_guard_without_exit_no_signal(self, tmp_path):
        app = GUARD_APP.replace("        return None", "        pass")
        repo = _write_app(tmp_path, app)
        assert prescreen_finding(
            paths=[_guard_path()], repo_root=repo,
            rule_id="py/path-injection",
        ) is None

    def test_validator_for_unrelated_variable_no_signal(self, tmp_path):
        # Guard constrains `other`; the sink consumes `name`.
        app = GUARD_APP.replace(
            "    name = request.args.get('name')",
            "    name = request.args.get('name')\n"
            "    other = request.args.get('other')",
        ).replace(
            "re.match(r'^[A-Za-z0-9_+-]+$', name)",
            "re.match(r'^[A-Za-z0-9_+-]+$', other)",
        )
        repo = _write_app(tmp_path, app)
        # Lines shift by one after the inserted assignment.
        path = _path("app.py", GUARD_SOURCE_LINE,
                     [GUARD_VALIDATOR_LINE + 1], GUARD_SINK_LINE + 1)
        assert prescreen_finding(
            paths=[path], repo_root=repo, rule_id="py/path-injection",
        ) is None

    def test_cross_file_validator_no_signal(self, guard_repo):
        (guard_repo / "other.py").write_text(GUARD_APP, encoding="utf-8")
        path = _path("app.py", GUARD_SOURCE_LINE, [], GUARD_SINK_LINE)
        path.intermediate_steps = [_step("other.py", GUARD_VALIDATOR_LINE)]
        assert prescreen_finding(
            paths=[path], repo_root=guard_repo,
            rule_id="py/path-injection",
        ) is None

    def test_path_escape_refused(self, guard_repo):
        path = _path("app.py", GUARD_SOURCE_LINE,
                     [GUARD_VALIDATOR_LINE], GUARD_SINK_LINE)
        path.intermediate_steps = [_step("../outside.py", 7)]
        assert prescreen_finding(
            paths=[path], repo_root=guard_repo,
            rule_id="py/path-injection",
        ) is None


# ---------------------------------------------------------------------------
# Multi-path all-or-nothing
# ---------------------------------------------------------------------------


class TestMultiPath:
    def test_all_paths_refuted(self, guard_repo):
        verdict = prescreen_finding(
            paths=[_guard_path(), _guard_path()], repo_root=guard_repo,
            rule_id="py/path-injection",
        )
        assert verdict is not None and verdict.refuted is True
        assert verdict.paths_checked == 2
        assert len(verdict.evidence) == 2

    def test_one_unliftable_path_kills_the_signal(self, guard_repo):
        bare = _path("app.py", GUARD_SOURCE_LINE, [], GUARD_SINK_LINE)
        assert prescreen_finding(
            paths=[_guard_path(), bare], repo_root=guard_repo,
            rule_id="py/path-injection",
        ) is None

    def test_path_cap_yields_no_signal(self, guard_repo):
        paths = [_guard_path() for _ in range(ip.MAX_PRESCREEN_PATHS + 1)]
        assert prescreen_finding(
            paths=paths, repo_root=guard_repo,
            rule_id="py/path-injection",
        ) is None


# ---------------------------------------------------------------------------
# Gates, timeout threading, telemetry
# ---------------------------------------------------------------------------


class TestGatesAndTelemetry:
    def test_unsupported_language_no_signal(self, tmp_path):
        repo = _write_app(tmp_path, "int main() { return 0; }\n",
                          name="app.c")
        path = _path("app.c", 1, [1], 1)
        assert prescreen_finding(
            paths=[path], repo_root=repo, rule_id="cpp/path-injection",
        ) is None

    def test_z3_unavailable_no_signal(self, guard_repo):
        with patch.object(ip, "_z3_available", return_value=False):
            assert prescreen_finding(
                paths=[_guard_path()], repo_root=guard_repo,
                rule_id="py/path-injection",
            ) is None

    def test_solver_timeout_is_threaded(self, guard_repo):
        seen = {}

        def fake_prove(spec, sink_class, timeout_ms=None):
            seen["timeout_ms"] = timeout_ms
            return SimpleNamespace(sound=False, counterexample=None,
                                   reasoning="z3 returned unknown")

        with patch.object(ip, "prove_neutralizes", side_effect=fake_prove):
            verdict = prescreen_finding(
                paths=[_guard_path()], repo_root=guard_repo,
                rule_id="py/path-injection",
            )
        assert verdict is None  # unknown/timeout can never refute
        assert seen["timeout_ms"] == ip.SOLVER_TIMEOUT_MS

    def test_stats_counters(self, guard_repo, tmp_path):
        before = snapshot_stats()
        prescreen_finding(
            paths=[_guard_path()], repo_root=guard_repo,
            rule_id="py/path-injection",
        )
        after_refute = snapshot_stats()
        assert after_refute["attempted"] == before["attempted"] + 1
        assert after_refute["refuted"] == before["refuted"] + 1
        assert after_refute["lifted"] == before["lifted"] + 1

        bare = _path("app.py", GUARD_SOURCE_LINE, [], GUARD_SINK_LINE)
        prescreen_finding(
            paths=[bare], repo_root=guard_repo,
            rule_id="py/path-injection",
        )
        after_miss = snapshot_stats()
        assert after_miss["no_signal"] == after_refute["no_signal"] + 1
        assert after_miss["refuted"] == after_refute["refuted"]


class TestNonPythonRebindKill:
    """a204f309: the non-Python value-reach must apply the rebind-KILL, so
    a charset guard whose variable is re-tainted after the guard does NOT
    suppress a live JS/TS/Java finding."""

    _SPEC = ValidatorSpec(
        kind="charset", var_name="p", charset="A-Za-z0-9",
        source_line="+  p = p.replace(/[^A-Za-z0-9]/g, '')", forbidden=0,
    )

    def _refute(self, src, step_line, sink_line):
        return ip._step_refutes_path(
            spec=self._SPEC, step_file="app.js", step_line=step_line,
            sink_file="app.js", sink_line=sink_line, source_text=src,
            language="javascript", sink_classes=frozenset({"pathtrav"}),
        )

    def test_no_rebind_still_refutes(self):
        # legitimate guard, value flows straight to the sink -> suppressed
        src = (
            "function h(req){\n"
            "  let p = req.query.name;\n"
            "  p = p.replace(/[^A-Za-z0-9]/g, '');\n"   # 3 validator
            "  fs.readFile('/data/'+p);\n"              # 4 sink
            "}\n"
        )
        refuted, _reason, _conf = self._refute(src, 3, 4)
        assert refuted is True

    def test_rebind_to_attacker_data_does_not_refute(self):
        # p re-tainted after the guard -> the charset proof is stale -> the
        # finding must fall through to LLM validation, not be suppressed.
        src = (
            "function h(req){\n"
            "  let p = req.query.name;\n"
            "  p = p.replace(/[^A-Za-z0-9]/g, '');\n"   # 3 validator
            "  p = req.query.evil;\n"                   # 4 rebind
            "  fs.readFile('/data/'+p);\n"              # 5 sink
            "}\n"
        )
        refuted, reason, _conf = self._refute(src, 3, 5)
        assert refuted is False
        assert "value chain" in reason
