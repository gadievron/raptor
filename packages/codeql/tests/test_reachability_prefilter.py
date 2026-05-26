"""Tests for the CodeQL autonomous analyzer's reachability
prefilter — the inventory-based pre-check that short-circuits
expensive LLM analysis when the sink function isn't called from
anywhere in the project."""

from __future__ import annotations

from unittest.mock import MagicMock


from core.inventory.reach_witness import (
    STRUCTURALLY_SUPPRESSIBLE_KINDS,
    verdict_from_classification,
)
from packages.codeql.autonomous_analyzer import (
    AutonomousCodeQLAnalyzer,
    CodeQLFinding,
)


def _suppresses(verdict, earned=STRUCTURALLY_SUPPRESSIBLE_KINDS) -> bool:
    """Mirror the caller's hard-skip decision: a verdict hard-suppresses
    iff its witness may_suppress on the earned set (empty earned set =
    --allow-unreachable mode)."""
    return verdict_from_classification(verdict).may_suppress(earned)


def _analyzer() -> AutonomousCodeQLAnalyzer:
    """Construct an analyzer with mocked LLM + validator."""
    return AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(),
        exploit_validator=MagicMock(),
        multi_turn_analyzer=None,
        enable_visualization=False,
    )


def _finding(file_path: str, line: int = 10) -> CodeQLFinding:
    return CodeQLFinding(
        rule_id="py/sql-injection",
        rule_name="SQL injection",
        message="Tainted data flows to a SQL query",
        level="error",
        file_path=file_path,
        start_line=line,
        end_line=line,
        snippet="cursor.execute(query)",
    )


# ---------------------------------------------------------------------------
# _path_to_module helper
# ---------------------------------------------------------------------------


def test_path_to_module_simple():
    a = _analyzer()
    assert a._path_to_module("packages/foo/bar.py") == "packages.foo.bar"


def test_path_to_module_handles_windows_separators():
    a = _analyzer()
    assert a._path_to_module(
        "packages\\foo\\bar.py"
    ) == "packages.foo.bar"


def test_path_to_module_returns_none_without_extension():
    a = _analyzer()
    assert a._path_to_module("Makefile") is None


def test_path_to_module_strips_extension():
    a = _analyzer()
    assert a._path_to_module("src/main.go") == "src.main"
    assert a._path_to_module("src/main.js") == "src.main"


def test_path_to_module_empty():
    a = _analyzer()
    assert a._path_to_module("") is None


# ---------------------------------------------------------------------------
# _check_reachability — end-to-end on a real source tree
# ---------------------------------------------------------------------------


def test_reachability_reachable_for_used_function(tmp_path):
    """A function reachable from an entry (here: called by ``main``)
    returns ``"reachable"`` under the entry-aware classifier — and is
    not hard-suppressed."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "def vulnerable(query):\n"
        "    cursor.execute(query)\n"
    )
    (src / "main.py").write_text(
        "from src.vuln import vulnerable\n"
        "def main():\n"
        "    vulnerable('SELECT 1')\n"
    )
    a = _analyzer()
    finding = _finding("src/vuln.py", line=2)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "reachable"
    assert _suppresses(verdict) is False


def test_reachability_not_called_for_dead_function(tmp_path):
    """A function that nothing else calls — sink is in dead code."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "def dead_handler(query):\n"
        "    cursor.execute(query)\n"
        "\n"
        "def other():\n"
        "    pass\n"
    )
    (src / "main.py").write_text(
        "from src.vuln import other\n"
        "def main():\n"
        "    other()\n"
    )
    a = _analyzer()
    finding = _finding("src/vuln.py", line=2)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "not_called"


def test_reachability_uncertain_with_dynamic_dispatch(tmp_path):
    """A file using getattr to dispatch by name on a tail-matching
    target → UNCERTAIN."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "def affected(query):\n"
        "    cursor.execute(query)\n"
    )
    (src / "main.py").write_text(
        "from src import vuln\n"
        "def main():\n"
        "    fn = getattr(vuln, 'affected')\n"
        "    fn('SELECT 1')\n"
    )
    a = _analyzer()
    finding = _finding("src/vuln.py", line=2)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "uncertain"


def test_reachability_returns_none_for_unknown_file(tmp_path):
    """Sink path doesn't exist in the inventory → can't determine."""
    (tmp_path / "main.py").write_text("def f(): pass\n")
    a = _analyzer()
    finding = _finding("nonexistent/file.py", line=1)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict is None


def test_reachability_returns_none_when_sink_outside_function(tmp_path):
    """Sink line outside any function (module-level statement) →
    no enclosing function to query → None."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "# line 1\n"
        "x = 1\n"               # module-level, no enclosing function
        "def f():\n"
        "    pass\n"
    )
    a = _analyzer()
    finding = _finding("src/vuln.py", line=2)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict is None


def test_reachability_inventory_cache_reused(tmp_path):
    """Two consecutive calls reuse the inventory build."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.py").write_text("def x(): pass\n")
    a = _analyzer()
    f1 = _finding("src/f.py", line=1)
    a._check_reachability(f1, tmp_path)
    inv_after_first = a._reachability_inventory
    a._check_reachability(f1, tmp_path)
    assert a._reachability_inventory is inv_after_first


def test_reachability_failed_build_doesnt_retry(tmp_path):
    """If inventory build fails once (e.g. inaccessible target),
    subsequent calls return None without retrying."""
    a = _analyzer()
    # Force the cache to the "failed" sentinel.
    a._reachability_inventory = False
    finding = _finding("src/f.py", line=1)
    assert a._check_reachability(finding, tmp_path) is None


# ---------------------------------------------------------------------------
# DI'd inventory + checklist-from-disk (in-process / cross-process sharing)
# ---------------------------------------------------------------------------


def test_caller_provided_inventory_used_directly(tmp_path):
    """Caller passes ``reachability_inventory=`` at construction
    → no fresh build, used directly. Lets the agentic prepass
    share its inventory with codeql in the same process."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text("def dead(): pass\n")
    (src / "main.py").write_text("x = 1\n")

    from core.inventory.builder import build_inventory
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        inv = build_inventory(str(tmp_path), td)

    a = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(),
        exploit_validator=MagicMock(),
        reachability_inventory=inv,
    )
    assert a._reachability_inventory is inv

    finding = _finding("src/vuln.py", line=1)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "not_called"


def test_checklist_path_loaded_when_no_inventory(tmp_path):
    """``reachability_checklist_path=`` provides a serialised
    checklist. Loaded in lieu of building. Lets a subprocess
    analyzer reuse the parent /agentic run's checklist."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text("def dead(): pass\n")

    from core.inventory.builder import build_inventory
    out = tmp_path / "shared-out"
    build_inventory(str(tmp_path), str(out))
    checklist_path = out / "checklist.json"
    assert checklist_path.exists()

    a = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(),
        exploit_validator=MagicMock(),
        reachability_checklist_path=checklist_path,
    )
    finding = _finding("src/vuln.py", line=1)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "not_called"


def test_checklist_path_invalid_falls_back_to_build(tmp_path):
    """Missing checklist path → falls back to fresh build."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text("def dead(): pass\n")

    a = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(),
        exploit_validator=MagicMock(),
        reachability_checklist_path=tmp_path / "does-not-exist.json",
    )
    finding = _finding("src/vuln.py", line=1)
    verdict = a._check_reachability(finding, tmp_path)
    # Fresh build worked; verdict same.
    assert verdict == "not_called"


# ---------------------------------------------------------------------------
# Short-circuit behaviour in analyze_finding_autonomous
# ---------------------------------------------------------------------------


def test_sound_witness_short_circuits(tmp_path, monkeypatch):
    """A SOUND, corpus-earned witness (module_aborts) hard-suppresses:
    analyze_finding_autonomous returns immediately, before the expensive
    dataflow validator + LLM stages."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "disabled.py").write_text(
        "raise ImportError('retired')\n"
        "def dead(q):\n"
        "    cursor.execute(q)\n"
    )
    a = _analyzer()
    canned = _finding("src/disabled.py", line=3)
    monkeypatch.setattr(a, "parse_sarif_finding", lambda r, run: canned)
    a.dataflow_validator = MagicMock()
    a.dataflow_validator.validate_finding.side_effect = AssertionError(
        "dataflow validator was invoked despite short-circuit"
    )
    result = a.analyze_finding_autonomous(
        sarif_result={}, sarif_run={},
        repo_path=tmp_path, out_dir=tmp_path / "out",
    )
    assert result.skipped_reason == "reachability_module_aborts"
    assert result.reachability_verdict == "module_aborts"
    assert result.exploitable is False
    a.dataflow_validator.validate_finding.assert_not_called()


def test_allow_unreachable_disables_hard_skip_in_analyze(tmp_path, monkeypatch):
    """Wiring: with allow_unreachable=True the analyzer's earned set is
    empty, so even a module_aborts finding is NOT short-circuited — the
    pipeline proceeds (dataflow validator IS reached)."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "disabled.py").write_text(
        "raise ImportError('retired')\n"
        "def dead(q):\n"
        "    cursor.execute(q)\n"
    )
    a = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(), exploit_validator=MagicMock(),
        multi_turn_analyzer=None, enable_visualization=False,
        allow_unreachable=True,
    )
    canned = _finding("src/disabled.py", line=3)
    monkeypatch.setattr(a, "parse_sarif_finding", lambda r, run: canned)
    # Stop the pipeline right after the skip gate so we don't exercise the
    # whole analysis — a sentinel proves we got PAST the short-circuit.
    monkeypatch.setattr(
        a, "read_vulnerable_code",
        MagicMock(side_effect=RuntimeError("reached past skip gate")),
    )
    try:
        a.analyze_finding_autonomous(
            sarif_result={}, sarif_run={},
            repo_path=tmp_path, out_dir=tmp_path / "out",
        )
        reached = False
    except RuntimeError as e:
        reached = "past skip gate" in str(e)
    assert reached, "allow_unreachable must NOT short-circuit module_aborts"


def test_not_called_no_longer_hard_suppresses(tmp_path):
    """U11: not_called is HEURISTIC — it does NOT hard-suppress (surface-
    only). The prefilter still classifies it, but the caller's
    may_suppress() decision declines to skip."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "def dead(q):\n"
        "    cursor.execute(q)\n"
    )
    a = _analyzer()
    verdict = a._check_reachability(_finding("src/vuln.py", line=2), tmp_path)
    assert verdict == "not_called"
    assert _suppresses(verdict) is False, (
        "not_called is heuristic and must not hard-suppress"
    )


def test_no_short_circuit_when_called(tmp_path, monkeypatch):
    """When the prefilter returns ``"called"``, we proceed past
    the early-exit. We don't run the FULL flow here (would need
    extensive LLM mocking); just verify the reachability_verdict
    is set and the early-return didn't fire."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "vuln.py").write_text(
        "def vulnerable(q):\n"
        "    cursor.execute(q)\n"
    )
    (src / "main.py").write_text(
        "from src.vuln import vulnerable\nvulnerable('x')\n"
    )

    a = _analyzer()
    canned = _finding("src/vuln.py", line=2)
    monkeypatch.setattr(
        a, "parse_sarif_finding", lambda r, run: canned,
    )
    # Stub read_vulnerable_code so we don't depend on actual file
    # reading here.
    monkeypatch.setattr(
        a, "read_vulnerable_code", lambda f, p: "stub",
    )
    # Stub analyze_vulnerability to short-circuit before exploit.
    fake_analysis = MagicMock(is_exploitable=False)
    monkeypatch.setattr(
        a, "analyze_vulnerability",
        lambda *args, **kwargs: fake_analysis,
    )
    # The finding has no dataflow → skip dataflow stage.

    result = a.analyze_finding_autonomous(
        sarif_result={}, sarif_run={},
        repo_path=tmp_path, out_dir=tmp_path / "out",
    )
    # Got past the early-exit (analysis was attempted).
    assert result.skipped_reason is None
    assert result.reachability_verdict == "called"


# ---------------------------------------------------------------------------
# Framework-callable bypass — functions registered with framework
# dispatch (Flask @app.route, Celery @shared_task, etc.) have no
# static callers but ARE reachable at runtime. The prefilter must
# NOT short-circuit them as "not_called" — full LLM analysis runs.
# ---------------------------------------------------------------------------


def test_reachability_flask_route_returns_framework_callable(tmp_path):
    """A Flask route handler with no static callers must return
    the new ``framework_callable`` verdict, not ``not_called``."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "api.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/users')\n"
        "def list_users():\n"
        "    return request.args.get('q')\n"
    )
    a = _analyzer()
    finding = _finding("src/api.py", line=6)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "framework_callable", (
        f"Flask route handler must resolve framework_callable "
        f"(reachable via Flask runtime dispatch), got {verdict!r}"
    )


def test_reachability_django_receiver_returns_framework_callable(tmp_path):
    """Naked-decorator framework dispatch (S1b coverage)."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "signals.py").write_text(
        "from django.dispatch import receiver\n"
        "from django.db.models.signals import post_save\n"
        "\n"
        "@receiver(post_save)\n"
        "def update_profile(sender, instance, **kw):\n"
        "    cursor.execute(sender)\n"
    )
    a = _analyzer()
    finding = _finding("src/signals.py", line=6)
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "framework_callable"


def test_framework_callable_does_not_short_circuit(
    tmp_path, monkeypatch,
):
    """End-to-end: a framework-callable finding must NOT be
    short-circuited; full analysis runs and skipped_reason stays
    None."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "api.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/q')\n"
        "def handler():\n"
        "    return 1\n"
    )

    a = _analyzer()
    canned = _finding("src/api.py", line=6)
    monkeypatch.setattr(
        a, "parse_sarif_finding", lambda r, run: canned,
    )
    monkeypatch.setattr(
        a, "read_vulnerable_code", lambda f, p: "stub",
    )
    fake_analysis = MagicMock(is_exploitable=False)
    monkeypatch.setattr(
        a, "analyze_vulnerability",
        lambda *args, **kwargs: fake_analysis,
    )

    result = a.analyze_finding_autonomous(
        sarif_result={}, sarif_run={},
        repo_path=tmp_path, out_dir=tmp_path / "out",
    )
    # Crucial: framework_callable must NOT trigger the short-
    # circuit. skipped_reason stays None; analysis ran.
    assert result.skipped_reason is None
    assert result.reachability_verdict == "framework_callable"


# ---------------------------------------------------------------------------
# S2: registered_via_call — JS / Go function-as-argument registration.
# A handler passed as identifier argument to http.HandleFunc / app.get /
# router.use must NOT short-circuit; full LLM analysis runs.
# ---------------------------------------------------------------------------


def test_allow_unreachable_empties_earned_set_so_nothing_suppresses(tmp_path):
    """Under --allow-unreachable the caller's earned set is empty, so NO
    verdict hard-suppresses — even the sound module_aborts / lexical_dead.
    The prefilter still classifies (for reporting); the decision declines."""
    for verdict in ("module_aborts", "lexical_dead", "not_called"):
        # allow-unreachable: earned set empty -> nothing suppresses
        assert _suppresses(verdict, earned=frozenset()) is False, (
            f"{verdict} must not suppress under allow_unreachable"
        )
    # sanity: in default mode the sound witnesses DO suppress
    assert _suppresses("module_aborts") is True
    assert _suppresses("lexical_dead") is True
    assert _suppresses("not_called") is False   # heuristic, never suppresses


def test_default_still_returns_not_called(tmp_path):
    """Sanity: with allow_unreachable=False (default), dead
    function still returns 'not_called' — preserving the existing
    short-circuit path."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "v.py").write_text(
        "def dead(): cursor.execute('x')\n"
    )
    a = _analyzer()  # default constructor; allow_unreachable defaults False
    verdict = a._check_reachability(_finding("src/v.py", line=1), tmp_path)
    assert verdict == "not_called"


def test_go_handler_registered_via_call_returns_registered_via_call(tmp_path):
    """Go handler passed to http.HandleFunc resolves new
    ``registered_via_call`` verdict instead of ``not_called``."""
    try:
        import tree_sitter_go  # noqa: F401
    except ImportError:
        import pytest
        pytest.skip("tree_sitter_go not installed")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.go").write_text(
        'package main\n'
        'import "net/http"\n'
        'func handler(w http.ResponseWriter, r *http.Request) {\n'
        '\tcursor.Execute(r.URL.Query().Get("q"))\n'
        '}\n'
        'func main() {\n'
        '\thttp.HandleFunc("/x", handler)\n'
        '}\n'
    )
    a = _analyzer()
    # Need a JS / Go finding shape — _finding builds Python-style;
    # for Go we use src/main.go directly.
    from packages.codeql.autonomous_analyzer import CodeQLFinding
    finding = CodeQLFinding(
        rule_id="go/sql-injection", rule_name="x", message="x",
        level="error",
        file_path="src/main.go", start_line=4, end_line=4,
        snippet="cursor.Execute(...)",
    )
    verdict = a._check_reachability(finding, tmp_path)
    assert verdict == "registered_via_call", (
        f"Go handler registered via http.HandleFunc must resolve "
        f"registered_via_call, got {verdict!r}"
    )


# ---------------------------------------------------------------------------
# S4: module-load-abort gate
# ---------------------------------------------------------------------------


def test_reachability_module_aborts_for_sink_below_abort(tmp_path):
    """Sink in a file that raises ImportError at load → the prefilter
    returns the ``module_aborts`` verdict even though a same-file peer
    calls the sink (CALLED in the static graph)."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "disabled.py").write_text(
        "raise ImportError('module disabled')\n"
        "def entry(q):\n"
        "    return sink(q)\n"
        "def sink(q):\n"
        "    cursor.execute(q)\n"
    )
    a = _analyzer()
    verdict = a._check_reachability(_finding("src/disabled.py", line=5), tmp_path)
    assert verdict == "module_aborts", (
        f"sink below a module-load abort must resolve module_aborts, "
        f"got {verdict!r}"
    )


def test_module_abort_trumps_framework_callable_in_prefilter(tmp_path):
    """A Flask route handler below a module-load abort → module_aborts,
    NOT framework_callable (the decorator never runs)."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "api.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "raise ImportError('disabled')\n"
        "\n"
        "@app.route('/users')\n"
        "def list_users():\n"
        "    return cursor.execute(request.args.get('q'))\n"
    )
    a = _analyzer()
    verdict = a._check_reachability(_finding("src/api.py", line=7), tmp_path)
    assert verdict == "module_aborts"


def test_allow_unreachable_suppresses_module_abort(tmp_path):
    """--allow-unreachable disables the module-abort gate too —
    the operator wants in-isolation evaluation."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "disabled.py").write_text(
        "raise ImportError('disabled')\n"
        "def sink(q):\n"
        "    cursor.execute(q)\n"
    )
    a = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(), exploit_validator=MagicMock(),
        multi_turn_analyzer=None, enable_visualization=False,
        allow_unreachable=True,
    )
    # The prefilter still classifies module_aborts (for reporting); under
    # --allow-unreachable the caller's earned set is empty, so it does not
    # hard-suppress (the operator wants in-isolation evaluation).
    verdict = a._check_reachability(_finding("src/disabled.py", line=3), tmp_path)
    assert verdict == "module_aborts"
    assert _suppresses(verdict, earned=frozenset()) is False


def test_function_above_abort_not_module_aborts(tmp_path):
    """A sink whose function is defined ABOVE the abort line must NOT
    get the module_aborts verdict (its def ran before the abort)."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "mixed.py").write_text(
        "def early(q):\n"            # line 1
        "    cursor.execute(q)\n"    # line 2
        "raise SystemExit(1)\n"      # line 3
        "def late(q):\n"            # line 4
        "    cursor.execute(q)\n"   # line 5
    )
    (src / "main.py").write_text(
        "from src.mixed import early\n"
        "early('x')\n"
    )
    a = _analyzer()
    verdict = a._check_reachability(_finding("src/mixed.py", line=2), tmp_path)
    assert verdict != "module_aborts"


# ---------------------------------------------------------------------------
# S3: lexical-dead gate
# ---------------------------------------------------------------------------


def test_reachability_lexical_dead_for_sink_in_if_false(tmp_path):
    """Sink in a function defined inside `if False:` → lexical_dead,
    even though a same-scope peer calls it (CALLED in the graph)."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.py").write_text(
        "if False:\n"
        "    def dead_a(q):\n"
        "        return dead_b(q)\n"
        "    def dead_b(q):\n"
        "        cursor.execute(q)\n"
    )
    a = _analyzer()
    verdict = a._check_reachability(_finding("src/mod.py", line=5), tmp_path)
    assert verdict == "lexical_dead", (
        f"sink inside if False: must resolve lexical_dead, "
        f"got {verdict!r}"
    )


def test_allow_unreachable_suppresses_lexical_dead(tmp_path):
    """--allow-unreachable disables the lexical-dead gate too."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.py").write_text(
        "if False:\n"
        "    def dead(q):\n"
        "        cursor.execute(q)\n"
    )
    a = AutonomousCodeQLAnalyzer(
        llm_client=MagicMock(), exploit_validator=MagicMock(),
        multi_turn_analyzer=None, enable_visualization=False,
        allow_unreachable=True,
    )
    verdict = a._check_reachability(_finding("src/mod.py", line=3), tmp_path)
    assert verdict == "lexical_dead"
    assert _suppresses(verdict, earned=frozenset()) is False
