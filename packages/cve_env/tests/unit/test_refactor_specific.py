"""Phase 1.B: refactor-specific lock tests.

Each test pins a contract that one of Phase 2 / 3 / 4 / 5 must preserve.
Tests targeting modules created LATER (e.g. ``_smoke.py``, ``_image_resolve_state.py``)
use ``pytest.importorskip`` so they pass at HEAD and turn green when the
module lands.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import cve_env

# Package source dir, layout-independent (works for the standalone src/cve_env
# tree and the packages/cve_env/cve_env home under raptor).
_PKG = Path(cve_env.__file__).resolve().parent


# ----- Phase 3 contracts ------------------------------------------------------


def _result(
    type_: str,
    *,
    content_check_performed: bool | None = None,
    url: str | None = None,
    passed: bool = True,
) -> dict[str, object]:
    details: dict[str, object] = {}
    if content_check_performed is not None:
        details["content_check_performed"] = content_check_performed
    if url is not None:
        details["url"] = url
    return {"type": type_, "passed": passed, "details": details}


@pytest.mark.parametrize(
    ("a_active_ge3", "b_http_content_ge1", "c_paths_ge2", "expected"),
    [
        (False, False, False, False),
        (False, False, True, True),
        (False, True, False, True),
        (False, True, True, True),
        (True, False, False, True),
        (True, False, True, True),
        (True, True, False, True),
        (True, True, True, True),
    ],
)
def test_has_functional_smoke_truth_table(
    a_active_ge3: bool, b_http_content_ge1: bool, c_paths_ge2: bool, expected: bool
) -> None:
    """All 8 cells of the OR-of-3-predicates truth-table.

    Phase 63.2 heuristic: ``has_functional_smoke`` returns True iff
    ``active_count >= 3`` OR ``http_with_content_count >= 1`` OR
    ``len(distinct_http_paths) >= 2``. Drift in any of the 3 predicates
    silently re-misclassifies success vs success_partial.
    """
    from cve_env.tools.verify import has_functional_smoke

    results: list[dict[str, object]] = []
    if a_active_ge3:
        results += [
            _result("exec_check"),
            _result("http_request_check"),
            _result("tcp_probe_check"),
        ]
    if b_http_content_ge1:
        results.append(_result("http_check", content_check_performed=True, url="/x"))
    if c_paths_ge2:
        results.append(_result("http_check", url="/p1"))
        results.append(_result("http_check", url="/p2"))

    assert has_functional_smoke(results) is expected  # type: ignore[arg-type]


def test_has_functional_smoke_ignores_failed_probes() -> None:
    """P8-C-01 follow-on (independent-review finding, 2026-06-02): a FAILED smoke
    probe is NOT functional-smoke evidence. After P8-C-01 made injected smoke
    non-fatal, failed injected probes reach grading; counting them would let a
    broken app (e.g. 500 on /) + an agent version-assertion grade ``success``
    instead of ``verified_partial``. has_functional_smoke must skip passed=False
    entries.
    """
    from cve_env.tools.verify import has_functional_smoke

    # 2 distinct-path http_checks but BOTH failed -> not evidence.
    assert (
        has_functional_smoke(
            [
                _result("http_check", url="/", passed=False),
                _result("http_check", url="/nope404", passed=False),
            ]
        )
        is False
    )
    # a failed content-check probe -> not evidence.
    assert (
        has_functional_smoke(
            [
                _result(
                    "http_check", content_check_performed=True, url="/x", passed=False
                )
            ]
        )
        is False
    )
    # 3 failed active probes -> not evidence.
    assert (
        has_functional_smoke(
            [
                _result("exec_check", passed=False),
                _result("http_request_check", passed=False),
                _result("tcp_probe_check", passed=False),
            ]
        )
        is False
    )
    # sanity: the SAME shapes PASSING still count.
    assert (
        has_functional_smoke(
            [_result("http_check", url="/a"), _result("http_check", url="/b")]
        )
        is True
    )


def test_smoke_module_no_circular_imports() -> None:
    """Post-Phase-3, ``_smoke.py`` must NOT import from ``verify``.

    One-way dep: ``verify -> _smoke``, never the reverse. Skips until the
    module is created in Phase 3a.
    """
    pytest.importorskip("cve_env.tools._smoke")
    smoke_text = (_PKG / "tools" / "_smoke.py").read_text()
    tree = ast.parse(smoke_text)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "verify" not in node.module.split("."), (
                f"_smoke.py imports from {node.module!r} — circular dep risk."
            )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                assert "verify" not in alias.name.split("."), (
                    f"_smoke.py imports {alias.name!r} — circular dep risk."
                )


def test_verify_retry_self_heal_contract() -> None:
    """F3 finding: 10/16 May 4 successes used Pattern A verify-retry.

    When ``verify`` returns ``passed=False`` because of a missing arg, an
    agent that retries with adjusted args must reach ``passed=True``. We
    cannot run a real LLM here, so we lock the property at the
    ``has_functional_smoke`` boundary: the same heuristic must be reachable
    on a 2nd attempt with more checks (i.e. the heuristic is monotonic in
    the count of qualifying checks).
    """
    from cve_env.tools.verify import has_functional_smoke

    attempt1: list[dict[str, object]] = [_result("http_check", url="/")]
    assert has_functional_smoke(attempt1) is False  # type: ignore[arg-type]

    attempt2: list[dict[str, object]] = attempt1 + [
        _result("http_check", url="/health"),
    ]
    assert has_functional_smoke(attempt2) is True, (  # type: ignore[arg-type]
        "Adding a 2nd distinct http_check path must flip smoke to True. "
        "If this regresses, retry-self-heal pattern A breaks."
    )


# ----- Phase 4 contracts ------------------------------------------------------


def test_image_resolve_state_module_self_contained() -> None:
    """Post-Phase-4, ``_image_resolve_state.py`` must NOT import from
    ``image_resolve``. One-way dep: image_resolve -> _state only.
    """
    pytest.importorskip("cve_env.tools._image_resolve_state")
    state_text = (_PKG / "tools" / "_image_resolve_state.py").read_text()
    tree = ast.parse(state_text)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "image_resolve" not in node.module.replace(
                "_image_resolve_state", "X"
            ), f"_image_resolve_state.py imports {node.module!r} — circular dep."


def test_image_resolve_uses_state_via_helpers() -> None:
    """Post-Phase-4, ``image_resolve.py`` must NOT contain ``global _RATE_LIMIT_*``
    statements — the moved globals must be accessed via helpers in ``_state.py``.

    Mock #2 finding 2: ``global`` keyword leftovers cause silent NameError at
    runtime; G4 doesn't catch them. AST scan is the lock.
    """
    image_resolve_path = _PKG / "tools" / "image_resolve.py"
    state_path = _PKG / "tools" / "_image_resolve_state.py"
    if not state_path.exists():
        pytest.skip("Phase 4 not yet landed; _image_resolve_state.py missing")

    moved_names = {
        "_RATE_LIMIT_BUDGET",
        "_RATE_LIMIT_TOTAL",
        "_RATE_LIMIT_COOLDOWN_DONE",
        "_TRANSPORT_COOLDOWN_DONE",
        "_ARCH_INCOMPATIBLE_TOTAL",
    }
    tree = ast.parse(image_resolve_path.read_text())
    leftovers: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            for name in node.names:
                if name in moved_names:
                    leftovers.append(name)
    assert not leftovers, (
        f"image_resolve.py still has `global` for moved names: {leftovers}. "
        f"Mock #2 finding 2 — these will silently NameError at runtime."
    )


# ----- Phase 2 contract -------------------------------------------------------


# 30+ representative exec_check commands from real CVE benches; expected v-tag
# AGAINST THE CURRENT (cli.py) regex. Phase 2 MERGE must preserve the same
# tags: missing alternations in the merge surface as a tag flip here.
_V_TAG_CASES: list[tuple[str, str]] = [
    # V — version-assertion (current cli.py regex matches these)
    ("apache2ctl -M", "V"),
    ("httpd -M", "V"),
    ("nginx -V", "V"),
    ("php --version", "V"),
    ("php -m", "V"),
    ("java -version", "V"),
    ("python3 --version", "V"),
    ("dpkg -l libssl1.1", "V"),
    ("rpm -q openssl", "V"),
    ("apt-cache policy openssl", "V"),
    ("pip show flask", "V"),
    ("npm ls jquery", "V"),
    ("gem list rails", "V"),
    ("bundle list rails", "V"),
    ("go version", "V"),
    ("find /opt -name '*.jar'", "V"),
    ("unzip -p app.jar META-INF/MANIFEST.MF", "V"),
    ("grep -i 'const VERSION' /var/www/html/core/lib/Drupal.php", "V"),
    ("cat /etc/version", "V"),  # \bversion\b matches
    # A — active exec_check (no version pattern)
    ("ls /var/www/html", "A"),
    ("ps aux", "A"),
    ("curl http://target/admin", "A"),
    ("id", "A"),
    ("whoami", "A"),
    ("ls /tmp/uploads", "A"),
    ("cat /proc/cpuinfo", "A"),
    ("test -f /etc/passwd", "A"),
    ("env | grep PATH", "A"),
    ("uname -a", "A"),
    ("hostname", "A"),
    ("date", "A"),
]


def test_connection_reset_pattern_consistent_across_modules() -> None:
    """Phase 6.1 fix: both image_resolve._TRANSIENT_PATTERNS and
    _failure_class._TRANSPORT_PATTERNS must match canonical 'connection reset'
    Docker stderr strings.

    Pre-fix divergence: image_resolve used r"connection reset" (no word boundary);
    _failure_class used r"\bconnection reset\b". Both now use word-boundary form.
    If either module reverts or a new copy is introduced, this test fails.
    """
    from cve_env.tools._failure_class import _TRANSPORT_PATTERNS
    from cve_env.tools.image_resolve import _TRANSIENT_PATTERNS

    canonical = [
        "connection reset by peer",
        "Error: connection reset by remote host",
        "read tcp 10.0.0.1:443: connection reset",
    ]
    for text in canonical:
        assert any(p.search(text) for p in _TRANSIENT_PATTERNS), (
            f"image_resolve._TRANSIENT_PATTERNS missed: {text!r}"
        )
        assert any(p.search(text) for p in _TRANSPORT_PATTERNS), (
            f"_failure_class._TRANSPORT_PATTERNS missed: {text!r}"
        )


def test_v_tag_behavioral_equivalence_pre_post_merge() -> None:
    """Phase 2 MERGE must preserve [V]/[A] classification for ≥30 commands.

    cli.py's current regex is the BASELINE. Phase 2 replaces it with
    config.py's ``VERSION_ASSERTION_CMD_PATTERN`` (which has more
    alternations). Test asserts: every command currently tagged V stays V;
    every command currently tagged A stays A — UNLESS the new pattern
    intentionally widens (in which case the test must be updated in the
    same commit).
    """
    from cve_env.cli import _classify_check  # type: ignore[attr-defined]

    misclassified: list[tuple[str, str, str]] = []
    for cmd, expected in _V_TAG_CASES:
        got = _classify_check("exec_check", {"command": cmd})
        if got != expected:
            misclassified.append((cmd, expected, got))
    assert not misclassified, (
        f"v-tag classification drift: {misclassified}. "
        f"Phase 2 MERGE must preserve every existing V/A tag."
    )
    assert len(_V_TAG_CASES) >= 30, "Need >=30 cases per Phase 2 plan"


# ----- 1.D infrastructure tests -----------------------------------------------


def test_public_api_imports_stable() -> None:
    """1.D: the 6 critical import paths that other code and tests depend on
    must remain importable. Catches module renames and __all__ removals."""
    import importlib

    # critical paths: module path → symbol
    critical = {
        "cve_env.tools.verify": [
            "check_http",
            "check_exec",
            "check_logs",
            "check_http_request",
            "check_tcp_probe",
            "verify",
        ],
        "cve_env.tools._failure_class": [
            "classify_docker_stderr",
            "is_retry_eligible",
            "DockerFailureClass",
        ],
        "cve_env.tools._smoke": ["has_functional_smoke", "_ACTIVE_PROBE_TYPES"],
        "cve_env.agent.prompts": ["SYSTEM_PROMPT"],
        "cve_env.tools.image_resolve": ["image_resolve", "image_resolve_to_payload"],
        "cve_env.tools._image_resolve_state": ["reset_rate_limit_budget"],
    }
    missing: list[str] = []
    for module_path, symbols in critical.items():
        try:
            mod = importlib.import_module(module_path)
        except ImportError as exc:
            missing.append(f"cannot import {module_path}: {exc}")
            continue
        for sym in symbols:
            if not hasattr(mod, sym):
                missing.append(f"{module_path}.{sym} missing")
    assert not missing, f"Public API stability violations: {missing}"
