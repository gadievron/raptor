"""Functional-smoke heuristics — single source of truth for verify-quality
classification.

Holds ``_ACTIVE_PROBE_TYPES``, ``has_functional_smoke``, and
``_compute_verify_quality_warning``. Keeping these separate lets ``verify.py``
focus on plan canonicalisation + step dispatch + per-check execution, while
the success/success_partial classification heuristic lives in one module that
``loop.py`` can import without pulling the rest of ``verify`` into its module
graph.

One-way dep: ``verify -> _smoke``, never the reverse (locked by
``tests/unit/test_refactor_specific.py::test_smoke_module_no_circular_imports``).
"""

from __future__ import annotations

from typing import Any

from cve_env.config import VERSION_ASSERTION_CMD_PATTERN

CheckResult = dict[str, Any]

# The three check types that signal the agent invested beyond minimum
# lifecycle. Drives the ``>= 3 active checks`` branch of
# has_functional_smoke. Locked by
# tests/unit/test_drift_parity.py::test_functional_smoke_heuristic_parity
# (asserts these three are also advertised in prompts.py).
_ACTIVE_PROBE_TYPES: frozenset[str] = frozenset(
    {"http_request_check", "exec_check", "tcp_probe_check"}
)


def has_functional_smoke(results: list[CheckResult]) -> bool:
    """Shared functional-smoke heuristic — single source of truth.

    Returns True iff the passing verify ``results`` show the agent went beyond
    minimum lifecycle checks. This heuristic drives BOTH:

    * ``loop.py::_classify_verify_outcome`` (decides ``success`` vs
      ``success_partial``);
    * :func:`_compute_verify_quality_warning` (emits real-time guidance
      so the agent self-heals during the run; see verify.py).

    Heuristic (any of):

    * ``>= 3`` active-class checks (http_payload / exec / tcp_payload) —
      signal: the agent invested beyond the minimum.
    * ``>= 1`` http_check with ``content_check_performed`` — signal: the
      check actually validated body content, not just status.
    * ``>= 2`` distinct http_check paths/URLs — signal: multi-verb coverage
      (prescribed for HTTP services).

    Single source of truth prevents semantic drift between the two
    enforcement sites that consume it.
    """
    active_count = 0
    http_with_content_count = 0
    distinct_http_paths: set[str] = set()
    for entry in results:
        # A FAILED probe is NOT functional-smoke evidence. A failed *injected*
        # smoke probe is non-fatal and DOES reach grading — counting it would
        # let a broken app + an agent version-assertion grade `success` instead
        # of `verified_partial`. (For a passing verify, agent checks all passed,
        # so this only excludes failed injected smoke — the normal success path
        # is unchanged.)
        if entry.get("passed") is False:
            continue
        t = entry.get("type")
        if t in _ACTIVE_PROBE_TYPES:
            active_count += 1
        if t != "http_check":
            continue
        details = entry.get("details") or {}
        if not isinstance(details, dict):
            continue
        if details.get("content_check_performed"):
            http_with_content_count += 1
        path = details.get("url") or details.get("path")
        if isinstance(path, str) and path:
            distinct_http_paths.add(path)
    return (
        active_count >= 3
        or http_with_content_count >= 1
        or len(distinct_http_paths) >= 2
    )


def _compute_verify_quality_warning(results: list[CheckResult]) -> str:
    """Real-time feedback when a passing verify can't qualify as `success`
    because the build's correctness is unproven.

    The product's goal is to build pre-patch CVE environments at the right
    versions. ``success`` requires BOTH (a) version-assertion exec_check
    (proves the right binaries are deployed) AND (b) functional smoke (proves
    the app's normal operations work on benign input). Active payload checks
    are available primitives but not required for ``success``.

    Returns a non-empty warning string in TWO cases (agent self-heals
    in-band before outcome-time):

    - Missing version-assertion: plan passed but no exec_check command
      matches the version-discovery regex. Outcome will be
      ``success_partial``; add `pip show <pkg>` / `dpkg -l <pkg>` /
      `apache2 -v` / `find / -name '*.jar'` etc.

    - Missing functional smoke: plan passed with only lifecycle checks OR
      only minimum (version + 1 active check). Add 2-3 benign-input
      functional verbs: for HTTP — GET / + GET /<page> with content match +
      GET /<random-404>; for DB — SELECT 1 + INSERT/SELECT roundtrip; for
      libraries — trivial-use exec_check on benign input.

    Empty string means "no warning" (version + smoke both present →
    outcome will be ``success``). Active payload checks count toward the
    smoke heuristic like any other active check.
    """
    has_version_assertion = False
    for entry in results:
        t = entry.get("type")
        if t == "exec_check":
            details = entry.get("details") or {}
            command = details.get("command") if isinstance(details, dict) else None
            if isinstance(command, str) and VERSION_ASSERTION_CMD_PATTERN.search(command):
                has_version_assertion = True
                break  # only need one match
    # Functional-smoke predicate lives in has_functional_smoke()
    # (single source of truth shared with loop.py::_classify_verify_outcome).
    has_smoke = has_functional_smoke(results)
    if not has_version_assertion:
        return (
            "verify passed but no version-assertion exec_check (e.g. 'pip "
            "show <pkg>', 'dpkg -l <pkg>', 'apache2 -v', 'find / -name *.jar'). "
            "Outcome will be verified_partial. For status=success, add an "
            "exec_check pinning the pre-patch version per nvd_lookup."
        )
    if not has_smoke:
        return (
            "verify passed + version asserted, but no functional smoke "
            "(benign-input checks). Outcome will be verified_partial. For "
            "status=success, add 2-3 Phase 48 benign-input verbs: "
            "HTTP GET / + GET /<page> + GET /<404>; DB SELECT 1 + roundtrip; "
            "libraries trivial-use exec_check."
        )
    return ""
