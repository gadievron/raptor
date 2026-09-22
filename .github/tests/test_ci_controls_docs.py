"""Keep the CI controls docs tied to real repo controls."""

from __future__ import annotations

import sys
from pathlib import Path

# tomllib is stdlib on 3.11+; older interpreters need the `tomli` backport.
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover — env-dependent
    import tomli as tomllib


REPO = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (REPO / relative).read_text(encoding="utf-8")


def test_ruff_rules_live_in_root_pyproject() -> None:
    config = tomllib.loads(_read("pyproject.toml"))
    assert config["tool"]["ruff"]["target-version"] == "py310"
    assert config["tool"]["ruff"]["lint"]["select"] == [
        "F401",
        "F811",
        "F821",
        "F841",
    ]


def test_lint_workflow_uses_ruff_config_instead_of_inline_rule_flags() -> None:
    workflow = _read(".github/workflows/lint.yml")
    assert "ruff check --select" not in workflow
    assert workflow.count("ruff check --output-format=github") == 2


def test_readme_links_to_ci_controls_doc() -> None:
    readme = _read("README.md")
    assert "## How RAPTOR checks itself" in readme
    assert "docs/ci-controls.md" in readme


def test_documented_control_paths_exist() -> None:
    required = [
        "pyproject.toml",
        "pytest.ini",
        ".github/workflows/lint.yml",
        ".github/workflows/tests.yml",
        ".github/workflows/nightly.yml",
        ".github/workflows/nightly_shuffled.yml",
        ".github/workflows/preflight.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/miswiring-scan.yml",
        ".github/workflows/corpus-labels.yml",
        ".github/workflows/sca-pr-gate.yml",
        ".github/workflows/sca-self-bump.yml",
        ".github/workflows/sca-compromise-check.yml",
        ".github/workflows/sca-stress-sweep.yml",
        ".github/workflows/refresh-sca-calibration.yml",
        ".github/workflows/refresh-sca-project-samples.yml",
        ".github/workflows/refit-sca-calibration.yml",
        ".github/workflows/refresh-sca-data.yml",
        ".github/workflows/typosquat-reaudit.yml",
        ".github/workflows/weekly_corpus.yml",
        ".github/workflows/sandbox-matrix.yml",
        ".github/workflows/sandbox-matrix-image.yml",
        ".github/workflows/nightly-self-test.yml",
        ".github/workflows/ubuntu26-canary.yml",
        ".github/scripts/check_command_metadata.py",
        ".github/scripts/check_miswiring.py",
        ".github/scripts/check_env_docs.py",
        ".github/scripts/check_vocab_lists.py",
        ".github/scripts/check_optional_dep_imports.py",
        ".github/scripts/test_scope.py",
        ".github/scripts/codeql_scope.py",
        ".github/scripts/sarif_known_fp_suppressions.py",
        ".github/scripts/miswiring_baseline.json",
        ".github/scripts/vocab_baseline.json",
        ".github/scripts/env_docs_baseline.json",
        ".github/scripts/optional_dep_imports_baseline.json",
        ".github/codeql/codeql-config.yml",
        "core/security/tests/test_prompt_envelope_audit.py",
        "test/data/sca-e2e/compromise-corpus",
        "packages/sca/data/calibration",
        "packages/sca/data/calibration/stress_baseline.json",
        ".semgrepignore",
    ]

    missing = [path for path in required if not (REPO / path).exists()]
    assert not missing, f"CI controls docs point at missing paths: {missing}"


# Workflows that are legitimately absent from docs/ci-controls.md: they
# build or ship artifacts rather than verify the tree, so they are not
# CI *controls*. Everything else under .github/workflows/ must be
# referenced in the doc — the required-paths list above only checks
# docs -> disk, so without this inverse gate a workflow (or its doc row)
# can silently drop out of the controls doc.
_WORKFLOWS_EXEMPT_FROM_CONTROLS_DOC = {
    # Reusable callee only — the tests.yml tiers that call it are the
    # documented control; it has no trigger of its own.
    "_tier.yml",
    # Publish/infrastructure surfaces, not verification controls.
    "ci-deps-image.yml",
    "dockerhub-publish.yml",
    "release.yml",
}


def test_every_workflow_is_referenced_in_ci_controls_doc() -> None:
    # Anchored on the doc's link form, not bare-name substring
    # presence: `wf.name in doc` would also be satisfied by a future
    # workflow whose name is a substring of existing doc text.
    doc = _read("docs/ci-controls.md")
    missing = sorted(
        wf.name
        # ``*.y*ml``: GHA accepts both workflow extensions — a .yaml
        # workflow must not escape the universe (same idiom as the
        # token/checkout gates below).
        for wf in (REPO / ".github/workflows").glob("*.y*ml")
        if wf.name not in _WORKFLOWS_EXEMPT_FROM_CONTROLS_DOC
        and f"(../.github/workflows/{wf.name})" not in doc
    )
    assert not missing, (
        "workflows missing from docs/ci-controls.md (document them "
        "with a (../.github/workflows/<name>) link or, for "
        "publish/infra surfaces only, add them to "
        f"_WORKFLOWS_EXEMPT_FROM_CONTROLS_DOC): {missing}"
    )


import re as _re

# Scheduled workflows whose cadence is documented in PR-gate prose
# (a bullet naming the cron) rather than a scheduled-table row —
# their schedule is a secondary re-run of a control whose primary
# documentation home is the gates list. Each row needs a rationale;
# liveness is asserted (the prose line must still carry the link AND
# a cadence word), so a stale row cannot outlive its bullet.
_SCHEDULED_CADENCE_PROSE_DOCUMENTED = {
    # "Full-tree Python lint audit" bullet: the weekly cron re-runs
    # the same ruff audit the push-time job runs.
    "lint.yml": "full-tree lint audit bullet names the weekly cron",
    # "Code scanning" bullet: the weekly cron is a re-run of the
    # PR/push CodeQL control.
    "codeql.yml": "code-scanning bullet names the weekly cron",
}

_CADENCE_WORD_RE = _re.compile(
    r"\b(daily|weekly|monthly|nightly|cron)\b", _re.IGNORECASE
)


def test_scheduled_workflows_keep_a_cadence_documented_reference() -> None:
    """Every workflow with a ``schedule:`` trigger must hold a doc
    reference IN CADENCE CONTEXT — a scheduled-table row (a ``|``
    table line carrying its link and a cadence word), or an
    adjudicated prose bullet with the same content. The whole-doc
    substring gate above is vacuous against row-stripping for
    multiply-referenced workflows (tests.yml carries 15 references;
    deleting its scheduled-table row passed), so the row/cadence
    grain is pinned separately here.

    Grain bound, stated honestly: only the SCHEDULED reference is
    pinned to its context. A multiply-referenced workflow's
    non-cadence rows (hardening-practices table, PR-gate bullets)
    can still be stripped with this gate green — pinning every
    reference's row membership would freeze the doc's prose. The
    cadence-word match strips the workflow's own filename first so
    nightly*/weekly_* names cannot self-satisfy it.
    """
    doc = _read("docs/ci-controls.md")
    lines = doc.splitlines()
    offenders: list[str] = []
    checked = 0
    for wf in sorted((REPO / ".github/workflows").glob("*.y*ml")):
        if wf.name in _WORKFLOWS_EXEMPT_FROM_CONTROLS_DOC:
            continue
        if not _re.search(
            r"(?m)^\s{0,4}schedule:\s*(#.*)?$",
            wf.read_text(encoding="utf-8"),
        ):
            continue
        checked += 1
        link = f"(../.github/workflows/{wf.name})"

        def _cadence_line(ln: str) -> bool:
            return link in ln and bool(
                _CADENCE_WORD_RE.search(ln.replace(wf.name, ""))
            )

        if wf.name in _SCHEDULED_CADENCE_PROSE_DOCUMENTED:
            if not any(
                _cadence_line(ln) for ln in lines
                if not ln.lstrip().startswith("|")
            ):
                offenders.append(
                    f"{wf.name}: prose-documented adjudication went "
                    "stale (no non-table doc line carries its link + "
                    "a cadence word)"
                )
            continue
        if not any(
            _cadence_line(ln) for ln in lines
            if ln.lstrip().startswith("|")
        ):
            offenders.append(
                f"{wf.name}: scheduled workflow without a scheduled-"
                "table row (a | table line carrying its link and its "
                "cadence)"
            )
    assert checked >= 10, (
        f"scheduled-workflow enumeration broke (found {checked})"
    )
    assert not offenders, (
        "scheduled workflows lost their cadence-context doc row:\n"
        + "\n".join(offenders)
    )


def test_project_samples_collector_total_failure_reddens() -> None:
    # Partial failure proceeds to the diff/PR step; TOTAL failure
    # (nonzero collector exit AND no sample file changed) must fail
    # the step — an unconditional exit-code discard made a dead
    # collector (crash-at-import, all samples failed) read green
    # forever, the rot class the calibration refresh already guards.
    wf = _read(".github/workflows/refresh-sca-project-samples.yml")
    step = wf.split("- name: Collect samples", 1)[1].split("- name:", 1)[0]
    assert "rc=$?" in step
    assert 'exit "$rc"' in step
    assert "git diff --quiet -- packages/sca/data/calibration/project_samples/" in step
    assert "\n          true\n" not in step


def test_nightly_toolchain_installs_carry_refuse_backstops() -> None:
    """Both nightly workflows install external toolchains with
    continue-on-error (a transient mirror outage must not discard the
    tool-independent signal), and their tool-dependent test families
    skip-with-reason when the binaries are absent — so a persistently
    broken install reads as a green nightly with those families never
    executing. Each such workflow must carry the post-run
    refuse-backstop that verifies the tools actually landed
    (nightly.yml's pattern; nightly-self-test.yml lacked it)."""
    for wf in (
        ".github/workflows/nightly.yml",
        ".github/workflows/nightly-self-test.yml",
    ):
        text = _read(wf)
        assert "continue-on-error: true" in text, wf
        assert "Refuse a toolchain-less" in text, (
            f"{wf}: continue-on-error toolchain install without a "
            "refuse-backstop step — a broken install becomes "
            "permanent green skips"
        )
        assert "command -v r2" in text, wf
        assert "if: ${{ !cancelled() }}" in text, wf


# Write-capable default-token permission scopes. Universe ENTRY is
# shape-derived, never enumerated: ANY ``<scope>: write`` grant
# inside a permissions block — or the ``write-all`` umbrella — puts
# the holding job in the gate's universe. GitHub's documented scope
# vocabulary (GitHub Docs: "Controlling permissions for GITHUB_TOKEN"
# + workflow-syntax ``permissions:``; transcribed 2026-09-21:
# actions, attestations, checks, contents, deployments, discussions,
# id-token, issues, models, packages, pages, pull-requests,
# repository-projects, security-events, statuses) has grown before
# (attestations, models) and a typed alternation left every grant
# under a newer scope outside BOTH gates — a ``models: write`` job's
# default token escaped the walk entirely, recreating one level up
# the exact enumeration-bound entry that let ``packages: write``
# (push authority over the GHCR images every container-path CI tier
# then executes) and ``pull-requests: write`` / ``issues: write``
# escape the original contents-only filter. Scope names are matched
# generically; AUTHORITY stays default-deny in _SCOPE_PUBLISH_VERBS
# (an unknown scope enters the universe but blesses nothing).
_WRITE_SCOPE_RE = _re.compile(r"\b([\w-]+)\s*:\s*write\b")
# Grants are anchored on the token VALUE, any key name, any nesting
# level (step/job/workflow ``env:``, ``with: token:``, ...): matching
# only well-known env key names let a rename or a hoisted env block
# re-grant the token with the gate green.
_DEFAULT_TOKEN_RE = _re.compile(
    r"\$\{\{\s*(?:secrets\.GITHUB_TOKEN|github\.token)\s*\}\}"
)
# Publish/manage verbs PER SCOPE: a step is blessed only when its body
# performs a publish operation of a scope its job actually holds — a
# ``gh issue`` mention must not bless a step in a contents:write job
# (commenting on issues is not a publish operation that needs the
# contents scope), and vice versa. ``push --force`` covers
# release.yml's line-wrapped ``git -c http...extraheader \ push
# --force`` invocation. ``packages/container`` blesses the GHCR
# package-management API steps (visibility check, version retention)
# that legitimately carry the packages-scope token; like the heredoc
# boundary below, a parse step would need that coincidental path text
# to slip through. Scopes with NO row here (security-events, pages,
# ...) are default-deny: every grant in a job holding only such
# scopes is an offender until an adjudicated verb row is added.
_SCOPE_PUBLISH_VERBS: dict[str, str] = {
    "contents": r"git push|push --force|gh release",
    "pull-requests": r"gh pr ",
    "packages": r"docker login|docker push|packages/container",
    "issues": r"gh issue ",
}


def _scopes_at(lines: list[str], i: int) -> set[str]:
    """Write scopes granted by the ``permissions:`` key at ``lines[i]``
    (inline map, ``write-all``, or the indented block that follows).
    An explicit block granting nothing returns an empty set — a
    job-level block REPLACES the workflow default entirely."""
    ln = lines[i]
    indent = len(ln) - len(ln.lstrip())
    rest = ln.split("permissions:", 1)[1].split(" #", 1)[0].strip()
    scopes: set[str] = set()
    if rest:
        if "write-all" in rest:
            scopes.add("write-all")
        scopes.update(m.group(1) for m in _WRITE_SCOPE_RE.finditer(rest))
        return scopes
    for nxt in lines[i + 1:]:
        s = nxt.strip()
        if not s:
            continue
        if len(nxt) - len(nxt.lstrip()) <= indent:
            break
        if s.startswith("#"):
            continue
        m = _WRITE_SCOPE_RE.search(nxt.split(" #", 1)[0])
        if m:
            scopes.add(m.group(1))
        if "write-all" in nxt.split(" #", 1)[0]:
            scopes.add("write-all")
    return scopes


def _job_ranges(lines: list[str]) -> list[tuple[int, int]]:
    """[start, end) line ranges of every job under the ``jobs:`` key.
    Job ids are the mapping keys at the first child indent; anything
    deeper is job body, a dedent to ``jobs:``'s level ends the block."""
    ranges: list[tuple[int, int]] = []
    jobs_indent: int | None = None
    job_indent: int | None = None
    open_start: int | None = None
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip())
        if jobs_indent is None:
            if _re.match(r"^jobs:\s*(#.*)?$", ln):
                jobs_indent = indent
            continue
        if indent <= jobs_indent:
            if open_start is not None:
                ranges.append((open_start, i))
                open_start = None
            jobs_indent = None
            job_indent = None
            continue
        if job_indent is None:
            job_indent = indent
        if indent == job_indent and _re.match(r"^\s*[\w.-]+:\s*(#.*)?$", ln):
            if open_start is not None:
                ranges.append((open_start, i))
            open_start = i
    if open_start is not None:
        ranges.append((open_start, len(lines)))
    return ranges


def _job_write_scopes(lines: list[str]) -> list[tuple[int, int, set[str]]]:
    """(start, end, effective write scopes) per job.

    Job-level ``permissions:`` blocks REPLACE the workflow-level block
    (GitHub's model); a job with no block inherits the workflow's.
    ``permissions:`` is only legal at workflow and job level, so any
    ``permissions:`` key at a job's body indent is that job's block —
    deeper spellings (step ``with:`` inputs, run-body text) are not.
    Workflows with NO permissions block anywhere inherit the repo
    default, which this repo keeps read-only (declared boundary)."""
    workflow_scopes: set[str] = set()
    ranges = _job_ranges(lines)
    for i, ln in enumerate(lines):
        if _re.match(r"^permissions:", ln) and not any(
            r[0] <= i < r[1] for r in ranges
        ):
            workflow_scopes = _scopes_at(lines, i)
            break
    out: list[tuple[int, int, set[str]]] = []
    for start, end in ranges:
        job_key_indent = len(lines[start]) - len(lines[start].lstrip())
        scopes = workflow_scopes
        body_indent: int | None = None
        for i in range(start + 1, end):
            ln = lines[i]
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            indent = len(ln) - len(ln.lstrip())
            if body_indent is None and indent > job_key_indent:
                body_indent = indent
            if (
                body_indent is not None
                and indent == body_indent
                and _re.match(r"^\s*permissions:", ln)
            ):
                scopes = _scopes_at(lines, i)
                break
        out.append((start, end, scopes))
    return out


def _publish_verbs_re(scopes: set[str]) -> _re.Pattern[str] | None:
    """Union publish-verb regex for the scopes a job holds (None =
    no blessed verbs; every grant in the job is then an offender)."""
    if "write-all" in scopes:
        parts = sorted(set(_SCOPE_PUBLISH_VERBS.values()))
    else:
        parts = sorted(
            {_SCOPE_PUBLISH_VERBS[s] for s in scopes
             if s in _SCOPE_PUBLISH_VERBS}
        )
    return _re.compile("|".join(parts)) if parts else None


def _step_ranges(lines: list[str]) -> list[tuple[int, int]]:
    """Step segmentation: [start, end) line ranges of every step.
    Anchored on the ``steps:`` key; list items are the dashes at
    the FIRST item's exact indent (deeper dashes are run-body
    content, shallower lines end the block — a block end also
    closes the last step so it can never swallow the next job's
    job-level ``env:``)."""
    steps: list[tuple[int, int]] = []
    steps_indent: int | None = None
    item_indent: int | None = None
    open_start: int | None = None
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        if not stripped:
            continue
        indent = len(ln) - len(ln.lstrip())
        if steps_indent is not None:
            if indent <= steps_indent:
                if open_start is not None:
                    steps.append((open_start, i))
                    open_start = None
                steps_indent = None
                item_indent = None
            else:
                if stripped.startswith("- ") and (
                    item_indent is None or indent == item_indent
                ):
                    if item_indent is None:
                        item_indent = indent
                    if open_start is not None:
                        steps.append((open_start, i))
                    open_start = i
                continue
        if _re.match(r"^\s*steps:\s*(#.*)?$", ln):
            steps_indent = indent
            item_indent = None
    if open_start is not None:
        steps.append((open_start, len(lines)))
    return steps


def _default_token_offenders(workflows_dir: Path) -> tuple[list[str], int]:
    """(offender descriptions, grants checked) for every JOB in
    *workflows_dir* whose effective permissions hold a write-capable
    default token.

    Job-aware: a job's effective permissions are its own
    ``permissions:`` block when present, else the workflow-level one
    (GitHub's replace-not-merge model) — so a read-only job beside a
    write job (codeql.yml's scope jobs vs its upload job) is outside
    the universe, and a job-level write grant in a read-default
    workflow is inside it.

    Default-deny within the universe: ANY non-comment line carrying
    the default-token value must lie inside a step whose body performs
    a publish operation OF A SCOPE THE JOB HOLDS on a non-comment
    line. Everything else — job-level or workflow-level ``env:``
    (which hands the token to EVERY step), grants in steps without a
    publish command, grants under renamed keys or ``with:`` inputs,
    verbs of scopes the job does not hold — is an offender. A grant
    outside every job (workflow-level ``env:``) is an offender
    whenever ANY job of the workflow is in the universe. Step
    boundaries are anchored on the ``steps:`` key + list-dash
    indentation, not on first-key names (``name``/``id`` are optional
    and keys are order-free in GHA).
    """
    offenders: list[str] = []
    checked = 0
    # ``*.y*ml``: GHA accepts both workflow extensions — a .yaml
    # workflow must not escape the universe.
    for wf in sorted(workflows_dir.glob("*.y*ml")):
        lines = wf.read_text(encoding="utf-8").splitlines()
        jobs = _job_write_scopes(lines)
        if not any(scopes for _, _, scopes in jobs):
            continue
        steps = _step_ranges(lines)

        def _step_publishes(
            rng: tuple[int, int], verbs: _re.Pattern[str] | None
        ) -> bool:
            # Comments never bless a step: full-line comments are
            # skipped and trailing ``  # ...`` tails are stripped
            # before the publish match. Declared boundary: publish
            # text inside a heredoc or string literal in the run body
            # still matches (a token-granted parse step would need
            # that coincidental content to slip through — compound
            # accident, documented rather than parsed).
            if verbs is None:
                return False
            return any(
                verbs.search(body_ln.split(" #", 1)[0])
                for body_ln in lines[rng[0]:rng[1]]
                if not body_ln.lstrip().startswith("#")
            )

        for i, ln in enumerate(lines):
            if ln.lstrip().startswith("#"):
                continue
            if not _DEFAULT_TOKEN_RE.search(ln):
                continue
            job = next(
                (j for j in jobs if j[0] <= i < j[1]), None
            )
            if job is not None and not job[2]:
                continue  # read-only job — outside the universe
            checked += 1
            if job is None:
                offenders.append(
                    f"{wf.name}:{i + 1}: default-token grant outside "
                    f"any job (workflow scope, reaches the write "
                    f"job(s)): {ln.strip()}"
                )
                continue
            rng = next(
                (r for r in steps if r[0] <= i < r[1]
                 and job[0] <= r[0] < job[1]), None
            )
            if rng is None:
                offenders.append(
                    f"{wf.name}:{i + 1}: default-token grant outside "
                    f"any step (job scope, write-capable job): "
                    f"{ln.strip()}"
                )
            elif not _step_publishes(rng, _publish_verbs_re(job[2])):
                offenders.append(
                    f"{wf.name}:{i + 1}: default-token grant in a "
                    f"non-publish step of a write-capable job "
                    f"(scopes: {', '.join(sorted(job[2]))}): {ln.strip()}"
                )
    return offenders, checked


def test_write_token_confined_to_publish_steps() -> None:
    """In jobs holding a write-capable default token — ANY
    ``<scope>: write`` grant, not just contents — only publish steps
    of the granted scope(s) may carry it.

    Permissions are job-wide by GitHub's model, so the confinement IS
    the handoff: a run step that fetches and parses untrusted
    registry/network data with the default token in reach hands a
    credential that can push branches, open PRs, or push the GHCR
    images every container-path CI tier executes, to exactly the code
    most likely to hit a parsing bug (the sca-self-bump harden/bump
    phases carried one for rate limits alone).

    Declared boundaries: reusable-workflow / composite-action
    indirection (``secrets: inherit``, ``uses:`` inputs resolved in
    another file) is not followed — none is used by the write-
    permission workflows today; workflows with NO permissions block
    anywhere inherit the repo default, which this repo keeps
    read-only; publish text inside a heredoc or string literal can
    still bless a step (see _step_publishes), and so can a
    ``packages/container`` API path literal in a packages-scope job
    (same compound-accident class); write scopes with no
    _SCOPE_PUBLISH_VERBS row are default-deny (no step can be blessed
    in a job holding only those).
    """
    offenders, checked = _default_token_offenders(
        REPO / ".github/workflows"
    )
    assert checked >= 2, "token-grant enumeration broke (none found)"
    assert not offenders, (
        "write-capable default token reachable outside publish steps:\n"
        + "\n".join(offenders)
        + "\n— confine the token to the push/PR/release steps (the "
        "refresh-sca-* pattern) so untrusted-data parsing runs tokenless"
    )


_CHECKOUT_USES_RE = _re.compile(r"^\s*(?:-\s+)?uses:\s*\S*actions/checkout")
_PERSIST_FALSE_RE = _re.compile(r"^\s*persist-credentials:\s*false\s*(#.*)?$")


def _checkout_persistence_offenders(
    workflows_dir: Path,
) -> tuple[list[str], int]:
    """(offender descriptions, checkout steps checked) — every
    ``actions/checkout`` step in a write-capable job must carry
    ``persist-credentials: false``.

    ``actions/checkout`` persists the default token into
    ``.git/config`` by DEFAULT (``persist-credentials: true``) — no
    token text appears anywhere in the workflow — handing every
    subsequent step of the job a push-capable credential. That is an
    ungated re-grant channel the token-VALUE gate above cannot see:
    one hoisted or new checkout without the opt-out re-hands the token
    to the untrusted-parsing phases with CI green. Before this arm the
    live write-permission workflows defended the channel only by hand
    (each carried the opt-out with a comment naming exactly this
    risk); nothing mechanical enforced it. Same job-aware universe as
    ``_default_token_offenders``: a checkout in a read-only job beside
    a write job persists only that job's read token and stays outside
    the gate's rationale.
    """
    offenders: list[str] = []
    checked = 0
    for wf in sorted(workflows_dir.glob("*.y*ml")):
        lines = wf.read_text(encoding="utf-8").splitlines()
        jobs = _job_write_scopes(lines)
        if not any(scopes for _, _, scopes in jobs):
            continue
        steps = _step_ranges(lines)
        for start, end in steps:
            job = next((j for j in jobs if j[0] <= start < j[1]), None)
            if job is None or not job[2]:
                continue
            uses_line = next(
                (
                    i for i in range(start, end)
                    if not lines[i].lstrip().startswith("#")
                    and _CHECKOUT_USES_RE.match(lines[i].split(" #", 1)[0])
                ),
                None,
            )
            if uses_line is None:
                continue
            checked += 1
            opted_out = any(
                _PERSIST_FALSE_RE.match(lines[i])
                for i in range(start, end)
                if not lines[i].lstrip().startswith("#")
            )
            if not opted_out:
                offenders.append(
                    f"{wf.name}:{uses_line + 1}: actions/checkout in a "
                    f"write-capable job (scopes: "
                    f"{', '.join(sorted(job[2]))}) without "
                    f"persist-credentials: false — the default persists "
                    f"the write token into .git/config for every "
                    f"subsequent step"
                )
    return offenders, checked


def test_checkout_persists_no_credentials_in_write_jobs() -> None:
    """Every ``actions/checkout`` step in a write-capable job carries
    ``persist-credentials: false`` — the credential-persistence
    default is an ungated re-grant channel the token-value gate cannot
    see (see _checkout_persistence_offenders)."""
    offenders, checked = _checkout_persistence_offenders(
        REPO / ".github/workflows"
    )
    assert checked >= 2, "checkout enumeration broke (none found)"
    assert not offenders, (
        "checkout credential persistence in write-capable job(s):\n"
        + "\n".join(offenders)
        + "\n— add `persist-credentials: false` to the checkout's "
        "`with:` block (see release.yml / sca-self-bump.yml for the "
        "explicit-token publish pattern that replaces it)"
    )


def test_checkout_persistence_gate_flags_hostile_shapes(tmp_path) -> None:
    """Both hostile spellings — persist-credentials unset (the
    actions/checkout DEFAULT) and an explicit true — must be
    offenders; the opted-out spelling and read-only-job checkouts must
    not."""
    default_checkout = """\
permissions:
  contents: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - name: parse untrusted registry data
        run: |
          python parse_registry.py
"""
    explicit_true = """\
permissions:
  packages: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@v6
        with:
          persist-credentials: true
      - name: build image
        run: |
          docker build -t img .
"""
    for name, content in (
        ("default_checkout", default_checkout),
        ("explicit_true", explicit_true),
    ):
        wf_dir = tmp_path / name
        wf_dir.mkdir()
        (wf_dir / "hostile.yml").write_text(content, encoding="utf-8")
        offenders, checked = _checkout_persistence_offenders(wf_dir)
        assert checked == 1, f"{name}: checkout not even counted"
        assert offenders, f"{name}: persisting checkout passed the gate"

    opted_out = tmp_path / "opted_out"
    opted_out.mkdir()
    (opted_out / "ok.yml").write_text(
        """\
permissions:
  contents: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: push
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          git push origin main
""",
        encoding="utf-8",
    )
    offenders, checked = _checkout_persistence_offenders(opted_out)
    assert checked == 1
    assert offenders == []

    read_job = tmp_path / "read_job"
    read_job.mkdir()
    (read_job / "split.yml").write_text(
        """\
permissions:
  contents: write
jobs:
  scope:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v6
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - name: push
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          git push origin main
""",
        encoding="utf-8",
    )
    offenders, checked = _checkout_persistence_offenders(read_job)
    assert checked == 1  # only the write job's checkout is in-universe
    assert offenders == []


_HOSTILE_GRANT_WORKFLOWS = {
    # Job-level env: the token reaches EVERY step, including the
    # parse step — hoisting an env block during YAML cleanup is the
    # natural accidental regression.
    "job_level_env": """\
permissions: { contents: write }
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    steps:
      - name: parse untrusted registry data
        run: |
          python parse_registry.py
""",
    # Workflow-level env, github.token spelling.
    "workflow_level_env": """\
permissions:
  contents: write
env:
  GH_TOKEN: ${{ github.token }}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: parse untrusted registry data
        run: |
          python parse_registry.py
""",
    # Step whose FIRST key is env (name/id are optional, keys are
    # order-free): the grant must not be attributed to the preceding
    # publish step.
    "env_first_key_step": """\
permissions:
  contents: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: publish
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          git push origin main
      - env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          curl -s https://registry.example/pkg.json | python3 parse.py
""",
    # Renamed key: the value is the credential, not the key name.
    "renamed_key": """\
permissions:
  contents: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: parse untrusted registry data
        env:
          MY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python parse_registry.py
""",
    # write-all holds contents:write without naming it.
    "write_all": """\
permissions: write-all
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: parse untrusted registry data
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python parse_registry.py
""",
    # A comment mentioning git push must not bless a parse step.
    "comment_publish_mention": """\
permissions:
  contents: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: parse untrusted registry data
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          # a later step will git push the result
          python parse_registry.py
""",
    # ...nor a TRAILING comment on a code line.
    "trailing_comment_publish_mention": """\
permissions:
  contents: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: parse untrusted registry data
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python parse_registry.py  # a later job will git push the result
""",
    # A .yaml-extension workflow must not escape the gate's universe
    # (GHA accepts both spellings).
    "yaml_extension": """\
permissions:
  contents: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: parse untrusted registry data
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python parse_registry.py
""",
    # packages:write escaped the contents-only universe entirely — a
    # token that can push the CI deps image is a supply-chain write
    # into every subsequent run.
    "packages_write_parse_grant": """\
permissions:
  contents: read
  packages: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: parse untrusted registry data
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          curl -s https://registry.example/pkg.json | python3 parse.py
""",
    # pull-requests:write likewise.
    "pull_requests_write_parse_grant": """\
permissions:
  pull-requests: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: parse untrusted PR manifest
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python parse_manifest.py
""",
    # A scope OUTSIDE the gate's original 14-name alternation
    # (GitHub grew the vocabulary before: attestations, models) —
    # universe entry must be shape-derived (<scope>: write), else
    # every grant under a newer scope escapes the walk entirely.
    # No _SCOPE_PUBLISH_VERBS row exists for it, so default-deny
    # also means no step in the job can be blessed.
    "unlisted_scope_write_grant": """\
permissions:
  models: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: parse untrusted registry data
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python parse_registry.py
""",
    # Job-level elevation in a read-default workflow: the write grant
    # lives on the job, not the workflow — a workflow-granular walk
    # misses it.
    "job_level_write_grant": """\
permissions:
  contents: read
jobs:
  j:
    runs-on: ubuntu-latest
    permissions:
      packages: write
    steps:
      - name: parse untrusted registry data
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          python parse_registry.py
""",
    # A publish verb of a scope the job does NOT hold must not bless
    # the step (gh issue is issues-scope; the job holds contents).
    "cross_scope_verb": """\
permissions:
  contents: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: parse then comment
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          python parse_registry.py
          gh issue comment 1 --body done
""",
}


def test_token_gate_flags_hostile_grant_shapes(tmp_path) -> None:
    """Every mechanically-valid grant shape that reaches non-publish
    code must be an offender — these are the shapes that previously
    escaped the gate."""
    for name, content in _HOSTILE_GRANT_WORKFLOWS.items():
        wf_dir = tmp_path / name
        wf_dir.mkdir()
        ext = "yaml" if name == "yaml_extension" else "yml"
        (wf_dir / f"hostile.{ext}").write_text(content, encoding="utf-8")
        offenders, checked = _default_token_offenders(wf_dir)
        assert checked >= 1, f"{name}: grant not even counted"
        assert offenders, f"{name}: hostile grant shape passed the gate"


def test_token_gate_accepts_publish_grant_and_skips_read_only(
    tmp_path,
) -> None:
    """Both directions: a publish-step grant in a write workflow is
    legitimate, and read-only workflows are outside the universe."""
    ok = tmp_path / "ok"
    ok.mkdir()
    (ok / "publish.yml").write_text(
        """\
permissions:
  contents: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: push branch
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          git push --force-with-lease origin refresh
""",
        encoding="utf-8",
    )
    offenders, checked = _default_token_offenders(ok)
    assert checked == 1
    assert offenders == []

    ro = tmp_path / "ro"
    ro.mkdir()
    (ro / "readonly.yml").write_text(
        """\
permissions:
  contents: read
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: registry login
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          python parse_registry.py
""",
        encoding="utf-8",
    )
    offenders, checked = _default_token_offenders(ro)
    assert checked == 0
    assert offenders == []

    # Scope-matched publish grants are legitimate: docker login in a
    # packages:write job, gh issue in an issues:write job.
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "image.yml").write_text(
        """\
permissions:
  contents: read
  packages: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: log in to GHCR
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          echo "$GH_TOKEN" | docker login ghcr.io -u x --password-stdin
      - name: check visibility
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh api "users/o/packages/container/img" --jq .visibility
""",
        encoding="utf-8",
    )
    offenders, checked = _default_token_offenders(pkg)
    assert checked == 2
    assert offenders == []

    iss = tmp_path / "iss"
    iss.mkdir()
    (iss / "reaudit.yml").write_text(
        """\
permissions:
  contents: read
  issues: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: open issue
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh issue create --title x --body y
""",
        encoding="utf-8",
    )
    offenders, checked = _default_token_offenders(iss)
    assert checked == 1
    assert offenders == []

    # Job-aware universe, accepts direction: a read-only job's grant
    # beside a write job is OUTSIDE the universe (codeql.yml's scope
    # jobs vs its upload job) — job-level permissions REPLACE the
    # workflow default.
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    (mixed / "split.yml").write_text(
        """\
permissions:
  contents: write
jobs:
  scope:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
    steps:
      - name: query prior runs
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh api repos/o/r/actions/runs
  publish:
    runs-on: ubuntu-latest
    steps:
      - name: push
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          git push origin main
""",
        encoding="utf-8",
    )
    offenders, checked = _default_token_offenders(mixed)
    assert checked == 1  # only the write job's grant is in-universe
    assert offenders == []
