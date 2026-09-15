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


import re as _re

# The workflow holds a write-capable default token: an explicit
# contents:write grant (line-start or inline ``permissions: { ... }``)
# or the write-all umbrella.
_WRITE_PERMISSION_RE = _re.compile(
    r"contents:\s*write|permissions:\s*write-all"
)
# Grants are anchored on the token VALUE, any key name, any nesting
# level (step/job/workflow ``env:``, ``with: token:``, ...): matching
# only well-known env key names let a rename or a hoisted env block
# re-grant the token with the gate green.
_DEFAULT_TOKEN_RE = _re.compile(
    r"\$\{\{\s*(?:secrets\.GITHUB_TOKEN|github\.token)\s*\}\}"
)
# ``push --force`` covers release.yml's line-wrapped
# ``git -c http...extraheader \ push --force`` invocation. Deliberately
# NOT ``gh issue``: commenting on issues is not a publish operation
# that needs the write token's contents scope.
_PUBLISH_RE = _re.compile(r"git push|push --force|gh pr |gh release")


def _default_token_offenders(workflows_dir: Path) -> tuple[list[str], int]:
    """(offender descriptions, grants checked) for every workflow in
    *workflows_dir* that holds a write-capable default token.

    Default-deny: ANY non-comment line carrying the default-token
    value must lie inside a step whose body performs a publish
    operation on a non-comment line. Everything else — job-level or
    workflow-level ``env:`` (which hands the token to EVERY step),
    grants in steps without a publish command, grants under renamed
    keys or ``with:`` inputs — is an offender. Step boundaries are
    anchored on the ``steps:`` key + list-dash indentation, not on
    first-key names (``name``/``id`` are optional and keys are
    order-free in GHA).
    """
    offenders: list[str] = []
    checked = 0
    # ``*.y*ml``: GHA accepts both workflow extensions — a .yaml
    # workflow must not escape the universe.
    for wf in sorted(workflows_dir.glob("*.y*ml")):
        lines = wf.read_text(encoding="utf-8").splitlines()
        if not any(_WRITE_PERMISSION_RE.search(ln) for ln in lines
                   if not ln.lstrip().startswith("#")):
            continue

        # Step segmentation: [start, end) line ranges of every step.
        # Anchored on the ``steps:`` key; list items are the dashes at
        # the FIRST item's exact indent (deeper dashes are run-body
        # content, shallower lines end the block — a block end also
        # closes the last step so it can never swallow the next job's
        # job-level ``env:``).
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

        def _step_publishes(rng: tuple[int, int]) -> bool:
            # Comments never bless a step: full-line comments are
            # skipped and trailing ``  # ...`` tails are stripped
            # before the publish match. Declared boundary: publish
            # text inside a heredoc or string literal in the run body
            # still matches (a token-granted parse step would need
            # that coincidental content to slip through — compound
            # accident, documented rather than parsed).
            return any(
                _PUBLISH_RE.search(body_ln.split(" #", 1)[0])
                for body_ln in lines[rng[0]:rng[1]]
                if not body_ln.lstrip().startswith("#")
            )

        for i, ln in enumerate(lines):
            if ln.lstrip().startswith("#"):
                continue
            if not _DEFAULT_TOKEN_RE.search(ln):
                continue
            checked += 1
            rng = next(
                (r for r in steps if r[0] <= i < r[1]), None
            )
            if rng is None:
                offenders.append(
                    f"{wf.name}:{i + 1}: default-token grant outside "
                    f"any step (job/workflow scope): {ln.strip()}"
                )
            elif not _step_publishes(rng):
                offenders.append(
                    f"{wf.name}:{i + 1}: default-token grant in a "
                    f"non-publish step: {ln.strip()}"
                )
    return offenders, checked


def test_write_token_confined_to_publish_steps() -> None:
    """In workflows holding a write-capable default token, only
    publish steps may carry it.

    Permissions are job-wide by GitHub's model, so the confinement IS
    the handoff: a run step that fetches and parses untrusted
    registry/network data with the default token in reach hands a
    credential that can push branches and open PRs to exactly the
    code most likely to hit a parsing bug (the sca-self-bump
    harden/bump phases carried one for rate limits alone).

    Declared boundaries: reusable-workflow / composite-action
    indirection (``secrets: inherit``, ``uses:`` inputs resolved in
    another file) is not followed — none is used by the write-
    permission workflows today; workflows with NO permissions block
    inherit the repo default, which this repo keeps read-only; and
    publish text inside a heredoc or string literal can still bless a
    step (see _step_publishes).
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
