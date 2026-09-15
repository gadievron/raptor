"""File-shape predicate grammar + package-wide closure.

One grammar per file shape, defined once in
``packages.sca.file_shapes``. The per-module copies these replaced
had drifted (a hidden ``.dockerfile`` matched in one walker only;
composite-action coverage differed between a parser and a rewriter
that must see the same files). The closure scan keeps new local
copies out of the package.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from packages.sca.file_shapes import (  # noqa: E402
    is_compose_file,
    is_dockerfile,
    is_gha_workflow,
    is_gha_workflow_or_action,
    is_gitlab_ci_file,
)


class TestIsDockerfile:

    def test_canonical_names(self):
        assert is_dockerfile(Path("Dockerfile"))
        assert is_dockerfile(Path("deploy/Containerfile"))

    def test_variant_spellings(self):
        assert is_dockerfile(Path("Dockerfile.alpine"))
        assert is_dockerfile(Path("base.Dockerfile"))
        assert is_dockerfile(Path("worker.dockerfile"))

    def test_hidden_dockerfile_suffix_form(self):
        # The widest of the replaced copies matched a bare hidden
        # ``.dockerfile`` (Path(".dockerfile").suffix is "" so the
        # suffix idiom missed it); the shared grammar keeps it.
        assert is_dockerfile(Path(".dockerfile"))

    def test_negatives(self):
        assert not is_dockerfile(Path("dockerfile"))       # lowercase name
        assert not is_dockerfile(Path("Dockerfile.md/x"))  # dir component
        assert not is_dockerfile(Path("Makefile"))
        assert not is_dockerfile(Path("docker-compose.yml"))


class TestIsComposeFile:

    def test_positive_spellings(self):
        for name in ("compose.yml", "compose.yaml", "docker-compose.yml",
                     "docker-compose.dev.yaml", "compose.override.yml",
                     "Docker-Compose.YML"):
            assert is_compose_file(Path(name)), name

    def test_negatives(self):
        for name in ("decompose.yml", "compose.json", "compose",
                     "mycompose.yml", "values.yaml"):
            assert not is_compose_file(Path(name)), name


class TestGhaPredicates:

    def test_workflow_paths(self):
        assert is_gha_workflow(Path(".github/workflows/ci.yml"))
        assert is_gha_workflow(Path("repo/.github/workflows/x.yaml"))
        assert not is_gha_workflow(Path(".github/actions/ci.yml"))
        assert not is_gha_workflow(Path("ci.yml"))
        assert not is_gha_workflow(Path(".github/workflows/ci.txt"))

    def test_action_manifest_split_is_explicit(self):
        # The drift this closes: one lane matched action.yml, its
        # sibling did not. The two jobs now carry two NAMES.
        assert not is_gha_workflow(Path("some/dir/action.yml"))
        assert is_gha_workflow_or_action(Path("some/dir/action.yml"))
        assert is_gha_workflow_or_action(Path("action.yaml"))
        assert is_gha_workflow_or_action(Path(".github/workflows/ci.yml"))
        assert not is_gha_workflow_or_action(Path("actions.yml"))


class TestGitlabCi:

    def test_spellings(self):
        assert is_gitlab_ci_file(Path(".gitlab-ci.yml"))
        assert is_gitlab_ci_file(Path("sub/.gitlab-ci.yaml"))
        assert not is_gitlab_ci_file(Path("gitlab-ci.yml"))


class TestPackageClosure:
    """No SCA runtime module may re-roll a file-shape predicate."""

    _FORBIDDEN_DEFS = (
        "def _is_dockerfile",
        "def _is_compose_file",
        "def _is_gha_workflow",
        "def _is_gitlab_ci_file",
        "def is_dockerfile",
        "def is_compose_file",
        "def is_gha_workflow",
        "def is_gitlab_ci_file",
    )

    def test_no_local_predicate_copies(self):
        sca_root = REPO_ROOT / "packages" / "sca"
        offenders = []
        for p in sca_root.rglob("*.py"):
            parts = set(p.parts)
            if "tests" in parts or "scripts" in parts:
                continue
            if p.name == "file_shapes.py":
                continue
            text = p.read_text(encoding="utf-8")
            for d in self._FORBIDDEN_DEFS:
                if d + "(" in text:
                    offenders.append(
                        f"{p.relative_to(REPO_ROOT)}: {d} — import "
                        "packages.sca.file_shapes instead")
        assert offenders == [], "\n".join(offenders)
