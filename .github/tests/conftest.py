"""Shared measurements of the read-only checkout for whole-tree CI tests."""
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def whole_repo_import_graph():
    """Build the real graph once per process for both CI scoper suites.

    Synthetic repositories and mutation tests still build their own graphs.
    Collect entry-script references in the same AST pass used by dispatch.
    """
    from codeql_scope import build_graph, discover_py_files

    repo = Path(__file__).resolve().parents[2]
    references = {
        literal: set() for root in (repo / "bin", repo / "libexec")
        for script in root.rglob("*") if script.is_file()
        for literal in (str(script.relative_to(repo)), script.name)
    }
    files = discover_py_files(repo)
    reverse, failures = build_graph(files, repo, literal_references=references)
    return files, reverse, failures, references, repo
