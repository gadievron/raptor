"""Per-directory test infra.

Journal appends stamp rows with an HMAC key under
``$XDG_DATA_HOME/raptor/journal-mac.key`` (``core.coverage.journal_mac``;
the witness/iris/scorecard integrity layers keep sibling keys in the
same directory). Point XDG_DATA_HOME at a per-test tmp dir so the
suite never touches (or depends on) the developer's real key files,
and every test starts from a fresh-key state. Same pattern as
``core/llm/scorecard/tests/conftest.py``. Tests that need a specific
key state set XDG_DATA_HOME themselves inside the test body, which
runs after this autouse fixture and wins.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

    from core.audit.tests.checklist_corpus import ChecklistBuildCache


@pytest.fixture(scope="session")
def checklist_builds(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[ChecklistBuildCache]:
    """Build-once cache for checklist-CLI corpora (one build per
    DISTINCT corpus per pytest process; per xdist worker). Shared
    trees are read-only on disk — mutation fails loudly; consumers
    write into ``make_run_dir`` copies. Doctrine + identity contract:
    ``core.audit.tests.checklist_corpus``."""
    from core.audit.tests.checklist_corpus import ChecklistBuildCache

    cache = ChecklistBuildCache(tmp_path_factory.mktemp)
    yield cache
    cache.restore_writability()


@pytest.fixture(autouse=True)
def _isolated_mac_keys(tmp_path_factory, monkeypatch):
    monkeypatch.setenv(
        "XDG_DATA_HOME", str(tmp_path_factory.mktemp("xdg-data")),
    )


# ── Repo-root workspace tripwire ────────────────────────────────────
# A fleet battery once left a `workspace/cpg.bin/` tree at a worktree
# root FROM THIS SUITE: the audit joern presweep runs in a background
# thread that outlives its test, and a spawn lane that loses its cwd
# pin writes Joern's workspace under the process cwd. Same tripwire
# as packages/joern/tests/conftest.py — deliberately replicated, not
# hoisted: each suite's tripwire must stand alone so a refactor of
# one never silently disarms the other. Self-contained addition — it
# reads and edits nothing else in this file.

def _repo_root() -> Path:
    """The root the tripwire watches — a seam the meta-test
    (test_workspace_tripwire_meta.py) retargets at a scratch root so
    the REAL fixture below is what its nested sessions exercise."""
    return Path(__file__).resolve().parents[3]


@pytest.fixture(scope="session", autouse=True)
def _no_repo_root_workspace_debris() -> Iterator[None]:
    """Fail the session when an audit suite drops `workspace/` at the
    repo root: some spawn ran with the caller's cwd unpinned. A
    pre-existing `workspace/` is not this session's debris and is
    left alone (and unblamed)."""
    debris = _repo_root() / "workspace"
    existed_before = debris.exists()
    yield
    if debris.exists() and not existed_before:
        pytest.fail(
            "audit tests left workspace/ debris at the repo root "
            f"({debris}) — a spawn lane ran with an unpinned cwd; "
            "pin cwd to a run-owned directory and keep background "
            "presweep runners submit-time pinned "
            "(see core/audit/joern_backend.resolve_joern_evidence)",
            pytrace=False,
        )


@pytest.fixture(autouse=True)
def _isolated_scorecard_sidecar(tmp_path_factory, monkeypatch):
    """The audit pipeline records per-model reliability events into the
    scorecard sidecar (``core.audit.scorecard_events``), whose default
    path resolves to the shared install ledger (or a cwd-relative
    ``out/llm_scorecard.json`` when RAPTOR_DIR is unset). Point the
    override at a per-test tmp file so no audit test can write the
    developer's real reliability data or drop artifacts into the repo
    tree. Tests that need a specific path set the variable themselves
    inside the test body, which runs after this autouse fixture and
    wins."""
    monkeypatch.setenv(
        "RAPTOR_SCORECARD_PATH",
        str(tmp_path_factory.mktemp("scorecard") / "llm_scorecard.json"),
    )


@pytest.fixture(autouse=True)
def _reset_llm_egress_state(monkeypatch):
    """Audit tests construct real LLMClients (llm_review, synthesis,
    budget suites), whose enable_llm_egress side effect swaps the
    HTTPS_PROXY family to a loopback in-process proxy. Without this
    reset the dead pointer outlives the suite and later packages in
    the same session (observed: core/sandbox proxy tests tunnelling
    via a long-gone 127.0.0.1 upstream). Same shared body the
    core/llm and core/dataflow conftests wrap."""
    from core.testing import reset_llm_egress_state

    yield from reset_llm_egress_state(monkeypatch)


@pytest.fixture(autouse=True)
def _hermetic_sigterm_disposition():
    """The orchestrator installs a process-wide SIGTERM salvage
    handler (install_sigterm_grace, reached by any test that runs the
    orchestrator in-process) and the CLI never uninstalls it. Leaked
    past the test it poisons every LATER test in the same worker
    process: fork children inherit the disposition, so SIGTERM starts
    a salvage drain in the child instead of killing it — observed as
    pool-teardown tests SIGKILLing provably responsive workers after
    their full grace. Restore the disposition (production
    uninstall first, belt-and-braces direct restore second) around
    every audit test.

    The snapshot itself can be the grace handler: a HIGHER-scoped
    fixture (a module-scoped fixture running run_orchestrator
    in-process) installs the handler during this test's setup chain,
    BEFORE this function-scoped guard captures ``prev``. Restoring
    that snapshot re-installs the leak — and once the orchestrator's
    bookkeeping is cleared by the uninstall, every later guard
    faithfully preserves the poisoned disposition for the rest of the
    session (observed as the sigterm-grace roundtrip test finding the
    handler pre-installed). The grace handler is therefore never a
    restore target: if it is still current after the production
    uninstall, re-install the snapshot when it is a legitimate prior
    handler (a pytest plugin's SIGTERM handler is the case this
    protects), else fall back to the interpreter default."""
    import signal

    try:
        prev = signal.getsignal(signal.SIGTERM)
    except (ValueError, OSError):  # non-main thread / exotic platform
        yield
        return
    yield
    from core.audit import orchestrator as _orch

    _orch.uninstall_sigterm_grace()
    try:
        current = signal.getsignal(signal.SIGTERM)
        if current is _orch._handle_sigterm:
            # Uninstall could not restore (its bookkeeping was
            # cleared by an earlier teardown while the handler stayed
            # installed). A legitimate snapshot IS the true baseline —
            # restore it (a pytest plugin's SIGTERM handler must
            # survive the guard). Only a missing or grace-poisoned
            # snapshot leaves the baseline unrecoverable; there the
            # interpreter default beats leaving salvage semantics
            # leaked into every later fork child.
            if prev is not None and prev is not _orch._handle_sigterm:
                signal.signal(signal.SIGTERM, prev)
            else:
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
        elif (prev is not None
                and prev is not _orch._handle_sigterm
                and current is not prev):
            # prev None = C-installed prior handler (getsignal cannot
            # represent it and signal.signal cannot re-install it) —
            # leave whatever is current rather than raise TypeError.
            signal.signal(signal.SIGTERM, prev)
    except (TypeError, ValueError, OSError):
        pass
