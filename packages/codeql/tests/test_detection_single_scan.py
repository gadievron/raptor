"""Phase-1 language detection walks the repository once per run.

Sparse targets drive the tiered retry ladder (min_files → min_files=1
→ file-count floor); each tier used to perform its own repository walk,
so walk-scoped once-per-run lines — the unsupported-primary warning in
particular — printed once per tier. The flow now scans once and hands
the same statistics to every tier. Fully mocked: no codeql CLI, no
network.
"""

from pathlib import Path
from unittest.mock import MagicMock

from packages.codeql import agent as agent_mod
from packages.codeql import language_detector as ld_mod
from packages.codeql.agent import CodeQLAgent


def _sparse_php_repo(tmp_path: Path) -> Path:
    # No CodeQL extractor language present: every tier returns empty,
    # so Phase 1 runs the full retry ladder and then stops the run.
    repo = tmp_path / "repo"
    for i in range(12):
        page = repo / "src" / f"page{i}.php"
        page.parent.mkdir(parents=True, exist_ok=True)
        page.write_text("<?php\n", encoding="utf-8")
    return repo


def _hermetic_agent(tmp_path: Path, monkeypatch) -> CodeQLAgent:
    monkeypatch.setattr(
        agent_mod.DatabaseManager, "__init__",
        lambda self, db_root=None, codeql_cli=None: None)
    monkeypatch.setattr(
        agent_mod.QueryRunner, "__init__",
        lambda self, codeql_cli=None: None)
    monkeypatch.setattr(
        "core.sage.hooks.recall_context_for_codeql_build",
        lambda *args, **kwargs: [])
    return CodeQLAgent(_sparse_php_repo(tmp_path), out_dir=tmp_path / "out")


def test_retry_ladder_walks_once_and_banners_once(tmp_path, monkeypatch):
    agent = _hermetic_agent(tmp_path, monkeypatch)

    walks: list[int] = []
    original = agent.language_detector._scan_repository

    def counting() -> dict:
        walks.append(1)
        return original()

    monkeypatch.setattr(
        agent.language_detector, "_scan_repository", counting)
    mock_logger = MagicMock()
    monkeypatch.setattr(ld_mod, "logger", mock_logger)

    result = agent.run_autonomous_analysis()

    # The run must still stop in Phase 1 with the historic error —
    # scan reuse changes emission, never the detection outcome.
    assert result.success is False
    assert "No CodeQL-supported languages detected" in result.errors

    assert len(walks) == 1, (
        "the retry ladder must reuse the first walk's statistics"
    )
    warnings = [
        c.args[0] % tuple(c.args[1:]) if c.args[1:] else c.args[0]
        for c in mock_logger.warning.call_args_list
    ]
    banners = [m for m in warnings if "no extractor" in m]
    assert len(banners) == 1, (
        f"unsupported-primary banner must print once per run; got "
        f"{len(banners)}"
    )
