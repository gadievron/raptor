"""SAGE-recalled build commands on the CodeQL agent.

An HMAC-verified build-reliability row may drive a traced build
(`BuildSystem(type="sage_prior")`); a row whose MAC is missing, fails
verification, or was minted for a DIFFERENT repo than the one being
analysed must never be auto-executed — it demotes to a single
operator-visible hint suggesting `--build-command`.

No real SAGE server and no LLM: the SAGE client is a MagicMock and the
HMAC verifier is stubbed where the unverified path is exercised.
"""

import contextlib
import logging
from unittest.mock import MagicMock, patch

import pytest

from core.build.build_detector import BuildSystem
from core.sage import rowmac


@pytest.fixture(autouse=True)
def _isolated_rowmac_key(tmp_path):
    """Mint/verify against a throwaway key, never the operator's."""
    key_path = tmp_path / "rowmac-key" / "rowmac.key"
    with patch("core.sage.rowmac._key_path", return_value=key_path):
        yield


def _stamped_row(repo_path, cmd="make all", languages="cpp"):
    """A build-reliability row shaped like store_codeql_build_reliability's.

    The MAC binds the key of the repo that stored the row.
    ``recall_context_for_codeql_build`` annotates every recalled row
    with the CALLER's repo key and verification binds to that, so a
    row is only verified when *repo_path* is the repo the agent
    analyses — stamp a different path to exercise cross-repo demotion.
    """
    from core.sage.hooks import _repo_key
    repo_key = _repo_key(str(repo_path))
    content = (
        f"CodeQL build reliability for repo myapp: "
        f"languages {languages}, outcome success, "
        f"build command {cmd}, analyses completed 5, "
        f"failure modes none. ||repo={repo_key}||"
    )
    fields = {
        "kind": "codeql_build",
        "repo": repo_key,
        "outcome": "success",
        "build_command": cmd,
        "languages": languages,
    }
    return {"content": rowmac.stamp(content, fields), "confidence": 0.9}


def _agent(tmp_path):
    from packages.codeql.agent import CodeQLAgent
    agent = CodeQLAgent.__new__(CodeQLAgent)
    agent.repo_path = tmp_path
    agent.out_dir = tmp_path / "out"
    agent.start_time = 0.0
    agent.language_detector = MagicMock()
    agent.build_detector = MagicMock()
    agent.database_manager = MagicMock()
    agent.query_runner = MagicMock()
    agent.build_detector.detect_build_system.return_value = None
    agent.build_detector.synthesise_build_command.return_value = None
    agent.build_detector.generate_no_build_config.return_value = BuildSystem(
        type="no-build", command="", working_dir=tmp_path,
        env_vars={}, confidence=1.0, detected_files=[],
    )
    agent.database_manager.create_databases_parallel.return_value = {}
    return agent


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


def _run_with_row(agent, row, verify=None):
    """Run the agent with SAGE recall returning *row*; capture raptor log."""
    client = MagicMock()
    client.query.return_value = [row]
    handler = _Capture()
    raptor_logger = logging.getLogger("raptor")
    raptor_logger.addHandler(handler)
    try:
        ctx = (
            patch("core.sage.rowmac.verify", return_value=verify)
            if verify is not None else contextlib.nullcontext()
        )
        with patch("core.sage.hooks._get_client", return_value=client), ctx:
            agent.run_autonomous_analysis(languages=["cpp"], traced_build=True)
    finally:
        raptor_logger.removeHandler(handler)
    return [r.getMessage() for r in handler.records]


class TestSageBuildPrior:
    def test_verified_row_drives_sage_prior_build(self, tmp_path):
        """MAC verifies → the recalled command becomes the BuildSystem."""
        agent = _agent(tmp_path)
        _run_with_row(agent, _stamped_row(tmp_path, cmd="make all"))
        lang_map = (
            agent.database_manager.create_databases_parallel.call_args[0][1]
        )
        assert lang_map["cpp"].type == "sage_prior"
        assert lang_map["cpp"].command == "make all"

    def test_unverified_row_never_executes_and_hints_operator(self, tmp_path):
        """MAC fails → no sage_prior BuildSystem; one warning names the
        command and points at --build-command."""
        agent = _agent(tmp_path)
        messages = _run_with_row(
            agent, _stamped_row(tmp_path, cmd="make all"), verify=False,
        )
        lang_map = (
            agent.database_manager.create_databases_parallel.call_args[0][1]
        )
        assert lang_map["cpp"].type == "no-build"
        hints = [
            m for m in messages
            if "unverified" in m and "--build-command" in m
        ]
        assert len(hints) == 1, messages
        assert "make all" in hints[0]

    def test_unstamped_legacy_row_demotes_to_hint(self, tmp_path):
        """A row with no MAC token at all takes the same demote path."""
        agent = _agent(tmp_path)
        row = _stamped_row(tmp_path, cmd="cmake --build build")
        clean, _token = rowmac.strip(row["content"])
        row["content"] = clean
        messages = _run_with_row(agent, row)
        lang_map = (
            agent.database_manager.create_databases_parallel.call_args[0][1]
        )
        assert lang_map["cpp"].type == "no-build"
        assert any(
            "unverified" in m and "cmake --build build" in m
            for m in messages
        ), messages

    def test_foreign_repo_row_demotes_to_hint(self, tmp_path):
        """A row MAC-minted while analysing repo A must never drive a
        build in repo B — the rows live in the global methodology
        domain, so a hostile repo A could otherwise plant a command
        that executes inside repo B's checkout. Valid MAC, wrong repo
        binding: demote to the operator hint."""
        agent = _agent(tmp_path)
        foreign_repo = tmp_path.parent / f"{tmp_path.name}-foreign"
        row = _stamped_row(foreign_repo, cmd="make pwn")
        messages = _run_with_row(agent, row)
        lang_map = (
            agent.database_manager.create_databases_parallel.call_args[0][1]
        )
        assert lang_map["cpp"].type == "no-build"
        assert any(
            "unverified" in m and "make pwn" in m for m in messages
        ), messages
