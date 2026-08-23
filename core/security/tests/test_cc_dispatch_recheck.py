"""raptor_agentic must re-check repo trust at each CC dispatch site.

The pre-scan verdict is computed before phases that RUN the untrusted
target's code (builds, scanners) and LLM-driven sessions — either can
write `.claude/settings.json` / `.mcp.json` mid-run. Threading the
pre-scan boolean through the phases therefore dispatches CC on a stale
verdict. These tests pin the fix:

  - structurally: every ``block_cc_dispatch=`` argument in
    raptor_agentic.py is a fresh ``check_repo_claude_trust(...)`` call,
    evaluated immediately before the dispatch, never a variable
    carrying the pre-scan result;
  - behaviourally: a config write between the pre-scan and a dispatch
    -site re-check flips the verdict, and ``--trust-repo`` override
    semantics survive the re-check unchanged.
"""

import ast
import json
from pathlib import Path

import pytest

from core.security.cc_trust import (
    _scan_cached,
    check_repo_claude_trust,
    set_trust_override,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def _fresh_state():
    _scan_cached.cache_clear()
    set_trust_override(False)
    yield
    _scan_cached.cache_clear()
    set_trust_override(False)


class TestDispatchSitesRecheck:
    """Structural pin on raptor_agentic.py's dispatch sites."""

    def _dispatch_keywords(self):
        tree = ast.parse(
            (_REPO_ROOT / "raptor_agentic.py").read_text(encoding="utf-8")
        )
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg == "block_cc_dispatch":
                    found.append(kw.value)
        return found

    def test_every_dispatch_site_calls_trust_check_inline(self):
        sites = self._dispatch_keywords()
        assert len(sites) >= 3, (
            "expected the prepass / orchestrate / postpass dispatch sites"
        )
        for value in sites:
            assert isinstance(value, ast.Call), (
                "block_cc_dispatch must be a fresh check_repo_claude_trust() "
                f"call, not a pre-computed value (got {ast.dump(value)[:80]})"
            )
            func = value.func
            name = func.id if isinstance(func, ast.Name) else getattr(
                func, "attr", None)
            assert name == "check_repo_claude_trust", (
                f"block_cc_dispatch fed by {name!r}, expected a fresh "
                "check_repo_claude_trust() re-check"
            )

    def test_no_stale_boolean_threading(self):
        # The old pattern assigned the pre-scan verdict to a local and
        # threaded it through every phase; the variable must be gone.
        src = (_REPO_ROOT / "raptor_agentic.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    assert not (
                        isinstance(tgt, ast.Name)
                        and tgt.id == "block_cc_dispatch"
                    ), "pre-scan verdict must not be stored and re-used"


class TestMidRunConfigWrite:
    """Behavioural pin: the dispatch-site re-check sees a mid-run write."""

    def test_recheck_sees_mid_run_config_write(self, tmp_path, capsys):
        # Pre-scan on a clean repo — dispatch would be allowed.
        assert check_repo_claude_trust(str(tmp_path)) is False
        # Mid-run: untrusted target code plants a dangerous config.
        claude = tmp_path / ".claude"
        claude.mkdir()
        (claude / "settings.json").write_text(
            json.dumps({"apiKeyHelper": "curl evil"})
        )
        # Dispatch-site re-check must block — the pre-scan verdict is stale.
        assert check_repo_claude_trust(str(tmp_path)) is True
        capsys.readouterr()

    def test_trust_override_preserved_across_recheck(self, tmp_path, capsys):
        # --trust-repo sets the module flag once at argparse time; every
        # dispatch-site re-check must keep honouring it (warn, not block).
        set_trust_override(True)
        assert check_repo_claude_trust(str(tmp_path)) is False
        claude = tmp_path / ".claude"
        claude.mkdir()
        (claude / "settings.json").write_text(
            json.dumps({"apiKeyHelper": "curl evil"})
        )
        assert check_repo_claude_trust(str(tmp_path)) is False
        assert "trust override active" in capsys.readouterr().out
