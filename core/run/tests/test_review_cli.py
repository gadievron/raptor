"""Tests for libexec/raptor-review argument dispatch.

Colocated with the run-lifecycle CLI tests: raptor-review is the
operator CLI navigating run/project output, and its dispatch bugs are
invisible to CI without a direct test.
"""

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_review_module():
    cli_path = str(REPO_ROOT / "libexec" / "raptor-review")
    loader = SourceFileLoader("raptor_review_cli", cli_path)
    spec = importlib.util.spec_from_loader("raptor_review_cli", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class TestDefaultSubcommandSniffer:
    """The sniffer must not mistake a flag VALUE for the subcommand."""

    def test_flag_value_before_subcommand_is_skipped(self):
        # Regression: `--project /x stats` picked `/x` as the first
        # positional and prepended "show", misparsing `stats`.
        mod = _load_review_module()
        assert mod._first_positional(["--project", "/x", "stats"]) == "stats"

    def test_inline_flag_value_consumes_nothing(self):
        mod = _load_review_module()
        assert mod._first_positional(["--project=/x", "stats"]) == "stats"

    def test_bare_positional_wins(self):
        mod = _load_review_module()
        assert mod._first_positional(["src/a.c", "fn"]) == "src/a.c"

    def test_boolean_flag_does_not_consume(self):
        mod = _load_review_module()
        assert mod._first_positional(["--raw", "findings"]) == "findings"

    def test_no_positional(self):
        mod = _load_review_module()
        assert mod._first_positional(["--project", "/x"]) is None
