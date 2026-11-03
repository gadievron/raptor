"""Shared test scaffolding — the canonical fakes and fixtures that
test suites across the tree had copy-pasted (and drifted).

NOT collected as tests (no ``test_*.py`` modules except under
``tests/``); import from suites as ``from core.testing import ...``.

The expected-crash subprocess helper lives in ``core.testing.expected_crash``;
use the root ``expected_crash_runner`` fixture for capability-gated tests.

Patterns provided (each replaces a family of per-suite copies):

* :class:`FakeStructuredProvider` — provider-level stub for
  ``generate_structured`` with canned ``(result, raw)``, call
  counting, last-kwargs capture, and the full usage-counter block
  ``LLMClient`` diffs. Carries ``**kwargs`` — the drifted copies that
  dropped it TypeError'd on per-call ``temperature``.
* :func:`make_test_client` / :func:`install_provider` — the minimal
  no-API-key ``LLMClient`` builder (the ``LLMClient.__new__`` private-
  attribute litany that four suites re-spelled) plus the provider-key
  wiring.
* :func:`reset_llm_egress_state` — the egress/proxy-env/OLLAMA_HOST
  hermeticity fixture body shared by per-directory conftests (wrap
  with ``yield from`` in an autouse fixture).
* :func:`init_scratch_repo` / :func:`git_run` — hermetic git fixture
  repos: scrubbed global/system config, pinned identity, signing off,
  deterministic default branch.

Dead-scaffolding cleanups elsewhere should converge suites onto these
rather than deleting-and-reinventing.
"""

# Pytest loads infrastructure plugins before capture and test configuration.
# Importing this package must not initialize SDKs, logging handlers, or model
# selection merely to reach a lightweight helper such as llm_tripwire.
_EXPORT_MODULES = {
    "FakeModel": "fake_llm",
    "FakeStructuredProvider": "fake_llm",
    "ensure_anthropic_error_types": "fake_llm",
    "install_provider": "fake_llm",
    "make_anthropic_provider": "fake_llm",
    "make_test_client": "fake_llm",
    "git_run": "gitrepo",
    "init_scratch_repo": "gitrepo",
    "DEFAULT_OLLAMA_HOST": "llm_env",
    "PROXY_ENV_VARS": "llm_env",
    "reset_llm_egress_state": "llm_env",
    "force_census_regex_fallback": "treesitter",
    "requires_ts": "treesitter",
    "ts_parser_available": "treesitter",
}


def __getattr__(name):
    module = _EXPORT_MODULES.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module
    value = getattr(import_module(f"{__name__}.{module}"), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))

__all__ = [
    "DEFAULT_OLLAMA_HOST",
    "PROXY_ENV_VARS",
    "FakeModel",
    "FakeStructuredProvider",
    "ensure_anthropic_error_types",
    "force_census_regex_fallback",
    "git_run",
    "init_scratch_repo",
    "install_provider",
    "make_anthropic_provider",
    "make_test_client",
    "requires_ts",
    "reset_llm_egress_state",
    "ts_parser_available",
]
