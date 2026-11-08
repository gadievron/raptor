"""Flag acceptance requires an actual argparse result, never startup failure."""

import os
from pathlib import Path
import subprocess

import pytest

from core.startup.tests import test_cli_smoke as smoke
from core.testing.module_views import scoped_function_imports


@pytest.mark.parametrize("returncode,stdout,stderr,expected", [
    (2, "", "mode.py: error: unrecognized arguments: SENTINEL\n", True),
    (0, "", "mode.py: error: unrecognized arguments: SENTINEL\n", False),
    (1, "", "ImportError: missing SDK\n", False),
    (2, "", "mode.py: error: unrecognized arguments: --typo SENTINEL\n", False),
    (2, "", "mode.py: error: argument --duration: invalid int value: 'bad'\n", False),
    (2, "mode.py: error: unrecognized arguments: SENTINEL\n", "", False),
    (0, "analysis unexpectedly started\n", "", False),
])
def test_acceptance_requires_only_the_sentinel_error(
    monkeypatch, returncode, stdout, stderr, expected,
):
    monkeypatch.setattr(smoke, "_run_mode_parser", lambda *args, **kwargs:
                        subprocess.CompletedProcess(
                            args, returncode, stdout.replace("SENTINEL", smoke._PARSER_SENTINEL),
                            stderr.replace("SENTINEL", smoke._PARSER_SENTINEL)))
    assert smoke._argparse_accepted("fuzz", "--binary", "/owned") is expected


def test_timeout_before_parsing_is_not_acceptance(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args, 0.01)

    monkeypatch.setattr(smoke, "_run_mode_parser", timeout)
    assert smoke._argparse_accepted("fuzz", "--not-a-real-flag") is False


def test_parser_probe_owns_locale_and_working_directory(monkeypatch):
    monkeypatch.setenv("LC_ALL", "fr_FR.UTF-8")
    monkeypatch.setenv("LANGUAGE", "fr_FR:fr")
    observed = {}

    def command(args, *, env, timeout, cwd):
        observed.update(env=env, cwd=cwd)
        assert Path(cwd).is_dir()
        return subprocess.CompletedProcess(args, 2, "", "owned diagnostic")

    monkeypatch.setattr(smoke, "_run_smoke_command", command)
    smoke._run_mode_parser("fuzz", "--binary", "./bin")
    assert observed["env"]["LC_ALL"] == observed["env"]["LANGUAGE"] == "C"
    assert observed["cwd"] == observed["env"]["HOME"]
    assert not Path(observed["cwd"]).exists()
    assert os.environ["LC_ALL"] == "fr_FR.UTF-8"
    assert os.environ["LANGUAGE"] == "fr_FR:fr"


@pytest.mark.parametrize("mode,args", [
    ("scan", ["--repo", "./repo", "--policy_groups_typo", "secrets"]),
    ("agentic", ["--repo", "./repo", "--max-findings-typo", "10"]),
    ("fuzz", ["--binary", "./bin", "--duration-typo", "60"]),
])
def test_actual_mode_parser_rejects_unknown_requested_flags(mode, args):
    assert smoke._argparse_accepted(mode, *args) is False


@pytest.mark.parametrize("mode,args", [
    ("scan", ["--repo", "/owned", "--policy_groups", "secrets"]),
    ("agentic", ["--repo", "/owned", "--no-codeql", "--max-findings", "10"]),
    ("fuzz", ["--binary", "/owned", "--duration", "60"]),
    ("fuzz", ["--export-seed-corpus", "/owned/seeds"]),
])
def test_dispatcher_forwards_flags_to_the_probed_mode_script(monkeypatch, mode, args):
    import raptor
    from core.sandbox import preflight

    calls = []
    original_args = list(args)

    def lifecycle(command, script, forwarded, label):
        calls.append((command, script, list(forwarded)))
        return 37

    def standalone(script, forwarded, **kwargs):
        calls.append((mode, script, list(forwarded)))
        return 37

    monkeypatch.setattr(raptor, "_run_with_lifecycle", lifecycle)
    monkeypatch.setattr(raptor, "_run_script", standalone)
    monkeypatch.setattr(raptor, "_TRUST_REPO_SEEN", False)
    monkeypatch.setattr(raptor, "_NO_TRUST_REPO_SEEN", False)
    # Routing is the contract here; the native containment checks have their
    # own suites. Keep this preflight override on the scan consumer only.
    with scoped_function_imports(raptor, ("mode_scan",), {
        "core.sandbox.preflight": preflight,
    }) as imports:
        monkeypatch.setitem(vars(getattr(imports, "core.sandbox.preflight")),
                            "preflight_scan_cli", lambda _args: None)
        assert getattr(raptor, "mode_" + mode)(args) == 37
    assert calls == [(mode, raptor._mode_help_scripts()[mode], original_args)]
    assert args == original_args
