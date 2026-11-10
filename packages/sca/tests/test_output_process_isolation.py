"""Default SCA outputs separate process identities within one clock tick."""

from __future__ import annotations

import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.run import output as run_output
from core.testing.logging_state import isolated_cli_logging
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_views import scoped_function_imports
from packages.sca import cli, harden, optimise, update


@pytest.fixture
def process_clock(monkeypatch):
    fixed = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)

    class Clock:
        @classmethod
        def now(cls, tz=None):
            return fixed

    # Own the consuming namespaces; leave datetime/time/os themselves intact.
    for module in (cli, harden, update):
        monkeypatch.setattr(module, "datetime", Clock, raising=False)
    process = [11001]
    patch_module_attribute(monkeypatch, run_output, "time", "strftime", lambda fmt: fixed.strftime(fmt))
    patch_module_attribute(monkeypatch, run_output, "time", "monotonic_ns", lambda: 1234)
    patch_module_attribute(monkeypatch, run_output, "os", "getpid", lambda: process[0])
    with scoped_function_imports(optimise, ["_resolve_out_dir"], {"datetime": datetime}) as imports:
        monkeypatch.setattr(imports.datetime, "datetime", Clock)
        yield process


def _resolve(kind, target, explicit=None, suffix=""):
    if kind == "analyse":
        return cli._resolve_output_dir(explicit, prefix="sca")
    if kind == "fix":
        return optimise._resolve_out_dir(explicit)
    if kind == "update":
        return update._resolve_out_dir(SimpleNamespace(out=explicit), suffix=suffix)
    assert kind == "harden"
    return harden._default_out_dir(target)


@pytest.mark.parametrize("kind", ["analyse", "fix", "update", "harden"])
def test_default_paths_separate_processes_in_same_second(tmp_path, process_clock, kind):
    first = _resolve(kind, tmp_path / "target")
    process_clock[0] = 11002
    second = _resolve(kind, tmp_path / "target")
    assert first != second
    assert first.parent == second.parent == Path("out")
    prefix = {"analyse": "sca-", "fix": "sca-fix-", "update": "sca-update-",
              "harden": "sca-harden-target-"}[kind]
    assert first.name.startswith(prefix) and second.name.startswith(prefix)
    assert "20260102-030405" in first.name
    assert "20260102-030405" in second.name


@pytest.mark.parametrize("kind", ["analyse", "fix", "update"])
def test_explicit_output_remains_operator_selected(tmp_path, process_clock, kind):
    explicit = tmp_path / "chosen"
    first = _resolve(kind, tmp_path / "target", str(explicit))
    process_clock[0] = 11002
    assert first == _resolve(kind, tmp_path / "target", str(explicit)) == explicit.resolve()


def test_update_prepass_suffix_and_explicit_subdirectory_survive(tmp_path, process_clock):
    default = _resolve("update", tmp_path / "target", suffix="-prepass")
    assert default.name.endswith("-prepass")
    explicit = tmp_path / "chosen"
    assert _resolve("update", tmp_path / "target", str(explicit), "-prepass") == explicit / "prepass"


@isolated_cli_logging()
def test_two_offline_scans_keep_both_real_reports(tmp_path, monkeypatch, process_clock):
    monkeypatch.chdir(tmp_path)
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    # Empty actual targets: the production scan/report path has no dependency
    # resolver, native backend or provider work to perform.
    args = ["--offline", "--no-llm", "--no-cache"]
    assert cli.main([str(first), *args]) == 0
    first_out = next((tmp_path / "out").iterdir())
    report = (first_out / "report.md").read_bytes()
    process_clock[0] = 11002
    assert cli.main([str(second), *args]) == 0
    assert (first_out / "report.md").read_bytes() == report
    assert len(list((tmp_path / "out").iterdir())) == 2
    assert (first_out / "findings.json").is_file()
