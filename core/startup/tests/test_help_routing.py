"""Fast help routing checks; full cold rendering stays in the slow suite."""

from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

_MODES = (
    "scan",
    "binary",
    "fuzz",
    "web",
    "agentic",
    "codeql",
    "analyze",
    "openant",
    "sca",
    "doctor",
)


@pytest.mark.parametrize("mode", _MODES)
@pytest.mark.parametrize("help_flag", ["--help", "-h"])
def test_mode_help_routes_before_lifecycle(mode, help_flag, monkeypatch, capsys):
    import raptor
    from core.startup import doctor

    calls = []

    def forbidden(*args, **kwargs):
        raise AssertionError("help entered the run lifecycle or diagnostic probes")

    def child(command, **options):
        calls.append((command, options))
        print("owned child help")
        return subprocess.CompletedProcess(command, 0)

    for name in (
        "_run_with_lifecycle",
        "get_output_dir",
        "start_run",
        "complete_run",
        "fail_run",
    ):
        monkeypatch.setattr(raptor, name, forbidden)
    monkeypatch.setattr(doctor, "_gather", forbidden)
    monkeypatch.setattr(
        raptor,
        "subprocess",
        SimpleNamespace(
            **(vars(subprocess) | {"run": child}),
        ),
    )
    monkeypatch.setattr(sys, "argv", ["raptor.py", mode, help_flag])
    assert raptor.main() == 0
    output = capsys.readouterr()
    combined = output.out + output.err
    assert "OUTPUT_DIR=" not in combined
    assert "Target license:" not in combined
    assert "[*] Starting" not in combined
    assert "llm-dispatcher server.start" not in combined
    if mode == "doctor":
        assert not calls
        assert "usage: raptor doctor" in output.out
    else:
        assert len(calls) == 1
        command, options = calls[0]
        assert command[0] == sys.executable
        if mode == "sca":
            assert (
                Path(command[1])
                == Path(raptor.__file__).parent / "libexec/raptor-sca-run"
            )
            assert command[2:] == [help_flag]
        else:
            assert Path(command[1]) == raptor._mode_help_scripts()[mode]
            assert command[2:] == ["--help"]
            assert options["timeout"] == 10
        assert options["check"] is False
        assert isinstance(options["env"], dict)
