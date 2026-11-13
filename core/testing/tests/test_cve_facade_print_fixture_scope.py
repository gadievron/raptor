"""Facade stdout faults remain local while the actual sidecar writer runs."""
import builtins
from contextlib import nullcontext
import json
from pathlib import Path

import pytest

from packages.cve_env.tests.unit import test_facade_contract as native


@pytest.mark.parametrize("inherited", [False, True], ids=["absent", "present"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_sidecar_print_fixture_restores_lookup(tmp_path, capsys, inherited, failure):
    printer = builtins.print
    main = native.cli_mod.main
    expected_source = Path(native.__file__).resolve().parents[2] / "cve_env" / "cli.py"
    assert Path(main.__code__.co_filename).resolve() == expected_source
    missing = object()
    binding = vars(native.cli_mod).get("print", missing)
    written = []

    def borrowed(*args, **kwargs):
        raise AssertionError("owned print fault must replace inherited CLI printer")

    def observed(*args, **kwargs):
        assert builtins.print is printer
        assert callable(vars(native.cli_mod)["print"])
        assert vars(native.cli_mod)["print"] is not borrowed
        try:
            return main(*args, **kwargs)
        except BrokenPipeError as exc:
            assert str(exc) == "stdout gone"
            sidecar = tmp_path / f"{native.CVE}.outcome.json"
            assert sidecar.is_file()
            assert json.loads(sidecar.read_text())["status"] == "success"
            written.append(sidecar)
            if failure:
                raise failure("owned body failure") from exc
            raise

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        if inherited:
            owner.setitem(vars(native.cli_mod), "print", borrowed)
        else:
            owner.delitem(vars(native.cli_mod), "print", raising=False)
        owner.setattr(native.cli_mod, "main", observed)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                native.TestOutcomeContract().test_sidecar_survives_stdout_failure(tmp_path, body, capsys)
        assert len(written) == 1
        assert vars(native.cli_mod).get("print", missing) is (borrowed if inherited else missing)
        assert builtins.print is printer
    assert vars(native.cli_mod).get("print", missing) is binding
    assert native.cli_mod.main is main
