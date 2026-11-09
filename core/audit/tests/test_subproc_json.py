"""JSON child protocol for the Z3/SMT verification layer."""

from __future__ import annotations

import pytest

from pathlib import Path

from core.audit.subproc_json import _CHILD_SCRIPT_PATH, run_json_child
from core.audit.sweep import SweepResult, smt_child_env


class TestChildScript:
    def test_no_pickle_in_protocol(self) -> None:
        """The child protocol must never unpickle — a compromised or
        crashed child hands back at worst malformed JSON."""
        src = Path(_CHILD_SCRIPT_PATH).read_text(encoding="utf-8")
        assert "pickle" not in src
        assert "json" in src

    def test_child_is_a_named_in_tree_script(self) -> None:
        """EDR coexistence: the child must be an on-disk script inside
        the RAPTOR tree executed by path — never a ``python -c`` blob
        (loader-shaped to endpoint-security heuristics)."""
        child = Path(_CHILD_SCRIPT_PATH)
        assert child.is_file()
        assert child.name == "_json_child.py"
        repo_root = Path(__file__).resolve().parents[3]
        assert repo_root in child.parents
        import inspect

        from core.audit import subproc_json
        src = inspect.getsource(subproc_json)
        assert '"-c"' not in src


@pytest.mark.usefixtures("owned_smt_subprocess")
class TestRunJsonChild:
    def test_round_trip_through_real_child(self) -> None:
        """Full spawn: the SMT verb adapter returns a SweepResult dict
        (inconclusive — no operands extractable; no solver needed)."""
        out = run_json_child(
            "core.audit.sweep:_run_smt_verb_inner_json",
            {
                "file_path": "f.c", "function_name": "f",
                "verb": "check-negative-bypass", "source": "int x;",
                "hypothesis": "nothing", "target_path": None,
            },
            env=smt_child_env(),
            timeout=30,
        )
        assert isinstance(out, dict)
        sr = SweepResult(**out)
        assert sr.outcome == "inconclusive"
        assert sr.tool == "smt"

    def test_child_exception_returns_none(self, monkeypatch) -> None:
        from core.audit import subproc_json

        real_run = subproc_json._sandbox_run
        outcomes = []

        def observe(command, **options):
            proc = real_run(command, **options)
            options["stderr"].seek(0)
            outcomes.append((proc.returncode, options["stderr"].read()))
            return proc

        monkeypatch.setattr(subproc_json, "_sandbox_run", observe)
        # This allowed dispatcher raises TypeError for missing arguments.
        # An unregistered entry would return before starting the worker.
        out = run_json_child(
            "core.audit.sweep:_run_smt_verb_inner_json",
            {},
            env=smt_child_env(),
            timeout=30,
        )
        assert out is None
        assert len(outcomes) == 1
        assert outcomes[0][0] != 0
        assert b"SMT worker failed: TypeError" in outcomes[0][1]

    def test_timeout_returns_none(self, monkeypatch) -> None:
        import subprocess
        from core.audit import subproc_json
        from core.audit._json_protocol import decode, MAX_REQUEST_BYTES

        calls = []
        request = {"tag": "nope", "args": {}}
        entry = "core.audit.condition_smt:_z3_dispatch_json"

        def timeout(command, **options):
            assert entry in command
            assert decode(options["input"], MAX_REQUEST_BYTES) == request
            assert options["timeout"] == 1
            calls.append((options["stdout"], options["stderr"], Path(options["cwd"])))
            raise subprocess.TimeoutExpired(command, options["timeout"])

        monkeypatch.setattr(subproc_json, "_sandbox_run", timeout)
        assert run_json_child(entry, request, env=smt_child_env(), timeout=1) is None
        assert len(calls) == 1
        stdout, stderr, scratch = calls[0]
        assert stdout.closed and stderr.closed
        assert not scratch.exists()

    @pytest.mark.parametrize("entry", ["time:sleep", "core.audit.subproc_json:does_not_exist"])
    def test_unregistered_entry_never_dispatches(self, monkeypatch, entry) -> None:
        from core.audit import subproc_json

        def unexpected(*args, **kwargs):
            pytest.fail("unregistered entry reached worker execution")

        monkeypatch.setattr(subproc_json, "_sandbox_run", unexpected)
        assert run_json_child(entry, {}, env=smt_child_env()) is None

    def test_unserialisable_request_returns_none(self) -> None:
        out = run_json_child(
            "core.audit.sweep:_run_smt_verb_inner_json",
            {"bad": object()},
            env=smt_child_env(),
        )
        assert out is None


@pytest.mark.usefixtures("owned_smt_subprocess")
class TestZ3DispatchJson:
    def test_unknown_tag_returns_none(self) -> None:
        from core.audit.condition_smt import _z3_dispatch_json
        assert _z3_dispatch_json({"tag": "nope", "args": {}}) is None

    def test_path_feasibility_round_trip(self) -> None:
        pytest.importorskip("z3")
        from core.audit.condition_smt import (
            BoundsConstraint,
            _try_z3_path_feasibility,
        )
        contradiction = [
            BoundsConstraint("x", "<", 10, "x < 10"),
            BoundsConstraint("x", ">", 20, "x > 20"),
        ]
        result = _try_z3_path_feasibility(contradiction)
        assert result is not None
        feasible, reasoning, witness = result
        assert feasible is False
        assert "infeasible" in reasoning
        assert witness is None

    def test_signed_mismatch_round_trip(self) -> None:
        pytest.importorskip("z3")
        from core.audit.condition_smt import _try_z3_signed_mismatch
        result = _try_z3_signed_mismatch("n", "<", 100, 32)
        assert result is not None
        assert result.mismatch is True
        assert result.witness  # concrete int witness survives JSON

    def test_guard_sufficiency_round_trip(self) -> None:
        pytest.importorskip("z3")
        from core.audit.condition_smt import BoundsConstraint, _try_z3_check
        result = _try_z3_check(
            [BoundsConstraint("len", "<", 4096, "len < 4096")],
            256,
            "memcpy",
        )
        assert result is not None
        assert result[0] is True  # guard insufficient for 256-byte dst
        assert isinstance(result[2], dict)


@pytest.mark.parametrize('platform,limit_name,allowed', [
    pytest.param('darwin', 'RLIMIT_AS', True, id='macos-address-space'),
    pytest.param('linux', 'RLIMIT_AS', False, id='linux-address-space'),
    pytest.param('darwin', 'RLIMIT_CPU', False, id='macos-cpu'),
    pytest.param('darwin', 'RLIMIT_FSIZE', False, id='macos-file-size'),
])
def test_worker_limit_refusals_are_platform_and_resource_specific(monkeypatch, platform, limit_name, allowed):
    import io
    import resource
    from types import SimpleNamespace
    from core.audit import _json_child as worker

    output = io.StringIO()
    monkeypatch.setattr(worker, 'sys', SimpleNamespace(platform=platform, stderr=output))
    monkeypatch.setattr(resource, 'getrlimit', lambda which: (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    def refused(which, value):
        raise ValueError('unsupported resource limit')
    monkeypatch.setattr(resource, 'setrlimit', refused)
    if allowed:
        worker._limit(getattr(resource, limit_name), 2048)
        assert 'not enforced' in output.getvalue()
    else:
        with pytest.raises(ValueError, match='unsupported resource limit'):
            worker._limit(getattr(resource, limit_name), 2048)
        assert output.getvalue() == ''
