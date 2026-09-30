"""Required-output contract of raptor-study-loop.

``--require-domain-model`` marks an invocation whose caller consumes
``domain-model.json`` (the binary-study / engagement path): a run
that ends without the model must exit nonzero AT study-loop's own
boundary, with the actual cause on stderr and in the machine-readable
``study-failure.json`` record — not exit 0 and leave the diagnosis to
whichever consumer looks for the model one stage later.

Without the flag the documented operator contracts are unchanged:
the overview-only run and the zero-item WARNING outcome still exit 0.
"""

import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

RAPTOR_DIR = Path(__file__).resolve().parents[3]
STUDY_LOOP = str(RAPTOR_DIR / "libexec" / "raptor-study-loop")


def _load_loop_module() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(
        "raptor_study_loop_contract", STUDY_LOOP)
    spec = importlib.util.spec_from_file_location(
        "raptor_study_loop_contract", STUDY_LOOP, loader=loader,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_loop = _load_loop_module()


def _failure_record(out: Path) -> dict | None:
    p = out / "study-failure.json"
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def _main(argv: list[str]) -> int:
    with patch.object(_loop, "_run", return_value=0), \
            patch.object(sys, "argv", ["raptor-study-loop"] + argv):
        return _loop.main()


def _setup(tmp_path: Path) -> tuple[Path, Path]:
    target = tmp_path / "src"
    target.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    return target, out


def _write_reading_list(out: Path) -> None:
    (out / "reading-list.json").write_text(json.dumps({"items": [
        {"id": "rl-1", "question": "Does `ghost_fn` check bounds?",
         "resolved": False, "resolution": "identifier"},
    ]}), encoding="utf-8")


class TestRequireDomainModelStudyPath:
    """Study-path runs under the flag: rc 0 is reserved for runs
    that end with domain-model.json on disk."""

    def test_zero_items_without_model_fails(self, tmp_path, capsys):
        target, out = _setup(tmp_path)
        # Prep (mocked to a no-op) "produced" an empty study list and
        # nothing wrote a domain model.
        (out / "study-list.json").write_text(
            json.dumps({"items": []}), encoding="utf-8")
        rc = _main([str(target), str(out), "--identifier", "some_fn",
                    "--require-domain-model"])
        assert rc == 1
        record = _failure_record(out)
        assert record is not None
        assert record["reason"] == "no_domain_model"
        assert "no study scope" in record["detail"]
        err = capsys.readouterr().err
        assert "study-loop: ERROR:" in err
        assert "domain model" in err

    def test_dropped_reading_names_are_the_named_cause(self, tmp_path):
        target, out = _setup(tmp_path)
        _write_reading_list(out)
        (out / "study-list.json").write_text(json.dumps({
            "items": [], "reading_list_dropped": 2,
        }), encoding="utf-8")
        rc = _main([str(target), str(out), "--require-domain-model"])
        assert rc == 1
        record = _failure_record(out)
        assert record is not None
        assert record["reason"] == "no_domain_model"
        assert "2 reading-list identifier(s)" in record["detail"]

    def test_study_pass_that_writes_no_model_fails(self, tmp_path):
        """Belt-and-braces: items were studied (mocked study-run
        exited 0) but no model landed — still a contract failure."""
        target, out = _setup(tmp_path)
        (out / "study-list.json").write_text(json.dumps({
            "items": [{"kind": "function", "name": "f", "file": "a.c"}],
        }), encoding="utf-8")
        rc = _main([str(target), str(out), "--identifier", "f",
                    "--skip-compile", "--require-domain-model"])
        assert rc == 1
        record = _failure_record(out)
        assert record is not None
        assert record["reason"] == "no_domain_model"
        assert "without writing domain-model.json" in record["detail"]

    def test_contract_failure_skips_promotion(self, tmp_path):
        target, out = _setup(tmp_path)
        (out / "study-list.json").write_text(
            json.dumps({"items": []}), encoding="utf-8")
        with patch.object(_loop, "_run", return_value=0), \
                patch.object(_loop, "_promote_to_project") as promote, \
                patch.object(_loop, "_store_in_sage") as sage, \
                patch.object(sys, "argv", [
                    "raptor-study-loop", str(target), str(out),
                    "--identifier", "some_fn",
                    "--require-domain-model"]):
            rc = _loop.main()
        assert rc == 1
        assert not promote.called
        assert not sage.called

    def test_model_on_disk_satisfies_the_contract(self, tmp_path):
        target, out = _setup(tmp_path)
        (out / "study-list.json").write_text(
            json.dumps({"items": []}), encoding="utf-8")
        # The prior-model resume shape: domain-model.json exists (e.g.
        # copied in from the project store, or written by pass 1).
        (out / "domain-model.json").write_text(json.dumps({
            "concepts": [], "invariants": [], "contracts": [],
        }), encoding="utf-8")
        # Stale record from an earlier failed run in the reused dir.
        (out / "study-failure.json").write_text(json.dumps({
            "schema": "study-failure/1", "reason": "study_error",
            "detail": "stale",
        }), encoding="utf-8")
        rc = _main([str(target), str(out), "--identifier", "some_fn",
                    "--require-domain-model"])
        assert rc == 0
        # The stale record was cleared at run start — a present record
        # always describes the LATEST failed run.
        assert _failure_record(out) is None

    def test_produced_model_exits_zero(self, tmp_path):
        target, out = _setup(tmp_path)
        (out / "study-list.json").write_text(json.dumps({
            "items": [{"kind": "function", "name": "f", "file": "a.c"}],
        }), encoding="utf-8")

        def fake_run(cmd, *, verbose=False):
            if "raptor-study-run" in cmd[1]:
                (out / "domain-model.json").write_text(json.dumps({
                    "concepts": [], "invariants": [], "contracts": [],
                }), encoding="utf-8")
            return 0

        with patch.object(_loop, "_run", side_effect=fake_run), \
                patch.object(sys, "argv", [
                    "raptor-study-loop", str(target), str(out),
                    "--identifier", "f", "--skip-compile",
                    "--require-domain-model"]):
            rc = _loop.main()
        assert rc == 0
        assert _failure_record(out) is None


class TestRequireDomainModelOverviewFallback:
    """An invocation that promises a domain model must refuse the
    overview-only fallback — an overview can never produce one."""

    def test_overview_fallback_refused_before_spending(self, tmp_path,
                                                       capsys):
        target, out = _setup(tmp_path)
        with patch.object(_loop, "_overview_from_directory") as ov, \
                patch.object(sys, "argv", [
                    "raptor-study-loop", str(target), str(out),
                    "--require-domain-model"]):
            rc = _loop.main()
        assert rc == 1
        # Refused BEFORE the overview LLM call — no spend on a run
        # that already cannot meet its contract.
        assert not ov.called
        record = _failure_record(out)
        assert record is not None
        assert record["reason"] == "no_domain_model"
        assert "overview" in record["detail"]
        assert "study-loop: ERROR:" in capsys.readouterr().err


class TestWithoutFlagUnchanged:
    """The documented operator contracts keep their rc-0 outcomes."""

    def test_zero_items_still_exits_zero(self, tmp_path, capsys):
        target, out = _setup(tmp_path)
        (out / "study-list.json").write_text(
            json.dumps({"items": []}), encoding="utf-8")
        rc = _main([str(target), str(out), "--identifier", "some_fn"])
        assert rc == 0
        assert _failure_record(out) is None
        assert "no study items — done" in capsys.readouterr().err

    def test_overview_mode_still_exits_zero(self, tmp_path):
        target, out = _setup(tmp_path)
        with patch.object(
                    _loop, "_overview_from_directory",
                    return_value=(["a_fn"], ["a concept"], "s", "t"),
                ), \
                patch.object(sys, "argv", [
                    "raptor-study-loop", str(target), str(out)]):
            rc = _loop.main()
        assert rc == 0
        assert (out / "overview.json").is_file()
        assert _failure_record(out) is None
