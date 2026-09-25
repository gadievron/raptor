"""Tests for the raptor-review verdict verb (operator FP/TP/retest)."""

import argparse
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_review_module():
    cli_path = str(REPO_ROOT / "libexec" / "raptor-review")
    loader = SourceFileLoader("raptor_review_cli_verdict", cli_path)
    spec = importlib.util.spec_from_loader(
        "raptor_review_cli_verdict", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _make_run(tmp_path, target: Path) -> Path:
    run = tmp_path / "run_001"
    run.mkdir()
    (run / ".raptor-run.json").write_text(json.dumps({
        "command": "agentic",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "status": "completed",
        "target_path": str(target),
    }), encoding="utf-8")
    (run / "findings.json").write_text(json.dumps([
        {"id": "find-001", "file": "src/a.c", "function": "parse",
         "line": 3, "rule_id": "cpp/overflow"},
        {"id": "find-002", "file": "src/a.c", "function": "emit",
         "line": 9, "rule_id": "cpp/format"},
    ]), encoding="utf-8")
    return run


def _make_target(tmp_path) -> Path:
    target = tmp_path / "repo"
    (target / "src").mkdir(parents=True)
    (target / "src" / "a.c").write_text(
        "\n".join(f"int l{i};" for i in range(20)), encoding="utf-8")
    return target


def _args(run, finding_id, verdict, **extra):
    ns = argparse.Namespace(
        out=str(run), finding_id=finding_id, verdict=verdict,
        reason=extra.pop("reason", None),
        target=extra.pop("target", None),
        source=extra.pop("source", None),
    )
    for k, v in extra.items():
        setattr(ns, k, v)
    return ns


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Loaded CLI module + run/target dirs + captured SAGE calls."""
    mod = _load_review_module()
    target = _make_target(tmp_path)
    run = _make_run(tmp_path, target)

    import core.sage.hooks as hooks

    calls = {"store": [], "forget": [], "client": object()}
    monkeypatch.setattr(hooks, "operator_client",
                        lambda: calls["client"])

    def fake_store(repo, rule, file, fn, src, verdict, *, note="",
                   client=None):
        calls["store"].append((repo, rule, file, fn, src, verdict,
                               note, client))
        return True

    def fake_forget(repo, rule, file, fn, *, verdicts=None, reason="",
                    client=None):
        calls["forget"].append((repo, rule, file, fn, verdicts, reason))
        return (2, 0)

    monkeypatch.setattr(hooks, "store_finding_verdict", fake_store)
    monkeypatch.setattr(hooks, "forget_finding_verdicts", fake_forget)
    return mod, run, target, calls


def _patch_provenance(monkeypatch, interactive: bool):
    import core.annotations.provenance as prov
    ctx = {
        prov.TTY_KEY: "stdin,stdout,stderr" if interactive else "none",
        prov.PROVENANCE_KEY: (prov.INTERACTIVE_TTY if interactive
                              else prov.NON_TTY),
        prov.SID_KEY: prov.SID_INHERITED,
        prov.ENV_MARKERS_KEY: "none",
        prov.PARENTS_KEY: "bash",
    }
    monkeypatch.setattr(prov, "detect_invocation_context", lambda: ctx)


class TestFpVerb:
    def test_tty_records_human_source(self, env, monkeypatch, capsys):
        mod, run, target, calls = env
        _patch_provenance(monkeypatch, interactive=True)
        mod.cmd_verdict(_args(run, "find-001", "fp", reason="dup of x"))
        (store,) = calls["store"]
        repo, rule, file, fn, src, verdict, note, client = store
        assert verdict == "false_positive"
        assert (rule, file, fn) == ("cpp/overflow", "src/a.c", "parse")
        assert repo == str(target)
        assert src  # windowed hash computed against the target tree
        assert "source=human" in note
        assert "provenance=interactive-tty" in note
        assert "reason=dup of x" in note
        assert client is calls["client"]
        out = capsys.readouterr().out
        assert "False Positive" in out
        assert "FALSE" not in out  # never ALL_CAPS in human output
        # Disk-side audit record via the suppressions single-writer.
        recs = [json.loads(line) for line in
                (run / "suppressions.jsonl").read_text(
                    encoding="utf-8").splitlines()]
        assert recs[0]["verdict"] == "operator_false_positive"
        assert recs[0]["dropped"] is False
        assert recs[0]["source"] == "human"

    def test_fp_refused_on_non_tty_with_zero_mutation(
            self, env, monkeypatch, capsys):
        # Probe-P6 shape: a non-interactive fp must refuse — no SAGE
        # row, no suppressions record, no findings-file change.
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=False)
        before = (run / "findings.json").read_text(encoding="utf-8")
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "fp"))
        assert exc.value.code != 0
        err = capsys.readouterr().err
        assert "Refused" in err and "interactive" in err
        assert calls["store"] == []
        assert not (run / "suppressions.jsonl").exists()
        assert (run / "findings.json").read_text(
            encoding="utf-8") == before

    def test_fp_refused_on_non_tty_even_with_explicit_source(
            self, env, monkeypatch, capsys):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=False)
        with pytest.raises(SystemExit):
            mod.cmd_verdict(_args(run, "find-001", "fp",
                                  source="human"))
        assert calls["store"] == []

    def test_non_tty_source_is_agent(self, env, monkeypatch):
        # tp stays available non-interactively (fail-safe: it only
        # causes re-analysis); its stamp records the agent context.
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=False)
        mod.cmd_verdict(_args(run, "find-001", "tp"))
        note = calls["store"][0][6]
        assert "source=agent" in note
        assert "provenance=non-tty" in note

    def test_explicit_human_on_non_tty_demotes_with_warning(
            self, env, monkeypatch, capsys):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=False)
        mod.cmd_verdict(_args(run, "find-001", "tp", source="human"))
        assert "source=agent" in calls["store"][0][6]
        assert "source=agent" in capsys.readouterr().err

    def test_explicit_human_on_tty_kept(self, env, monkeypatch):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True)
        mod.cmd_verdict(_args(run, "find-001", "fp", source="human"))
        assert "source=human" in calls["store"][0][6]

    def test_sage_absent_is_a_clear_error(self, env, monkeypatch,
                                          capsys):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True)
        import core.sage.hooks as hooks
        monkeypatch.setattr(hooks, "operator_client", lambda: None)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "fp"))
        assert exc.value.code == 1
        assert "SAGE" in capsys.readouterr().err
        assert calls["store"] == []

    def test_fp_store_failure_leaves_disk_untouched(self, env,
                                                    monkeypatch,
                                                    capsys):
        # SAGE store first, disk second: a refused row must not leave
        # a half-applied verdict (cleared force-through) behind.
        mod, run, _target, _calls = env
        _patch_provenance(monkeypatch, interactive=True)
        path = run / "findings.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data[0]["manual_override"] = True
        path.write_text(json.dumps(data), encoding="utf-8")
        import core.sage.hooks as hooks
        monkeypatch.setattr(hooks, "store_finding_verdict",
                            lambda *a, **k: False)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "fp"))
        assert exc.value.code == 1
        assert "Nothing was changed" in capsys.readouterr().err
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data[0]["manual_override"] is True

    def test_fp_clears_standing_manual_override(self, env, monkeypatch):
        mod, run, _target, _calls = env
        _patch_provenance(monkeypatch, interactive=True)
        path = run / "findings.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data[0]["manual_override"] = True
        path.write_text(json.dumps(data), encoding="utf-8")
        mod.cmd_verdict(_args(run, "find-001", "fp"))
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "manual_override" not in data[0]


class TestTpVerb:
    def test_clears_suppression_and_sets_override(self, env,
                                                  monkeypatch, capsys):
        mod, run, target, calls = env
        _patch_provenance(monkeypatch, interactive=True)
        mod.cmd_verdict(_args(run, "find-001", "tp", reason="verified"))
        (forget,) = calls["forget"]
        repo, rule, file, fn, verdicts, _reason = forget
        assert repo == str(target)
        from core.sage.hooks import SUPPRESS_VERDICTS
        assert verdicts == SUPPRESS_VERDICTS
        # true_positive row stored for the knowledge base.
        assert calls["store"][0][5] == "true_positive"
        data = json.loads((run / "findings.json").read_text(
            encoding="utf-8"))
        assert data[0]["manual_override"] is True
        assert data[0]["manual_override_reason"] == "verified"
        assert "manual_override" not in data[1]
        out = capsys.readouterr().out
        assert "True Positive" in out

    def test_sage_absent_still_sets_override(self, env, monkeypatch,
                                             capsys):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True)
        import core.sage.hooks as hooks
        monkeypatch.setattr(hooks, "operator_client", lambda: None)
        mod.cmd_verdict(_args(run, "find-001", "tp"))
        data = json.loads((run / "findings.json").read_text(
            encoding="utf-8"))
        assert data[0]["manual_override"] is True
        assert calls["forget"] == []
        assert "SAGE" in capsys.readouterr().err


    def test_refused_deprecations_fail_loudly(self, env, monkeypatch,
                                              capsys):
        # Probe-P4 shape: a server refusing some deprecations must
        # surface as failure — the surviving suppressing row would
        # otherwise be reported as cleared. No store, no disk edit.
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True)
        import core.sage.hooks as hooks
        monkeypatch.setattr(
            hooks, "forget_finding_verdicts",
            lambda *a, **k: (1, 2))
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "tp"))
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert "could not be deprecated" in err
        assert calls["store"] == []
        data = json.loads((run / "findings.json").read_text(
            encoding="utf-8"))
        assert "manual_override" not in data[0]

    def test_truncated_walk_fails_closed_before_disk_edits(
            self, env, monkeypatch, capsys):
        mod, run, _target, _calls = env
        _patch_provenance(monkeypatch, interactive=True)
        import core.sage.hooks as hooks

        def raising_forget(*a, **k):
            raise hooks.VerdictWalkTruncated("page cap reached")

        monkeypatch.setattr(hooks, "forget_finding_verdicts",
                            raising_forget)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "tp"))
        assert exc.value.code == 1
        assert "enumerate" in capsys.readouterr().err
        data = json.loads((run / "findings.json").read_text(
            encoding="utf-8"))
        assert "manual_override" not in data[0]

    def test_unknown_target_warns_instead_of_cleared_zero(
            self, env, monkeypatch, capsys):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True)
        # Sever the manifest's target_path.
        meta_path = run / ".raptor-run.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        del meta["target_path"]
        meta_path.write_text(json.dumps(meta), encoding="utf-8")
        mod.cmd_verdict(_args(run, "find-001", "tp"))
        captured = capsys.readouterr()
        assert "NOT cleared" in captured.err
        assert "Cleared:  0" not in captured.out
        assert calls["forget"] == []


class TestRetestVerb:
    def test_clears_everything(self, env, monkeypatch, capsys):
        mod, run, target, calls = env
        _patch_provenance(monkeypatch, interactive=True)
        path = run / "findings.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data[0]["manual_override"] = True
        data[0]["manual_override_reason"] = "old"
        path.write_text(json.dumps(data), encoding="utf-8")
        mod.cmd_verdict(_args(run, "find-001", "retest"))
        (forget,) = calls["forget"]
        assert forget[0] == str(target)
        assert forget[4] is None  # all verdicts cleared
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "manual_override" not in data[0]
        out = capsys.readouterr().out
        assert "re-analyzes" in out


class TestResolution:
    def test_miss_prints_did_you_mean_and_exits_2(self, env,
                                                  monkeypatch, capsys):
        mod, run, _target, _calls = env
        _patch_provenance(monkeypatch, interactive=True)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-003", "fp"))
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "Did you mean" in err
        assert "find-001" in err or "find-002" in err

    def test_second_finding_uses_its_own_coords(self, env, monkeypatch):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True)
        mod.cmd_verdict(_args(run, "find-002", "fp"))
        assert calls["store"][0][3] == "emit"

    def test_ambiguous_prefix_exits_2(self, env, monkeypatch, capsys):
        mod, run, _target, _calls = env
        _patch_provenance(monkeypatch, interactive=True)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-0", "fp"))
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "find-001" in err and "find-002" in err

    def test_no_runs_exits_1(self, env, monkeypatch, capsys):
        mod, _run, _target, _calls = env
        _patch_provenance(monkeypatch, interactive=True)
        ns = _args("", "find-001", "fp")
        ns.out = None
        ns.project = None
        monkeypatch.setattr(mod, "_project_dir_for", lambda a: None)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(ns)
        assert exc.value.code == 1
