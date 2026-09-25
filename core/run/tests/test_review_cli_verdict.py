"""Tests for the raptor-review verdict verb (operator FP/TP/retest)."""

import argparse
import importlib.util
import json
import os
import subprocess
import sys
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
    # The CLI's interpreter-env hardening refuses to run when
    # PYTHON* startup variables are set (they can forge provenance
    # before the file's first line). The in-process harness is not
    # that threat — clear them around the load so a CI runner's own
    # PYTHONPATH cannot fail every test here; the refusal itself is
    # covered by TestInterpreterEnvHardening's subprocess test.
    saved = {k: os.environ.pop(k) for k in
             ("PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME")
             if k in os.environ}
    try:
        loader.exec_module(mod)
    finally:
        os.environ.update(saved)
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
                   mint=None, client=None):
        calls["store"].append((repo, rule, file, fn, src, verdict,
                               note, client, mint))
        return True

    def fake_forget(repo, rule, file, fn, *, verdicts=None, reason="",
                    client=None):
        calls["forget"].append((repo, rule, file, fn, verdicts, reason))
        return (2, 0)

    monkeypatch.setattr(hooks, "store_finding_verdict", fake_store)
    monkeypatch.setattr(hooks, "forget_finding_verdicts", fake_forget)
    return mod, run, target, calls


def _patch_provenance(monkeypatch, interactive: bool, *,
                      envm: str = "none",
                      parents: str = "bash,sshd",
                      tty: str | None = None,
                      sid: str | None = None):
    """Inject an invocation context at the documented test seam.

    ``interactive=True`` with the defaults is a context that earns the
    full OPERATOR grant (``live_context_grants_operator``): an
    interactive TTY, inherited session, no dispatch environment
    marker, and a shell-rooted ancestry that does not END at the
    shell (an interactive shell has a live parent — hence
    ``bash,sshd``; a bare ``bash`` chain is the orphaned launder
    shape and does NOT grant). Override ``envm``/``parents`` to model
    the interactive-but-not-operator shapes the fp gate must refuse,
    and ``tty``/``sid`` to model the fd/session shapes the fp
    ceremony's own gates must refuse.
    """
    import core.annotations.provenance as prov
    if tty is None:
        tty = "stdin,stdout,stderr" if interactive else "none"
    ctx = {
        prov.TTY_KEY: tty,
        prov.PROVENANCE_KEY: (prov.INTERACTIVE_TTY if interactive
                              else prov.NON_TTY),
        prov.SID_KEY: sid if sid is not None else prov.SID_INHERITED,
        prov.ENV_MARKERS_KEY: envm,
        prov.PARENTS_KEY: parents,
    }
    monkeypatch.setattr(prov, "detect_invocation_context", lambda: ctx)


class TestFpVerb:
    def test_tty_records_human_source(self, env, monkeypatch, capsys):
        mod, run, target, calls = env
        _patch_provenance(monkeypatch, interactive=True)
        mod.cmd_verdict(_args(run, "find-001", "fp", reason="dup of x"))
        (store,) = calls["store"]
        repo, rule, file, fn, src, verdict, note, client, _mint = store
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

    def test_fp_refused_on_tty_without_operator_grant(
            self, env, monkeypatch, capsys):
        # The gate is live_context_grants_operator, NOT bare isatty:
        # an in-session agent invocation on the launcher's pty is
        # interactive-TTY while carrying the dispatch environment
        # marker — the exact laundering shape that could otherwise
        # mint a standing 30-day suppression. Refuse with zero
        # mutation and a message naming the operator requirement.
        # (Reverting the gate to a bare TTY check reds this test.)
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True,
                          envm="claudecode")
        before = (run / "findings.json").read_text(encoding="utf-8")
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "fp"))
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "Refused" in err
        assert "operator context" in err
        assert "live_context_grants_operator" in err
        assert calls["store"] == []
        assert not (run / "suppressions.jsonl").exists()
        assert (run / "findings.json").read_text(
            encoding="utf-8") == before

    def test_fp_refused_on_tty_with_orphaned_ancestry(
            self, env, monkeypatch, capsys):
        # Second interactive-but-not-operator axis: a chain that ends
        # at the shell (no live parent) is the orphaned/reparented
        # launder shape — interactive-TTY, grant refused.
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True,
                          parents="bash")
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "fp"))
        assert exc.value.code == 2
        assert "operator context" in capsys.readouterr().err
        assert calls["store"] == []

    def test_tp_and_retest_stay_available_without_operator_grant(
            self, env, monkeypatch):
        # The fail-safe asymmetry is unchanged: tp/retest only cause
        # re-analysis, so the interactive-agent context that the fp
        # gate refuses still runs them (their stamp records the
        # context, envm included, for the auditor).
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True,
                          envm="claudecode")
        mod.cmd_verdict(_args(run, "find-001", "tp"))
        assert calls["store"][0][5] == "true_positive"
        assert "envm=claudecode" in calls["store"][0][6]
        mod.cmd_verdict(_args(run, "find-001", "retest"))
        assert len(calls["forget"]) == 2

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


def _patch_input(monkeypatch, answer=None, *, record=None):
    """Drive (or forbid) the ceremony's typed confirmation.

    ``answer=None`` forbids the prompt entirely — reaching it is the
    failure (gates must refuse BEFORE consent is requested). A
    callable raises/returns per call; a string is returned once.
    """
    import builtins

    def fake_input(prompt=""):
        if record is not None:
            record.append(prompt)
        if answer is None:
            raise AssertionError(
                "ceremony prompt reached — the context gate should "
                "have refused first")
        if callable(answer):
            return answer(prompt)
        return answer

    monkeypatch.setattr(builtins, "input", fake_input)


class TestFpCeremony:
    """The typed-consent production route for the fp mint."""

    # The launcher-route production shape: bin/raptor exports
    # _RAPTOR_TRUSTED=1 (envm=trusted), so the operator grant refuses
    # — the ceremony is exactly for this context.
    _PROD = {"envm": "trusted", "parents": "bash,sshd"}

    def test_ceremony_mints_where_the_grant_refuses(
            self, env, monkeypatch, capsys):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True, **self._PROD)
        prompts: list = []
        _patch_input(monkeypatch, "suppress find-001", record=prompts)
        mod.cmd_verdict(_args(run, "find-001", "fp", ceremony=True))
        (store,) = calls["store"]
        note, mint = store[6], store[8]
        assert store[5] == "false_positive"
        # The mint provenance rides the MAC-bound mint fields, not
        # free note text: ceremony-minted, grant result recorded
        # alongside (the ceremony never silently bypasses the grant),
        # and the detected context bound in as mintctx.
        assert mint["minted"] == "ceremony"
        assert mint["grant"] == "refused"
        assert "envm=trusted" in mint["mintctx"]
        assert "sid=inherited" in mint["mintctx"]
        assert "envm=trusted" in note
        recs = [json.loads(line) for line in
                (run / "suppressions.jsonl").read_text(
                    encoding="utf-8").splitlines()]
        assert recs[0]["minted"] == "ceremony"
        assert recs[0]["operator_grant"] is False
        # The consent display named the phrase and the finding.
        assert prompts and "suppress find-001" in prompts[0]
        out = capsys.readouterr().out
        assert "Ceremony" in out
        assert "retest" in out  # revocation named at the consent

    def test_ceremony_records_grant_granted_when_it_grants(
            self, env, monkeypatch):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True)
        _patch_input(monkeypatch, "suppress find-001")
        mod.cmd_verdict(_args(run, "find-001", "fp", ceremony=True))
        mint = calls["store"][0][8]
        assert mint["minted"] == "ceremony"
        assert mint["grant"] == "granted"

    def test_grant_minted_rows_stay_distinguishable(
            self, env, monkeypatch):
        # A plain fp in a granting context stamps minted=grant — an
        # auditor can always tell the two mint authorities apart.
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True)
        mod.cmd_verdict(_args(run, "find-001", "fp"))
        mint = calls["store"][0][8]
        assert mint["minted"] == "grant"
        assert mint["grant"] == "granted"
        assert "mintctx" in mint
        recs = [json.loads(line) for line in
                (run / "suppressions.jsonl").read_text(
                    encoding="utf-8").splitlines()]
        assert recs[0]["minted"] == "grant"
        assert recs[0]["operator_grant"] is True

    @pytest.mark.parametrize("tty", [
        "none", "stdin", "stdout", "stderr", "stdin,stdout",
        "stdin,stderr", "stdout,stderr",
    ])
    def test_ceremony_refuses_any_non_tty_fd(self, env, monkeypatch,
                                             capsys, tty):
        # Hard non-TTY refusal on ALL std fds: every combination
        # short of three TTYs refuses, before the prompt, with zero
        # mutation. (The agent harness's Bash tool runs commands with
        # all three fds piped — tty=none — so the stock tool-call
        # route stops here.)
        mod, run, _target, calls = env
        interactive = tty != "none"
        _patch_provenance(monkeypatch, interactive=interactive,
                          tty=tty, **self._PROD)
        _patch_input(monkeypatch, None)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "fp",
                                  ceremony=True))
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "Ceremony refused" in err
        assert "Nothing was stored or changed" in err
        assert calls["store"] == []
        assert not (run / "suppressions.jsonl").exists()

    def test_ceremony_refuses_session_leader(self, env, monkeypatch,
                                             capsys):
        # The direct script(1)/pty.fork exec shape: the process IS
        # its own session leader — a shell never execs a command as
        # one.
        mod, run, _target, calls = env
        import core.annotations.provenance as prov
        _patch_provenance(monkeypatch, interactive=True,
                          sid=prov.SID_SELF, **self._PROD)
        _patch_input(monkeypatch, None)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "fp",
                                  ceremony=True))
        assert exc.value.code == 2
        assert "session leader" in capsys.readouterr().err
        assert calls["store"] == []

    def test_ceremony_refuses_script_wrapper_ancestry(
            self, env, monkeypatch, capsys):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True,
                          envm="trusted", parents="bash,script,sshd")
        _patch_input(monkeypatch, None)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "fp",
                                  ceremony=True))
        assert exc.value.code == 2
        assert "script" in capsys.readouterr().err
        assert calls["store"] == []

    def test_wrong_phrase_refuses_with_zero_mutation(
            self, env, monkeypatch, capsys):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True, **self._PROD)
        _patch_input(monkeypatch, "y")
        before = (run / "findings.json").read_text(encoding="utf-8")
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "fp",
                                  ceremony=True))
        assert exc.value.code == 3
        assert "Aborted" in capsys.readouterr().out
        assert calls["store"] == []
        assert not (run / "suppressions.jsonl").exists()
        assert (run / "findings.json").read_text(
            encoding="utf-8") == before

    def test_phrase_for_another_finding_cannot_confirm(
            self, env, monkeypatch, capsys):
        # Phrase-includes-id: a copy-pasted phrase minted for finding
        # A must not confirm finding B.
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True, **self._PROD)
        _patch_input(monkeypatch, "suppress find-001")
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-002", "fp",
                                  ceremony=True))
        assert exc.value.code == 3
        assert calls["store"] == []
        # And the right phrase for THAT finding mints it.
        _patch_input(monkeypatch, "suppress find-002")
        mod.cmd_verdict(_args(run, "find-002", "fp", ceremony=True))
        assert calls["store"][0][3] == "emit"

    def test_eof_aborts_without_mutation(self, env, monkeypatch,
                                         capsys):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True, **self._PROD)

        def raise_eof(_prompt):
            raise EOFError

        _patch_input(monkeypatch, raise_eof)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "fp",
                                  ceremony=True))
        assert exc.value.code == 3
        assert "Aborted" in capsys.readouterr().out
        assert calls["store"] == []

    def test_preconditions_fail_before_consent_is_requested(
            self, env, monkeypatch, capsys):
        # SAGE unreachable: the operator must never be asked to type
        # consent for a mint that then fails.
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True, **self._PROD)
        _patch_input(monkeypatch, None)
        import core.sage.hooks as hooks
        monkeypatch.setattr(hooks, "operator_client", lambda: None)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "fp",
                                  ceremony=True))
        assert exc.value.code == 1
        assert "SAGE" in capsys.readouterr().err

    def test_hostile_finding_id_refuses_before_prompt(
            self, env, monkeypatch, capsys):
        # A finding id is attacker bytes; one that does not render
        # verbatim cannot appear inside a phrase the operator
        # verifies by eye — refuse toward /annotate, and never emit
        # the raw bytes.
        mod, run, _target, calls = env
        evil = "find-\x1b[31mevil"
        path = run / "findings.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data.append({"id": evil, "file": "src/a.c",
                     "function": "parse", "line": 3,
                     "rule_id": "cpp/overflow"})
        path.write_text(json.dumps(data), encoding="utf-8")
        _patch_provenance(monkeypatch, interactive=True, **self._PROD)
        _patch_input(monkeypatch, None)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, evil, "fp", ceremony=True))
        assert exc.value.code == 2
        captured = capsys.readouterr()
        assert "outside the ceremony charset" in captured.err
        assert "\x1b" not in captured.err
        assert calls["store"] == []

    def test_confusable_finding_id_refuses_before_prompt(
            self, env, monkeypatch, capsys):
        # Printable-Unicode confusables (U+2011 non-breaking hyphen)
        # render indistinguishably from the ASCII form but compare
        # unequal — the authority phrase must never be built from
        # one. Conservative charset refuses before the prompt.
        mod, run, _target, calls = env
        confusable = "find‑001"  # U+2011 vs ASCII '-'
        path = run / "findings.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data.append({"id": confusable, "file": "src/a.c",
                     "function": "parse", "line": 3,
                     "rule_id": "cpp/overflow"})
        path.write_text(json.dumps(data), encoding="utf-8")
        _patch_provenance(monkeypatch, interactive=True, **self._PROD)
        _patch_input(monkeypatch, None)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, confusable, "fp",
                                  ceremony=True))
        assert exc.value.code == 2
        assert "outside the ceremony charset" in capsys.readouterr().err
        assert calls["store"] == []

    def test_display_escapes_hostile_title(self, env, monkeypatch,
                                           capsys):
        mod, run, _target, calls = env
        path = run / "findings.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data[0]["message"] = "over\x1b[2Jflow in parse"
        path.write_text(json.dumps(data), encoding="utf-8")
        _patch_provenance(monkeypatch, interactive=True, **self._PROD)
        _patch_input(monkeypatch, "suppress find-001")
        mod.cmd_verdict(_args(run, "find-001", "fp", ceremony=True))
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert "\\x1b" in out  # escaped, not dropped: evidence shown
        assert calls["store"]  # minted after the escaped display

    def test_refused_context_plain_fp_still_refuses_and_names_ceremony(
            self, env, monkeypatch, capsys):
        # The ceremony's existence must not weaken the plain-fp gate:
        # without --ceremony the grant refusal stands, and now names
        # the ceremony as the suppression-specific route.
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True, **self._PROD)
        _patch_input(monkeypatch, None)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_verdict(_args(run, "find-001", "fp"))
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "Refused" in err
        assert "--ceremony" in err
        assert calls["store"] == []

    def test_ceremony_flag_refused_on_tp_and_retest(
            self, env, monkeypatch, capsys):
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True, **self._PROD)
        for verb in ("tp", "retest"):
            with pytest.raises(SystemExit) as exc:
                mod.cmd_verdict(_args(run, "find-001", verb,
                                      ceremony=True))
            assert exc.value.code == 2
        assert "fp verb only" in capsys.readouterr().err
        assert calls["store"] == []
        assert calls["forget"] == []

    def test_retest_revokes_a_ceremony_mint(self, env, monkeypatch):
        # Revocation needs no ceremony and no TTL wait: retest clears
        # the stored rows (fail-safe — it only causes re-analysis),
        # from any context.
        mod, run, _target, calls = env
        _patch_provenance(monkeypatch, interactive=True, **self._PROD)
        _patch_input(monkeypatch, "suppress find-001")
        mod.cmd_verdict(_args(run, "find-001", "fp", ceremony=True))
        assert calls["store"]
        _patch_provenance(monkeypatch, interactive=False)
        mod.cmd_verdict(_args(run, "find-001", "retest"))
        (forget,) = calls["forget"]
        assert forget[4] is None  # all verdicts cleared


class TestInterpreterEnvHardening:
    """The preamble refuses PYTHON* startup variables — the
    sitecustomize forge shape from adversarial review: PYTHONPATH
    loads caller-controlled code BEFORE the CLI's first line, which
    can monkeypatch provenance detection and mint the ideal operator
    row in one piped command. The refusal happens before any verb
    logic, for every subcommand."""

    _CLI = str(REPO_ROOT / "libexec" / "raptor-review")

    def _run(self, extra_env, args=("verdict", "x", "fp")):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "_RAPTOR_TRUSTED": "1",
        }
        env.update(extra_env)
        return subprocess.run(
            [sys.executable, self._CLI, *args],
            capture_output=True, text=True, timeout=60, env=env)

    @pytest.mark.parametrize("var", [
        "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE",
    ])
    def test_refuses_python_startup_vars(self, tmp_path, var):
        # PYTHONHOME with a bogus value can kill the interpreter
        # before our code runs — that is ALSO a refusal (nothing
        # minted), but to pin OUR message use a value the interpreter
        # tolerates where possible.
        value = str(tmp_path)
        if var == "PYTHONSTARTUP":
            value = str(tmp_path / "startup.py")
        proc = self._run({var: value})
        assert proc.returncode != 0
        if var != "PYTHONHOME":  # interpreter may die first there
            assert "refusing to run with" in proc.stderr
            assert var in proc.stderr
        # Zero mutation is structural: the refusal exits before any
        # argument parsing or store import.

    def test_sitecustomize_forge_shape_refuses(self, tmp_path):
        # The exact reviewer shape: a sitecustomize on PYTHONPATH
        # that would forge detect_invocation_context, the phrase
        # piped on stdin. Post-fix it must never reach the verb.
        evil = tmp_path / "sitecustomize.py"
        marker = tmp_path / "loaded"
        evil.write_text(
            "import pathlib\n"
            f"pathlib.Path({str(marker)!r}).write_text('x')\n",
            encoding="utf-8")
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "_RAPTOR_TRUSTED": "1",
            "PYTHONPATH": str(tmp_path),
        }
        proc = subprocess.run(
            [sys.executable, self._CLI, "verdict", "find-001", "fp",
             "--ceremony"],
            input="suppress find-001\n",
            capture_output=True, text=True, timeout=60, env=env)
        assert proc.returncode == 2
        assert "refusing to run with PYTHONPATH" in proc.stderr
        # Honest bound, pinned: the hook DID run (interpreter
        # startup precedes any in-process check — that is exactly
        # why the surviving defenses are out-of-process); the
        # refusal stops the MINT, not the load.
        assert marker.exists()

    def test_usersite_forge_shape_refuses(self, tmp_path):
        # The r2 re-verify shape: PYTHONUSERBASE redirects the user
        # site, whose usercustomize.py / .pth lines run the forge
        # before the preamble — none of the r2-refused variables set.
        # PYTHONUSERBASE now refuses like the other three. (The
        # zero-variable variant — a .pth in the DEFAULT user site —
        # is undetectable by ANY env check; documented residual, the
        # closure is interpreter isolated mode.)
        pyver = f"python{sys.version_info[0]}.{sys.version_info[1]}"
        sp = tmp_path / "lib" / pyver / "site-packages"
        sp.mkdir(parents=True)
        marker = tmp_path / "loaded"
        (sp / "usercustomize.py").write_text(
            "import pathlib\n"
            f"pathlib.Path({str(marker)!r}).write_text('x')\n",
            encoding="utf-8")
        proc = self._run({"PYTHONUSERBASE": str(tmp_path)},
                         args=("verdict", "find-001", "fp",
                               "--ceremony"))
        assert proc.returncode == 2
        assert "refusing to run with PYTHONUSERBASE" in proc.stderr

    def test_clean_env_runs(self):
        proc = self._run({}, args=("--help",))
        assert proc.returncode == 0
        assert "raptor-review" in proc.stdout


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
