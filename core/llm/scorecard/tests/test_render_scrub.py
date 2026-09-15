"""Sidecar-derived strings (event_type, decision_class, model,
schema_version) are attacker-choosable — the sidecar AND the MAC key
are same-user writable, so a same-user forger can stamp a valid
provenance token onto hostile content (and the key-unusable clamp
keeps unverified content readable regardless). Every render surface
must escape + bound them before the operator's terminal."""

from __future__ import annotations

import json

import pytest

from core.llm.scorecard.audit import audit, render_markdown
from core.llm.scorecard.cli import (
    _render_compare,
    _render_samples,
    _render_table,
)
from core.llm.scorecard.scorecard import DecisionClassStats, _EventCounts

HOSTILE = "\x1b]0;pwned\x07\x9b2J‮evil"
RAW = ("\x1b", "\x07", "\x9b", "‮")


def _stat(dc: str, model: str) -> DecisionClassStats:
    from core.llm.scorecard.scorecard import ALL_EVENT_TYPES
    return DecisionClassStats(
        decision_class=dc,
        model=model,
        first_seen_at="2026-01-01T00:00:00Z",
        last_seen_at="2026-01-01T00:00:00Z",
        model_version="",
        policy_override="auto",
        events={et: _EventCounts(correct=1, incorrect=1)
                for et in ALL_EVENT_TYPES},
        disagreement_samples=[],
    )


class TestAuditRenderScrub:
    def test_forged_sidecar_event_type_escaped(self, tmp_path, monkeypatch):
        # Hostile shape end-to-end: forged sidecar on disk, through
        # _load_raw / _iter_raw_event_counts / render_markdown. The
        # forger stamps a valid token (the MAC key is same-user
        # writable), so the integrity gate ingests the hostile content
        # — render must still escape it. version must be the current
        # schema (a forged version string is fatal at load, before any
        # render), so the hostile bytes ride the model / decision-class
        # / event-type keys.
        from core.llm.scorecard import integrity
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        sidecar = tmp_path / "llm_scorecard.json"
        sidecar.write_text(json.dumps({
            "version": 2,
            "models": {
                f"model-{HOSTILE}": {
                    f"dc-{HOSTILE}": {
                        "events": {
                            f"evil-{HOSTILE}": {"correct": 3, "incorrect": 1},
                        },
                    },
                },
            },
        }))
        assert integrity.stamp_file(sidecar)
        report = audit(sidecar)
        md = render_markdown(report)
        for raw in RAW:
            assert raw not in md
        assert "evil-" in md  # the row itself still renders


class TestCliRenderScrub:
    def test_table_cells_escaped(self):
        out = _render_table([_stat(f"dc{HOSTILE}", f"m{HOSTILE}")])
        for raw in RAW:
            assert raw not in out

    def test_compare_cells_escaped(self):
        a = _stat(f"dc{HOSTILE}", "model-a")
        b = _stat(f"dc{HOSTILE}", "model-b")
        out = _render_compare([a], [b], model_a="model-a", model_b="model-b")
        for raw in RAW:
            assert raw not in out

    def test_samples_header_escaped(self):
        stat = _stat(f"dc{HOSTILE}", f"m{HOSTILE}")
        stat.disagreement_samples.append(
            {"finding_id": "f1", "reasoning": f"why {HOSTILE}"},
        )
        out = _render_samples(stat)
        for raw in RAW:
            assert raw not in out
        out_empty = _render_samples(_stat(f"dc{HOSTILE}", f"m{HOSTILE}"))
        for raw in RAW:
            assert raw not in out_empty


class TestReplayRenderScrub:
    def test_models_and_classes_escaped(self):
        from core.llm.multi_model.replay import (
            ClassSummary,
            ReplayReport,
            render_markdown as replay_render,
        )
        report = ReplayReport(
            sources=["r"],
            total_panels=1,
            total_findings_with_panel=1,
            distinct_models=[f"m{HOSTILE}"],
            distinct_decision_classes=[f"dc{HOSTILE}"],
            findings=[],
            class_summaries=[ClassSummary(
                decision_class=f"dc{HOSTILE}", n_findings=1,
                n_flips_to_exploitable=0, n_flips_to_not_exploitable=0,
                converged=True, iterations=1,
            )],
            flip_rate=0.0,
            flip_to_exploitable_rate=0.0,
            flip_to_not_exploitable_rate=0.0,
            posterior_distribution={},
        )
        md = replay_render(report)
        for raw in RAW:
            assert raw not in md


class TestHumaniseAgeScrub:
    def test_unparseable_timestamp_is_scrubbed(self):
        from core.llm.scorecard.cli import _humanise_age
        out = _humanise_age(f"2026-13-45T99:99:99{HOSTILE}")
        for raw in RAW:
            assert raw not in out
        assert "pwned" in out  # content survives, escaped

    def test_valid_timestamp_still_humanised(self):
        import datetime as dt
        from core.llm.scorecard.cli import _humanise_age
        now = dt.datetime(2026, 1, 2, tzinfo=dt.timezone.utc)
        assert _humanise_age("2026-01-01T00:00:00+00:00", now=now) == "1d ago"

    def test_table_last_seen_escaped(self):
        stat = _stat("dc", "model")
        stat.last_seen_at = f"2026-13-45T99:99:99{HOSTILE}"
        out = _render_table([stat])
        for raw in RAW:
            assert raw not in out

    def test_forged_sidecar_last_seen_escaped_end_to_end(
            self, tmp_path, monkeypatch):
        # Hostile shape end-to-end: a same-user forger rewrites
        # last_seen_at on disk and re-stamps (the MAC key is same-user
        # writable). last_seen_at is not a foreign key, so only the
        # render-side scrub stands between it and the TTY.
        import io
        from contextlib import redirect_stdout
        from types import SimpleNamespace

        from core.llm.scorecard import integrity
        from core.llm.scorecard.cli import cmd_list
        from core.llm.scorecard.scorecard import EventType, ModelScorecard
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        sidecar = tmp_path / "llm_scorecard.json"
        sc = ModelScorecard(sidecar)
        for _ in range(3):
            sc.record_event(
                "dc-forged", "model-a",
                EventType.CHEAP_SHORT_CIRCUIT, "correct",
            )
        data = json.loads(sidecar.read_text())
        data["models"]["model-a"]["dc-forged"]["last_seen_at"] = (
            f"2026-13-45T99:99:99{HOSTILE}"
        )
        sidecar.write_text(json.dumps(data))
        assert integrity.stamp_file(sidecar)
        args = SimpleNamespace(
            path=sidecar, json=False, since=None, consumer=None,
            untrusted=False, learning=False, by_savings=False,
            by_miss_rate=False, by_cost=False,
            event_type=EventType.CHEAP_SHORT_CIRCUIT,
            freshness_half_life_days=None,
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert cmd_list(args) == 0
        out = buf.getvalue()
        assert "dc-forged" in out
        for raw in RAW:
            assert raw not in out


class TestJsonLanesAsciiEncoded:
    """Every ``--json`` lane must ASCII-encode: JSON escapes C0 but
    passes C1 terminal controls (U+0080-U+009F, incl. single-byte CSI
    0x9B / OSC 0x9D) through raw unless ensure_ascii is on, and the
    payload dicts carry the same forgeable sidecar strings the table
    lanes scrub."""

    C1_DC = "dc-\x9b2J\x9d0;pwn"
    C1_MODEL = "model-\x9b31m\x9d;evil"
    C1_RAW = ("\x9b", "\x9d", "\x1b")

    @pytest.fixture
    def hostile_sidecar(self, tmp_path):
        from core.llm.scorecard.scorecard import EventType, ModelScorecard
        path = tmp_path / "sc.json"
        sc = ModelScorecard(path)
        events = []
        for _ in range(12):
            events.append({
                "decision_class": self.C1_DC, "model": self.C1_MODEL,
                "event_type": EventType.CHEAP_SHORT_CIRCUIT,
                "outcome": "correct",
            })
            events.append({
                "decision_class": "exploit_chain_closure",
                "model": self.C1_MODEL,
                "event_type": EventType.EXPLOIT_CHAIN_CLOSURE,
                "outcome": "correct",
            })
        sc.record_events(events)
        return path

    def _args(self, path, **kw):
        from types import SimpleNamespace
        from core.llm.scorecard.scorecard import EventType
        base = dict(
            path=path, json=True, since=None, consumer=None,
            untrusted=False, learning=False, by_savings=False,
            by_miss_rate=False, by_cost=False,
            event_type=EventType.CHEAP_SHORT_CIRCUIT,
            freshness_half_life_days=None, half_life_days=None,
            decision_class=None, model_a=None, model_b=None, cwe=None,
        )
        base.update(kw)
        return SimpleNamespace(**base)

    def _run(self, handler, args) -> str:
        import io
        from contextlib import redirect_stderr, redirect_stdout
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = handler(args)
        assert rc == 0
        combined = out.getvalue() + err.getvalue()
        for raw in self.C1_RAW:
            assert raw not in combined
        return out.getvalue()

    def test_list_json(self, hostile_sidecar):
        from core.llm.scorecard.cli import cmd_list
        out = self._run(cmd_list, self._args(hostile_sidecar))
        assert any(
            self.C1_DC in c["decision_class"]
            for c in json.loads(out)["cells"]
        )  # still valid JSON; hostile bytes only as \uXXXX escapes

    def test_summary_json(self, hostile_sidecar):
        from core.llm.scorecard.cli import cmd_summary
        out = self._run(cmd_summary, self._args(hostile_sidecar))
        assert json.loads(out)["cells_total"] >= 1

    def test_recommend_json(self, hostile_sidecar):
        from core.llm.scorecard.cli import cmd_recommend
        out = self._run(cmd_recommend, self._args(
            hostile_sidecar, decision_class=self.C1_DC))
        assert json.loads(out)["decision_class"] == self.C1_DC

    def test_chain_closure_json(self, hostile_sidecar):
        from core.llm.scorecard.cli import cmd_chain_closure
        out = self._run(cmd_chain_closure, self._args(hostile_sidecar))
        parsed = json.loads(out)
        assert parsed["candidates"]

    def test_chain_closure_no_data_json(self, hostile_sidecar):
        from core.llm.scorecard.cli import cmd_chain_closure
        out = self._run(cmd_chain_closure, self._args(
            hostile_sidecar, cwe="cwe-\x9b6n121"))
        parsed = json.loads(out)
        assert parsed["candidates"] == []

    def test_compare_json(self, hostile_sidecar):
        from core.llm.scorecard.cli import cmd_compare
        out = self._run(cmd_compare, self._args(
            hostile_sidecar, model_a=self.C1_MODEL, model_b=self.C1_MODEL))
        assert json.loads(out)["shared"]

    def test_no_dumps_display_lane_left_in_cli(self):
        # Class pin: dumps_display (ensure_ascii off) must not regrow
        # a terminal lane in this module — every JSON print routes
        # through _dumps_json_lane.
        import inspect
        from core.llm.scorecard import cli as cli_mod
        src = inspect.getsource(cli_mod)
        assert "dumps_display(" not in src


class TestHumanLanesModelNamesScrubbed:
    """summary / recommend / chain-closure human lanes print
    sidecar-derived model names — same forgeable provenance as the
    table cells, same scrub requirement."""

    def _sidecar(self, tmp_path, dc: str):
        from core.llm.scorecard.scorecard import EventType, ModelScorecard
        path = tmp_path / "sc.json"
        sc = ModelScorecard(path)
        et = (EventType.EXPLOIT_CHAIN_CLOSURE
              if dc == "exploit_chain_closure"
              else EventType.CHEAP_SHORT_CIRCUIT)
        sc.record_events([
            {"decision_class": dc, "model": f"m-{HOSTILE}",
             "event_type": et, "outcome": "correct"}
            for _ in range(12)
        ])
        # _usage row so the summary lanes (most-used, spend breakdown,
        # cheapest-trusted) actually print the hostile model name.
        sc.register_uses([{
            "model": f"m-{HOSTILE}", "decision_class": "_usage",
            "calls": 5, "cost_usd": 0.5,
        }])
        return path

    def _run(self, handler, args) -> str:
        import io
        from contextlib import redirect_stderr, redirect_stdout
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = handler(args)
        assert rc == 0
        combined = out.getvalue() + err.getvalue()
        assert "m-" in combined and "pwned" in combined  # non-vacuous
        for raw in RAW:
            assert raw not in combined
        return combined

    def _args(self, path, **kw):
        from types import SimpleNamespace
        from core.llm.scorecard.scorecard import EventType
        base = dict(
            path=path, json=False, since=None, consumer=None,
            untrusted=False, learning=False, by_savings=False,
            by_miss_rate=False, by_cost=False,
            event_type=EventType.CHEAP_SHORT_CIRCUIT,
            freshness_half_life_days=None, half_life_days=None,
            decision_class=None, model_a=None, model_b=None, cwe=None,
        )
        base.update(kw)
        return SimpleNamespace(**base)

    def test_summary_human(self, tmp_path):
        from core.llm.scorecard.cli import cmd_summary
        self._run(cmd_summary, self._args(self._sidecar(tmp_path, "dc")))

    def test_recommend_human(self, tmp_path):
        from core.llm.scorecard.cli import cmd_recommend
        self._run(cmd_recommend, self._args(
            self._sidecar(tmp_path, "dc"), decision_class="dc"))

    def test_chain_closure_human(self, tmp_path):
        from core.llm.scorecard.cli import cmd_chain_closure
        self._run(cmd_chain_closure, self._args(
            self._sidecar(tmp_path, "exploit_chain_closure")))


class TestReplayReliabilityTableScrub:
    """The per-model reliability table is fed by
    ``class_summaries[].model_reliabilities[]["model"]`` — same
    orchestrated_report provenance as the scrubbed distinct_models /
    decision_class cells. The hostile fixture must populate
    model_reliabilities (the default-empty fixture never exercised
    the cell)."""

    def test_reliability_model_cell_escaped(self):
        from core.llm.multi_model.replay import (
            ClassSummary,
            ReplayReport,
            render_markdown as replay_render,
        )
        report = ReplayReport(
            sources=["r"],
            total_panels=1,
            total_findings_with_panel=1,
            distinct_models=[f"m{HOSTILE}"],
            distinct_decision_classes=["dc"],
            findings=[],
            class_summaries=[ClassSummary(
                decision_class="dc", n_findings=1,
                n_flips_to_exploitable=0, n_flips_to_not_exploitable=0,
                converged=True, iterations=1,
                model_reliabilities=[
                    {"model": f"m{HOSTILE}", "alpha": 0.9, "beta": 0.8},
                ],
            )],
            flip_rate=0.0,
            flip_to_exploitable_rate=0.0,
            flip_to_not_exploitable_rate=0.0,
            posterior_distribution={},
        )
        md = replay_render(report)
        for raw in RAW:
            assert raw not in md
        assert "Inferred per-model reliability" in md

    def test_replay_render_json_ascii_encoded(self):
        from core.llm.multi_model.replay import (
            ClassSummary,
            ReplayReport,
            render_json as replay_render_json,
        )
        report = ReplayReport(
            sources=["r"],
            total_panels=1,
            total_findings_with_panel=1,
            distinct_models=["m-\x9b31m"],
            distinct_decision_classes=["dc-\x9d0;pwn"],
            findings=[],
            class_summaries=[ClassSummary(
                decision_class="dc-\x9d0;pwn", n_findings=1,
                n_flips_to_exploitable=0, n_flips_to_not_exploitable=0,
                converged=True, iterations=1,
                model_reliabilities=[
                    {"model": "m-\x9b31m", "alpha": 0.9, "beta": 0.8},
                ],
            )],
            flip_rate=0.0,
            flip_to_exploitable_rate=0.0,
            flip_to_not_exploitable_rate=0.0,
            posterior_distribution={},
        )
        rendered = replay_render_json(report)
        assert "\x9b" not in rendered
        assert "\x9d" not in rendered
        parsed = json.loads(rendered)
        assert parsed["distinct_models"] == ["m-\x9b31m"]  # round-trips


class TestScorecardAuditJsonLane:
    """scorecard-audit's own --json lane (audit.render_json →
    sys.stdout.write) is the 7th JSON terminal lane; it must
    ASCII-encode like cli.py's six."""

    def test_render_json_ascii_encoded(self, tmp_path, monkeypatch):
        from core.llm.scorecard import integrity
        from core.llm.scorecard.audit import audit as run_audit, render_json
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        sidecar = tmp_path / "llm_scorecard.json"
        sidecar.write_text(json.dumps({
            "version": 2,
            "models": {
                "model-\x9b31m": {
                    "dc-\x9d0;pwn": {
                        "events": {
                            "evil-\x9b2J": {"correct": 3, "incorrect": 1},
                        },
                    },
                },
            },
        }))
        assert integrity.stamp_file(sidecar)
        report = run_audit(sidecar)
        rendered = render_json(report)
        assert "\x9b" not in rendered
        assert "\x9d" not in rendered
        json.loads(rendered)  # stays a valid JSON document

    def test_main_json_lane_ascii_encoded(self, tmp_path, monkeypatch):
        import io
        from contextlib import redirect_stdout

        from core.llm.scorecard import integrity
        from core.llm.scorecard.audit import main as audit_main
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        sidecar = tmp_path / "llm_scorecard.json"
        sidecar.write_text(json.dumps({
            "version": 2,
            "models": {
                "model-\x9b31m": {
                    "dc-\x9d0;pwn": {
                        "events": {
                            "evil-\x9b2J": {"correct": 3, "incorrect": 1},
                        },
                    },
                },
            },
        }))
        assert integrity.stamp_file(sidecar)
        buf = io.StringIO()
        with redirect_stdout(buf):
            audit_main(["--path", str(sidecar), "--json"])
        out = buf.getvalue()
        assert "\x9b" not in out
        assert "\x9d" not in out
        json.loads(out)
