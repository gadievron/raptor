"""Tests for cocci progress reporting.

Receipt: raptor-enrich-context-map-sites ran >300s on a 543-file C
target with zero output. Progress now flows analyze() → run_rules
``on_rule`` → RuleProgressPrinter, with an idle heartbeat covering a
single long rule.
"""

from __future__ import annotations

import io
import time
from unittest.mock import patch

from packages.source_intel.analyze import analyze
from packages.source_intel.progress import RuleProgressPrinter


class TestAnalyzeProgressPlumbing:
    def test_progress_reports_global_done_total_across_axes(
        self, tmp_path,
    ):
        """analyze() offsets per-axis rule indices into one global
        done/total counter."""
        rules_root = tmp_path / "rules"
        axis1 = rules_root / "axis1"
        axis2 = rules_root / "axis2"
        axis1.mkdir(parents=True)
        axis2.mkdir()
        (axis1 / "r1.cocci").write_text("@@\n@@\nmalloc(...);\n")
        (axis1 / "r2.cocci").write_text("@@\n@@\nfree(...);\n")
        (axis2 / "r3.cocci").write_text("@@\n@@\ncalloc(...);\n")

        target = tmp_path / "src"
        target.mkdir()
        (target / "x.c").write_text("int main(void){return 0;}\n")

        def fake_run_rules(*, target, rules_dir, on_rule=None, **_kw):
            import pathlib
            rules = sorted(pathlib.Path(rules_dir).glob("*.cocci"))
            if on_rule is not None:
                for i, r in enumerate(rules):
                    on_rule(i, len(rules), r.stem)
            return []

        seen = []
        with patch("packages.coccinelle.runner.is_available",
                   return_value=True), \
             patch("packages.coccinelle.runner.run_rules",
                   side_effect=fake_run_rules), \
             patch("packages.coccinelle.runner.version",
                   return_value="1.3"), \
             patch("packages.source_intel.analyze._maybe_register_inventory"):
            analyze(
                target, rules_dir=rules_root,
                progress=lambda d, t, name: seen.append((d, t, name)),
            )

        assert seen == [(0, 3, "r1"), (1, 3, "r2"), (2, 3, "r3")]

    def test_no_progress_callback_keeps_legacy_shape(self, tmp_path):
        rules_root = tmp_path / "rules"
        axis1 = rules_root / "axis1"
        axis1.mkdir(parents=True)
        (axis1 / "r1.cocci").write_text("@@\n@@\nmalloc(...);\n")
        target = tmp_path / "src"
        target.mkdir()
        (target / "x.c").write_text("int main(void){return 0;}\n")

        captured = {}

        def fake_run_rules(*, on_rule=None, **_kw):
            captured["on_rule"] = on_rule
            return []

        with patch("packages.coccinelle.runner.is_available",
                   return_value=True), \
             patch("packages.coccinelle.runner.run_rules",
                   side_effect=fake_run_rules), \
             patch("packages.coccinelle.runner.version",
                   return_value="1.3"), \
             patch("packages.source_intel.analyze._maybe_register_inventory"):
            analyze(target, rules_dir=rules_root)

        assert captured["on_rule"] is None


class TestRuleProgressPrinter:
    def test_rule_lines_use_house_counter_shape(self):
        stream = io.StringIO()
        with RuleProgressPrinter(stream, label="cocci") as prog:
            prog.on_rule(0, 3, "unchecked_alloc")
            prog.on_rule(1, 3, "abort_proximate")
        lines = stream.getvalue().splitlines()
        assert lines == [
            "  [1/3] cocci unchecked_alloc ...",
            "  [2/3] cocci abort_proximate ...",
        ]

    def test_heartbeat_fires_when_idle(self):
        stream = io.StringIO()
        with RuleProgressPrinter(
            stream, label="cocci",
            heartbeat_interval_s=0.05, poll_interval_s=0.02,
        ) as prog:
            prog.on_rule(0, 1, "slow_rule")
            time.sleep(0.3)
        lines = stream.getvalue().splitlines()
        beats = [ln for ln in lines if "still running" in ln]
        assert beats, "idle heartbeat expected"
        assert "slow_rule" in beats[0]

    def test_heartbeat_silent_while_rule_lines_flow(self):
        stream = io.StringIO()
        with RuleProgressPrinter(
            stream, label="cocci",
            heartbeat_interval_s=10.0, poll_interval_s=0.02,
        ) as prog:
            for i in range(5):
                prog.on_rule(i, 5, f"r{i}")
                time.sleep(0.03)
        lines = stream.getvalue().splitlines()
        assert all("still running" not in ln for ln in lines)
        assert len(lines) == 5

    def test_stops_cleanly_on_exit(self):
        stream = io.StringIO()
        printer = RuleProgressPrinter(
            stream, heartbeat_interval_s=0.05, poll_interval_s=0.02,
        )
        with printer:
            pass
        assert printer._thread is None
        before = stream.getvalue()
        time.sleep(0.15)  # no output after exit
        assert stream.getvalue() == before
