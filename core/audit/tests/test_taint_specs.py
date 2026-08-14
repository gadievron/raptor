"""Tests for core.audit.taint_specs."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.taint_specs import (
    TaintRole,
    TaintSpec,
    TaintSpecSet,
    TrustLevel,
    check_config_dependent,
    check_stored_taint,
    classify_role_heuristic,
    format_specs_for_joern,
    format_specs_for_prompt,
    format_specs_summary,
    load_taint_specs,
    save_taint_specs,
    spec_from_summary,
)


class TestTaintRole:
    def test_values(self):
        assert TaintRole.SOURCE.value == "source"
        assert TaintRole.SANITISER.value == "sanitiser"


class TestTaintSpec:
    def test_minimal(self):
        spec = TaintSpec(
            function="recv",
            file="src/net.c",
            role=TaintRole.SOURCE,
        )
        d = spec.to_dict()
        assert d["function"] == "recv"
        assert d["role"] == "source"
        assert "threat_classes" not in d

    def test_full(self):
        spec = TaintSpec(
            function="sanitize_html",
            file="src/util.c",
            role=TaintRole.SANITISER,
            threat_classes=["xss", "html_injection"],
            params_affected=["param[0]"],
            return_affected=True,
            confidence="high",
            reasoning="strips script tags",
        )
        d = spec.to_dict()
        assert d["threat_classes"] == ["xss", "html_injection"]
        assert d["return_affected"] is True
        assert d["reasoning"] == "strips script tags"


class TestTaintSpecSet:
    def test_add_and_filter(self):
        ss = TaintSpecSet()
        ss.add(TaintSpec(function="recv", file="a.c", role=TaintRole.SOURCE))
        ss.add(TaintSpec(function="exec", file="b.c", role=TaintRole.SINK))
        ss.add(TaintSpec(function="escape", file="c.c", role=TaintRole.SANITISER))
        ss.add(TaintSpec(function="wrap", file="d.c", role=TaintRole.PROPAGATOR))

        assert len(ss.sources()) == 1
        assert len(ss.sinks()) == 1
        assert len(ss.sanitisers()) == 1
        assert len(ss.propagators()) == 1

    def test_by_file(self):
        ss = TaintSpecSet()
        ss.add(TaintSpec(function="f1", file="a.c", role=TaintRole.SOURCE))
        ss.add(TaintSpec(function="f2", file="a.c", role=TaintRole.SINK))
        ss.add(TaintSpec(function="f3", file="b.c", role=TaintRole.SOURCE))

        assert len(ss.by_file("a.c")) == 2
        assert len(ss.by_file("b.c")) == 1

    def test_by_function(self):
        ss = TaintSpecSet()
        ss.add(TaintSpec(function="recv", file="a.c", role=TaintRole.SOURCE))
        ss.add(TaintSpec(function="recv", file="b.c", role=TaintRole.SOURCE))

        assert len(ss.by_function("recv")) == 2

    def test_to_dict(self):
        ss = TaintSpecSet()
        ss.add(TaintSpec(function="recv", file="a.c", role=TaintRole.SOURCE))
        ss.add(TaintSpec(function="exec", file="b.c", role=TaintRole.SINK))
        d = ss.to_dict()
        assert d["summary"]["total"] == 2
        assert d["summary"]["sources"] == 1
        assert d["summary"]["sinks"] == 1

    def test_merge_deduplicates(self):
        ss1 = TaintSpecSet()
        ss1.add(TaintSpec(function="recv", file="a.c", role=TaintRole.SOURCE))

        ss2 = TaintSpecSet()
        ss2.add(TaintSpec(function="recv", file="a.c", role=TaintRole.SOURCE))
        ss2.add(TaintSpec(function="exec", file="b.c", role=TaintRole.SINK))

        ss1.merge(ss2)
        assert len(ss1.specs) == 2


class TestPersistence:
    def test_save_and_load(self, tmp_path):
        ss = TaintSpecSet()
        ss.add(TaintSpec(
            function="sanitize_html",
            file="src/util.c",
            role=TaintRole.SANITISER,
            threat_classes=["xss"],
            confidence="high",
        ))
        ss.add(TaintSpec(
            function="recv_data",
            file="src/net.c",
            role=TaintRole.SOURCE,
            trust_level=TrustLevel.UNTRUSTED,
            taint_class="user_controlled",
            return_affected=True,
        ))

        path = tmp_path / "taint-specs.json"
        save_taint_specs(ss, path)

        loaded = load_taint_specs(path)
        assert len(loaded.specs) == 2
        assert loaded.sanitisers()[0].threat_classes == ["xss"]
        assert loaded.sources()[0].taint_class == "user_controlled"

    def test_load_missing_file(self, tmp_path):
        loaded = load_taint_specs(tmp_path / "nope.json")
        assert len(loaded.specs) == 0

    def test_load_corrupt(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not json")
        loaded = load_taint_specs(path)
        assert len(loaded.specs) == 0

    def test_load_skips_invalid_entries(self, tmp_path):
        path = tmp_path / "specs.json"
        data = {
            "specs": [
                {"function": "f1", "file": "a.c", "role": "source"},
                {"bad": "entry"},
                {"function": "f2", "file": "b.c", "role": "invalid_role"},
            ]
        }
        path.write_text(json.dumps(data))
        loaded = load_taint_specs(path)
        assert len(loaded.specs) == 1


class TestClassifyRoleHeuristic:
    def test_source(self):
        assert classify_role_heuristic("recv_data") == TaintRole.SOURCE
        assert classify_role_heuristic("load_config") == TaintRole.SOURCE
        assert classify_role_heuristic("get_param") == TaintRole.SOURCE

    def test_sink(self):
        assert classify_role_heuristic("exec_cmd") == TaintRole.SINK
        assert classify_role_heuristic("run_query") == TaintRole.SINK
        assert classify_role_heuristic("do_memcpy") == TaintRole.SINK

    def test_sanitiser(self):
        assert classify_role_heuristic("sanitize_html") == TaintRole.SANITISER
        assert classify_role_heuristic("escape_sql") == TaintRole.SANITISER
        assert classify_role_heuristic("validate_path") == TaintRole.SANITISER

    def test_unknown(self):
        assert classify_role_heuristic("calculate_total") is None
        assert classify_role_heuristic("process_item") is None

    def test_sanitiser_priority_over_source(self):
        assert classify_role_heuristic("validate_input") == TaintRole.SANITISER


class TestSpecFromSummary:
    def test_source(self):
        spec = spec_from_summary(
            "load_user_data", "src/data.c",
            {"callers": ["main"], "is_public": True},
        )
        assert spec is not None
        assert spec.role == TaintRole.SOURCE
        assert spec.return_affected is True

    def test_config_source(self):
        spec = spec_from_summary(
            "load_settings", "src/config.c",
            {"callers": ["config_init"], "is_public": True},
        )
        assert spec is not None
        assert spec.trust_level == TrustLevel.PARTIALLY_TRUSTED

    def test_sink(self):
        spec = spec_from_summary(
            "run_query", "src/db.c",
            {"side_effects": ["database"], "is_public": True},
        )
        assert spec is not None
        assert spec.role == TaintRole.SINK
        assert "sql_injection" in spec.threat_classes

    def test_sanitiser(self):
        spec = spec_from_summary(
            "sanitize_html_input", "src/util.c",
            {"is_public": True},
        )
        assert spec is not None
        assert spec.role == TaintRole.SANITISER
        assert "xss" in spec.threat_classes

    def test_no_match(self):
        spec = spec_from_summary(
            "calculate_total", "src/util.c",
            {"is_public": True},
        )
        assert spec is None

    def test_memcpy_sink(self):
        spec = spec_from_summary(
            "do_memcpy", "src/mem.c",
            {"is_public": True},
        )
        assert spec is not None
        assert spec.role == TaintRole.SINK
        assert "buffer_overflow" in spec.threat_classes


class TestFormatForJoern:
    def test_all_roles(self):
        ss = TaintSpecSet()
        ss.add(TaintSpec(
            function="recv", file="a.c", role=TaintRole.SOURCE,
            taint_class="user_controlled",
        ))
        ss.add(TaintSpec(
            function="exec", file="b.c", role=TaintRole.SINK,
            threat_classes=["command_injection"],
        ))
        ss.add(TaintSpec(
            function="escape", file="c.c", role=TaintRole.SANITISER,
            threat_classes=["xss"],
        ))

        output = format_specs_for_joern(ss)
        assert "source" in output
        assert "sink" in output
        assert "sanitizer" in output
        assert "recv" in output
        assert "exec" in output
        assert "escape" in output

    def test_empty(self):
        ss = TaintSpecSet()
        assert format_specs_for_joern(ss) == ""


class TestFormatForPrompt:
    def test_all_roles(self):
        ss = TaintSpecSet()
        ss.add(TaintSpec(
            function="recv", file="a.c", role=TaintRole.SOURCE,
            taint_class="user_controlled",
            trust_level=TrustLevel.UNTRUSTED,
        ))
        ss.add(TaintSpec(
            function="exec", file="b.c", role=TaintRole.SINK,
            threat_classes=["command_injection"],
        ))
        ss.add(TaintSpec(
            function="sanitize", file="c.c", role=TaintRole.SANITISER,
            threat_classes=["xss"],
        ))
        ss.add(TaintSpec(
            function="wrap", file="d.c", role=TaintRole.PROPAGATOR,
            taint_class_change="user_controlled -> encrypted",
        ))

        output = format_specs_for_prompt(ss)
        assert "taint sources" in output
        assert "user_controlled" in output
        assert "sinks" in output
        assert "sanitisers" in output
        assert "propagators" in output

    def test_empty(self):
        assert format_specs_for_prompt(TaintSpecSet()) == ""


class TestFormatSummary:
    def test_empty(self):
        assert "none" in format_specs_summary(TaintSpecSet())

    def test_with_specs(self):
        ss = TaintSpecSet()
        ss.add(TaintSpec(function="recv", file="a.c", role=TaintRole.SOURCE))
        ss.add(TaintSpec(function="exec", file="b.c", role=TaintRole.SINK))
        s = format_specs_summary(ss)
        assert "1 sources" in s
        assert "1 sinks" in s
        assert "2 total" in s


# ── Stored taint checks ─────────────────────────────────────────────


class TestStoredTaint:
    def test_detects_unescaped_db_read_render(self):
        gaps = [
            {
                "name": "save_bio",
                "file": "profile.py",
                "source": "def save_bio(bio): db.execute('UPDATE users SET bio = %s', (bio,))",
            },
            {
                "name": "show_profile",
                "file": "views.py",
                "source": "def show_profile(uid): row = db.get(uid); return render(row['bio'])",
            },
        ]
        findings = check_stored_taint(gaps)
        assert len(findings) == 1
        assert findings[0].check == "stored_taint"
        assert findings[0].cwe == "CWE-79"

    def test_no_finding_when_sanitized(self):
        gaps = [
            {
                "name": "save",
                "file": "a.py",
                "source": "db.execute('INSERT INTO t VALUES (%s)', (x,))",
            },
            {
                "name": "show",
                "file": "b.py",
                "source": "row = db.get(id); return render(escape(row['data']))",
            },
        ]
        assert check_stored_taint(gaps) == []

    def test_no_finding_without_render(self):
        gaps = [
            {
                "name": "write",
                "file": "a.py",
                "source": "db.execute('INSERT INTO t VALUES (%s)', (x,))",
            },
            {
                "name": "read",
                "file": "b.py",
                "source": "row = db.get(id); return row['count']",
            },
        ]
        assert check_stored_taint(gaps) == []

    def test_no_finding_without_writers(self):
        gaps = [
            {
                "name": "read",
                "file": "a.py",
                "source": "row = db.get(id); return render(row['bio'])",
            },
        ]
        assert check_stored_taint(gaps) == []


class TestConfigDependent:
    def test_detects_config_in_security_decision(self):
        gaps = [
            {
                "name": "check_auth",
                "file": "auth.py",
                "source": (
                    "debug = os.environ.get('DEBUG')\n"
                    "if debug: skip_auth = True"
                ),
            },
        ]
        findings = check_config_dependent(gaps)
        assert len(findings) == 1
        assert findings[0].check == "config_dependent"

    def test_no_finding_for_non_security_config(self):
        gaps = [
            {
                "name": "get_color",
                "file": "ui.py",
                "source": "color = os.environ.get('THEME_COLOR', 'blue')",
            },
        ]
        assert check_config_dependent(gaps) == []


class TestStoredTaintFromDisk:
    """check_stored_taint reads source from disk when gaps lack source."""

    def test_hydrates_from_target_path(self, tmp_path: Path):
        writer = tmp_path / "profile.py"
        writer.write_text(
            "def save_bio(bio):\n"
            "    db.execute('UPDATE users SET bio = %s', (bio,))\n"
        )
        reader = tmp_path / "views.py"
        reader.write_text(
            "def show_profile(uid):\n"
            "    row = db.get(uid)\n"
            "    return render(row['bio'])\n"
        )
        gaps = [
            {"name": "save_bio", "file": "profile.py", "line_start": 1, "line_end": 2},
            {"name": "show_profile", "file": "views.py", "line_start": 1, "line_end": 3},
        ]
        findings = check_stored_taint(gaps, target_path=tmp_path)
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-79"

    def test_skips_when_no_target_path(self):
        gaps = [
            {"name": "save_bio", "file": "profile.py", "line_start": 1, "line_end": 2},
            {"name": "show_profile", "file": "views.py", "line_start": 1, "line_end": 3},
        ]
        assert check_stored_taint(gaps) == []

    def test_skips_missing_file(self, tmp_path: Path):
        gaps = [
            {"name": "save_bio", "file": "nonexistent.py", "line_start": 1, "line_end": 2},
        ]
        assert check_stored_taint(gaps, target_path=tmp_path) == []

    def test_skips_when_line_end_is_none(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("db.execute('INSERT INTO t VALUES (%s)', (x,))\n")
        gaps = [
            {"name": "w", "file": "a.py", "line_start": 1, "line_end": None},
        ]
        assert check_stored_taint(gaps, target_path=tmp_path) == []

    def test_skips_path_traversal(self, tmp_path: Path):
        secret = tmp_path / "outside" / "secret.py"
        secret.parent.mkdir()
        secret.write_text("db.execute('INSERT INTO t VALUES (%s)', (x,))\n")
        target = tmp_path / "project"
        target.mkdir()
        gaps = [
            {"name": "w", "file": "../outside/secret.py", "line_start": 1, "line_end": 1},
        ]
        assert check_stored_taint(gaps, target_path=target) == []


class TestConfigDependentFromDisk:
    """check_config_dependent reads source from disk when gaps lack source."""

    def test_hydrates_from_target_path(self, tmp_path: Path):
        src = tmp_path / "auth.py"
        src.write_text(
            "def check_auth():\n"
            "    debug = os.environ.get('DEBUG')\n"
            "    if debug: skip_auth = True\n"
        )
        gaps = [
            {"name": "check_auth", "file": "auth.py", "line_start": 1, "line_end": 3},
        ]
        findings = check_config_dependent(gaps, target_path=tmp_path)
        assert len(findings) == 1
        assert findings[0].check == "config_dependent"

    def test_skips_when_no_target_path(self):
        gaps = [
            {"name": "check_auth", "file": "auth.py", "line_start": 1, "line_end": 3},
        ]
        assert check_config_dependent(gaps) == []

    def test_skips_when_line_end_is_none(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("debug = os.environ.get('DEBUG')\nif debug: skip_auth = True\n")
        gaps = [
            {"name": "f", "file": "a.py", "line_start": 1, "line_end": None},
        ]
        assert check_config_dependent(gaps, target_path=tmp_path) == []
