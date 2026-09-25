"""Juliet held-out manifest generator: spans, refusals, pin, doctrine."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from core.recall.juliet_manifest import (
    JULIET_PINNED_SHA,
    JulietManifestError,
    generate_manifest,
    generate_manifest_b,
    main as jm_main,
    split_bad_good_spans,
)
from core.recall.manifest import parse_manifest

_GOOD_FILE = """\
public class CWE89_SQL_Injection__test_01 {
    public void bad(HttpServletRequest request) throws Throwable {
        String data = request.getParameter("id");
        stmt.execute(q + data);
    }

    private void badHelper(String data) throws Throwable {
        sink(data);
    }

    public void good() throws Throwable {
        goodG2B();
    }

    private void goodG2B() throws Throwable {
        String data = "constant";
        stmt.execute(q + data);
    }
}
"""

_UNORDERED = """\
public class X {
    public void good() throws Throwable { }
    public void bad(HttpServletRequest r) throws Throwable { }
}
"""


class TestSplit:
    def test_spans_cover_bad_then_good(self):
        spans = split_bad_good_spans(_GOOD_FILE)
        assert spans is not None
        (bad_start, bad_end), (good_start, good_end) = spans
        lines = _GOOD_FILE.splitlines()
        assert "void bad(" in lines[bad_start - 1]
        assert "void good(" in lines[good_start - 1]
        assert bad_end == good_start - 1
        assert good_end == len(lines)
        # the bad helper sits inside the bad span
        helper_line = next(i for i, ln in enumerate(lines, 1)
                           if "badHelper" in ln)
        assert bad_start <= helper_line <= bad_end

    def test_ordering_violation_refused(self):
        assert split_bad_good_spans(_UNORDERED) is None

    def test_missing_methods_refused(self):
        assert split_bad_good_spans("class X { }") is None
        assert split_bad_good_spans(
            "public void bad() throws Throwable { }") is None


def _make_clone(tmp_path: Path) -> Path:
    clone = tmp_path / "juliet"
    d = clone / "src/testcases/CWE89_SQL_Injection/s01"
    d.mkdir(parents=True)
    (d / "CWE89_SQL_Injection__test_01.java").write_text(
        _GOOD_FILE, encoding="utf-8")
    # multi-file variant must be skipped and counted
    (d / "CWE89_SQL_Injection__test_54a.java").write_text(
        _GOOD_FILE, encoding="utf-8")
    # unsplittable support class must be skipped and counted
    (d / "Helper.java").write_text("class Helper { }", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(clone)], check=True)
    subprocess.run(["git", "-C", str(clone), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(clone), "-c", "user.email=t@example.org",
         "-c", "user.name=t", "commit", "-qm", "fixture"], check=True)
    return clone


class TestGenerate:
    def test_wrong_sha_refused(self, tmp_path):
        clone = _make_clone(tmp_path)
        with pytest.raises(JulietManifestError, match="pinned"):
            generate_manifest(clone)

    def test_manifest_shape_with_pin_bypassed(self, tmp_path,
                                              monkeypatch):
        clone = _make_clone(tmp_path)
        head = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        monkeypatch.setattr("core.recall.juliet_manifest."
                            "JULIET_PINNED_SHA", head)
        manifest = generate_manifest(clone)
        assert len(manifest["expected"]) == 1
        assert len(manifest["clean_regions"]) == 1
        exp = manifest["expected"][0]
        assert exp["cwe"] == "CWE-89"
        assert exp["line_start"] == 2
        assert exp["provenance"]["kind"] == "benchmark"
        clean = manifest["clean_regions"][0]
        assert clean["id"].endswith("__good")
        assert clean["line_start"] == exp["line_end"] + 1
        notes = manifest["notes"]
        assert notes["skipped_multi_file_variants"] == 1
        assert notes["skipped_no_bad_good_split"] == 1
        assert "never used to tune" in notes["holdout_doctrine"]
        # a generated manifest must validate against the schema
        # (target sha differs from the fixture pin; patch it back to a
        # valid hex sha for parsing)
        manifest["target"]["pinned_sha"] = head
        parsed = parse_manifest(json.loads(json.dumps(manifest)))
        assert parsed.name == "juliet-java-holdout"
        assert parsed.tolerance.cwe_family_match is True
        # scan-codeql is the recall-bearing posture (84.3% vs 29.7%
        # semgrep-only on this corpus) — the generator must emit it.
        assert parsed.profile == "scan-codeql"

    def test_missing_clone_refused(self, tmp_path):
        with pytest.raises(JulietManifestError, match="acquire"):
            generate_manifest(tmp_path / "nope")


def test_pinned_sha_is_full_hex():
    assert len(JULIET_PINNED_SHA) == 40
    int(JULIET_PINNED_SHA, 16)


# ---------------------------------------------------------------------------
# Family slices (concurrency / integer)
# ---------------------------------------------------------------------------

_LOCK_FILE = """\
public class CWE609_Double_Checked_Locking__test_01 {
    public void bad() throws Throwable {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) { instance = mk(); }
            }
        }
    }

    public void good() throws Throwable {
        synchronized (lock) {
            if (instance == null) { instance = mk(); }
        }
    }
}
"""

_INT_FILE = """\
public class CWE190_Integer_Overflow__test_01 {
    public void bad() throws Throwable {
        int data = source();
        sink(data + 1);
    }

    public void good() throws Throwable {
        int data = 2;
        sink(data + 1);
    }
}
"""


def _make_family_clone(tmp_path: Path) -> Path:
    clone = tmp_path / "juliet-fam"
    lock = clone / "src/testcases/CWE609_Double_Checked_Locking/s01"
    lock.mkdir(parents=True)
    (lock / "CWE609_Double_Checked_Locking__test_01.java").write_text(
        _LOCK_FILE, encoding="utf-8")
    integer = clone / "src/testcases/CWE190_Integer_Overflow/s01"
    integer.mkdir(parents=True)
    (integer / "CWE190_Integer_Overflow__test_01.java").write_text(
        _INT_FILE, encoding="utf-8")
    # injection-set dir must stay OUT of the family manifests
    inj = clone / "src/testcases/CWE89_SQL_Injection/s01"
    inj.mkdir(parents=True)
    (inj / "CWE89_SQL_Injection__test_01.java").write_text(
        _GOOD_FILE, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(clone)], check=True)
    subprocess.run(["git", "-C", str(clone), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(clone), "-c", "user.email=t@example.org",
         "-c", "user.name=t", "commit", "-qm", "fixture"], check=True)
    return clone


class TestFamilies:
    def _generate(self, tmp_path, monkeypatch, family):
        clone = _make_family_clone(tmp_path)
        head = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        monkeypatch.setattr("core.recall.juliet_manifest."
                            "JULIET_PINNED_SHA", head)
        return generate_manifest(clone, family=family), head

    def test_concurrency_slice(self, tmp_path, monkeypatch):
        manifest, head = self._generate(tmp_path, monkeypatch,
                                        "concurrency")
        assert manifest["name"] == "juliet-java-concurrency"
        assert manifest["notes"]["family"] == "concurrency"
        assert [e["cwe"] for e in manifest["expected"]] == ["CWE-609"]
        assert manifest["expected"][0]["provenance"]["kind"] == "benchmark"
        manifest["target"]["pinned_sha"] = head
        parsed = parse_manifest(json.loads(json.dumps(manifest)))
        assert parsed.profile == "scan-codeql"

    def test_integer_slice(self, tmp_path, monkeypatch):
        manifest, _ = self._generate(tmp_path, monkeypatch, "integer")
        assert manifest["name"] == "juliet-java-integer"
        assert [e["cwe"] for e in manifest["expected"]] == ["CWE-190"]
        # the injection dir present in the clone must not leak in
        ids = {e["id"] for e in manifest["expected"]}
        assert not any("SQL_Injection" in i for i in ids)

    def test_default_family_is_the_injection_set(self, tmp_path,
                                                 monkeypatch):
        manifest, _ = self._generate(tmp_path, monkeypatch, "injection")
        assert manifest["name"] == "juliet-java-holdout"
        assert [e["cwe"] for e in manifest["expected"]] == ["CWE-89"]

    def test_unknown_family_refused(self, tmp_path):
        clone = _make_family_clone(tmp_path)
        with pytest.raises(JulietManifestError, match="unknown"):
            generate_manifest(clone, family="nope")
        with pytest.raises(JulietManifestError, match="unknown"):
            generate_manifest_b(clone, family="nope")

    def test_family_doctrine_notes_present(self, tmp_path, monkeypatch):
        manifest, _ = self._generate(tmp_path, monkeypatch,
                                     "concurrency")
        assert "never used to tune" in manifest["notes"][
            "holdout_doctrine"]

    def test_cli_family_flag(self, tmp_path, monkeypatch):
        clone = _make_family_clone(tmp_path)
        head = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        monkeypatch.setattr("core.recall.juliet_manifest."
                            "JULIET_PINNED_SHA", head)
        out = tmp_path / "fam.json"
        rc = jm_main(["--clone-dir", str(clone), "--out", str(out),
                      "--family", "integer"])
        assert rc == 0
        assert json.loads(out.read_text())["name"] == "juliet-java-integer"


# ---------------------------------------------------------------------------
# Juliet-B (multi-file variants)
# ---------------------------------------------------------------------------

_CHAIN_A = """class A {
    public void bad() throws Throwable {
        (new B()).badSink("x");
    }
    public void good() throws Throwable { goodG2B(); }
    private void goodG2B() throws Throwable {
        (new B()).goodG2BSink("c");
    }
}
"""

_CHAIN_B_TERMINAL = """class B {
    public void badSink(String data) throws Throwable {
        sink(data);
    }
    public void goodG2BSink(String data) throws Throwable {
        sink(data);
    }
}
"""

_CHAIN_B_FORWARDING = """class B {
    public void badSink(String data) throws Throwable {
        (new C()).badSink(data);
    }
    public void goodG2BSink(String data) throws Throwable {
        (new C()).goodG2BSink(data);
    }
}
"""

_SOURCE_SPLIT_A = """class A {
    public void bad() throws Throwable {
        String data = (new B()).badSource();
        sink(data);
    }
    public void good() throws Throwable { }
    private void goodG2B() throws Throwable {
        String data = (new B()).goodG2BSource();
        sink(data);
    }
}
"""

_SOURCE_SPLIT_B = """class B {
    public String badSource() throws Throwable { return src(); }
    public String goodG2BSource() throws Throwable { return "c"; }
}
"""

_POLAR_BAD = """class X_bad extends X_base {
    public void action(String data) throws Throwable { sink(data); }
}
"""

_POLAR_GOOD = """class X_goodG2B extends X_base {
    public void action(String data) throws Throwable { safe(data); }
}
"""


def _make_clone_b(tmp_path: Path) -> Path:
    clone = tmp_path / "juliet-b"
    d = clone / "src/testcases/CWE89_SQL_Injection/s01"
    d.mkdir(parents=True)
    base = "CWE89_SQL_Injection__t"
    # terminal chain: sink file is b
    (d / f"{base}_51a.java").write_text(_CHAIN_A, encoding="utf-8")
    (d / f"{base}_51b.java").write_text(
        _CHAIN_B_TERMINAL, encoding="utf-8")
    # forwarding-terminal chain must refuse
    (d / f"{base}_53a.java").write_text(_CHAIN_A, encoding="utf-8")
    (d / f"{base}_53b.java").write_text(
        _CHAIN_B_FORWARDING, encoding="utf-8")
    # source-split chain: sink file is a
    (d / f"{base}_61a.java").write_text(
        _SOURCE_SPLIT_A, encoding="utf-8")
    (d / f"{base}_61b.java").write_text(
        _SOURCE_SPLIT_B, encoding="utf-8")
    # polarity split
    (d / f"{base}_81_bad.java").write_text(_POLAR_BAD, encoding="utf-8")
    (d / f"{base}_81_base.java").write_text(
        "abstract class X_base { }", encoding="utf-8")
    (d / f"{base}_81_goodG2B.java").write_text(
        _POLAR_GOOD, encoding="utf-8")
    # polarity split missing its good twin must refuse
    (d / f"{base}_82_bad.java").write_text(_POLAR_BAD, encoding="utf-8")
    (d / f"{base}_82_base.java").write_text(
        "abstract class X_base { }", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(clone)], check=True)
    subprocess.run(["git", "-C", str(clone), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(clone), "-c", "user.email=t@example.org",
         "-c", "user.name=t", "commit", "-qm", "fixture"], check=True)
    return clone


class TestGenerateB:
    def _manifest(self, tmp_path, monkeypatch):
        clone = _make_clone_b(tmp_path)
        head = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        monkeypatch.setattr("core.recall.juliet_manifest."
                            "JULIET_PINNED_SHA", head)
        return generate_manifest_b(clone), head

    def test_layouts_anchor_at_the_sink_file(self, tmp_path,
                                             monkeypatch):
        manifest, head = self._manifest(tmp_path, monkeypatch)
        by_id = {e["id"]: e for e in manifest["expected"]}
        assert by_id["CWE89_SQL_Injection__t_51"]["file"].endswith(
            "_51b.java")
        assert by_id["CWE89_SQL_Injection__t_61"]["file"].endswith(
            "_61a.java")
        assert by_id["CWE89_SQL_Injection__t_81"]["file"].endswith(
            "_81_bad.java")
        assert len(manifest["expected"]) == 3

    def test_refusals_counted_by_reason(self, tmp_path, monkeypatch):
        manifest, _ = self._manifest(tmp_path, monkeypatch)
        refused = manifest["notes"]["refused"]
        assert refused["chain_sink_ambiguous"] == 1  # forwarding 53
        assert refused["polarity_missing_good_twin"] == 1  # 82
        ids = {e["id"] for e in manifest["expected"]}
        assert "CWE89_SQL_Injection__t_53" not in ids
        assert "CWE89_SQL_Injection__t_82" not in ids

    def test_polarity_good_files_are_clean_regions(self, tmp_path,
                                                   monkeypatch):
        manifest, _ = self._manifest(tmp_path, monkeypatch)
        goods = [c for c in manifest["clean_regions"]
                 if c["id"].startswith("CWE89_SQL_Injection__t_81")]
        assert len(goods) == 1
        assert goods[0]["file"].endswith("_81_goodG2B.java")

    def test_manifest_parses_and_declares_ledger(self, tmp_path,
                                                 monkeypatch):
        manifest, head = self._manifest(tmp_path, monkeypatch)
        assert "LEDGER-FRESH" in manifest["notes"]["ledger"]
        assert manifest["profile"] == "scan-codeql"
        manifest["target"]["pinned_sha"] = head
        parsed = parse_manifest(json.loads(json.dumps(manifest)))
        assert parsed.name == "juliet-b-multifile"

    def test_cli_variant_b(self, tmp_path, monkeypatch, capsys):
        clone = _make_clone_b(tmp_path)
        head = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        monkeypatch.setattr("core.recall.juliet_manifest."
                            "JULIET_PINNED_SHA", head)
        out = tmp_path / "b.json"
        rc = jm_main(["--clone-dir", str(clone), "--out", str(out),
                      "--variant-b"])
        assert rc == 0
        assert "refused" in capsys.readouterr().out
        assert json.loads(out.read_text())["name"] == "juliet-b-multifile"


class TestSingleLetterLeftoverCounted:
    def test_leftover_refused_by_reason(self, tmp_path, monkeypatch):
        """A chain with only one letter present is not a multi-file
        case — it must join the refused-by-reason counts, never drop
        silently (the module's coverage-honesty posture)."""
        clone = _make_clone_b(tmp_path)
        d = clone / "src/testcases/CWE89_SQL_Injection/s01"
        (d / "CWE89_SQL_Injection__t_99a.java").write_text(
            _CHAIN_A, encoding="utf-8")
        subprocess.run(["git", "-C", str(clone), "add", "-A"],
                       check=True)
        subprocess.run(
            ["git", "-C", str(clone), "-c", "user.email=t@example.org",
             "-c", "user.name=t", "commit", "-qm", "leftover"],
            check=True)
        head = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        monkeypatch.setattr(
            "core.recall.juliet_manifest.JULIET_PINNED_SHA", head)
        manifest = generate_manifest_b(clone)
        refused = manifest["notes"]["refused"]
        assert refused.get("single_letter_chain_leftover", 0) >= 1
        ids = {e["id"] for e in manifest["expected"]}
        assert "CWE89_SQL_Injection__t_99" not in ids
