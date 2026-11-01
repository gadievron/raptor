"""Tests for the corpus label linter (schema + pin verification)."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

import core.audit.corpus.lint as lint
from core.audit.corpus.label import compute_span_sha, load_label
from core.audit.corpus.lint import (
    PIN_MISSING,
    PIN_NO_FIXTURE,
    PIN_OK,
    PIN_RELOCATABLE,
    collect_label_files,
    load_labels,
    schema_check,
    stamp_labels,
    verify_pin,
    verify_pins,
)

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None, reason="git not available",
)

_SOURCE = """\
#include <stdio.h>

static int helper(void)
{
    return 41;
}

int target_fn(int x)
{
    if (x < 0)
        return -1;
    return helper() + x;
}
"""

# target_fn spans lines 8-13 of _SOURCE.
_FN_START, _FN_END = 8, 13


def _label_dict(**overrides):
    d = {
        "schema_version": 1,
        "function_id": "src/a.c:target_fn",
        "bug_class": "auth",
        "expected_status": "clean",
        "rationale": "Test label.",
        "source": {
            "repo": "test-repo",
            "sha": "v1.0.0",
            "file": "src/a.c",
            "line_start": _FN_START,
            "line_end": _FN_END,
        },
        "labeler": "test",
        "labeled_at": "2026-08-18",
    }
    source = overrides.pop("source", {})
    d.update(overrides)
    d["source"].update(source)
    return d


def _write_label(path, **overrides):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_label_dict(**overrides), indent=4) + "\n")
    return path


@pytest.fixture()
def pinned_tree(tmp_path):
    """A fixture tree at fixtures/test-repo, checked out at v1.0.0."""
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
           "HOME": str(tmp_path), "PATH": "/usr/bin:/bin:/usr/local/bin"}
    fixtures = tmp_path / "fixtures"
    repo = fixtures / "test-repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.c").write_text(_SOURCE)

    def git(*args):
        subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True, capture_output=True, env=env,
        )

    subprocess.run(
        ["git", "init", "-q", str(repo)],
        check=True, capture_output=True, env=env,
    )
    git("add", "-A")
    git("commit", "-q", "-m", "pinned")
    git("tag", "v1.0.0")
    return fixtures, repo


def _load(path):
    return load_label(path)


class TestSchemaMode:
    def test_clean_labels_pass(self, tmp_path, capsys):
        _write_label(tmp_path / "labels" / "auth" / "a.label.json")
        rc = lint.main(["--mode", "schema", str(tmp_path / "labels")])
        assert rc == 0
        assert "Schema lint clean." in capsys.readouterr().out

    def test_invalid_json_reported_with_path(self, tmp_path, capsys):
        bad = tmp_path / "labels" / "auth" / "bad.label.json"
        bad.parent.mkdir(parents=True)
        bad.write_text("{not json")
        rc = lint.main([str(tmp_path / "labels")])
        assert rc == 2
        assert "bad.label.json" in capsys.readouterr().err

    def test_function_id_file_mismatch(self, tmp_path):
        p = _write_label(
            tmp_path / "l.label.json",
            function_id="other/b.c:target_fn",
        )
        errors = schema_check([(p, _load(p))])
        assert len(errors) == 1
        assert "source.file" in errors[0]

    def test_duplicate_function_ids(self, tmp_path):
        a = _write_label(tmp_path / "a.label.json")
        b = _write_label(tmp_path / "b.label.json")
        _, errors = load_labels([a, b])
        assert len(errors) == 1
        assert "duplicate function_id" in errors[0]

    def test_escaping_file_path_rejected(self, tmp_path):
        p = _write_label(
            tmp_path / "l.label.json",
            function_id="../../etc/passwd:target_fn",
            source={"file": "../../etc/passwd"},
        )
        errors = schema_check([(p, _load(p))])
        assert any("repo-relative" in e for e in errors)

    def test_missing_path_is_infra_error(self, tmp_path):
        assert lint.main([str(tmp_path / "nope")]) == 1

    def test_no_labels_is_infra_error(self, tmp_path):
        assert lint.main([str(tmp_path)]) == 1


class TestExpectedRuleHitsCheck:
    """Dangling expected_rule_hits pins are lint failures; absent
    engine dirs (CI without a rules checkout) skip gracefully."""

    def _patch_inventory(self, monkeypatch, *, shipped=(), graduated=()):
        import core.audit.corpus.rule_eval as rule_eval

        def fake_discover(engines):
            return [r for r in shipped if r.engine in engines], []

        def fake_graduated(engines, base):
            return [r for r in graduated if r.engine in engines], []

        monkeypatch.setattr(rule_eval, "discover_rules", fake_discover)
        monkeypatch.setattr(
            rule_eval, "discover_graduated_rules", fake_graduated,
        )
        monkeypatch.setattr(
            rule_eval, "find_engine_rules_base",
            lambda out_dir, fixture_roots=(): None,
        )

    def _rule(self, engine="coccinelle", rule_id="use_after_free",
              provenance="shipped"):
        from core.audit.corpus.rule_eval import RuleInfo

        return RuleInfo(engine=engine, rule_id=rule_id, path="x",
                        provenance=provenance)

    def _pair(self, tmp_path, hits):
        p = _write_label(
            tmp_path / "l.label.json", expected_rule_hits=hits,
        )
        return [(p, _load(p))]

    def test_dangling_rule_named_with_label_and_engine(
        self, tmp_path, monkeypatch,
    ):
        self._patch_inventory(monkeypatch, shipped=[self._rule()])
        pairs = self._pair(
            tmp_path, {"coccinelle": ["gone_rule", "use_after_free"]},
        )
        (err,) = lint.expected_rule_hits_check(pairs)
        assert "src/a.c:target_fn" in err
        assert "coccinelle" in err
        assert "'gone_rule'" in err

    def test_known_shipped_and_graduated_ids_pass(
        self, tmp_path, monkeypatch,
    ):
        self._patch_inventory(
            monkeypatch,
            shipped=[self._rule()],
            graduated=[self._rule(
                engine="semgrep", rule_id="raptor-synth-uaf",
                provenance="graduated",
            )],
        )
        pairs = self._pair(tmp_path, {
            "coccinelle": ["use_after_free"],
            "semgrep": ["raptor-synth-uaf"],
        })
        assert lint.expected_rule_hits_check(pairs) == []

    def test_absent_engine_dirs_skip_gracefully(
        self, tmp_path, monkeypatch,
    ):
        # Discovery finds nothing at all (no rules checkout): the
        # pinned ids cannot be checked and must not fail.
        self._patch_inventory(monkeypatch)
        pairs = self._pair(tmp_path, {"coccinelle": ["use_after_free"]})
        assert lint.expected_rule_hits_check(pairs) == []

    def test_foreign_engine_names_skip(self, tmp_path, monkeypatch):
        # The label schema deliberately allows pinning rule sets this
        # checkout doesn't ship.
        self._patch_inventory(monkeypatch, shipped=[self._rule()])
        pairs = self._pair(tmp_path, {"quickcheck": ["some.rule"]})
        assert lint.expected_rule_hits_check(pairs) == []

    def test_no_pins_never_touches_discovery(self, tmp_path, monkeypatch):
        import core.audit.corpus.rule_eval as rule_eval

        def boom(*a, **kw):
            raise AssertionError("discovery must not run without pins")

        monkeypatch.setattr(rule_eval, "discover_rules", boom)
        pairs = self._pair(tmp_path, {})
        assert lint.expected_rule_hits_check(pairs) == []

    def test_cli_schema_mode_fails_on_dangling_pin(
        self, tmp_path, monkeypatch, capsys,
    ):
        self._patch_inventory(monkeypatch, shipped=[self._rule()])
        _write_label(
            tmp_path / "labels" / "auth" / "a.label.json",
            expected_rule_hits={"coccinelle": ["gone_rule"]},
        )
        rc = lint.main(["--mode", "schema", str(tmp_path / "labels")])
        assert rc == 2
        assert "gone_rule" in capsys.readouterr().err


class TestVerifyPin:
    def test_ok_without_span_sha(self, tmp_path, pinned_tree):
        _, repo = pinned_tree
        p = _write_label(tmp_path / "l.label.json")
        check = verify_pin(_load(p), repo, path=p)
        assert check.outcome == PIN_OK
        assert check.current_span_sha == compute_span_sha(
            _SOURCE, _FN_START, _FN_END,
        )

    def test_ok_with_matching_span_sha(self, tmp_path, pinned_tree):
        _, repo = pinned_tree
        sha = compute_span_sha(_SOURCE, _FN_START, _FN_END)
        p = _write_label(
            tmp_path / "l.label.json", source={"span_sha": sha},
        )
        assert verify_pin(_load(p), repo, path=p).outcome == PIN_OK

    def test_moved_span_relocated_by_hash(self, tmp_path, pinned_tree):
        _, repo = pinned_tree
        sha = compute_span_sha(_SOURCE, _FN_START, _FN_END)
        p = _write_label(
            tmp_path / "l.label.json", source={"span_sha": sha},
        )
        # Insert three lines above the function: the span content is
        # intact but the pinned line numbers now point elsewhere.
        (repo / "src" / "a.c").write_text(
            "/* new */\n/* new */\n/* new */\n" + _SOURCE,
        )
        check = verify_pin(_load(p), repo, path=p)
        assert check.outcome == PIN_RELOCATABLE
        assert check.suggested_start == _FN_START + 3
        assert check.suggested_end == _FN_END + 3

    def test_moved_function_relocated_by_name(self, tmp_path, pinned_tree):
        _, repo = pinned_tree
        p = _write_label(tmp_path / "l.label.json")
        (repo / "src" / "a.c").write_text(
            "/* new */\n" * 20 + _SOURCE,
        )
        check = verify_pin(_load(p), repo, path=p)
        assert check.outcome == PIN_RELOCATABLE
        assert check.suggested_start == _FN_START + 20

    def test_removed_function_missing(self, tmp_path, pinned_tree):
        _, repo = pinned_tree
        p = _write_label(tmp_path / "l.label.json")
        (repo / "src" / "a.c").write_text(
            _SOURCE.replace("target_fn", "renamed_fn"),
        )
        check = verify_pin(_load(p), repo, path=p)
        assert check.outcome == PIN_MISSING

    def test_tree_search_reports_new_home(self, tmp_path, pinned_tree):
        _, repo = pinned_tree
        p = _write_label(tmp_path / "l.label.json")
        (repo / "src" / "a.c").write_text(
            _SOURCE.replace("target_fn", "renamed_fn"),
        )
        (repo / "src" / "b.c").write_text(_SOURCE)
        check = verify_pin(_load(p), repo, path=p, tree_search=True)
        assert check.outcome == PIN_MISSING
        assert "src/b.c" in check.detail

    def test_name_substring_does_not_count(self, tmp_path, pinned_tree):
        """``target_fn`` must not match ``target_fn_v2``."""
        _, repo = pinned_tree
        p = _write_label(tmp_path / "l.label.json")
        (repo / "src" / "a.c").write_text(
            _SOURCE.replace("target_fn", "target_fn_v2"),
        )
        check = verify_pin(_load(p), repo, path=p)
        assert check.outcome == PIN_MISSING

    def test_prefix_probe_suggests_relocation(self, tmp_path, pinned_tree):
        """src/-rooted repo shape: label path resolves under src/."""
        _, repo = pinned_tree
        p = _write_label(
            tmp_path / "l.label.json",
            function_id="a.c:target_fn",
            source={"file": "a.c"},
        )
        check = verify_pin(_load(p), repo, path=p)
        assert check.outcome == PIN_RELOCATABLE
        assert check.suggested_file == "src/a.c"

    def test_missing_file(self, tmp_path, pinned_tree):
        _, repo = pinned_tree
        p = _write_label(
            tmp_path / "l.label.json",
            function_id="src/gone.c:target_fn",
            source={"file": "src/gone.c"},
        )
        check = verify_pin(_load(p), repo, path=p)
        assert check.outcome == PIN_MISSING
        assert "not found" in check.detail

    def test_out_of_bounds_range_relocates(self, tmp_path, pinned_tree):
        _, repo = pinned_tree
        p = _write_label(
            tmp_path / "l.label.json",
            source={"line_start": 500, "line_end": 520},
        )
        check = verify_pin(_load(p), repo, path=p)
        assert check.outcome == PIN_RELOCATABLE
        assert "out of bounds" in check.detail


class TestResolveTrees:
    def test_fixture_at_pinned_ref_used(self, tmp_path, pinned_tree):
        fixtures, repo = pinned_tree
        p = _write_label(tmp_path / "l.label.json")
        checks = verify_pins([(p, _load(p))], fixtures_dir=fixtures)
        assert checks[0].outcome == PIN_OK

    def test_fixture_at_other_ref_is_no_fixture(
        self, tmp_path, pinned_tree,
    ):
        fixtures, repo = pinned_tree
        p = _write_label(
            tmp_path / "l.label.json", source={"sha": "v9.9.9"},
        )
        checks = verify_pins([(p, _load(p))], fixtures_dir=fixtures)
        assert checks[0].outcome == PIN_NO_FIXTURE
        assert "another ref" in checks[0].detail

    def test_absent_fixture_is_no_fixture(self, tmp_path):
        p = _write_label(tmp_path / "l.label.json")
        checks = verify_pins(
            [(p, _load(p))], fixtures_dir=tmp_path / "nowhere",
        )
        assert checks[0].outcome == PIN_NO_FIXTURE

    def test_fetch_missing_populates_cache(
        self, tmp_path, pinned_tree, monkeypatch,
    ):
        import core.audit.corpus.sources as sources_mod
        from core.audit.corpus.sources import SourceEntry

        fixtures, repo = pinned_tree
        entry = SourceEntry(
            repo_key="test-repo", url=f"file://{repo}",
        )
        monkeypatch.setattr(
            sources_mod, "load_sources", lambda path=None: {
                "test-repo": entry,
            },
        )
        p = _write_label(tmp_path / "l.label.json")
        cache = tmp_path / "cache"
        checks = verify_pins(
            [(p, _load(p))],
            fixtures_dir=tmp_path / "nowhere",
            cache_dir=cache,
            fetch_missing=True,
        )
        assert checks[0].outcome == PIN_OK
        assert (cache / "test-repo@v1.0.0" / "src" / "a.c").is_file()
        # Second run reuses the cache without fetching.
        monkeypatch.setattr(
            sources_mod, "fetch_files",
            lambda *a, **k: pytest.fail("cache should have been reused"),
        )
        checks = verify_pins(
            [(p, _load(p))],
            fixtures_dir=tmp_path / "nowhere",
            cache_dir=cache,
            fetch_missing=True,
        )
        assert checks[0].outcome == PIN_OK

    def test_deleted_upstream_ref_is_missing(
        self, tmp_path, pinned_tree, monkeypatch,
    ):
        import core.audit.corpus.sources as sources_mod
        from core.audit.corpus.sources import SourceEntry

        fixtures, repo = pinned_tree
        entry = SourceEntry(
            repo_key="test-repo", url=f"file://{repo}",
        )
        monkeypatch.setattr(
            sources_mod, "load_sources", lambda path=None: {
                "test-repo": entry,
            },
        )
        p = _write_label(
            tmp_path / "l.label.json", source={"sha": "v9.9.9"},
        )
        checks = verify_pins(
            [(p, _load(p))],
            fixtures_dir=tmp_path / "nowhere",
            cache_dir=tmp_path / "cache",
            fetch_missing=True,
        )
        assert checks[0].outcome == PIN_MISSING
        assert "no longer fetchable" in checks[0].detail

    def test_offline_is_no_fixture(self, tmp_path, monkeypatch):
        import core.audit.corpus.sources as sources_mod
        from core.audit.corpus.sources import (
            SourceEntry,
            SourceFetchError,
        )

        monkeypatch.setattr(
            sources_mod, "load_sources", lambda path=None: {
                "test-repo": SourceEntry(
                    repo_key="test-repo", url="https://x.invalid/r.git",
                ),
            },
        )

        def fake_fetch(*a, **k):
            raise SourceFetchError(
                "could not resolve host", connectivity=True,
            )

        monkeypatch.setattr(sources_mod, "fetch_files", fake_fetch)
        p = _write_label(tmp_path / "l.label.json")
        checks = verify_pins(
            [(p, _load(p))],
            fixtures_dir=tmp_path / "nowhere",
            cache_dir=tmp_path / "cache",
            fetch_missing=True,
        )
        assert checks[0].outcome == PIN_NO_FIXTURE
        assert "unreachable" in checks[0].detail

    def test_repo_not_in_registry_is_no_fixture(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.corpus.sources as sources_mod

        monkeypatch.setattr(
            sources_mod, "load_sources", lambda path=None: {},
        )
        p = _write_label(tmp_path / "l.label.json")
        checks = verify_pins(
            [(p, _load(p))],
            fixtures_dir=tmp_path / "nowhere",
            cache_dir=tmp_path / "cache",
            fetch_missing=True,
        )
        assert checks[0].outcome == PIN_NO_FIXTURE
        assert "not in sources.json" in checks[0].detail


class TestStamp:
    def test_stamp_roundtrip(self, tmp_path, pinned_tree):
        _, repo = pinned_tree
        p = _write_label(tmp_path / "l.label.json")
        check = verify_pin(_load(p), repo, path=p)
        stamped = stamp_labels([check])
        assert stamped == [p]
        raw = json.loads(p.read_text())
        expected = compute_span_sha(_SOURCE, _FN_START, _FN_END)
        assert raw["source"]["span_sha"] == expected
        # Key order: span_sha lands directly after line_end.
        keys = list(raw["source"].keys())
        assert keys.index("span_sha") == keys.index("line_end") + 1
        # File shape preserved: 4-space indent, trailing newline.
        text = p.read_text()
        assert text.endswith("}\n")
        assert '    "function_id"' in text
        # The stamped label now verifies ok with the hash enforced.
        assert verify_pin(_load(p), repo, path=p).outcome == PIN_OK

    def test_stamp_preserves_non_ascii_prose(self, tmp_path, pinned_tree):
        _, repo = pinned_tree
        p = _write_label(
            tmp_path / "l.label.json",
            rationale="Correct teardown — no dangling callback.",
        )
        stamp_labels([verify_pin(_load(p), repo, path=p)])
        assert "teardown — no" in p.read_text()
        assert "\\u2014" not in p.read_text()

    def test_stamp_is_idempotent(self, tmp_path, pinned_tree):
        _, repo = pinned_tree
        p = _write_label(tmp_path / "l.label.json")
        stamp_labels([verify_pin(_load(p), repo, path=p)])
        before = p.read_text()
        assert stamp_labels([verify_pin(_load(p), repo, path=p)]) == []
        assert p.read_text() == before

    def test_failing_label_never_stamped(self, tmp_path, pinned_tree):
        _, repo = pinned_tree
        p = _write_label(tmp_path / "l.label.json")
        (repo / "src" / "a.c").write_text(
            _SOURCE.replace("target_fn", "renamed_fn"),
        )
        check = verify_pin(_load(p), repo, path=p)
        assert check.outcome != PIN_OK
        assert stamp_labels([check]) == []
        assert "span_sha" not in json.loads(p.read_text())["source"]


class TestCli:
    def test_pins_mode_exit_codes(self, tmp_path, pinned_tree, capsys):
        fixtures, repo = pinned_tree
        labels = tmp_path / "labels" / "auth"
        _write_label(labels / "ok.label.json")
        rc = lint.main([
            "--mode", "pins", "--fixtures-dir", str(fixtures),
            str(labels),
        ])
        assert rc == 0
        assert "1 ok, 0 relocatable" in capsys.readouterr().out

        (repo / "src" / "a.c").write_text(
            _SOURCE.replace("target_fn", "renamed_fn"),
        )
        rc = lint.main([
            "--mode", "pins", "--fixtures-dir", str(fixtures),
            str(labels),
        ])
        assert rc == 2

    def test_no_fixture_warns_but_passes(self, tmp_path, capsys):
        labels = tmp_path / "labels" / "auth"
        _write_label(labels / "l.label.json")
        rc = lint.main([
            "--mode", "pins",
            "--fixtures-dir", str(tmp_path / "nowhere"),
            "--cache-dir", str(tmp_path / "cache"),
            str(labels),
        ])
        assert rc == 0
        assert "WARNING" in capsys.readouterr().out

    def test_require_fixtures_fails_on_no_fixture(self, tmp_path):
        labels = tmp_path / "labels" / "auth"
        _write_label(labels / "l.label.json")
        rc = lint.main([
            "--mode", "pins", "--require-fixtures",
            "--fixtures-dir", str(tmp_path / "nowhere"),
            "--cache-dir", str(tmp_path / "cache"),
            str(labels),
        ])
        assert rc == 2

    def test_stamp_via_cli(self, tmp_path, pinned_tree):
        fixtures, _ = pinned_tree
        labels = tmp_path / "labels" / "auth"
        p = _write_label(labels / "l.label.json")
        rc = lint.main([
            "--mode", "pins", "--stamp",
            "--fixtures-dir", str(fixtures), str(labels),
        ])
        assert rc == 0
        assert json.loads(p.read_text())["source"]["span_sha"]

    def test_collect_label_files_mixes_dirs_and_files(self, tmp_path):
        a = _write_label(tmp_path / "d" / "a.label.json")
        b = _write_label(
            tmp_path / "b.label.json", function_id="src/a.c:other",
        )
        assert collect_label_files([tmp_path / "d", b]) == [a, b]


class TestProvenanceCheck:
    """Vulnerable-class labels need public provenance (cve or
    fix_commit); the lint surfaces the gap as a WARNING, never a
    failure."""

    def test_vulnerable_label_without_provenance_warns(self, tmp_path):
        p = _write_label(
            tmp_path / "a.label.json", expected_status="finding",
        )
        warnings = lint.provenance_check([(p, load_label(p))])
        assert len(warnings) == 1
        assert "public provenance" in warnings[0]

    def test_fix_commit_satisfies_provenance(self, tmp_path):
        p = _write_label(
            tmp_path / "a.label.json",
            expected_status="finding",
            fix_commit="https://github.com/x/y/commit/abc123",
        )
        label = load_label(p)
        assert label.fix_commit.endswith("abc123")
        assert lint.provenance_check([(p, label)]) == []

    def test_cve_satisfies_provenance(self, tmp_path):
        p = _write_label(
            tmp_path / "a.label.json",
            expected_status="suspicious", cve="CVE-2024-0001",
        )
        assert lint.provenance_check([(p, load_label(p))]) == []

    def test_clean_label_needs_no_provenance(self, tmp_path):
        p = _write_label(tmp_path / "a.label.json")
        assert lint.provenance_check([(p, load_label(p))]) == []

    def test_warning_does_not_fail_schema_mode(self, tmp_path):
        _write_label(
            tmp_path / "a.label.json", expected_status="finding",
        )
        rc = lint.main([str(tmp_path), "--mode", "schema"])
        assert rc == 0


class TestDefinitionIdentity:
    def check(self, tmp_path, text, *, name="target_fn", suffix=".c", start=1, end=None, span_sha=""):
        tree = tmp_path / "tree"
        tree.mkdir(exist_ok=True)
        filename = "src/a" + suffix
        source = tree / filename
        source.parent.mkdir(exist_ok=True)
        source.write_text(text)
        label = _write_label(tmp_path / "l.label.json", function_id=filename + ":" + name,
                             source={"file": filename, "line_start": start,
                                     "line_end": end or len(text.splitlines()), "span_sha": span_sha})
        return verify_pin(_load(label), tree)

    @pytest.mark.parametrize("text", [
        "int caller(void) { return target_fn(); }\n",
        "// target_fn is intentionally absent\nint other(void) { return 0; }\n",
        'char *s = "target_fn";\n',
        "int target_fn(void);\n",
    ])
    def test_mentions_and_declarations_are_not_definitions(self, tmp_path, text):
        assert self.check(tmp_path, text).outcome == PIN_MISSING

    def test_call_before_definition_relocates_complete_body(self, tmp_path):
        text = "int caller(void) { return target_fn(); }\n\nint target_fn(void) {\n return 0;\n}\n"
        check = self.check(tmp_path, text, start=1, end=1)
        assert (check.outcome, check.suggested_start, check.suggested_end) == (PIN_RELOCATABLE, 3, 5)

    def test_matching_hash_does_not_certify_call_site(self, tmp_path):
        text = "int caller(void) { return target_fn(); }\nint target_fn(void) { return 0; }\n"
        check = self.check(tmp_path, text, end=1, span_sha=compute_span_sha(text, 1, 1))
        assert (check.outcome, check.suggested_start, check.suggested_end) == (PIN_RELOCATABLE, 2, 2)

    def test_incomplete_body_relocated_to_full_definition(self, tmp_path):
        check = self.check(tmp_path, "int target_fn(void) {\n return 0;\n}\n", end=1)
        assert (check.outcome, check.suggested_start, check.suggested_end) == (PIN_RELOCATABLE, 1, 3)

    def test_conditional_definitions_require_one_complete_variant(self, tmp_path):
        text = "#ifdef FAST\nint target_fn(void) { return 1; }\n#else\nint target_fn(void) { return 2; }\n#endif\n"
        assert self.check(tmp_path, text).outcome == lint.PIN_UNVERIFIABLE
        assert self.check(tmp_path, text, start=2, end=2).outcome == PIN_OK

    def test_python_qualified_method_does_not_match_another_class(self, tmp_path):
        text = "class Wrong:\n def target_fn(self):\n  pass\nclass Right:\n def target_fn(self):\n  return 1\n"
        check = self.check(tmp_path, text, suffix=".py", name="Right.target_fn", end=3)
        assert (check.outcome, check.suggested_start, check.suggested_end) == (PIN_RELOCATABLE, 5, 6)

    def test_go_version_suffix_and_receiver(self, tmp_path):
        text = "package p\ntype Scanner struct {}\nfunc (s *Scanner) scanNumber() {\n}\n"
        check = self.check(tmp_path, text, suffix=".go", name="Scanner.scanNumber@go1.24.5", start=3, end=4)
        assert check.outcome == PIN_OK

    def test_unsupported_language_is_not_stamped(self, tmp_path):
        check = self.check(tmp_path, "function target_fn() {}\n", suffix=".js")
        assert check.outcome == lint.PIN_UNVERIFIABLE
        assert not check.current_span_sha

    def test_parse_error_in_definition_is_unverifiable(self, tmp_path):
        check = self.check(tmp_path, "int target_fn(void) { return ???; }\n")
        assert check.outcome == lint.PIN_UNVERIFIABLE

    @pytest.mark.parametrize("suffix,text", [
        (".c", "int target_fn(void) { return 0; }\n"),
        (".go", "package p\nfunc target_fn() {}\n"),
    ])
    def test_missing_native_parser_refuses_validation_and_stamping(self, tmp_path, monkeypatch, suffix, text):
        from core.inventory import extractors
        monkeypatch.setattr(extractors, "_ts_parser_for", lambda language: None)
        check = self.check(tmp_path, text, suffix=suffix)
        assert check.outcome == lint.PIN_UNVERIFIABLE
        assert "parser unavailable" in check.detail
        assert not check.current_span_sha
        monkeypatch.setattr(lint, "verify_pins", lambda *a, **kw: [check])
        path = tmp_path / "l.label.json"
        before = path.read_bytes()
        assert lint.main(["--mode", "pins", "--stamp", str(path)]) == lint.EXIT_LINT
        assert path.read_bytes() == before

    def test_unverifiable_cli_fails_even_without_require_fixtures(self, tmp_path, monkeypatch):
        check = self.check(tmp_path, "function target_fn() {}\n", suffix=".js")
        monkeypatch.setattr(lint, "verify_pins", lambda *a, **kw: [check])
        assert lint.main(["--mode", "pins", str(tmp_path / "l.label.json")]) == lint.EXIT_LINT


def test_runner_refuses_mixed_revisions_before_fetch(tmp_path, monkeypatch):
    from core.audit.corpus import run_corpus
    a = _load(_write_label(tmp_path / "a.label.json"))
    b = _load(_write_label(tmp_path / "b.label.json", source={"sha": "v2.0.0"}))
    monkeypatch.setattr(run_corpus, "_fetch_source", lambda *a: pytest.fail("must refuse before fetching"))
    for labels in ([a, b], [b, a]):
        with pytest.raises(ValueError, match="multiple pinned revisions"):
            run_corpus._resolve_source_dirs(labels, do_fetch=True)


def test_version_normalization_preserves_source_path_and_qualification():
    from core.audit.corpus.definitions import function_name, source_function_id
    label_id = "vendor/@scope/a.go:Scanner.scanNumber@go1.24.5"
    assert source_function_id(label_id) == "vendor/@scope/a.go:Scanner.scanNumber"
    assert function_name(label_id) == "scanNumber"
    assert function_name(label_id, qualified=True) == "Scanner.scanNumber"


def test_version_suffix_removed_from_probe_context(tmp_path):
    from core.audit.corpus.run_corpus import _build_probe_context
    label = _load(_write_label(tmp_path / "l.label.json", function_id="src/a.go:Scanner.scanNumber@go1.24.5", source={"file": "src/a.go"}))
    assert _build_probe_context(label, "package p")['function'] == "Scanner.scanNumber"
