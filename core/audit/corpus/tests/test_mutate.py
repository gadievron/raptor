"""Tests for the synthetic-mutant generator CLI and site finders."""

from __future__ import annotations

import pytest

from core.audit.corpus import mutate
from core.audit.corpus.label import load_label
from core.audit.corpus.mutation import (
    MutationError,
    apply_mutation_to_text,
)


RET_CHECK_SRC = (
    "int g(int fd)\n"
    "{\n"
    "    if (dev_read(fd) < 0) return -1;\n"
    "    return 0;\n"
    "}\n"
)

GUARD_TWO_LINE_SRC = (
    "int h(char *p)\n"
    "{\n"
    "    if (!p)\n"
    "        return -1;\n"
    "    p[0] = 1;\n"
    "    return 0;\n"
    "}\n"
)

LOOP_SRC = (
    "int s(int *a, int n)\n"
    "{\n"
    "    int i, t = 0;\n"
    "    for (i = 0; i < n; i++) {\n"
    "        t += a[i];\n"
    "    }\n"
    "    return t;\n"
    "}\n"
)

ORDER_SRC = (
    "void w(int fd)\n"
    "{\n"
    "    lock_take(fd);\n"
    "    buf_write(fd);\n"
    "    lock_drop(fd);\n"
    "}\n"
)


def _lines(src):
    return src.split("\n")


class TestFindSite:
    def test_drop_return_check(self):
        edits, site = mutate.find_site(
            _lines(RET_CHECK_SRC), (1, 5), "drop-return-check",
        )
        assert site == 3
        assert edits == [(3, 3, ["    dev_read(fd);"])]

    def test_drop_return_check_callee_filter(self):
        with pytest.raises(MutationError, match="no-matching-site"):
            mutate.find_site(
                _lines(RET_CHECK_SRC), (1, 5), "drop-return-check",
                callee="other_fn",
            )

    def test_drop_guard_two_line(self):
        edits, site = mutate.find_site(
            _lines(GUARD_TWO_LINE_SRC), (1, 7), "drop-guard",
        )
        assert site == 3
        assert edits == [(3, 4, [])]

    def test_drop_guard_one_line(self):
        src = _lines(
            "int h(char *p)\n"
            "{\n"
            "    if (!p) return -1;\n"
            "    p[0] = 1;\n"
            "    return 0;\n"
            "}\n",
        )
        edits, site = mutate.find_site(src, (1, 6), "drop-guard")
        assert site == 3
        assert edits == [(3, 3, [])]

    def test_flip_bound(self):
        edits, site = mutate.find_site(
            _lines(LOOP_SRC), (1, 8), "flip-bound",
        )
        assert site == 4
        assert edits[0][2] == ["    for (i = 0; i <= n; i++) {"]

    def test_flip_bound_ignores_arrow_and_shift(self):
        src = _lines(
            "int q(struct s *p)\n"
            "{\n"
            "    if (p->len >= (1 << 4)) return -1;\n"
            "    return 0;\n"
            "}\n",
        )
        edits, site = mutate.find_site(src, (1, 5), "flip-bound")
        assert site == 3
        assert edits[0][2] == [
            "    if (p->len > (1 << 4)) return -1;",
        ]

    def test_swap_order(self):
        edits, site = mutate.find_site(
            _lines(ORDER_SRC), (1, 6), "swap-order",
        )
        assert site == 3
        assert edits == [(3, 4, [
            "    buf_write(fd);", "    lock_take(fd);",
        ])]

    def test_remove_pair_release_requires_callee(self):
        with pytest.raises(MutationError, match="callee-required"):
            mutate.find_site(
                _lines(ORDER_SRC), (1, 6), "remove-pair-release",
            )

    def test_remove_pair_release(self):
        edits, site = mutate.find_site(
            _lines(ORDER_SRC), (1, 6), "remove-pair-release",
            callee="lock_drop",
        )
        assert site == 5
        assert edits == [(5, 5, [])]

    def test_line_out_of_span_refused(self):
        with pytest.raises(MutationError, match="line-out-of-span"):
            mutate.find_site(
                _lines(ORDER_SRC), (1, 6), "flip-bound", line=40,
            )

    def test_no_site_enumerated_refusal(self):
        with pytest.raises(MutationError, match="no-matching-site"):
            mutate.find_site(
                _lines(RET_CHECK_SRC), (1, 5), "swap-order",
            )


class TestSiteFinderPatternPins:
    """Two-direction language pins for the site-finder patterns.

    The patterns carry linearity folds (optional-atom whitespace gated
    into its group, ``[^;]*`` subsuming the pre-``;`` whitespace) —
    these pins hold the matched language still through any such
    reshaping, exercising each alternation branch both directions.
    """

    DROP_RETURN_ACCEPT = [
        "if (f(x)) return -1;",
        "    if (!init(a, b)) goto err;",
        "\tif ( ! check(p) ) break;",
        "if (read(fd, buf, n) < 0) return NULL;",
        "if (g()) continue;",
        "if (h(x)) goto out ;",
        "if (h(x)) break ;",
        "if (f(x)) return ;",
    ]
    DROP_RETURN_REJECT = [
        "if (f(x)) return -1",       # no terminator
        "if (f(x) return -1;",       # unbalanced parens
        "f(x); return -1;",          # no guard
        "if (f(x)) returning;",      # keyword boundary
        "if (f(x)) breakage;",
        "if (f(x)) continue x;",
        "while (f(x)) return -1;",   # not an if
    ]

    def test_drop_return_pattern_both_directions(self):
        for line in self.DROP_RETURN_ACCEPT:
            assert mutate._DROP_RETURN_RE.match(line), line
        for line in self.DROP_RETURN_REJECT:
            assert not mutate._DROP_RETURN_RE.match(line), line

    def test_drop_return_pattern_captures(self):
        m = mutate._DROP_RETURN_RE.match("    if (!init(a, b)) goto err;")
        assert m is not None
        assert m.group("ind") == "    "
        assert m.group("fn") == "init"
        assert m.group("args") == "a, b"

    GUARD_HEAD_ACCEPT = [
        "if (!p)",
        "if (!p) return -1;",
        "  if ( ! ptr )",
        "if ( ptr == NULL )   goto fail;",
        "if (q == nullptr)",
        "if (r == 0) break;",
    ]
    GUARD_HEAD_REJECT = [
        "if (p != NULL) return;",
        "if (p == q) return;",
        "if (p == 1) return;",
        "while (!p) return;",
    ]

    def test_null_guard_head_both_directions(self):
        for line in self.GUARD_HEAD_ACCEPT:
            assert mutate._NULL_GUARD_HEAD_RE.match(line), line
        for line in self.GUARD_HEAD_REJECT:
            assert not mutate._NULL_GUARD_HEAD_RE.match(line), line

    def test_null_guard_rest_group_strips_clean(self):
        # The one consumer strips ``rest``; the stripped value is the
        # pinned contract (leading whitespace may ride in the group).
        m = mutate._NULL_GUARD_HEAD_RE.match("if (!p)   return -1;")
        assert m is not None
        assert m.group("rest").strip() == "return -1;"
        m = mutate._NULL_GUARD_HEAD_RE.match("if (!p)")
        assert m is not None
        assert m.group("rest").strip() == ""

    EARLY_EXIT_ACCEPT = [
        "return -1;",
        "  goto out;",
        "goto out ;",
        "break;",
        " continue ;",
        "return err_code ;",
        "return;",
    ]
    EARLY_EXIT_REJECT = [
        "return -1",
        "goto;",
        "breakage;",
        "x = 1;",
        "return -1; extra",
    ]

    def test_early_exit_both_directions(self):
        for line in self.EARLY_EXIT_ACCEPT:
            assert mutate._EARLY_EXIT_RE.match(line), line
        for line in self.EARLY_EXIT_REJECT:
            assert not mutate._EARLY_EXIT_RE.match(line), line


class TestBuildMutantLabel:
    def test_label_validates_and_applies(self):
        label = mutate.build_mutant_label(
            GUARD_TWO_LINE_SRC,
            repo_key="demo", ref="abc123",
            file="src/h.c", function="h", span=(1, 7),
            operator="drop-guard",
        )
        assert label.provenance_kind == "synthetic_mutant"
        assert label.bug_class == "consistency"
        assert label.cwe == "CWE-476"
        assert label.expected_mechanism == "consistency"
        assert label.excerpt_scope == "peer_set"
        mutated = apply_mutation_to_text(GUARD_TWO_LINE_SRC, label)
        assert "if (!p)" not in mutated

    def test_rationale_states_floor_framing_and_excerpt(self):
        label = mutate.build_mutant_label(
            RET_CHECK_SRC,
            repo_key="demo", ref="abc123",
            file="src/g.c", function="g", span=(1, 5),
            operator="drop-return-check",
        )
        assert "Regression floor" in label.rationale
        assert "NOT a real defect report" in label.rationale
        assert "dev_read(fd)" in label.rationale

    def test_cwe_override(self):
        label = mutate.build_mutant_label(
            ORDER_SRC,
            repo_key="demo", ref="abc123",
            file="src/w.c", function="w", span=(1, 6),
            operator="remove-pair-release", callee="lock_drop",
            cwe="CWE-667",
        )
        assert label.cwe == "CWE-667"


class TestCli:
    def _fixture(self, tmp_path):
        fixture = tmp_path / "fixture"
        (fixture / "src").mkdir(parents=True)
        (fixture / "src" / "h.c").write_text(GUARD_TWO_LINE_SRC)
        return fixture

    def _argv(self, fixture, out=None, extra=()):
        argv = [
            "--fixture", str(fixture),
            "--repo-key", "demo", "--ref", "abc123",
            "--file", "src/h.c", "--function", "h",
            "--lines", "1-7", "--operator", "drop-guard",
        ]
        if out is not None:
            argv += ["--out", str(out)]
        return argv + list(extra)

    def test_writes_loadable_label(self, tmp_path, capsys):
        fixture = self._fixture(tmp_path)
        out = tmp_path / "labels"
        rc = mutate.main(self._argv(fixture, out))
        assert rc == 0
        files = list(out.rglob("*.label.json"))
        assert len(files) == 1
        assert files[0].parent.name == "consistency"
        label = load_label(files[0])
        assert label.provenance_kind == "synthetic_mutant"
        assert label.function_id == "src/h.c:h"
        assert "--labels-dir" in capsys.readouterr().out

    def test_dry_run_writes_nothing(self, tmp_path, capsys):
        fixture = self._fixture(tmp_path)
        rc = mutate.main(self._argv(fixture, extra=["--dry-run"]))
        assert rc == 0
        assert not list(tmp_path.rglob("*.label.json"))
        assert "not written" in capsys.readouterr().out

    def test_out_required_without_dry_run(self, tmp_path):
        fixture = self._fixture(tmp_path)
        with pytest.raises(SystemExit):
            mutate.main(self._argv(fixture))

    def test_refusal_exit_one(self, tmp_path, capsys):
        fixture = self._fixture(tmp_path)
        argv = self._argv(fixture, extra=["--dry-run"])
        argv[argv.index("--operator") + 1] = "swap-order"
        rc = mutate.main(argv)
        assert rc == 1
        assert "no-matching-site" in capsys.readouterr().err

    def test_missing_file_exit_one(self, tmp_path, capsys):
        rc = mutate.main(self._argv(tmp_path / "nowhere",
                                    extra=["--dry-run"]))
        assert rc == 1
        assert "not found" in capsys.readouterr().err

    def test_file_escaping_fixture_root_refused(self, tmp_path, capsys):
        fixture = self._fixture(tmp_path)
        (tmp_path / "outside.c").write_text(GUARD_TWO_LINE_SRC)
        argv = self._argv(fixture, extra=["--dry-run"])
        argv[argv.index("--file") + 1] = "../outside.c"
        rc = mutate.main(argv)
        assert rc == 1
        assert "escapes the fixture root" in capsys.readouterr().err

    def test_symlink_escape_refused(self, tmp_path, capsys):
        fixture = self._fixture(tmp_path)
        (tmp_path / "outside.c").write_text(GUARD_TWO_LINE_SRC)
        (fixture / "src" / "link.c").symlink_to(tmp_path / "outside.c")
        argv = self._argv(fixture, extra=["--dry-run"])
        argv[argv.index("--file") + 1] = "src/link.c"
        rc = mutate.main(argv)
        assert rc == 1
        assert "escapes the fixture root" in capsys.readouterr().err
