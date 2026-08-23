"""Caller-contract call-site digest.

Observed field failure: an audit of a C server exported dozens of
teardown/NULL-contract hypotheses ("double free if called twice",
"NULL deref if a caller passes NULL") at high confidence, and every
one died in validation on caller enumeration alone — each real call
site upheld the assumed precondition.  The review context showed only
the first call line per caller with one line of context, so the
reviewer had no per-site guard/reuse evidence to weigh the hypothesis
against.  The digest enumerates ALL in-repo call sites for
contract-risk functions with guard windows above and reuse windows
below each call, caps ubiquitous APIs, and carries its own
enumeration-honesty and demote-don't-suppress framing.  Hermetic —
no LLM, no subprocesses.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.caller_contract import (
    DECLINE_OVER_SITES,
    MAX_SITES_RENDERED,
    build_caller_contract_digest,
    is_contract_risk_function,
)
from core.audit.context import (
    _format_caller_contract,
    assemble_context,
    format_context_for_prompt,
)

DEFINITION = """\
void bitmap_free(struct bitmap *b)
{
\tif (b == NULL)
\t\treturn;
\tfree(b->d);
\tfree(b);
}
"""

GUARDED_CALLER = """\
static void
teardown(struct session *s)
{
\tif (s->bm != NULL) {
\t\tbitmap_free(s->bm);
\t\ts->bm = NULL;
\t}
}
"""

UNGUARDED_CALLER = """\
static void
abort_session(struct session *s)
{
\tbitmap_free(s->bm);
\tbitmap_free(s->bm);
}
"""


def _write_target(tmp_path: Path) -> Path:
    (tmp_path / "bitmap.c").write_text(DEFINITION)
    return tmp_path


class TestTrigger:
    def test_teardown_named_function_triggers(self):
        assert is_contract_risk_function("bitmap_free", {}, "")
        assert is_contract_risk_function("channel_clear_timeouts", {}, "")
        assert is_contract_risk_function("auth2_challenge_stop", {}, "")

    def test_dealloc_of_parameter_triggers(self):
        src = "void drop(struct ctx *c)\n{\n\tsshbuf_release(c->buf);\n}\n"
        meta = {"parameters": [("c", "struct ctx *")]}
        assert is_contract_risk_function("drop", meta, src)

    def test_dealloc_of_local_does_not_trigger(self):
        # Frees a local on an error path — not a teardown wrapper.
        src = (
            "int parse(const char *s)\n{\n"
            "\tchar *tmp = strdup(s);\n"
            "\tfree(tmp);\n\treturn 0;\n}\n"
        )
        meta = {"parameters": [("s", "const char *")]}
        assert not is_contract_risk_function("parse", meta, src)

    def test_plain_function_does_not_trigger(self):
        assert not is_contract_risk_function(
            "parse_packet", {"parameters": [("pkt", "struct pkt *")]},
            "int parse_packet(struct pkt *pkt) { return pkt->len; }",
        )


class TestDigest:
    def test_all_sites_enumerated_with_guard_and_reuse_windows(
        self, tmp_path,
    ):
        target = _write_target(tmp_path)
        (target / "session.c").write_text(GUARDED_CALLER)
        (target / "abort.c").write_text(UNGUARDED_CALLER)

        digest = build_caller_contract_digest(
            target, "bitmap.c", "bitmap_free",
            line_start=1, line_end=7,
        )
        assert digest is not None
        assert digest["total_sites"] == 3
        assert not digest["declined"]
        assert digest["enumeration"] == "tree-scan"

        by_file = {}
        for site in digest["sites"]:
            by_file.setdefault(site["file"], []).append(site)
        # Guard window above the guarded call is visible.
        guarded = by_file["session.c"][0]
        assert "s->bm != NULL" in guarded["excerpt"]
        # Reuse window below the first unguarded call shows the
        # second free — the "called twice" evidence.
        double = by_file["abort.c"][0]
        assert double["excerpt"].count("bitmap_free(s->bm)") == 2

    def test_definition_span_excluded(self, tmp_path):
        target = _write_target(tmp_path)
        (target / "session.c").write_text(GUARDED_CALLER)
        digest = build_caller_contract_digest(
            target, "bitmap.c", "bitmap_free",
            line_start=1, line_end=7,
        )
        assert digest is not None
        assert all(s["file"] != "bitmap.c" for s in digest["sites"])

    def test_zero_sites_is_reported_not_none(self, tmp_path):
        target = _write_target(tmp_path)
        digest = build_caller_contract_digest(
            target, "bitmap.c", "bitmap_free",
            line_start=1, line_end=7,
        )
        assert digest is not None
        assert digest["total_sites"] == 0
        assert digest["sites"] == []

    def test_ubiquitous_api_declines(self, tmp_path):
        target = _write_target(tmp_path)
        calls = "\n".join(
            f"void c{i}(struct bitmap *b) {{ bitmap_free(b); }}"
            for i in range(DECLINE_OVER_SITES + 5)
        )
        (target / "many.c").write_text(calls + "\n")
        digest = build_caller_contract_digest(
            target, "bitmap.c", "bitmap_free",
            line_start=1, line_end=7,
        )
        assert digest is not None
        assert digest["declined"]
        assert digest["total_sites"] > DECLINE_OVER_SITES
        assert digest["sites"] == []

    def test_symlinked_caller_outside_target_yields_no_excerpt(
        self, tmp_path,
    ):
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "secret.c"
        secret.write_text(
            "void x(struct bitmap *b)\n{\n\tbitmap_free(b);\n}\n",
        )
        target = tmp_path / "repo"
        target.mkdir()
        (target / "bitmap.c").write_text(DEFINITION)
        (target / "link.c").symlink_to(secret)
        digest = build_caller_contract_digest(
            target, "bitmap.c", "bitmap_free",
            line_start=1, line_end=7,
        )
        assert digest is not None
        for site in digest["sites"]:
            assert site["excerpt"] == ""

    def test_unresolving_inventory_reports_tree_scan(self, tmp_path):
        # The honesty bug the digest exists to avoid: an inventory
        # that is PRESENT but whose call graph cannot answer must not
        # be labelled "call graph" — the tree scan did the work.
        target = _write_target(tmp_path)
        (target / "session.c").write_text(GUARDED_CALLER)
        digest = build_caller_contract_digest(
            target, "bitmap.c", "bitmap_free",
            line_start=1, line_end=7,
            inventory={"files": []},
        )
        assert digest is not None
        assert digest["total_sites"] == 1
        assert digest["enumeration"] == "tree-scan"
        # Graph did not drive the enumeration: no graph-derived
        # uncertainty number may lend it false precision.
        assert digest["uncertain_callers"] is None

    def test_test_file_sites_set_aside_and_counted(self, tmp_path):
        target = _write_target(tmp_path)
        (target / "session.c").write_text(GUARDED_CALLER)
        tests_dir = target / "tests"
        tests_dir.mkdir()
        (tests_dir / "caller.c").write_text(
            "void t(struct bitmap *b)\n{\n\tbitmap_free(b);\n}\n",
        )
        digest = build_caller_contract_digest(
            target, "bitmap.c", "bitmap_free",
            line_start=1, line_end=7,
        )
        assert digest is not None
        # Mirrors the inventory path's exclude_test_files=True.
        assert digest["total_sites"] == 1
        assert digest["test_sites_excluded"] == 1
        assert all(
            not s["file"].startswith("tests/") for s in digest["sites"]
        )

    def test_recursive_call_without_line_end_not_a_site(self, tmp_path):
        target = tmp_path
        (target / "tree.c").write_text(
            "void tree_free(struct node *n)\n"
            "{\n"
            "\tif (n == NULL)\n"
            "\t\treturn;\n"
            "\ttree_free(n->left);\n"
            "\ttree_free(n->right);\n"
            "\tfree(n);\n"
            "}\n",
        )
        (target / "main.c").write_text(
            "void drop(struct node *root)\n{\n\ttree_free(root);\n}\n",
        )
        digest = build_caller_contract_digest(
            target, "tree.c", "tree_free",
            line_start=1,  # line_end deliberately omitted
        )
        assert digest is not None
        # The inferred definition span keeps the self-recursive calls
        # from counting as caller evidence.
        assert digest["total_sites"] == 1
        assert digest["sites"][0]["file"] == "main.c"

    def test_scan_cap_recorded_in_digest(self, tmp_path, monkeypatch):
        import core.audit.api_boundary as ab

        monkeypatch.setattr(ab, "_MAX_SCAN_FILES", 0)
        target = _write_target(tmp_path)
        (target / "session.c").write_text(GUARDED_CALLER)
        digest = build_caller_contract_digest(
            target, "bitmap.c", "bitmap_free",
            line_start=1, line_end=7,
        )
        assert digest is not None
        assert digest["scan_capped"] is True
        assert digest["total_sites"] == 0
        from core.audit.context import _format_caller_contract

        text = _format_caller_contract(digest)
        assert "NOT evidence that no callers exist" in text

    def test_site_render_cap(self, tmp_path):
        target = _write_target(tmp_path)
        calls = "\n".join(
            f"void c{i}(struct bitmap *b) {{ bitmap_free(b); }}"
            for i in range(MAX_SITES_RENDERED + 3)
        )
        (target / "many.c").write_text(calls + "\n")
        digest = build_caller_contract_digest(
            target, "bitmap.c", "bitmap_free",
            line_start=1, line_end=7,
        )
        assert digest is not None
        assert not digest["declined"]
        assert digest["total_sites"] == MAX_SITES_RENDERED + 3
        assert len(digest["sites"]) == MAX_SITES_RENDERED


class TestPromptRendering:
    def _digest(self, **over):
        base = {
            "function": "bitmap_free",
            "file": "bitmap.c",
            "total_sites": 1,
            "sites": [{
                "file": "session.c",
                "caller": "teardown",
                "line": 5,
                "excerpt": "    4  if (s->bm != NULL) {\n"
                           "    5>     bitmap_free(s->bm);",
            }],
            "declined": False,
            "enumeration": "call-graph",
            "scan_capped": False,
            "scanned_files": 0,
            "uncertain_callers": 0,
            "test_sites_excluded": 0,
        }
        base.update(over)
        return base

    def test_sites_epistemics_and_honesty_rendered(self):
        text = _format_caller_contract(self._digest())
        assert "Caller-contract evidence (1 in-repo call sites)" in text
        assert "session.c:teardown" in text
        assert "s->bm != NULL" in text
        # Demote-don't-suppress framing.
        assert "confidence low" in text
        assert "violated-in-waiting" in text
        # Enumeration honesty.
        assert "function pointers" in text

    def test_uncertain_callers_flagged_incomplete(self):
        text = _format_caller_contract(
            self._digest(uncertain_callers=2),
        )
        assert "enumeration is incomplete" in text

    def test_declined_renders_single_line(self):
        text = _format_caller_contract(self._digest(
            declined=True, total_sites=113, sites=[],
        ))
        assert "too many to enumerate" in text
        assert "confidence low" not in text

    def test_zero_sites_renders_external_only(self):
        text = _format_caller_contract(self._digest(
            total_sites=0, sites=[],
        ))
        assert "No in-repo call sites" in text

    def test_zero_sites_under_scan_cap_renders_incomplete(self):
        # A capped scan finding nothing must NOT claim there are no
        # callers — absence of evidence, honestly labelled.
        text = _format_caller_contract(self._digest(
            total_sites=0, sites=[],
            enumeration="tree-scan", scan_capped=True,
            scanned_files=4000,
        ))
        assert "No in-repo call sites" not in text
        assert "capped at 4000 files" in text
        assert "NOT evidence that no callers exist" in text

    def test_scan_cap_with_sites_flagged_incomplete(self):
        text = _format_caller_contract(self._digest(
            enumeration="tree-scan", scan_capped=True,
            scanned_files=4000,
        ))
        assert "4000-file cap" in text
        assert "enumeration is incomplete" in text

    def test_test_file_exclusion_noted(self):
        text = _format_caller_contract(self._digest(
            test_sites_excluded=3,
        ))
        assert "3 test-file call site(s) set aside" in text

    def test_render_size_cap_bounds_pathological_digests(self):
        from core.audit.context import _CALLER_CONTRACT_MAX_RENDER_CHARS

        long_excerpt = "\n".join(
            f"{i:5d}  " + "x" * 200 for i in range(1, 12)
        )
        sites = [
            {"file": f"f{i}.c", "caller": f"c{i}", "line": 5,
             "excerpt": long_excerpt}
            for i in range(20)
        ]
        text = _format_caller_contract(self._digest(
            total_sites=20, sites=sites,
        ))
        assert "digest size-capped" in text
        # Bounded: cap + one final oversized block + framing prose.
        assert len(text) < _CALLER_CONTRACT_MAX_RENDER_CHARS + 4000


class TestContextWiring:
    def _assemble(self, tmp_path, *, enabled: bool):
        target = _write_target(tmp_path)
        (target / "session.c").write_text(GUARDED_CALLER)
        return assemble_context(
            target_path=target,
            file_path="bitmap.c",
            function_name="bitmap_free",
            line_start=1,
            line_end=7,
            caller_contract=enabled,
        )

    def test_digest_in_context_and_prompt(self, tmp_path):
        ctx = self._assemble(tmp_path, enabled=True)
        assert ctx["caller_contract"] is not None
        assert ctx["caller_contract"]["total_sites"] == 1
        prompt = format_context_for_prompt(ctx)
        assert "Caller-contract evidence" in prompt
        assert "s->bm != NULL" in prompt

    def test_digest_supersedes_shallow_callers_section(self, tmp_path):
        ctx = self._assemble(tmp_path, enabled=True)
        # Simulate the inventory-derived shallow caller list.
        ctx["callers"] = [
            {"file": "session.c", "name": "teardown", "line_start": 1,
             "call_site": "bitmap_free(s->bm);"},
        ]
        prompt = format_context_for_prompt(ctx)
        assert "Caller-contract evidence" in prompt
        assert "### Callers (1-hop)" not in prompt

    def test_flag_off_restores_prior_behaviour(self, tmp_path):
        ctx = self._assemble(tmp_path, enabled=False)
        assert "caller_contract" not in ctx
        ctx["callers"] = [
            {"file": "session.c", "name": "teardown", "line_start": 1},
        ]
        prompt = format_context_for_prompt(ctx)
        assert "Caller-contract evidence" not in prompt
        assert "### Callers (1-hop)" in prompt

    def test_non_risk_function_gets_no_digest(self, tmp_path):
        target = _write_target(tmp_path)
        (target / "parse.c").write_text(
            "int parse_packet(struct pkt *p) { return p->len; }\n",
        )
        ctx = assemble_context(
            target_path=target,
            file_path="parse.c",
            function_name="parse_packet",
            line_start=1,
        )
        assert ctx.get("caller_contract") is None


class TestFlagPassthrough:
    """caller_contract_context must reach OrchestratorConfig from the
    pipeline opts (the single opts -> config mapping both pipelines
    share)."""

    class _StubClient:
        class config:  # noqa: D106 — attribute bag
            max_cost_per_scan = 10.0

    def _build(self, opts):
        from core.audit.pipeline import ReviewMode, _build_orchestrator_config

        return _build_orchestrator_config(
            opts, self._StubClient(), ["default"], ReviewMode.SECURITY,
        )

    def test_default_on(self, tmp_path):
        from core.audit.pipeline import AuditPipelineOpts

        opts = AuditPipelineOpts(
            target_path=tmp_path, out_dir=tmp_path / "out",
        )
        assert self._build(opts).caller_contract_context is True

    def test_disable_reaches_config(self, tmp_path):
        from core.audit.pipeline import AuditPipelineOpts

        opts = AuditPipelineOpts(
            target_path=tmp_path, out_dir=tmp_path / "out",
            caller_contract_context=False,
        )
        assert self._build(opts).caller_contract_context is False
