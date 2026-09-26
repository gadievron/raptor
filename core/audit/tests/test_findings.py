"""Tests for core.audit.findings — findings emission."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.findings import (
    emit_finding,
    load_findings,
    write_findings,
)


class TestEmitFinding:
    def test_basic_finding(self, tmp_path: Path):
        finding = emit_finding(
            out_dir=tmp_path,
            file_path="src/handler.c",
            function_name="parse_request",
            line=42,
            title="Buffer overflow in parse_request",
            description="Unbounded memcpy with user-controlled length.",
            cwe="CWE-120",
            severity="high",
            tool_evidence=[
                {"tool": "semgrep", "rule": "unbounded-memcpy", "output": "match at line 42"},
            ],
            hypothesis="If user-supplied length exceeds buffer size, memcpy overflows.",
        )

        assert finding["file"] == "src/handler.c"
        assert finding["cwe"] == "CWE-120"
        assert finding["origin"] == "audit"
        assert len(finding["tool_evidence"]) == 1

        findings = load_findings(tmp_path)
        assert len(findings) == 1

    def test_finding_without_cwe(self, tmp_path: Path):
        finding = emit_finding(
            out_dir=tmp_path,
            file_path="src/splice.c",
            function_name="do_splice",
            line=100,
            title="Page cache aliasing",
            description="Read-only pages aliased into writable buffer.",
        )

        assert finding["vuln_type"] == "novel"
        assert "cwe" not in finding

    def test_multiple_findings_appended(self, tmp_path: Path):
        emit_finding(
            out_dir=tmp_path,
            file_path="a.c",
            function_name="f1",
            line=10,
            title="First",
            description="First finding.",
        )
        emit_finding(
            out_dir=tmp_path,
            file_path="b.c",
            function_name="f2",
            line=20,
            title="Second",
            description="Second finding.",
        )

        findings = load_findings(tmp_path)
        assert len(findings) == 2
        assert findings[0]["title"] == "First"
        assert findings[1]["title"] == "Second"


class TestLoadFindings:
    def test_load_list_format(self, tmp_path: Path):
        (tmp_path / "findings.json").write_text(json.dumps([
            {"title": "A", "file": "a.c"},
        ]))
        findings = load_findings(tmp_path)
        assert len(findings) == 1

    def test_load_dict_format(self, tmp_path: Path):
        (tmp_path / "findings.json").write_text(json.dumps({
            "findings": [
                {"title": "A", "file": "a.c"},
            ],
        }))
        findings = load_findings(tmp_path)
        assert len(findings) == 1

    def test_load_missing(self, tmp_path: Path):
        findings = load_findings(tmp_path)
        assert findings == []


class TestWriteFindings:
    def test_writes_json(self, tmp_path: Path):
        findings = [{"title": "Test", "file": "a.c", "line": 1}]
        path = write_findings(findings, tmp_path)
        assert path.exists()

        with open(path) as f:
            data = json.load(f)
        assert len(data) == 1


class TestPersistFindings:
    """_persist_findings is the (idempotent, atomic) full rewrite the
    orchestrator repeats after the last status-mutating pass: late-
    minted findings must appear, retracted ones must disappear, and a
    zero-finding run must not create an empty file."""

    @staticmethod
    def _result(*statuses):
        from core.audit.orchestrator import OrchestratorResult, ReviewOutcome

        result = OrchestratorResult()
        for i, status in enumerate(statuses):
            result.outcomes.append(ReviewOutcome(
                file=f"src/f{i}.c", function=f"fn{i}", status=status,
                body="b", hypothesis=f"h{i}",
            ))
        return result

    @staticmethod
    def _config(tmp_path):
        from core.audit.orchestrator import OrchestratorConfig

        return OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

    def test_late_minted_finding_written_after_re_persist(self, tmp_path):
        from core.audit.orchestrator import _persist_findings

        result = self._result("clean")
        config = self._config(tmp_path)
        _persist_findings(result, config)  # mid-pipeline: no findings yet
        assert not (tmp_path / "findings.json").exists()

        # A post-loop pass promotes the outcome to finding.
        result.outcomes[0].status = "finding"
        _persist_findings(result, config)
        data = json.loads((tmp_path / "findings.json").read_text())
        assert len(data) == 1
        assert data[0]["function"] == "fn0"

    def test_retracted_finding_removed_on_re_persist(self, tmp_path):
        from core.audit.orchestrator import _persist_findings

        result = self._result("finding", "finding")
        config = self._config(tmp_path)
        _persist_findings(result, config)
        assert len(json.loads((tmp_path / "findings.json").read_text())) == 2

        # A post-loop pass retracts both (e.g. absent demotion).
        for o in result.outcomes:
            o.status = "dormant"
        _persist_findings(result, config)
        assert json.loads((tmp_path / "findings.json").read_text()) == []

    def test_zero_findings_never_creates_file(self, tmp_path):
        from core.audit.orchestrator import _persist_findings

        _persist_findings(self._result("clean", "error"), self._config(tmp_path))
        assert not (tmp_path / "findings.json").exists()

    def test_idempotent_rewrite(self, tmp_path):
        from core.audit.orchestrator import _persist_findings

        result = self._result("finding")
        config = self._config(tmp_path)
        _persist_findings(result, config)
        first = (tmp_path / "findings.json").read_text()
        _persist_findings(result, config)
        assert (tmp_path / "findings.json").read_text() == first

    def test_tree_class_stamped_on_every_persisted_finding(self, tmp_path):
        """This writer is the findings.json path the in-session audit
        loop's findings take — sweep-promoted composites included — and
        it used to be the one emission path without the tree-class tag.
        Field fixture shapes: an openbsd-compat portability shim
        classifies vendored-compat, a first-party source file
        production."""
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _persist_findings,
        )

        result = OrchestratorResult()
        result.outcomes.append(ReviewOutcome(
            file="openbsd-compat/glob.c", function="glob2",
            status="finding",
            body="[sweep promoted via smt:check-overflow]\n\nbody",
            hypothesis="off-by-one EOS store past pathend_last",
        ))
        result.outcomes.append(ReviewOutcome(
            file="sshbuf-getput-basic.c",
            function="sshbuf_put_bignum2_bytes", status="finding",
            body="[sweep promoted via joern:live+smt:invariant]\n\nbody",
            hypothesis="len + 4 + prepend sizing overflow",
        ))
        _persist_findings(result, self._config(tmp_path))
        data = json.loads((tmp_path / "findings.json").read_text())
        by_file = {f["file"]: f for f in data}
        assert (by_file["openbsd-compat/glob.c"]["tree_class"]
                == "vendored-compat")
        assert (by_file["sshbuf-getput-basic.c"]["tree_class"]
                == "production")

    def test_vendor_verdicts_refine_the_persisted_stamp(self, tmp_path):
        """A prep-time vendored verdict for the file wins over the
        path-only production default (same threading contract as the
        graded export)."""
        from core.audit.orchestrator import _persist_findings

        result = self._result("finding")
        _persist_findings(
            result, self._config(tmp_path),
            vendor_verdicts={"src/f0.c": object()},
        )
        data = json.loads((tmp_path / "findings.json").read_text())
        assert data[0]["tree_class"] == "vendored-compat"

    def test_final_persist_overwrites_tick_path_only_stamp(self, tmp_path):
        """Convergence: the tick's verdict-less mid-run write stamps
        path-only; the final unconditional re-persist (full rewrite)
        threads the prep verdicts and must OVERWRITE the record with
        the verdict-refined value."""
        from core.audit.orchestrator import _persist_findings

        result = self._result("finding")
        config = self._config(tmp_path)
        _persist_findings(result, config)  # tick shape: no verdicts
        data = json.loads((tmp_path / "findings.json").read_text())
        assert data[0]["tree_class"] == "production"
        _persist_findings(  # final persist: verdicts threaded
            result, config, vendor_verdicts={"src/f0.c": object()},
        )
        data = json.loads((tmp_path / "findings.json").read_text())
        assert data[0]["tree_class"] == "vendored-compat"


class TestPersistFindingsJournalReimport:
    """A segment's ``result.outcomes`` holds only its own reviews; the
    persist is a full rewrite. Finalization must therefore also persist
    every function whose FINAL journal verdict is finding — a resumed
    finalize segment used to rewrite prior-segment findings away."""

    @staticmethod
    def _config(tmp_path):
        from core.audit.orchestrator import OrchestratorConfig

        return OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

    @staticmethod
    def _journal_row(
        tmp_path: Path,
        *,
        function: str,
        verdict: str,
        ts: str,
        file: str = "src/net.c",
        line_start: int = 10,
        body: str = "prior-segment body",
        evidence_tools: list[str] | None = None,
        hypotheses: list[dict[str, str]] | None = None,
        strategies: list[str] | None = None,
        run_id: str | None = None,
        raw: bool = False,
        legacy_stamp: bool = False,
    ) -> None:
        """One prior-segment journal row.

        Default = what the run's own writer produces: MAC-stamped via
        ``append_entry``, which stamps the resolved run-dir
        ``run_path`` into the MAC-covered row. ``run_id`` overrides
        the name attribution; ``raw=True`` appends the line without a
        stamp (planted-row pins); ``legacy_stamp=True`` mints a
        verified row WITHOUT ``run_path`` — the shape every row had
        before the field existed (legacy-journal pins).
        """
        from core.coverage.journal import ReviewJournalEntry, append_entry

        entry = ReviewJournalEntry(
            ts=ts,
            run_id=tmp_path.name if run_id is None else run_id,
            file=file,
            function=function,
            verdict=verdict,
            source_hash="deadbeef",
            line_start=line_start,
            body=body,
            evidence_tools=evidence_tools or [],
            hypotheses=hypotheses or [],
            strategies=strategies or [],
            producer="audit",
        )
        if raw:
            with open(tmp_path / "review-journal.jsonl", "a") as fh:
                fh.write(json.dumps(entry.to_dict()) + "\n")
        elif legacy_stamp:
            from core.coverage import journal_mac

            row = entry.to_dict()
            row.pop(journal_mac.TOKEN_KEY, None)
            token = journal_mac.mint_row(row)
            if token:
                row[journal_mac.TOKEN_KEY] = token
            with open(tmp_path / "review-journal.jsonl", "a") as fh:
                fh.write(json.dumps(row) + "\n")
        else:
            append_entry(tmp_path, entry)

    def test_prior_segment_finding_survives_finalize_rewrite(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _persist_findings,
        )

        self._journal_row(
            tmp_path,
            function="parse_len",
            verdict="finding",
            ts="2026-01-01T00:00:01.000000Z",
            evidence_tools=["smt:check-overflow", "joern:live"],
            hypotheses=[{"mechanism": "len wraps before bounds check"}],
        )
        # Fresh finalize segment: no segment-local outcomes at all.
        _persist_findings(OrchestratorResult(), self._config(tmp_path))
        data = json.loads((tmp_path / "findings.json").read_text())
        assert len(data) == 1
        assert data[0]["function"] == "parse_len"
        assert data[0]["file"] == "src/net.c"
        assert data[0]["line"] == 10
        assert data[0]["evidence_tool"] == "smt:check-overflow+joern:live"
        assert data[0]["hypothesis"] == "len wraps before bounds check"
        # Same seam as segment-local findings: tree class stamped.
        assert data[0]["tree_class"] == "production"

    def test_demoted_prior_finding_stays_out(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _persist_findings,
        )

        self._journal_row(
            tmp_path, function="fp_fn", verdict="finding",
            ts="2026-01-01T00:00:01.000000Z",
        )
        # Correction row: the run later demoted the verdict.
        self._journal_row(
            tmp_path, function="fp_fn", verdict="suspicious",
            ts="2026-01-01T00:00:02.000000Z",
        )
        # The interrupted segment had persisted the finding already.
        write_findings(
            [{"id": "FIND-001", "file": "src/net.c", "function": "fp_fn"}],
            tmp_path,
        )
        _persist_findings(OrchestratorResult(), self._config(tmp_path))
        assert json.loads((tmp_path / "findings.json").read_text()) == []

    def test_segment_local_outcome_supersedes_journal_rows(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _persist_findings,
        )

        self._journal_row(
            tmp_path, function="rechecked", verdict="finding",
            ts="2026-01-01T00:00:01.000000Z",
        )
        # This segment re-reviewed the function and a post pass demoted
        # it — no corrective journal row exists yet at persist time.
        result = OrchestratorResult()
        result.outcomes.append(ReviewOutcome(
            file="src/net.c", function="rechecked", status="clean",
            body="demoted this segment",
        ))
        write_findings([{"id": "FIND-001", "function": "rechecked"}], tmp_path)
        _persist_findings(result, self._config(tmp_path))
        assert json.loads((tmp_path / "findings.json").read_text()) == []

    def test_twin_site_journal_finding_yields_to_any_local_twin(
        self, tmp_path,
    ):
        """Deliberate coarse-key behavior pin: the journal collapse is
        per-site, but the segment-local dedup is (file, function) — a
        journal finding at one site of a same-named twin is withheld
        when THIS segment holds any outcome for the name, because a
        site-joined key could double-ship the same finding when
        outcome.line and the journal line_start disagree. The dropped
        twin resurfaces on the next re-review; see the trade-off
        comment at the dedup site before changing either direction."""
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _persist_findings,
        )

        self._journal_row(
            tmp_path, function="twin", verdict="finding",
            ts="2026-01-01T00:00:01.000000Z", line_start=200,
        )
        result = OrchestratorResult()
        # This segment re-reviewed only the OTHER same-named site.
        clean_twin = ReviewOutcome(
            file="src/net.c", function="twin", status="clean", body="b",
        )
        clean_twin.line = 10
        result.outcomes.append(clean_twin)
        _persist_findings(result, self._config(tmp_path))
        assert not (tmp_path / "findings.json").exists()

    def test_mechanical_echo_rows_carry_no_verdict_authority(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _persist_findings,
        )

        self._journal_row(
            tmp_path, function="pattern_fn", verdict="finding",
            ts="2026-01-01T00:00:01.000000Z",
            strategies=["post-loop-mechanical"],
        )
        _persist_findings(OrchestratorResult(), self._config(tmp_path))
        assert not (tmp_path / "findings.json").exists()

    def test_journal_reimport_dedups_against_local_finding(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _persist_findings,
        )

        self._journal_row(
            tmp_path, function="live_fn", verdict="finding",
            ts="2026-01-01T00:00:01.000000Z",
        )
        result = OrchestratorResult()
        result.outcomes.append(ReviewOutcome(
            file="src/net.c", function="live_fn", status="finding",
            body="this segment's own row for the same function",
        ))
        _persist_findings(result, self._config(tmp_path))
        data = json.loads((tmp_path / "findings.json").read_text())
        assert len(data) == 1

    def test_planted_unstamped_finding_row_is_refused(self, tmp_path):
        """The transport PoC: a raw journal line (no MAC) with
        verdict=finding must NOT re-materialise a phantom finding
        into findings.json on a finalize segment."""
        from core.audit.orchestrator import (
            OrchestratorResult,
            _persist_findings,
        )

        self._journal_row(
            tmp_path, function="phantom_fn", verdict="finding",
            ts="2026-01-01T00:00:01.000000Z", raw=True,
        )
        _persist_findings(OrchestratorResult(), self._config(tmp_path))
        assert not (tmp_path / "findings.json").exists()

    def test_foreign_run_verified_row_imports_receipt_less(self, tmp_path):
        """A verified row byte-copied from a SIBLING run dir carries
        that run's MAC-covered ``run_path``. The MAC proves it is
        genuine install history (not attacker-minted), so the finding
        survives the re-import — refusing it silently lost real
        findings — but its receipts demote to the LLM-claimed tier:
        raw tool receipts belong only to the run dir that earned
        them."""
        from core.audit.orchestrator import (
            OrchestratorResult,
            _persist_findings,
        )

        own = tmp_path / "own-run"
        own.mkdir()
        sibling = tmp_path / "sibling-run"
        sibling.mkdir()
        self._journal_row(
            sibling, function="sibling_fn", verdict="finding",
            ts="2026-01-01T00:00:01.000000Z",
            # One COMPOSITE element: the demotion must sanitize every
            # "+"-part, not just prefix the element — split-on-"+"
            # consumers would otherwise see a raw receipt part.
            evidence_tools=["smt:check-overflow+joern:live"],
        )
        with open(own / "review-journal.jsonl", "a") as fh:
            fh.write((sibling / "review-journal.jsonl").read_text())
        _persist_findings(OrchestratorResult(), self._config(own))
        data = json.loads((own / "findings.json").read_text())
        assert data[0]["function"] == "sibling_fn"
        assert data[0]["evidence_tool"] == (
            "llm-claimed:smt:check-overflow+llm-claimed:joern:live")

    def test_same_basename_sibling_row_demotes_receipts(self, tmp_path):
        """Receipt replay via basename collision: a verified row from
        a run dir with the SAME basename under a different parent used
        to pass the run_id (basename) scope check and ride its raw
        receipts through. Scope is full resolved ``run_path`` now —
        the row still imports (verified = genuine history) but its
        receipts demote."""
        from core.audit.orchestrator import (
            OrchestratorResult,
            _persist_findings,
        )

        own = tmp_path / "run-x"
        own.mkdir()
        twin = tmp_path / "elsewhere" / "run-x"
        twin.mkdir(parents=True)
        self._journal_row(
            twin, function="twin_fn", verdict="finding",
            ts="2026-01-01T00:00:01.000000Z",
            evidence_tools=["smt:check-overflow", "joern:live"],
        )
        with open(own / "review-journal.jsonl", "a") as fh:
            fh.write((twin / "review-journal.jsonl").read_text())
        _persist_findings(OrchestratorResult(), self._config(own))
        data = json.loads((own / "findings.json").read_text())
        assert data[0]["function"] == "twin_fn"
        assert data[0]["evidence_tool"] == (
            "llm-claimed:smt:check-overflow+llm-claimed:joern:live")

    def test_symlink_alias_write_stays_run_scoped(self, tmp_path):
        """A writer that reached the run dir through a symlink alias
        stamps the RESOLVED path, so the reader (resolving its own
        identity the same way) still scopes the row to this run —
        the old basename compare broke on symlinked --out dirs."""
        from core.audit.orchestrator import (
            OrchestratorResult,
            _persist_findings,
        )

        real = tmp_path / "real-run"
        real.mkdir()
        alias = tmp_path / "alias-run"
        alias.symlink_to(real)
        self._journal_row(
            alias, function="aliased_fn", verdict="finding",
            ts="2026-01-01T00:00:01.000000Z",
            evidence_tools=["smt:check-overflow"],
        )
        _persist_findings(OrchestratorResult(), self._config(real))
        data = json.loads((real / "findings.json").read_text())
        assert data[0]["function"] == "aliased_fn"
        assert data[0]["evidence_tool"] == "smt:check-overflow"

    def test_unattributed_row_reimports_receipt_less(self, tmp_path):
        """Verified rows with no run attribution (legacy run_id="" /
        the RUN_ID_UNATTRIBUTED sentinel) keep the finding — erasing
        them would regress honest relative---out runs — but their
        receipt stamp demotes to the LLM-claimed tier so it can never
        mint confirmed_by receipts downstream."""
        from core.audit.orchestrator import (
            OrchestratorResult,
            _persist_findings,
        )
        from core.coverage.journal import RUN_ID_UNATTRIBUTED

        for run_id, fn in ((RUN_ID_UNATTRIBUTED, "sentinel_fn"),
                           ("", "legacy_fn")):
            self._journal_row(
                tmp_path, function=fn, verdict="finding",
                ts="2026-01-01T00:00:01.000000Z", run_id=run_id,
                evidence_tools=["smt:check-overflow"],
                legacy_stamp=True,
            )
        _persist_findings(OrchestratorResult(), self._config(tmp_path))
        data = json.loads((tmp_path / "findings.json").read_text())
        assert {d["function"] for d in data} == {"sentinel_fn",
                                                 "legacy_fn"}
        for d in data:
            assert d["evidence_tool"] == "llm-claimed:smt:check-overflow"

    def test_own_run_row_keeps_receipt_stamp(self, tmp_path):
        """The default harness row IS run-scoped (``append_entry``
        stamps this run dir's resolved ``run_path`` into the MAC) —
        its journaled evidence stamp rides through whole; the record
        gate enforced grounding at record time."""
        from core.audit.orchestrator import (
            OrchestratorResult,
            _persist_findings,
        )

        self._journal_row(
            tmp_path, function="own_fn", verdict="finding",
            ts="2026-01-01T00:00:01.000000Z",
            evidence_tools=["smt:check-overflow", "joern:live"],
        )
        _persist_findings(OrchestratorResult(), self._config(tmp_path))
        data = json.loads((tmp_path / "findings.json").read_text())
        assert data[0]["evidence_tool"] == "smt:check-overflow+joern:live"


class TestFindingsRobustness:
    def test_scalar_findings_json_degrades_to_empty(self, tmp_path):
        # Wrong-shaped VALID JSON must degrade like corrupt content
        # (the docstring contract) — it used to raise AttributeError
        # out of the record CLI.
        from core.audit.findings import load_findings

        (tmp_path / "findings.json").write_text("5")
        assert load_findings(tmp_path) == []

    def test_dict_with_non_list_findings_degrades(self, tmp_path):
        from core.audit.findings import load_findings

        (tmp_path / "findings.json").write_text('{"findings": 7}')
        assert load_findings(tmp_path) == []

    def test_next_id_survives_external_deletion(self, tmp_path):
        # len()+1 collided after any deletion; ids now go above every
        # existing numeric suffix.
        from core.audit.findings import emit_finding, load_findings

        for n in (1, 2, 3):
            emit_finding(
                out_dir=tmp_path, file_path="a.c", function_name="f",
                line=n, title=f"t{n}", description="d",
            )
        rows = load_findings(tmp_path)
        rows = [r for r in rows if r["id"] != "AUDIT-002"]
        from core.audit.findings import write_findings
        write_findings(rows, tmp_path)
        f4 = emit_finding(
            out_dir=tmp_path, file_path="a.c", function_name="f",
            line=4, title="t4", description="d",
        )
        assert f4["id"] == "AUDIT-004"
        ids = [r["id"] for r in load_findings(tmp_path)]
        assert len(ids) == len(set(ids))

    def test_concurrent_emitters_lose_nothing(self, tmp_path):
        # Two processes appending under the advisory lock: all
        # findings land, ids unique (the unlocked read-modify-write
        # lost one and duplicated the id).
        import multiprocessing as mp

        from core.audit.findings import load_findings

        procs = [
            mp.Process(target=_emit_many, args=(tmp_path, tag))
            for tag in ("a", "b")
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join()
        rows = load_findings(tmp_path)
        assert len(rows) == 10
        ids = [r["id"] for r in rows]
        assert len(set(ids)) == 10


def _emit_many(out_dir, tag):
    from core.audit.findings import emit_finding

    for i in range(5):
        emit_finding(
            out_dir=out_dir, file_path="a.c", function_name=f"{tag}{i}",
            line=i, title=f"{tag}{i}", description="d",
        )
