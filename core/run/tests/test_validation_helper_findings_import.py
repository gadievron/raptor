"""Tests for libexec/raptor-validation-helper ``--findings`` imports.

The import chokepoint must accept the canonical findings container,
a bare finding list, and the /understand --hunt variants.json
container (whose skill documents "Pass variants.json to /validate
--findings"), while degrading unrecognisable payloads to the legacy
verbatim copy. Colocated with the run-lifecycle CLI tests.
"""

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

from core.json import load_json

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_helper():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    script = str(REPO_ROOT / "libexec" / "raptor-validation-helper")
    loader = SourceFileLoader("raptor_validation_helper", script)
    spec = importlib.util.spec_from_loader("raptor_validation_helper", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _finding(fid: str, **overrides) -> dict:
    base = {
        "id": fid,
        "file": "a.c",
        "function": "add",
        "line": 3,
        "vuln_type": "buffer_overflow",
        "status": "not_disproven",
    }
    base.update(overrides)
    return base


def _variant(vid: str, **overrides) -> dict:
    base = {
        "id": vid,
        "file": "src/query.py",
        "function": "run_query",
        "line": 31,
        "vuln_type": "sqli",
        "status": "not_disproven",
        "taint_status": "confirmed_tainted",
    }
    base.update(overrides)
    return base


class TestCoerceFindingsContainer:

    def test_canonical_container_passes_through(self):
        mod = _load_helper()
        data = {"findings": [_finding("FIND-1")], "target_path": "/t",
                "extra_key": {"kept": True}}
        container, note = mod._coerce_findings_container(data)
        assert container is data  # untouched, extra keys preserved
        assert note is None

    def test_bare_list_wrapped(self):
        mod = _load_helper()
        container, note = mod._coerce_findings_container(
            [_finding("FIND-1"), "not-a-dict"], target_path="/t")
        assert [f["id"] for f in container["findings"]] == ["FIND-1"]
        assert container["target_path"] == "/t"
        assert "bare finding list" in note

    def test_variants_container_converted(self):
        mod = _load_helper()
        data = {
            "meta": {"seed": "FIND-001 | pattern"},
            "variants": [
                _variant("VAR-001"),
                _variant("VAR-002", taint_status="false_positive"),
                _variant("VAR-003", status=None),
            ],
        }
        # Remove the explicit None status so setdefault applies.
        del data["variants"][2]["status"]
        container, note = mod._coerce_findings_container(
            data, target_path="/t")
        ids = [f["id"] for f in container["findings"]]
        # false_positive variants are audit-trail-only in variants.json
        # and documented as excluded from validation scope.
        assert ids == ["VAR-001", "VAR-003"]
        assert container["findings"][1]["status"] == "not_disproven"
        assert container["target_path"] == "/t"
        assert "1 false_positive variant(s) excluded" in note

    def test_unrecognisable_shapes_rejected(self):
        mod = _load_helper()
        for payload in (None, "text", {"neither": []},
                        {"findings": "not-a-list"}):
            container, note = mod._coerce_findings_container(payload)
            assert container is None
            assert note is None


class TestImportFindingsFile:

    def test_variants_file_imported_with_normalised_ids(self, tmp_path,
                                                        capsys):
        mod = _load_helper()
        src = tmp_path / "variants.json"
        src.write_text(json.dumps({"variants": [_variant("VAR-001")]}))
        dest = tmp_path / "findings.json"
        mod._import_findings_file(src, dest, target="/t")
        saved = load_json(dest)
        assert saved["findings"][0]["id"] == "FIND-1"
        assert saved["findings"][0]["source_id"] == "VAR-001"
        out = capsys.readouterr().out
        assert "Pre-existing findings: 1 from variants.json" in out

    def test_canonical_file_findings_unchanged(self, tmp_path, capsys):
        mod = _load_helper()
        finding = _finding("FIND-7", description="keep me")
        src = tmp_path / "exported.json"
        src.write_text(json.dumps({"findings": [finding],
                                   "target_path": "/orig"}))
        dest = tmp_path / "findings.json"
        mod._import_findings_file(src, dest, target="/other")
        saved = load_json(dest)
        # Conforming ids and the container's own target_path survive.
        assert saved["findings"] == [finding]
        assert saved["target_path"] == "/orig"
        out = capsys.readouterr().out
        assert "Pre-existing findings: 1 from exported.json" in out

    def test_unrecognisable_file_copied_verbatim(self, tmp_path, capsys):
        mod = _load_helper()
        src = tmp_path / "weird.json"
        src.write_text(json.dumps({"neither": "shape"}))
        dest = tmp_path / "findings.json"
        mod._import_findings_file(src, dest)
        assert json.loads(dest.read_text()) == {"neither": "shape"}
        captured = capsys.readouterr()
        assert "Pre-existing findings: 0 from weird.json" in captured.out
        assert "no recognisable findings/variants" in captured.err


def _graded(fid: str, status: str, **overrides) -> dict:
    """A findings-graded.json-shaped row (audit graded export)."""
    base = {
        "id": fid,
        "file": "src/auth.c",
        "function": "check_token",
        "line": 12,
        "vuln_type": "auth_bypass",
        "cwe_id": "CWE-287",
        "status": status,
        "hypothesis": "token compare skips expiry",
        "evidence_tool": "smt",
    }
    base.update(overrides)
    return base


class TestDarkImportPolicy:
    """Dark rows are a witness-acquisition backlog by default;
    --include-dark restores candidacy. Two directions pinned."""

    def test_default_routes_dark_to_witness_backlog(self, tmp_path, capsys):
        mod = _load_helper()
        src = tmp_path / "findings-graded.json"
        src.write_text(json.dumps({"findings": [
            _graded("EXT-1", "finding"),
            _graded("EXT-2", "suspicious", function="parse_len",
                    cwe_id="CWE-190", vuln_type="integer_overflow"),
            _graded("EXT-3", "dark"),
            _graded("EXT-4", "dark", function="handle_req",
                    cwe_id="CWE-862"),
        ]}))
        dest = tmp_path / "findings.json"
        mod._import_findings_file(src, dest, target="/t")

        saved = load_json(dest)
        # Dark rows excluded from stage-A candidacy; finding AND
        # suspicious rows keep the same contract as scanner findings.
        assert len(saved["findings"]) == 2
        assert all(f.get("source_status") != "dark"
                   for f in saved["findings"])
        suspicious = [f for f in saved["findings"]
                      if f.get("source_status") == "suspicious"]
        assert len(suspicious) == 1

        backlog = load_json(tmp_path / "witness-backlog.json")
        assert backlog["total"] == 2
        classes = {c["class"]: c["count"] for c in backlog["clusters"]}
        # Per-class clustering: which CWE classes need new witnesses.
        assert classes == {"CWE-287": 1, "CWE-862": 1}
        # Backlog rows keep the producer's own ids and grade — no
        # verdict is rewritten on the routed rows.
        sites = [s for c in backlog["clusters"] for s in c["sites"]]
        assert {s["id"] for s in sites} == {"EXT-3", "EXT-4"}

        out = capsys.readouterr().out
        assert ("2 dark item(s) routed to the witness backlog — not "
                "validated; --include-dark to override") in out
        # Honest import count excludes the routed rows.
        assert "Pre-existing findings: 2 from findings-graded.json" in out
        marker = load_json(tmp_path / "findings-import.json")
        assert marker["imported"] == 2
        assert marker["dark_routed"] == 2

    def test_include_dark_restores_candidacy(self, tmp_path, capsys):
        mod = _load_helper()
        src = tmp_path / "findings-graded.json"
        src.write_text(json.dumps({"findings": [
            _graded("EXT-1", "finding"),
            _graded("EXT-3", "dark"),
        ]}))
        dest = tmp_path / "findings.json"
        mod._import_findings_file(src, dest, target="/t",
                                  include_dark=True)
        saved = load_json(dest)
        # Opt-in restores the pre-policy behaviour: every row is a
        # stage-A candidate, dark grade preserved as source_status.
        assert len(saved["findings"]) == 2
        assert any(f.get("source_status") == "dark"
                   for f in saved["findings"])
        assert not (tmp_path / "witness-backlog.json").exists()
        out = capsys.readouterr().out
        assert "1 dark item(s) included in stage-A candidacy" in out
        assert "Pre-existing findings: 2 from findings-graded.json" in out
        marker = load_json(tmp_path / "findings-import.json")
        assert marker["dark_routed"] == 0

    def test_audit_status_shape_detected(self, tmp_path):
        # validate-selection.json rows carry audit_status="dark" with a
        # pipeline-entry status, not status="dark".
        mod = _load_helper()
        src = tmp_path / "selection.json"
        src.write_text(json.dumps({"findings": [
            _graded("FIND-001", "pending", audit_status="dark",
                    needs_validation=True),
            _graded("FIND-002", "pending"),
        ]}))
        dest = tmp_path / "findings.json"
        mod._import_findings_file(src, dest, target="/t")
        saved = load_json(dest)
        assert len(saved["findings"]) == 1
        backlog = load_json(tmp_path / "witness-backlog.json")
        assert backlog["total"] == 1

    def test_no_dark_rows_no_backlog(self, tmp_path):
        mod = _load_helper()
        src = tmp_path / "scan.json"
        src.write_text(json.dumps([_finding("FIND-1")]))
        dest = tmp_path / "findings.json"
        mod._import_findings_file(src, dest, target="/t")
        assert not (tmp_path / "witness-backlog.json").exists()
        saved = load_json(dest)
        assert len(saved["findings"]) == 1

    def test_cluster_site_listing_capped_counts_exact(self, tmp_path):
        mod = _load_helper()
        cap = mod._BACKLOG_SITES_PER_CLUSTER
        rows = [_graded(f"EXT-{i}", "dark", function=f"fn{i}")
                for i in range(cap + 5)]
        src = tmp_path / "findings-graded.json"
        src.write_text(json.dumps({"findings": rows}))
        mod._import_findings_file(src, tmp_path / "findings.json",
                                  target="/t")
        backlog = load_json(tmp_path / "witness-backlog.json")
        cluster = backlog["clusters"][0]
        assert cluster["count"] == cap + 5      # counts stay honest
        assert len(cluster["sites"]) == cap     # listing bounded
        assert cluster["sites_truncated"] is True


class TestImportReadjudicationCrossCheck:
    """The --findings import cross-checks incoming rows against
    disproofs already recorded in the run dir BEFORE overwriting them
    — the drop behaviour is unchanged, the contradiction is queued."""

    def test_contradiction_queued_and_overwrite_unchanged(
            self, tmp_path, capsys):
        mod = _load_helper()
        dest = tmp_path / "findings.json"
        dest.write_text(json.dumps({"findings": [{
            "id": "FIND-1",
            "file": "a.c",
            "function": "add",
            "line": 3,
            "vuln_type": "buffer_overflow",
            "status": "disproven",
            "disproved_because": {
                "conclusion": "bounded by caller",
                "would_reconsider_if": "a caller passes unchecked input",
            },
        }]}))
        src = tmp_path / "rescan.json"
        src.write_text(json.dumps([_finding("SCAN-1")]))
        mod._import_findings_file(src, dest, target="/t")

        queue = (tmp_path / "readjudication-queue.jsonl").read_text()
        records = [json.loads(line) for line in queue.splitlines()]
        assert len(records) == 1
        rec = records[0]
        assert rec["action"] == "queued"
        assert rec["site"] == {"file": "a.c", "function": "add", "line": 3}
        assert rec["disproof"]["would_reconsider_if"] == (
            "a caller passes unchecked input")
        # Overwrite behaviour unchanged: the import replaced dest with
        # the incoming container (id normalised as ever, original kept
        # as source_id); nothing was auto-overturned or kept.
        saved = load_json(dest)
        assert [f.get("source_id") for f in saved["findings"]] == ["SCAN-1"]
        # The queue record carries the producer's ORIGINAL id — the
        # cross-check ran before normalisation.
        assert rec["new_claim"]["id"] == "SCAN-1"
        out = capsys.readouterr().out
        assert ("1 incoming finding(s) contradict recorded disproofs"
                in out)
        assert "nothing auto-overturned" in out

    def test_no_prior_disproofs_no_queue(self, tmp_path):
        mod = _load_helper()
        dest = tmp_path / "findings.json"
        src = tmp_path / "scan.json"
        src.write_text(json.dumps([_finding("SCAN-1")]))
        mod._import_findings_file(src, dest, target="/t")
        assert not (tmp_path / "readjudication-queue.jsonl").exists()

    def test_incoming_disproof_agreement_not_queued(self, tmp_path):
        mod = _load_helper()
        dest = tmp_path / "findings.json"
        dest.write_text(json.dumps({"findings": [
            _finding("FIND-1", status="disproven"),
        ]}))
        src = tmp_path / "rescan.json"
        src.write_text(json.dumps([_finding("SCAN-1",
                                            status="false_positive")]))
        mod._import_findings_file(src, dest, target="/t")
        assert not (tmp_path / "readjudication-queue.jsonl").exists()

    def test_reimport_refreshes_queue(self, tmp_path):
        # Fresh-write semantics: a second import over a now-clean prior
        # container clears the stale queue instead of appending.
        mod = _load_helper()
        dest = tmp_path / "findings.json"
        dest.write_text(json.dumps({"findings": [
            _finding("FIND-1", status="disproven"),
        ]}))
        src = tmp_path / "rescan.json"
        src.write_text(json.dumps([_finding("SCAN-1")]))
        mod._import_findings_file(src, dest, target="/t")
        assert (tmp_path / "readjudication-queue.jsonl").exists()
        # Second import: prior container (just written) has no
        # disproofs any more.
        mod._import_findings_file(src, dest, target="/t")
        assert not (tmp_path / "readjudication-queue.jsonl").exists()


class TestWitnessBacklogStaleness:
    """The backlog must not outlive its inputs: a shared --out
    re-import with no routed rows (or with --include-dark) removes the
    previous import's artifact — otherwise the report renders a
    phantom routed count the fresh marker contradicts. Two-direction:
    routed rows write it, non-routing imports clear it."""

    def _import(self, mod, tmp_path, rows, **kw):
        src = tmp_path / "in.json"
        src.write_text(json.dumps({"findings": rows}))
        mod._import_findings_file(src, tmp_path / "findings.json",
                                  target="/t", **kw)

    def test_zero_dark_reimport_clears_stale_backlog(self, tmp_path):
        mod = _load_helper()
        self._import(mod, tmp_path, [_graded("EXT-1", "dark")])
        assert (tmp_path / "witness-backlog.json").exists()
        # Re-import into the SAME --out with no dark rows.
        self._import(mod, tmp_path, [_graded("EXT-2", "finding")])
        assert not (tmp_path / "witness-backlog.json").exists()
        marker = load_json(tmp_path / "findings-import.json")
        assert marker["dark_routed"] == 0

    def test_include_dark_reimport_clears_stale_backlog(self, tmp_path):
        mod = _load_helper()
        self._import(mod, tmp_path, [_graded("EXT-1", "dark")])
        assert (tmp_path / "witness-backlog.json").exists()
        self._import(mod, tmp_path, [_graded("EXT-1", "dark")],
                     include_dark=True)
        assert not (tmp_path / "witness-backlog.json").exists()

    def test_symlinked_backlog_not_operated_through(self, tmp_path,
                                                    capsys):
        mod = _load_helper()
        victim = tmp_path / "victim.txt"
        victim.write_text("keep")
        (tmp_path / "witness-backlog.json").symlink_to(victim)
        self._import(mod, tmp_path, [_graded("EXT-1", "finding")])
        # Stale-removal must not unlink through (or remove) a planted
        # special silently — it is left in place with a loud note.
        assert victim.read_text() == "keep"
        assert (tmp_path / "witness-backlog.json").is_symlink()
        assert "not a regular file" in capsys.readouterr().err


class TestWitnessBacklogFieldBounds:
    """Backlog fields derive from hostile import rows — every stored
    field is typed/capped and every listing bounded with exact
    counts."""

    def test_junk_line_and_class_capped(self, tmp_path):
        mod = _load_helper()
        src = tmp_path / "in.json"
        src.write_text(json.dumps({"findings": [
            _graded("EXT-1", "dark", line={"evil": "x" * 100},
                    cwe_id="CWE-787" + "Z" * 500),
        ]}))
        mod._import_findings_file(src, tmp_path / "findings.json",
                                  target="/t")
        backlog = load_json(tmp_path / "witness-backlog.json")
        cluster = backlog["clusters"][0]
        assert len(cluster["class"]) <= 100
        assert cluster["sites"][0]["line"] == 0  # dict-shaped → unknown

    def test_cluster_listing_bounded_total_exact(self, tmp_path):
        mod = _load_helper()
        cap = mod._BACKLOG_CLUSTER_CAP
        rows = [_graded(f"EXT-{i}", "dark", cwe_id=f"CWE-{i}")
                for i in range(cap + 5)]
        src = tmp_path / "in.json"
        src.write_text(json.dumps({"findings": rows}))
        mod._import_findings_file(src, tmp_path / "findings.json",
                                  target="/t")
        backlog = load_json(tmp_path / "witness-backlog.json")
        assert backlog["total"] == cap + 5          # counts stay honest
        assert len(backlog["clusters"]) == cap      # listing bounded
        assert backlog["clusters_truncated"] is True
        assert backlog["cluster_classes_total"] == cap + 5


class TestMajorityDarkHint:

    def test_majority_dark_import_gets_the_note(self, tmp_path, capsys):
        mod = _load_helper()
        src = tmp_path / "in.json"
        src.write_text(json.dumps({"findings": [
            _graded("EXT-1", "dark"),
            _graded("EXT-2", "dark", function="g"),
            _graded("EXT-3", "finding"),
        ]}))
        mod._import_findings_file(src, tmp_path / "findings.json",
                                  target="/t")
        out = capsys.readouterr().out
        assert "majority of the import is dark" in out
        assert "--include-dark" in out

    def test_minority_dark_import_stays_quiet(self, tmp_path, capsys):
        mod = _load_helper()
        src = tmp_path / "in.json"
        src.write_text(json.dumps({"findings": [
            _graded("EXT-1", "dark"),
            _graded("EXT-2", "finding"),
            _graded("EXT-3", "finding", function="g"),
        ]}))
        mod._import_findings_file(src, tmp_path / "findings.json",
                                  target="/t")
        out = capsys.readouterr().out
        assert "routed to the witness backlog" in out  # count still prints
        assert "majority of the import is dark" not in out
