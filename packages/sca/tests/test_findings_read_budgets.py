"""Findings.json read budgets: self-produced vs operator-steered.

``run_sca`` re-reads the findings.json it JUST wrote (SARIF emission
consumes the canonical row shape). That read is of a self-produced
artifact — its size is the pipeline's own legitimate output, and big
targets write 75-202 MB findings.json — so it takes
``kinds.MAX_SELF_FINDINGS_BYTES``, not the 64 MiB steered-path
budget ``kinds.MAX_FINDINGS_BYTES`` that guards reads of
operator-supplied paths (--findings / --baseline / another run's
directory). These tests pin the policy split in BOTH directions for
each budget: the self path accepts over-64-MiB output and still
refuses past its own bound; the steered path keeps refusing at
64 MiB.

The self-produced class covers every same-process read-back of the
just-written findings.json, not only run_sca's own SARIF re-read:
the CLI threshold gate (--fail-on-*), the baseline-delta current-rows
read, and the cross-tool link read (api.analyse) each get a per-site
test below, paired with the nearest steered read in the same function
where one exists (the --baseline read).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

import pytest

from core.json import JsonCache
from core.source.gated import ReadBudgetExceededError
from packages.sca.kinds import MAX_FINDINGS_BYTES, MAX_SELF_FINDINGS_BYTES
from packages.sca.pipeline import RunOptions, run_sca
from packages.sca.tests.test_pipeline import StubHttp

# Largest self-produced findings.json observed on a real target
# (superset-0.36: 202,145,302 bytes). The self budget must keep
# accommodating it — see the lower-bound pin below.
_LARGEST_OBSERVED_SELF_BYTES = 202_145_302


# ---------------------------------------------------------------------------
# Harness: hermetic run_sca whose findings.json is inflated on write
# ---------------------------------------------------------------------------

def _padding_writer(
    real_writer: Callable[..., int],
    pad_to_bytes: int | None,
    truncate_to_bytes: int | None = None,
) -> Callable[..., int]:
    """Wrap the real findings writer to inflate the written file.

    ``pad_to_bytes`` appends one valid padding row whose ``detail``
    string brings the file past the requested size (content is
    parsed, so it must stay valid JSON). ``truncate_to_bytes``
    sparse-extends the file instead — the budget refusal happens at
    the fstat gate before any read, so a sparse tail exercises the
    bound without disk or parse cost.
    """

    def wrapped(path: Path, **kw: Any) -> int:
        n = real_writer(path, **kw)
        if pad_to_bytes is not None:
            rows = json.loads(path.read_text(encoding="utf-8"))
            rows.append({
                "finding_id": "sca:scan_health:test_padding",
                "vuln_type": "sca:scan_health:test_padding",
                "severity": "info",
                "detail": "x" * pad_to_bytes,
            })
            path.write_text(json.dumps(rows), encoding="utf-8")
        if truncate_to_bytes is not None:
            os.truncate(path, truncate_to_bytes)
        return n
    return wrapped


def _run_padded_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    pad_to_bytes: int | None,
    truncate_to_bytes: int | None = None,
) -> Any:
    """Hermetic run_sca over a one-dep repo with an inflated
    findings.json — the exact frame the SCA stress lane failed in."""
    import packages.sca.pipeline as pl

    target = tmp_path / "repo"
    target.mkdir()
    (target / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        '<dependencies><dependency>'
        '<groupId>org.apache.logging.log4j</groupId>'
        '<artifactId>log4j-core</artifactId>'
        '<version>2.14.1</version>'
        '</dependency></dependencies></project>',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        pl, "write_findings_json",
        _padding_writer(
            pl.write_findings_json, pad_to_bytes, truncate_to_bytes,
        ),
    )
    return run_sca(
        target, tmp_path / "out",
        RunOptions(enable_llm_review=False, enable_triage=False),
        http=StubHttp(), cache=JsonCache(root=tmp_path / "cache"),
    )


# ---------------------------------------------------------------------------
# Self-produced path: accepts past 64 MiB ...
# ---------------------------------------------------------------------------

def test_self_reread_accepts_over_64mib_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_sca must not refuse its OWN findings.json at the steered
    64 MiB budget (regression: big-target scans died at the SARIF
    re-read, their final step)."""
    result = _run_padded_scan(
        tmp_path, monkeypatch, pad_to_bytes=MAX_FINDINGS_BYTES + 1,
    )
    assert result.findings_path.stat().st_size > MAX_FINDINGS_BYTES
    assert result.sarif_path.exists()


@pytest.mark.slow
def test_self_reread_accepts_superset_scale_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full-size variant at the largest observed real output
    (202 MB, superset-0.36) — actually parsed, not sparse."""
    result = _run_padded_scan(
        tmp_path, monkeypatch, pad_to_bytes=_LARGEST_OBSERVED_SELF_BYTES,
    )
    assert (result.findings_path.stat().st_size
            > _LARGEST_OBSERVED_SELF_BYTES)
    assert result.sarif_path.exists()


# ---------------------------------------------------------------------------
# ... and still refuses past its own bound (raised, not removed)
# ---------------------------------------------------------------------------

def test_self_reread_refuses_past_self_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A findings.json past MAX_SELF_FINDINGS_BYTES signals a
    row-explosion bug; the read must refuse loudly, not OOM. Sparse
    tail: the refusal fires at the fstat gate, before any read."""
    with pytest.raises(ReadBudgetExceededError, match="exceeds max_bytes"):
        _run_padded_scan(
            tmp_path, monkeypatch,
            pad_to_bytes=None,
            truncate_to_bytes=MAX_SELF_FINDINGS_BYTES + 1,
        )


# ---------------------------------------------------------------------------
# Steered path keeps the 64 MiB budget
# ---------------------------------------------------------------------------

def test_operator_supplied_findings_read_keeps_64mib_cap(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """The operator-steered --findings read must keep refusing at the
    steered budget — the self-produced relaxation must not leak to
    reads of arbitrary operator-named locations."""
    import argparse

    from packages.sca.update import _load_findings

    big = tmp_path / "findings.json"
    big.touch()
    os.truncate(big, MAX_FINDINGS_BYTES + 1)

    args = argparse.Namespace(findings=str(big))
    assert _load_findings(args) is None
    err = capsys.readouterr().err
    assert "exceeds max_bytes" in err


def test_operator_supplied_findings_read_under_cap_still_loads(
    tmp_path: Path,
) -> None:
    """Two-direction check on the steered budget: an in-budget
    operator-supplied findings.json still loads."""
    import argparse

    from packages.sca.update import _load_findings

    small = tmp_path / "findings.json"
    small.write_text("[]", encoding="utf-8")
    args = argparse.Namespace(findings=str(small))
    assert _load_findings(args) == []


# ---------------------------------------------------------------------------
# The other same-process read-back consumers of the just-written
# findings.json (threshold gate, baseline delta, cross-tool link)
# ---------------------------------------------------------------------------

def _write_big_findings(
    path: Path,
    *,
    pad_to_bytes: int,
    rows: list[dict[str, Any]] | None = None,
) -> None:
    """Write a VALID findings.json list padded past ``pad_to_bytes``
    with one parsed padding row — every consumer under test
    whole-document json-parses the file, so it must stay well-formed
    (sparse tails are only good for fstat-gate refusal probes)."""
    all_rows = list(rows or [])
    all_rows.append({
        "finding_id": "sca:scan_health:test_padding",
        "vuln_type": "sca:scan_health:test_padding",
        "severity": "info",
        "detail": "x" * pad_to_bytes,
    })
    path.write_text(json.dumps(all_rows), encoding="utf-8")


def test_cli_threshold_gate_accepts_over_64mib_self_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The --fail-on-* threshold gate re-reads the findings.json the
    in-process run_sca just wrote; at the steered budget a COMPLETED
    big-target scan exited 3 there ("cannot read findings for
    threshold check"). --out steers only the directory name — the
    read is reachable only after run_sca succeeded, so the content
    is self-produced."""
    from packages.sca import cli
    from packages.sca.pipeline import RunResult

    target = tmp_path / "repo"
    target.mkdir()
    out = tmp_path / "out"

    def fake_run_sca(*, target: Path, output_dir: Path, options: Any) -> Any:
        _write_big_findings(
            output_dir / "findings.json",
            pad_to_bytes=MAX_FINDINGS_BYTES + 1,
        )
        return RunResult(
            target=target, output_dir=output_dir,
            findings_path=output_dir / "findings.json",
            report_path=output_dir / "report.md",
            sbom_path=output_dir / "sbom.cdx.json",
            sarif_path=output_dir / "findings.sarif",
            deps_analysed=0, vuln_findings=0, hygiene_findings=0,
            supply_chain_findings=0, suppressed_findings=0,
            in_kev=0, cache_hits=0, cache_misses=0,
        )

    monkeypatch.setattr(cli, "run_sca", fake_run_sca)
    rc = cli.main([str(target), "--out", str(out), "--offline",
                   "--fail-on-severity", "critical"])
    assert (out / "findings.json").stat().st_size > MAX_FINDINGS_BYTES
    assert rc == 0  # gate read the rows and evaluated them: no crits


def test_baseline_delta_current_read_takes_self_budget(
    tmp_path: Path,
) -> None:
    """_emit_baseline_delta's current-rows read is of the findings.json
    the in-process run_sca just wrote; at the steered budget big-target
    --baseline runs silently lost baseline-delta.json. The in-budget
    --baseline (steered) read loading here is the steered budget's
    accept direction for this function."""
    from packages.sca.cli import _emit_baseline_delta

    out = tmp_path / "out"
    out.mkdir()
    current = out / "findings.json"
    _write_big_findings(current, pad_to_bytes=MAX_FINDINGS_BYTES + 1)
    baseline = tmp_path / "baseline.json"
    baseline.write_text("[]", encoding="utf-8")

    _emit_baseline_delta(
        baseline_path=baseline, current_findings=current, output_dir=out,
    )
    assert (out / "baseline-delta.json").exists()


def test_baseline_delta_baseline_read_keeps_64mib_cap(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """The steered branch in the SAME function must keep refusing:
    --baseline points wherever the operator says, so the self-produced
    relaxation of the sibling current-rows read must not leak to it."""
    import logging

    from packages.sca.cli import _emit_baseline_delta

    out = tmp_path / "out"
    out.mkdir()
    current = out / "findings.json"
    current.write_text("[]", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.touch()
    os.truncate(baseline, MAX_FINDINGS_BYTES + 1)  # fstat-gate probe

    with caplog.at_level(logging.WARNING, logger="packages.sca.cli"):
        _emit_baseline_delta(
            baseline_path=baseline, current_findings=current,
            output_dir=out,
        )
    assert not (out / "baseline-delta.json").exists()
    assert "exceeds max_bytes" in caplog.text


def test_cross_tool_link_reads_self_findings_over_64mib(
    tmp_path: Path,
) -> None:
    """cross_tool._load_findings reads RunResult.findings_path from
    the in-process run_sca that just wrote it (api.analyse is the only
    production caller); at the steered budget, oversize came back as
    None and every cross-tool link was silently dropped."""
    from packages.sca.cross_tool import link_related_findings

    findings_path = tmp_path / "findings.json"
    _write_big_findings(
        findings_path,
        pad_to_bytes=MAX_FINDINGS_BYTES + 1,
        rows=[{
            "finding_id": "sca:vuln:PyPI:requests:2.31.0:CVE-2024-1234",
            "sca": {"advisory": {"id": "CVE-2024-1234", "aliases": []},
                    "all_advisories": []},
            "related_findings": [],
        }],
    )
    assert findings_path.stat().st_size > MAX_FINDINGS_BYTES

    sarif_dir = tmp_path / "semgrep"
    sarif_dir.mkdir()
    (sarif_dir / "combined.sarif").write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep", "rules": []}},
            "results": [{
                "ruleId": "py/sqli",
                "message": {"text": "SQL injection via CVE-2024-1234"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "db.py"},
                        "region": {"startLine": 10},
                    },
                }],
            }],
        }],
    }), encoding="utf-8")

    added = link_related_findings(findings_path, [sarif_dir])
    assert added == 1
    updated = json.loads(findings_path.read_text(encoding="utf-8"))
    assert any(r.startswith("sarif:")
               for r in updated[0]["related_findings"])


# ---------------------------------------------------------------------------
# Constant pins (churn-prone limits: both directions)
# ---------------------------------------------------------------------------

def test_self_budget_accommodates_largest_observed_output() -> None:
    """Lower direction: shrinking MAX_SELF_FINDINGS_BYTES below real
    observed output re-breaks big-target scans at their final step."""
    assert MAX_SELF_FINDINGS_BYTES >= 2 * _LARGEST_OBSERVED_SELF_BYTES


def test_self_budget_stays_bounded() -> None:
    """Upper direction: the whole-document parse pins several times
    the file size in memory — past ~512 MiB the parse peak endangers
    the host, so growth beyond that needs a storage-format change,
    not a bigger constant (see kinds.py)."""
    assert MAX_SELF_FINDINGS_BYTES <= 1024 * 1024 * 1024


def test_steered_budget_unchanged_by_self_split() -> None:
    """The steered-path budget is the untrusted-read protection; the
    self-produced split must not move it in either direction."""
    assert MAX_FINDINGS_BYTES == 64 * 1024 * 1024
    assert MAX_FINDINGS_BYTES < MAX_SELF_FINDINGS_BYTES
