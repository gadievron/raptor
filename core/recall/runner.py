"""Execute a detection profile against a recall target and collect findings.

The runner drives the pipeline exactly the way an operator does —
``python3 raptor.py <mode> --repo <target>`` as a subprocess — and
locates the run's artifacts through the documented ``OUTPUT_DIR=``
sentinel. It never reaches into producer internals: what the operator
would get is what gets scored.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from core.sarif.parser import parse_sarif_findings

from core.recall.manifest import PROFILES, RecallManifest

logger = logging.getLogger(__name__)

_OUTPUT_DIR_RE = re.compile(r"^OUTPUT_DIR=(.+)$", re.MULTILINE)

#: Ceiling for one pipeline run. Benchmark targets build + scan well
#: inside this; a hung run should fail the measurement, not the host.
DEFAULT_TIMEOUT_S = 4 * 3600


class RunnerError(RuntimeError):
    """The pipeline run could not produce scoreable output."""


def verify_pinned_clone(manifest: RecallManifest,
                        repo_root: Path) -> Path:
    """Resolve and sha-verify the target clone; offline-friendly errors.

    Labels are written against an exact sha — scoring any other tree
    silently invalidates them, so this is a hard gate (mirrors the
    dataflow corpus setup contract).
    """
    target = Path(manifest.local_path)
    if not target.is_absolute():
        target = repo_root / target
    if not target.is_dir():
        raise RunnerError(
            f"target clone missing: {target}\n"
            f"Acquire it (offline hosts: from a connected machine):\n"
            f"  git clone {manifest.repo_url} {target}\n"
            f"  git -C {target} fetch --depth 1 origin "
            f"{manifest.pinned_sha}\n"
            f"  git -C {target} checkout {manifest.pinned_sha}"
        )
    try:
        proc = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RunnerError(f"cannot sha-verify {target}: {exc}") from exc
    head = proc.stdout.strip().lower()
    if proc.returncode != 0 or not head:
        raise RunnerError(
            f"cannot sha-verify {target}: {proc.stderr.strip()}")
    if not head.startswith(manifest.pinned_sha):
        raise RunnerError(
            f"{target} is at {head[:12]}, manifest pins "
            f"{manifest.pinned_sha[:12]} — labels are invalid against "
            "this tree; re-checkout the pinned sha")
    return target


def build_pipeline_argv(manifest: RecallManifest, target: Path,
                        repo_root: Path,
                        pipeline_out: Path | None = None) -> list[str]:
    """Argv for the manifest's detection profile (operator surface).

    ``pipeline_out`` pins the run's output directory. Without it the
    lifecycle resolves the ACTIVE PROJECT when the target path matches
    — a recall measurement would then attach to (and pollute) whatever
    project the operator happens to have active. Measurement runs must
    be hermetic.
    """
    raptor_py = repo_root / "raptor.py"
    if manifest.profile == "scan":
        argv = [sys.executable, str(raptor_py), "scan",
                "--repo", str(target)]
    elif manifest.profile == "scan-codeql":
        argv = [sys.executable, str(raptor_py), "scan",
                "--repo", str(target), "--codeql"]
    elif manifest.profile == "agentic":
        argv = [sys.executable, str(raptor_py), "agentic",
                "--repo", str(target)]
    else:  # pragma: no cover - manifest validation refuses others
        raise RunnerError(f"unknown profile {manifest.profile!r}")
    if pipeline_out is not None:
        argv += ["--out", str(pipeline_out)]
    if manifest.build_command:
        argv += ["--build-command", manifest.build_command]
        # The CodeQL agent refuses --build-command without exactly one
        # --languages; the manifest's language is the authority.
        if manifest.profile == "scan-codeql" and manifest.language:
            argv += ["--languages", manifest.language]
    return argv


def run_pipeline(manifest: RecallManifest, target: Path, repo_root: Path,
                 log_path: Path,
                 timeout_s: int = DEFAULT_TIMEOUT_S) -> Path:
    """Run the profile; return the pipeline's output dir.

    Full pipeline stdout/stderr goes to ``log_path`` (the sentinel is
    parsed from the captured stream, so operator visibility survives
    in the log even though the harness consumes the output).
    """
    profile_meta = PROFILES[manifest.profile]
    if profile_meta["uses_llm"]:
        logger.warning(
            "profile %s uses LLM analysis — every expected finding "
            "costs tokens; use scan/scan-codeql for free recall "
            "baselines", manifest.profile)

    pipeline_out = log_path.parent / "pipeline-run"
    argv = build_pipeline_argv(manifest, target, repo_root,
                               pipeline_out=pipeline_out)
    logger.info("running: %s", " ".join(argv))
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, cwd=str(repo_root),
            timeout=timeout_s, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RunnerError(
            f"pipeline timed out after {timeout_s}s") from exc

    log_path.write_text(
        (proc.stdout or "") + "\n--- stderr ---\n" + (proc.stderr or ""),
        encoding="utf-8")

    m = _OUTPUT_DIR_RE.search(proc.stdout or "")
    sentinel_dir = Path(m.group(1).strip()) if m else None

    # The artifacts land in the --out dir we pinned; the lifecycle's
    # OUTPUT_DIR sentinel can point elsewhere (raptor.py resolves the
    # lifecycle dir before honouring a forwarded --out — it never
    # passes it to get_output_dir(explicit_out=...)). Score where the
    # artifacts actually are; the sentinel is only a fallback.
    if pipeline_out.is_dir() and any(pipeline_out.glob("*.sarif")):
        if sentinel_dir is not None and sentinel_dir != pipeline_out:
            logger.warning(
                "OUTPUT_DIR sentinel (%s) diverges from the pinned "
                "--out dir; scoring the pinned dir", sentinel_dir)
        out_dir = pipeline_out
    elif sentinel_dir is not None:
        out_dir = sentinel_dir
    else:
        raise RunnerError(
            f"pipeline produced no SARIFs in {pipeline_out} and "
            f"printed no OUTPUT_DIR sentinel "
            f"(exit {proc.returncode}); full log: {log_path}")
    if proc.returncode != 0:
        # A partially-failed run may still hold SARIFs; the caller
        # decides, but the failure must be visible.
        logger.warning("pipeline exited %d — scoring whatever %s holds "
                       "(log: %s)", proc.returncode, out_dir, log_path)
    if not out_dir.is_dir():
        raise RunnerError(
            f"OUTPUT_DIR {out_dir} does not exist; log: {log_path}")
    return out_dir


#: Mirror of core.sarif.parser.load_sarif's size guard. Per-tool files
#: above this were dropped from combined.sarif by the merge (with a
#: pipeline ERROR); a ground-truth measurement must not silently
#: inherit that loss, so they are re-read here via chunking.
_SARIF_CHUNK_THRESHOLD = 100 * 1024 * 1024
#: Absolute ceiling for the chunker itself. A measurement artifact
#: above this is refused loudly rather than parsed — the recall run
#: fails visibly instead of consuming unbounded memory.
_SARIF_CHUNK_CAP = 512 * 1024 * 1024
#: Target chunk size, safely under the parser's guard.
_SARIF_CHUNK_TARGET = 80 * 1024 * 1024


def _chunk_oversized_sarif(path: Path, tmpdir: Path) -> list[Path]:
    """Split an over-guard SARIF into valid parseable chunk files.

    Each chunk copies the run header (tool/driver/rules, URI bases)
    and carries an even slice of ``results``, so the unmodified
    parser — with its size guard intact — reads every finding. The
    input is this harness's own pipeline artifact, not repo content;
    files above the hard cap are refused with an error.
    """
    size = path.stat().st_size
    if size > _SARIF_CHUNK_CAP:
        logger.error(
            "SARIF %s is %d MiB — above the %d MiB measurement cap; "
            "its findings are NOT collected (recall will undercount)",
            path, size // (1024 * 1024),
            _SARIF_CHUNK_CAP // (1024 * 1024))
        return []
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    runs = doc.get("runs")
    if not isinstance(runs, list):
        return []
    chunks: list[Path] = []
    for ri, run in enumerate(runs):
        results = run.get("results")
        if not isinstance(results, list) or not results:
            continue
        header = {k: v for k, v in run.items() if k != "results"}
        # The header rides in EVERY chunk and can itself be huge —
        # CodeQL's rules metadata plus the per-file artifacts index
        # reached ~53 MiB live. Budget for it explicitly, and shed the
        # artifacts index when it starves the budget: results carry
        # inline artifactLocation.uri values, which is what the parser
        # reads, so the run-level index is droppable for chunking.
        def _base_bytes() -> int:
            probe = dict(doc)
            probe["runs"] = [dict(header, results=[])]
            return len(json.dumps(probe))

        slack = max(1024, _SARIF_CHUNK_TARGET // 16)
        budget = _SARIF_CHUNK_TARGET - _base_bytes() - slack
        if budget <= 0 and "artifacts" in header:
            logger.warning(
                "SARIF %s: run %d header alone exceeds the chunk "
                "target; dropping the run-level artifacts index "
                "(results carry inline URIs)", path.name, ri)
            header.pop("artifacts")
            budget = _SARIF_CHUNK_TARGET - _base_bytes() - slack
        if budget <= 0:
            logger.error(
                "SARIF %s: run %d header cannot fit under the parser "
                "guard even without artifacts; findings from this run "
                "are NOT collected", path, ri)
            continue
        # Slice by SERIALIZED size, not by count: result sizes vary by
        # orders of magnitude (path-problem results carry codeFlows),
        # so an even count split can still produce an over-guard chunk
        # — observed live: 1 of 3 count-sliced chunks at 153 MiB.
        batch: list[Any] = []
        batch_bytes = 0
        ci = 0

        def _flush() -> None:
            nonlocal batch, batch_bytes, ci
            if not batch:
                return
            chunk_doc = dict(doc)
            chunk_doc["runs"] = [dict(header, results=batch)]
            out = tmpdir / f"{path.stem}.run{ri}.{ci:03d}.sarif"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(chunk_doc, f)
            chunks.append(out)
            batch, batch_bytes, ci = [], 0, ci + 1

        for res in results:
            res_bytes = len(json.dumps(res))
            if batch and batch_bytes + res_bytes > budget:
                _flush()
            batch.append(res)
            batch_bytes += res_bytes
        _flush()
    logger.warning(
        "SARIF %s (%d MiB) exceeded the parser guard; re-read as %d "
        "chunk(s) so the measurement does not inherit the merge's drop",
        path.name, size // (1024 * 1024), len(chunks))
    return chunks


def collect_findings(out_dir: Path,
                     source_root: Path | None = None) -> list[dict[str, Any]]:
    """Parse every produced finding from a pipeline output dir.

    Prefers ``combined.sarif`` (already tool-merged); otherwise parses
    every per-tool ``*.sarif``. Per-tool files above the parser's size
    guard were dropped from the merged view (pipeline ERROR) — those
    are additionally re-read via chunking so the measurement never
    silently undercounts a tool. Deduplicates on
    (tool, rule, file, startLine) so a finding present in both a
    per-tool file and a merged view counts once.
    """
    combined = out_dir / "combined.sarif"
    per_tool = sorted(p for p in out_dir.glob("*.sarif") if p != combined)
    sarifs = [combined] if combined.is_file() else list(per_tool)
    oversized = [p for p in per_tool
                 if p.stat().st_size > _SARIF_CHUNK_THRESHOLD]
    findings: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="recall-sarif-chunks-") as td:
        for path in oversized:
            if path in sarifs:
                sarifs.remove(path)
            sarifs.extend(_chunk_oversized_sarif(path, Path(td)))
        for path in sarifs:
            findings.extend(
                parse_sarif_findings(path, source_root=source_root))

    seen: set[tuple] = set()
    deduped: list[dict[str, Any]] = []
    for f in findings:
        key = (f.get("tool"), f.get("rule_id"), f.get("file"),
               f.get("startLine"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    logger.info("collected %d findings (%d after dedup) from %s",
                len(findings), len(deduped), out_dir)
    return deduped
