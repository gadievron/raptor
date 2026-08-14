"""Run the /audit calibration corpus and score results.

Usage:
    python3 -m core.audit.corpus.run_corpus [options]

Steps:
    1. Load labels from core/audit/corpus/labels/
    2. Fetch pinned sources if missing (--fetch)
    3. Build checklist + context map for each target
    4. Run /audit's orchestrator against the labeled functions
    5. Score each outcome against ground truth
    6. Emit JSON + detailed summary with cost, duration, per-function verdicts
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

CORPUS_DIR = Path(__file__).parent
LABELS_DIR = CORPUS_DIR / "labels"
FIXTURES_DIR = Path("out/audit-corpus-fixtures")


def _corpus_project_context(run_tag: str):
    """Context manager: create a temporary project, restore the previous one on exit."""
    from contextlib import contextmanager

    @contextmanager
    def _ctx():
        from core.project.project import ProjectManager

        mgr = ProjectManager()
        prev_active = mgr.get_active()
        project_name = f"corpus-{run_tag}"

        try:
            mgr.create(
                project_name,
                target="/tmp",
                description=f"Corpus measurement run {run_tag}",
            )
        except ValueError:
            pass
        mgr.set_active(project_name)

        try:
            yield project_name
        finally:
            if prev_active:
                mgr.set_active(prev_active)
            else:
                mgr.set_active(None)

    return _ctx()


def _is_hex_sha(ref: str) -> bool:
    return len(ref) >= 7 and all(c in "0123456789abcdef" for c in ref)


def _fetch_source(repo_key: str, sha: str) -> Path:
    """Fetch a pinned source tree.  Returns the local path."""
    dest = FIXTURES_DIR / repo_key
    from core.config import RaptorConfig
    safe_env = RaptorConfig.get_safe_env()
    if dest.is_dir():
        git_dir = dest / ".git"
        if not git_dir.exists():
            logger.info(
                "source %s present but not a git repo (tarball?), "
                "skipping SHA verification",
                repo_key,
            )
            return dest

        result = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=30, env=safe_env,
        )
        current = result.stdout.strip()

        # For tag/branch refs, resolve to commit hash for comparison
        if not _is_hex_sha(sha):
            verify = subprocess.run(
                ["git", "-C", str(dest), "rev-parse", sha],
                capture_output=True, text=True, timeout=30, env=safe_env,
            )
            if verify.returncode == 0 and verify.stdout.strip() == current:
                return dest
        elif current == sha:
            return dest

        logger.info("SHA mismatch for %s: %s != %s, re-fetching",
                     repo_key, current[:12], sha[:12])

        # Tags and branch names need 'git fetch origin tag <name>' syntax;
        # bare hex SHAs work with the direct form.
        if _is_hex_sha(sha):
            subprocess.run(
                ["git", "-C", str(dest), "fetch", "--depth", "1",
                 "origin", sha],
                check=True, capture_output=True, timeout=120, env=safe_env,
            )
        else:
            subprocess.run(
                ["git", "-C", str(dest), "fetch", "origin",
                 "tag", sha, "--depth", "1"],
                check=True, capture_output=True, timeout=120, env=safe_env,
            )

        subprocess.run(
            ["git", "-C", str(dest), "checkout", sha],
            check=True, capture_output=True, timeout=30, env=safe_env,
        )
        return dest

    logger.warning(
        "Source %s not found at %s. Run with --fetch or clone manually.",
        repo_key, dest,
    )
    return dest


def _resolve_source_dirs(
    labels: List[Any],
    *,
    do_fetch: bool = False,
) -> Dict[str, Path]:
    """Resolve and optionally fetch source directories for all labels."""
    repos: Dict[str, str] = {}
    for label in labels:
        key = label.source.repo
        if key not in repos:
            repos[key] = label.source.sha

    resolved = {}
    for key, sha in repos.items():
        if do_fetch:
            resolved[key] = _fetch_source(key, sha)
        else:
            dest = FIXTURES_DIR / key
            if not dest.is_dir():
                logger.warning("Source %s not found at %s", key, dest)
            resolved[key] = dest

    return resolved


QUICK_FILE_LIMIT = 5000
_SOURCE_EXTS = frozenset({
    ".c", ".h", ".py", ".go", ".rs", ".js", ".ts",
    ".java", ".cpp", ".cc", ".cxx", ".rb", ".swift",
})


def _count_source_files(path: Path, limit: int = QUICK_FILE_LIMIT + 1) -> int:
    """Quick source-file count, short-circuiting at *limit*."""
    count = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d not in (
                "vendor", "node_modules", "__pycache__", ".git",
            )
        ]
        for f in files:
            if Path(f).suffix in _SOURCE_EXTS:
                count += 1
                if count >= limit:
                    return count
    return count


def _build_excerpt_tree(
    labels: List[Any],
    source_dirs: Dict[str, Path],
) -> Dict[str, Path]:
    """Build minimal source trees containing only labelled files.

    Returns a mapping repo_key -> temp directory.  Caller must clean up.
    """
    by_repo: Dict[str, set] = {}
    for label in labels:
        by_repo.setdefault(label.source.repo, set()).add(label.source.file)

    excerpt_dirs: Dict[str, Path] = {}
    for repo_key, files in by_repo.items():
        src_dir = source_dirs.get(repo_key)
        if src_dir is None or not src_dir.is_dir():
            continue

        tmp = Path(tempfile.mkdtemp(prefix=f"corpus-excerpt-{repo_key}-"))
        copied = 0
        for rel_file in sorted(files):
            src = src_dir / rel_file
            dst = tmp / rel_file
            if src.is_file():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src), str(dst))
                copied += 1

        excerpt_dirs[repo_key] = tmp
        print(f"  Excerpt: {repo_key} — {copied} file(s)", flush=True)

    return excerpt_dirs


def _filter_quick_repos(
    labels: List[Any],
    source_dirs: Dict[str, Path],
) -> Tuple[List[Any], List[str]]:
    """Remove labels from repos exceeding QUICK_FILE_LIMIT.

    Returns (filtered_labels, skipped_repo_keys).
    """
    repo_ok: Dict[str, bool] = {}
    skipped: List[str] = []

    for label in labels:
        repo = label.source.repo
        if repo in repo_ok:
            continue
        src_dir = source_dirs.get(repo)
        if src_dir and src_dir.is_dir():
            count = _count_source_files(src_dir)
            repo_ok[repo] = count < QUICK_FILE_LIMIT
            if not repo_ok[repo]:
                n = sum(1 for lb in labels if lb.source.repo == repo)
                skipped.append(repo)
                print(
                    f"  Quick: skipping {repo} "
                    f"({count}+ source files, {n} labels)",
                    flush=True,
                )
        else:
            repo_ok[repo] = True

    kept = [lb for lb in labels if repo_ok.get(lb.source.repo, True)]
    return kept, skipped


def _verify_labels(
    labels: List[Any],
    source_dirs: Dict[str, Path],
) -> List[str]:
    """Verify that labeled functions exist in fetched sources."""
    errors = []
    for label in labels:
        src_dir = source_dirs.get(label.source.repo)
        if src_dir is None or not src_dir.is_dir():
            errors.append(f"{label.function_id}: source dir missing")
            continue
        src_file = src_dir / label.source.file
        if not src_file.is_file():
            errors.append(f"{label.function_id}: file not found: {src_file}")
    return errors


def _build_checklist(
    target_dir: Path,
    out_dir: Path,
) -> bool:
    """Build checklist for a target (mechanical, no LLM)."""
    checklist_path = out_dir / "checklist.json"
    if checklist_path.exists():
        return True

    print(f"  Building checklist for {target_dir.name}...", flush=True)
    try:
        from core.inventory import build_inventory

        build_inventory(str(target_dir), str(out_dir))
        return True
    except Exception as exc:
        print(f"  checklist build failed: {exc}", file=sys.stderr)
        return False



def _start_shared_joern(target_dirs: list[Path]):
    """Start a Joern server for the corpus run, if available."""
    try:
        from core.audit.joern_backend import (
            start_joern_server,
            target_has_c_sources,
            target_has_joern_sources,
        )
    except ImportError:
        return None
    for td in target_dirs:
        if target_has_c_sources(td) or target_has_joern_sources(td):
            srv = start_joern_server(td)
            if srv is not None:
                logger.info("shared Joern server started for corpus run")
                return srv
    return None


def _stop_shared_joern(srv):
    if srv is None:
        return
    try:
        from core.audit.joern_backend import stop_joern_server

        stop_joern_server(srv)
    except Exception:
        logger.debug("shared Joern server stop failed", exc_info=True)


def _load_inventoried_functions(audit_dir: Optional[Path]) -> set:
    """Return {(file, function_name)} for every function in the checklist."""
    if audit_dir is None:
        return set()
    ck_path = audit_dir / "checklist.json"
    if not ck_path.exists():
        return set()
    try:
        ck = json.loads(ck_path.read_text())
    except (json.JSONDecodeError, OSError):
        return set()
    result = set()
    for f in ck.get("files", []):
        fpath = f.get("path", "")
        for item in f.get("items", []):
            name = item.get("name", "")
            if name and not name.startswith("interstitial:"):
                result.add((fpath, name))
    return result


def _run_audit(
    labels: List[Any],
    source_dirs: Dict[str, Path],
    *,
    model: str = "",
    out_dir: Optional[Path] = None,
    full_source_dirs: Optional[Dict[str, Path]] = None,
    mode: Optional[str] = None,
    joern_server: Optional[Any] = None,
    max_workers: int = 0,
) -> Tuple[List[Dict[str, Any]], List[Path]]:
    """Run /audit's orchestrator against labeled functions.

    Returns (results, run_dirs) — results is a list of per-function
    outcome dicts; run_dirs lists the output directories used (for
    --debug journal retrieval).

    When *joern_server* is provided the caller owns its lifecycle;
    otherwise a server is started and stopped internally.
    """
    try:
        from .label import FunctionLabel  # noqa: F401
    except ImportError:
        pass

    by_repo: Dict[str, list] = {}
    for label in labels:
        by_repo.setdefault(label.source.repo, []).append(label)

    own_joern = joern_server is None
    joern_srv = (
        _start_shared_joern([d for d in source_dirs.values() if d.is_dir()])
        if own_joern
        else joern_server
    )

    results = []
    run_dirs: List[Path] = []
    try:
        for repo_key, repo_labels in by_repo.items():
            src_dir = source_dirs.get(repo_key)
            if src_dir is None or not src_dir.is_dir():
                for label in repo_labels:
                    results.append({
                        "function_id": label.function_id,
                        "bug_class": label.bug_class,
                        "expected": label.expected_status,
                        "actual": "error",
                        "match": False,
                        "hypothesis": "",
                        "evidence_tool": "",
                        "model": model,
                        "cost_usd": 0.0,
                        "duration_s": 0.0,
                        "error": f"source dir missing: {repo_key}",
                    })
                continue

            full_src = (
                full_source_dirs.get(repo_key)
                if full_source_dirs else None
            )
            study_root = full_src if full_src and full_src != src_dir else None
            repo_out = out_dir / repo_key if out_dir else None
            outcomes, bare_key_entries, audit_dir = _run_audit_on_target(
                src_dir, repo_labels, model=model, out_dir=repo_out,
                joern_server=joern_srv, study_root=study_root,
                mode=mode, max_workers=max_workers,
            )
            if audit_dir:
                run_dirs.append(audit_dir)

            inventoried = _load_inventoried_functions(audit_dir)

            for label in repo_labels:
                outcome = outcomes.get(label.function_id)
                if outcome is None:
                    # audit log keys use bare function name (no class/receiver),
                    # so Rows.Scan → Scan — try the stripped form
                    parts = label.function_id.rsplit(":", 1)
                    if len(parts) == 2 and "." in parts[1]:
                        stripped = parts[0] + ":" + parts[1].rsplit(".", 1)[-1]
                        same_stripped = [
                            lb for lb in repo_labels
                            if lb.function_id != label.function_id
                            and lb.function_id.rsplit(":", 1)[0] == parts[0]
                            and lb.function_id.rsplit(".", 1)[-1] == parts[1].rsplit(".", 1)[-1]
                        ]
                        if not same_stripped:
                            outcome = outcomes.get(stripped)
                        else:
                            line_key = f"{stripped}:{label.source.line_start}"
                            outcome = outcomes.get(line_key)
                            if outcome is None:
                                bare = bare_key_entries.get(stripped)
                                if bare is not None:
                                    outcome = bare
                if outcome is None:
                    fn_name = label.function_id.rsplit(":", 1)[-1]
                    if fn_name.count(".") > 0:
                        fn_name = fn_name.rsplit(".", 1)[-1]
                    if (label.source.file, fn_name) in inventoried:
                        actual = "clean"
                        hypothesis = ""
                        evidence_tool = "triage:classifier"
                        cost = 0.0
                        dur = 0.0
                    else:
                        actual = "error"
                        hypothesis = ""
                        evidence_tool = ""
                        cost = 0.0
                        dur = 0.0
                else:
                    actual = outcome["status"]
                    hypothesis = outcome.get("hypothesis", "")
                    evidence_tool = outcome.get("evidence_tool", "")
                    cost = outcome.get("cost_usd", 0.0)
                    dur = outcome.get("duration_s", 0.0)

                expected = label.expected_status
                mechanical_skip = evidence_tool in (
                    "triage:classifier",
                    "dead-code-gate",
                ) or (
                    isinstance(hypothesis, str)
                    and hypothesis.startswith("[dead-code gate:")
                )
                match = _status_matches(expected, actual)

                counter_hyp = ""
                if outcome is not None:
                    counter_hyp = outcome.get("counter_hypothesis", "")
                results.append({
                    "function_id": label.function_id,
                    "bug_class": label.bug_class,
                    "expected": expected,
                    "actual": actual,
                    "match": match,
                    "skipped": mechanical_skip,
                    "hypothesis": hypothesis,
                    "counter_hypothesis": counter_hyp,
                    "evidence_tool": evidence_tool,
                    "model": model,
                    "cost_usd": cost,
                    "duration_s": dur,
                })
    finally:
        if own_joern:
            _stop_shared_joern(joern_srv)

    return results, run_dirs


def _status_matches(
    expected: str,
    actual: str,
    *,
    probe: bool = False,
) -> bool:
    """Check if actual status satisfies the expected ground truth.

    In probe mode, dormant-labeled functions match on ``finding`` too —
    the model correctly detected the bug but lacks the reachability
    context (callers, binary oracle) that the orchestrator uses to
    downgrade findings to dormant.
    """
    if expected == "finding":
        return actual in ("finding", "suspicious")
    if expected == "clean":
        return actual in ("clean", "dormant")
    if expected == "dormant":
        accept = {"dormant", "clean", "finding"} if probe else {"dormant", "clean"}
        return actual in accept
    return False


# Ensemble constants and algorithms imported from pipeline.py (single source
# of truth — W8 unification).
from core.audit.pipeline import (  # noqa: E402
    STATUS_RANK as _STATUS_RANK,
    _has_any_mechanical_evidence,
    _is_verification_evidence,
    dampen_file_pileup as _dampen_file_pileup_generic,
)


def _dampen_file_pileup_dicts(results: list) -> int:
    """Dampen + recompute match flags on dicts."""
    before = [r.get("actual") for r in results]
    dampened = _dampen_file_pileup_generic(results)
    for i, r in enumerate(results):
        if r.get("actual") != before[i]:
            r["file_dampened"] = True
            r["match"] = _status_matches(r["expected"], r["actual"])
    return dampened


def _run_audit_on_target(
    target_dir: Path,
    labels: List[Any],
    *,
    model: str = "",
    out_dir: Optional[Path] = None,
    joern_server: Optional[Any] = None,
    study_root: Optional[Path] = None,
    mode: Optional[str] = None,
    max_workers: int = 0,
) -> Tuple[Dict[str, Any], Dict[str, Any], Optional[Path]]:
    """Run /audit orchestrator on a target (in-process).

    Returns (outcomes_by_function_id, bare_key_entries, audit_output_dir).
    """
    if out_dir is None:
        out_dir = Path(f"out/audit-corpus-{int(time.time())}")
    out_dir.mkdir(parents=True, exist_ok=True)

    _build_checklist(target_dir, out_dir)

    scope_dirs: list[str] = sorted({
        str(Path(label.source.file).parent) for label in labels
    })

    fn_specs: list[str] = []
    for label in labels:
        parts = label.function_id.split(":")
        name = parts[-1] if len(parts) >= 2 else parts[0]
        file = ":".join(parts[:-1]) if len(parts) >= 2 else ""
        fn_specs.append(f"{file}:{name}:{label.source.line_start}")

    labeled_ids = {label.function_id for label in labels}

    from core.audit.pipeline import AuditPipelineOpts, run_audit_pipeline

    def on_progress(idx, total, outcome):
        if idx < 0 or not outcome.file:
            return
        key = f"{outcome.file}:{outcome.function}"
        status = outcome.status
        marker = " *" if key in labeled_ids else ""
        char = {"clean": ".", "suspicious": "?", "finding": "!",
                "dormant": "~", "error": "x"}.get(status, ".")
        print(f"  [{total}] {key} -> {status} {char}{marker}", flush=True)

    print(f"  Audit started: {target_dir}", flush=True)
    t0 = time.monotonic()

    try:
        from core.audit.pipeline import ReviewMode

        review_mode = ReviewMode.SECURITY
        if mode:
            try:
                review_mode = ReviewMode(mode)
            except ValueError:
                pass

        pipeline_opts = AuditPipelineOpts(
            target_path=target_dir.resolve(),
            out_dir=out_dir,
            scope=scope_dirs or None,
            functions=fn_specs,
            models=[model] if model else None,
            max_cost_usd=150.0,
            no_binary_oracle=True,
            joern_server=joern_server,
            on_progress=on_progress,
            study_root=study_root,
            mode=review_mode,
            max_workers=max_workers,
            validate=False,
        )
        run_audit_pipeline(pipeline_opts)
        rc = 0
    except Exception:
        logger.error("Audit pipeline failed", exc_info=True)
        rc = 1

    wall_s = time.monotonic() - t0
    print(f"  Audit finished in {wall_s:.0f}s (rc={rc})", flush=True)

    outcomes_by_id: Dict[str, Dict[str, Any]] = {}
    bare_key_entries: Dict[str, Dict[str, Any]] = {}
    log_path = out_dir / ".audit-log.jsonl"
    if log_path.exists():
        with open(log_path) as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if entry.get("action") not in ("orchestrator_review", "sweep_promotion"):
                    continue
                key = entry.get("key", "")
                if not key:
                    continue
                outcomes_by_id[key] = entry
                head, _, tail = key.rpartition(":")
                if head and tail.isdigit():
                    outcomes_by_id[head] = entry
                else:
                    bare_key_entries[key] = entry

    return outcomes_by_id, bare_key_entries, out_dir


def _extract_source(
    source_dir: Path,
    label: Any,
) -> Optional[str]:
    """Read the labeled function's source lines from a fixture directory."""
    src_file = source_dir / label.source.file
    if not src_file.is_file():
        return None
    lines = src_file.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(0, label.source.line_start - 1)
    end = label.source.line_end
    return "\n".join(lines[start:end])


def _build_probe_context(
    label: Any,
    source: str,
    *,
    domain_model_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Build a minimal context dict for format_context_for_prompt.

    Mirrors the real audit pipeline's context slice but without call
    graph, context map, or mechanical evidence.  Tests whether the
    prompting alone is sufficient for correct bug detection.

    Probe mode deliberately omits reachability signals (callers, role
    classification) — the finding/dormant distinction is made by the
    orchestrator's G7 gate, not the LLM.  Probe scoring accounts for
    this: dormant-labeled functions match on finding or dormant.

    When *domain_model_dir* points to a directory containing
    ``domain-model.json``, the relevant domain knowledge is injected
    into the context — the same path the real pipeline takes after
    ``/understand --study``.
    """
    file_path = label.source.file
    func_name = (
        label.function_id.split(":")[-1]
        if ":" in label.function_id
        else label.function_id
    )

    ctx: Dict[str, Any] = {
        "file": file_path,
        "function": func_name,
        "line_start": label.source.line_start,
        "line_end": label.source.line_end,
        "source": source,
        "metadata": {},
        "callers": [],
        "callees": [],
    }

    if domain_model_dir:
        try:
            from core.concepts.audit_bridge import domain_model_context
            dm_block = domain_model_context(
                domain_model_dir, file_path, func_name, source,
            )
            if dm_block:
                ctx["domain_model"] = dm_block
        except Exception:
            logger.debug("domain model context failed for %s:%s",
                         file_path, func_name, exc_info=True)

    is_c = any(file_path.endswith(e) for e in (".c", ".h"))
    if is_c:
        try:
            from core.audit.condition_smt import check_race_protection
            rpr = check_race_protection(source)
            if rpr.protected:
                ctx["race_protected"] = rpr.reasoning
        except Exception:
            pass

    return ctx


def _run_probe(
    labels: List[Any],
    source_dirs: Dict[str, Path],
    *,
    model: str = "",
    max_tokens: int = 8192,
    domain_model_dir: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Run lightweight LLM probes against labeled functions.

    Uses the same system prompt, strategy primers, and review schema as
    the real audit pipeline, but skips the orchestrator, mechanical
    tools, and refinement loops.  Tests whether the prompting alone
    produces correct verdicts.

    When *domain_model_dir* points to a directory containing
    ``domain-model.json``, the domain model is used for both passive
    context injection and active primer generation.

    LLM calls are parallelised via ``run_parallel`` using the same
    adaptive throttle as /audit — concurrency is derived from the
    model's RPM limit and backs off on 429s.
    """
    import threading
    from core.audit.context import format_context_for_prompt
    from core.audit.llm_review import REVIEW_SCHEMA, _DEFAULT_SYSTEM_PROMPT
    from core.audit.strategy import infer_strategies, primers_for_strategies
    from core.llm.client import LLMClient
    from core.llm.concurrency import run_parallel, derive_max_workers
    from core.llm.log_quiet import quiet_noisy_loggers

    quiet_noisy_loggers()

    client = LLMClient()
    client.config.max_cost_per_scan = 100.0
    model_config = None
    if model:
        try:
            model_config = client.config.config_for_model(model)
        except (ValueError, AttributeError) as exc:
            logger.error("cannot resolve model %r: %s", model, exc)
            return []

    probe_schema = {
        "type": "object",
        "properties": {
            "hypothesis": REVIEW_SCHEMA["properties"]["hypothesis"],
            "hypotheses": REVIEW_SCHEMA["properties"]["hypotheses"],
            "counter_hypothesis": REVIEW_SCHEMA["properties"]["counter_hypothesis"],
            "cwe": REVIEW_SCHEMA["properties"].get("cwe", {"type": "string"}),
            "body": REVIEW_SCHEMA["properties"].get("body", {"type": "string"}),
            "status": REVIEW_SCHEMA["properties"]["status"],
        },
        "required": ["status"],
    }

    # --- Phase 1: prep (serial, cheap) ---
    work_items: List[Optional[Dict[str, Any]]] = []
    early_results: Dict[int, Dict[str, Any]] = {}
    total = len(labels)

    for i, label in enumerate(labels):
        src_dir = source_dirs.get(label.source.repo)
        if src_dir is None or not src_dir.is_dir():
            early_results[i] = {
                "function_id": label.function_id,
                "bug_class": label.bug_class,
                "expected": label.expected_status,
                "actual": "error",
                "match": False,
                "hypothesis": "",
                "evidence_tool": "probe",
                "model": model,
                "cost_usd": 0.0,
                "duration_s": 0.0,
                "error": f"source dir missing: {label.source.repo}",
            }
            work_items.append(None)
            continue

        source = _extract_source(src_dir, label)
        if source is None:
            early_results[i] = {
                "function_id": label.function_id,
                "bug_class": label.bug_class,
                "expected": label.expected_status,
                "actual": "error",
                "match": False,
                "hypothesis": "",
                "evidence_tool": "probe",
                "model": model,
                "cost_usd": 0.0,
                "duration_s": 0.0,
                "error": f"source file not found: {label.source.file}",
            }
            work_items.append(None)
            continue

        dm_dir = domain_model_dir

        ctx = _build_probe_context(label, source, domain_model_dir=dm_dir)
        prompt = format_context_for_prompt(ctx)

        strategies = infer_strategies(
            file_path=label.source.file,
            function_name=ctx["function"],
            source=source,
        )
        primers = primers_for_strategies(strategies)

        if dm_dir:
            try:
                from core.concepts.audit_bridge import primers_from_domain_model
                dynamic = primers_from_domain_model(
                    dm_dir, label.source.file,
                    ctx["function"], source,
                )
                if dynamic:
                    primers.extend(dynamic)
            except Exception:
                logger.debug("domain model primer extraction failed",
                             exc_info=True)

        system_prompt = _DEFAULT_SYSTEM_PROMPT
        if primers:
            system_prompt = (
                system_prompt + "\n\n"
                + "\n\n".join(primers)
            )

        work_items.append({
            "idx": i,
            "label": label,
            "prompt": prompt,
            "system_prompt": system_prompt,
            "strategies": strategies,
        })

    # --- Phase 2: LLM calls (parallel, throttled) ---
    llm_items = [w for w in work_items if w is not None]
    progress_lock = threading.Lock()
    progress_counter = [0]

    def _probe_one(item: Dict[str, Any]) -> Dict[str, Any]:
        label = item["label"]
        kwargs: Dict[str, Any] = {"max_tokens": max_tokens}
        if model_config is not None:
            kwargs["model_config"] = model_config
        else:
            kwargs["task_type"] = "audit"

        t0 = time.monotonic()
        try:
            response = client.generate_structured(
                item["prompt"],
                probe_schema,
                system_prompt=item["system_prompt"],
                **kwargs,
            )
            result = response.result if hasattr(response, "result") else {}
            cost = response.cost if hasattr(response, "cost") else 0.0
            cached = getattr(response, "cached", False)
        except Exception as exc:
            logger.error("probe failed for %s: %s", label.function_id, exc)
            result = {"status": "error"}
            cost = 0.0
            cached = False
        dur = time.monotonic() - t0

        actual = result.get("status", "error")
        expected = label.expected_status
        match = _status_matches(expected, actual, probe=True)
        hypothesis = result.get("hypothesis") or ""
        strategies = item["strategies"]

        with progress_lock:
            progress_counter[0] += 1
            n = progress_counter[0]
        strat_str = ",".join(sorted(strategies - {"general"})) or "general"
        status_marker = {"clean": ".", "finding": "!",
                         "dormant": "~", "suspicious": "?",
                         "error": "x"}.get(actual, "?")
        match_marker = " " if match else " MISS"
        cache_tag = " [cached]" if cached else ""
        print(f"  [{n}/{total}] {label.function_id} "
              f"[{strat_str}] "
              f"expected={expected} got={actual}{status_marker}"
              f"{match_marker} "
              f"(${cost:.4f}, {dur:.1f}s){cache_tag}",
              flush=True)

        return {
            "idx": item["idx"],
            "function_id": label.function_id,
            "bug_class": label.bug_class,
            "expected": expected,
            "actual": actual,
            "match": match,
            "hypothesis": hypothesis,
            "hypotheses": result.get("hypotheses", []),
            "counter_hypothesis": result.get("counter_hypothesis", ""),
            "strategies": sorted(strategies),
            "evidence_tool": "probe",
            "model": model,
            "cost_usd": cost,
            "duration_s": dur,
            "cached": cached,
        }

    model_name = model_config.model_name if model_config else (model or "default")
    workers = derive_max_workers(model_name)
    logger.debug("probe: %d items, %d workers (model=%s)",
                 len(llm_items), workers, model_name)

    llm_results = run_parallel(
        llm_items, _probe_one,
        max_workers=workers, model=model_name, label="probe",
    )

    # --- Phase 3: merge and order ---
    result_by_idx: Dict[int, Dict[str, Any]] = dict(early_results)
    for r in llm_results:
        if r is not None:
            result_by_idx[r.pop("idx")] = r

    results = [result_by_idx[i] for i in range(total) if i in result_by_idx]

    _record_scorecard(results, model)

    return results


def _record_scorecard(
    results: List[Dict[str, Any]],
    model: str,
) -> None:
    """Record probe results into the model scorecard.

    Each result becomes one CORPUS_GROUND_TRUTH event under the
    decision class ``audit:<bug_class>``.
    """
    if not model or not results:
        return
    try:
        from core.llm.scorecard.scorecard import EventType, ModelScorecard
        scorecard_path = Path(
            os.environ.get("RAPTOR_DIR", "."),
        ) / "out" / "llm_scorecard.json"
        scorecard = ModelScorecard(scorecard_path)
        for r in results:
            if r.get("actual") == "error":
                continue
            decision_class = f"audit:{r['bug_class']}"
            outcome = "correct" if r.get("match") else "incorrect"
            sample = None
            if outcome == "incorrect":
                hyp = (r.get("hypothesis") or "")[:200]
                sample = {
                    "function_id": r["function_id"],
                    "expected": r["expected"],
                    "actual": r["actual"],
                    "hypothesis": hyp,
                }
            scorecard.record_event(
                decision_class=decision_class,
                model=model,
                event_type=EventType.CORPUS_GROUND_TRUTH,
                outcome=outcome,
                sample=sample,
            )
    except Exception:
        logger.debug("scorecard recording failed", exc_info=True)


def _print_cross_model_summary(
    results: List[Dict[str, Any]],
    models: List[str],
) -> None:
    """Print a matrix showing per-function verdicts across models."""
    by_func: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for r in results:
        fid = r["function_id"]
        mdl = r.get("model", "") or "default"
        by_func.setdefault(fid, {})[mdl] = r

    model_labels = [m or "default" for m in models]
    header = f"{'Function':<45} {'Expected':<9}"
    for ml in model_labels:
        short = ml[:12]
        header += f" {short:<13}"
    header += " Agree?"

    print(f"\n{'=' * len(header)}")
    print("Cross-model comparison")
    print(header)
    print("-" * len(header))

    agree_count = 0
    disagree_count = 0
    for fid in sorted(by_func):
        verdicts = by_func[fid]
        first = next(iter(verdicts.values()))
        expected = first["expected"]

        fid_short = fid if len(fid) <= 44 else "..." + fid[-41:]
        line = f"{fid_short:<45} {expected:<9}"

        statuses = []
        for ml in model_labels:
            r = verdicts.get(ml)
            if r is None:
                line += f" {'—':<13}"
            else:
                actual = r["actual"]
                match = r.get("match", False)
                marker = "" if match else "*"
                line += f" {actual + marker:<13}"
                statuses.append(actual)

        all_agree = len(set(statuses)) <= 1
        if all_agree:
            agree_count += 1
            line += " yes"
        else:
            disagree_count += 1
            line += " NO"
        print(line)

    total = agree_count + disagree_count
    print(f"\nAgreement: {agree_count}/{total} "
          f"({100 * agree_count / total:.0f}%)" if total else "")

    per_model_acc = {}
    for ml in model_labels:
        model_results = [r for r in results if (r.get("model", "") or "default") == ml]
        matched = sum(1 for r in model_results if r.get("match"))
        per_model_acc[ml] = (matched, len(model_results))

    print("\nPer-model accuracy:")
    for ml in model_labels:
        matched, total = per_model_acc[ml]
        pct = 100 * matched / total if total else 0
        cost = sum(r.get("cost_usd", 0) for r in results
                   if (r.get("model", "") or "default") == ml)
        print(f"  {ml}: {matched}/{total} ({pct:.0f}%) ${cost:.4f}")


def _write_results(
    results: List[Dict[str, Any]],
    output: Path,
    *,
    meta: Dict[str, Any] | None = None,
) -> None:
    """Write results to a JSON file.

    When *meta* is provided, wraps results in ``{"meta": ..., "results": ...}``
    so wall time and cost are persisted alongside per-function verdicts.
    Consumers that expect a bare list should check for a dict wrapper.
    """
    if meta:
        data: Any = {"meta": meta, "results": results}
    else:
        data = results
    with open(output, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _format_detail_table(results: List[Dict[str, Any]]) -> str:
    """Format per-function detail table."""
    lines = []
    lines.append(f"{'Function':<45} {'Expected':<10} {'Actual':<12} "
                 f"{'Match':<6} {'Evidence':<25} {'Cost':>7}")
    lines.append("-" * 110)
    for r in results:
        fid = r["function_id"]
        if len(fid) > 44:
            fid = "..." + fid[-41:]
        match_str = "yes" if r["match"] else "NO"
        evidence = r.get("evidence_tool", "")
        if len(evidence) > 24:
            evidence = evidence[:21] + "..."
        cost = r.get("cost_usd", 0.0)
        cached_tag = " (cached)" if r.get("cached") else ""
        lines.append(
            f"{fid:<45} {r['expected']:<10} {r['actual']:<12} "
            f"{match_str:<6} {evidence:<25} ${cost:>6.4f}{cached_tag}"
        )
    return "\n".join(lines)


def _format_summary(
    results: List[Dict[str, Any]],
    wall_s: float,
    model: str,
) -> str:
    """Format the full summary block."""
    from .corpus_metrics import check_gate, compute_metrics, format_report

    aggregate, per_class, skipped_count = compute_metrics(results)
    reviewed = [r for r in results if not r.get("skipped")]
    total_cost = sum(r.get("cost_usd", 0.0) for r in results)
    total_llm_s = sum(r.get("duration_s", 0.0) for r in results)
    matched = sum(1 for r in reviewed if r.get("match"))
    mismatched = [r for r in reviewed if not r.get("match")]
    cached_count = sum(1 for r in results if r.get("cached"))

    lines = []
    lines.append("=" * 70)
    lines.append("Corpus run complete")
    lines.append(f"  Model: {model or 'default'}")
    lines.append(f"  Labels: {len(results)}")
    if skipped_count:
        lines.append(f"  Skipped by mechanical gates: {skipped_count}")
    if cached_count:
        lines.append(f"  Cached: {cached_count}/{len(results)} (cost and duration reflect cache hits)")
    lines.append(f"  Matched: {matched}/{len(reviewed)}")
    lines.append(f"  Cost: ${total_cost:.4f}")
    lines.append(f"  Wall clock: {wall_s:.0f}s ({wall_s/60:.1f}m)")
    lines.append(f"  LLM time: {total_llm_s:.0f}s ({total_llm_s/60:.1f}m)")
    lines.append("")
    lines.append(format_report(
        aggregate, per_class, model=model, skipped=skipped_count,
    ))
    lines.append("")
    lines.append(_format_detail_table(results))

    if mismatched:
        lines.append("")
        lines.append("Mismatches:")
        for r in mismatched:
            hyp = r.get("hypothesis", "")
            if len(hyp) > 80:
                hyp = hyp[:77] + "..."
            lines.append(f"  {r['function_id']}: "
                         f"expected={r['expected']} got={r['actual']} "
                         f"evidence={r.get('evidence_tool', '')}")
            if hyp:
                lines.append(f"    hypothesis: {hyp}")

    gates = check_gate(aggregate, per_class, results)
    if gates:
        lines.append("")
        for g in gates:
            lines.append(f"GATE FAIL: {g}")
    else:
        lines.append("")
        lines.append("All gates passed.")

    return "\n".join(lines)


def _save_debug(
    results: List[Dict[str, Any]],
    run_dirs: List[Path],
    output_path: Path,
) -> None:
    """Save LLM reasoning alongside results for diagnosis.

    Collects review-journal.jsonl entries from each run directory and
    writes a per-function debug JSONL next to the results file.  Each
    line has the function_id, verdict, hypotheses, and verdict_rationale.
    """
    debug_path = output_path.with_suffix(".debug.jsonl")

    journal_entries: Dict[str, Dict[str, Any]] = {}
    for d in run_dirs:
        jpath = d / "review-journal.jsonl"
        if not jpath.exists():
            continue
        with open(jpath) as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                fid = entry.get("file", "") + ":" + entry.get("function", "")
                if fid != ":":
                    journal_entries[fid] = entry

    labeled_ids = {r["function_id"] for r in results}
    with open(debug_path, "w") as f:
        for fid in sorted(labeled_ids):
            je = journal_entries.get(fid, {})
            hypotheses = je.get("hypotheses", [])
            record = {
                "function_id": fid,
                "verdict": je.get("verdict", ""),
                "hypotheses": hypotheses,
                "cwe": je.get("cwe", ""),
                "verdict_rationale": je.get("verdict_rationale", ""),
                "counter_hypothesis": je.get("counter_hypothesis", ""),
            }
            f.write(json.dumps(record) + "\n")

    print(f"Debug reasoning written to {debug_path}")


def _checkpoint_write(path: Path, data: Any) -> None:
    """Atomically write a JSON checkpoint."""
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    tmp.rename(path)


def _checkpoint_read(path: Path) -> Optional[Any]:
    """Read a checkpoint if it exists, else None."""
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _run_ensemble_audit(
    labels: List[Any],
    source_dirs: Dict[str, Path],
    *,
    model: str = "",
    out_dir: Optional[Path] = None,
    full_source_dirs: Optional[Dict[str, Path]] = None,
) -> Tuple[List[Dict[str, Any]], List[Path]]:
    """Run dual-mode ensemble: security + bug_first, merge, Phase 2 + 2b.

    Improvements over naive sequential:
    - Both passes run in parallel (ThreadPoolExecutor), halving wall time
    - Shared Joern server across both passes
    - Checkpoints after each stage for crash resilience
    - max_workers halved per pass to avoid overwhelming the LLM

    Returns (scored_results, run_dirs) — same shape as _run_audit.
    """
    from core.llm.concurrency import derive_max_workers

    base_out = out_dir or Path(f"out/audit-corpus-{int(time.time())}")
    base_out.mkdir(parents=True, exist_ok=True)

    sec_out = Path(str(base_out) + "-sec")
    bf_out = Path(str(base_out) + "-bf")
    sec_ckpt = base_out / "checkpoint-sec.json"
    bf_ckpt = base_out / "checkpoint-bf.json"
    merged_ckpt = base_out / "checkpoint-merged.json"

    # --- Shared Joern server (read-only, thread-safe over HTTP) ---
    joern_srv = _start_shared_joern(
        [d for d in source_dirs.values() if d.is_dir()],
    )

    # --- Worker budget: full for each sequential pass ---
    resolved_model = model or "default"
    full_workers = derive_max_workers(resolved_model)
    print(f"  Ensemble concurrency: {full_workers} workers per pass",
          flush=True)

    run_dirs: List[Path] = []

    try:
        # --- Pass 1: security mode, full workers ---
        sec_results = _checkpoint_read(sec_ckpt)
        bf_results = _checkpoint_read(bf_ckpt)

        if sec_results is not None and bf_results is not None:
            print("  Resuming from checkpoints (both passes cached)",
                  flush=True)
            sec_dirs = [sec_out] if sec_out.is_dir() else []
            bf_dirs = [bf_out] if bf_out.is_dir() else []
        else:
            if sec_results is None:
                print("\n--- Ensemble pass 1: security mode ---",
                      flush=True)
                sec_results, sec_dirs = _run_audit(
                    labels, source_dirs,
                    model=model, out_dir=sec_out,
                    full_source_dirs=full_source_dirs,
                    mode="security",
                    joern_server=joern_srv,
                    max_workers=full_workers,
                )
                _checkpoint_write(sec_ckpt, sec_results)
                print(f"  Security pass complete "
                      f"({len(sec_results)} results, checkpointed)",
                      flush=True)
            else:
                print("  Security pass: resuming from checkpoint",
                      flush=True)
                sec_dirs = [sec_out] if sec_out.is_dir() else []

            # --- Conditional skip: identify functions for pass 2 ---
            _counter_vuln_kw = (
                "overflow", "underflow", "null", "free",
                "race", "inject", "bypass", "truncat", "wrap",
                "leak", "uninitiali", "bounds", "sign", "cast",
                "format", "use-after", "double", "integer",
                "buffer", "stack", "heap", "oob",
                "out-of-bound", "attacker", "controlled",
                "tainted", "deadlock", "toctou",
            )

            def _needs_pass2(r):
                if r.get("actual", "clean") != "clean":
                    return True
                if r.get("evidence_tool", ""):
                    return True
                counter = (r.get("counter_hypothesis") or "").lower()
                if len(counter) >= 30 and any(
                    kw in counter for kw in _counter_vuln_kw
                ):
                    return True
                return False

            pass2_ids = {r["function_id"] for r in sec_results
                         if _needs_pass2(r)}
            skip_count = len(sec_results) - len(pass2_ids)
            print(f"\n  Conditional skip: {skip_count} confident clean, "
                  f"{len(pass2_ids)} to pass 2", flush=True)

            if bf_results is None:
                if pass2_ids:
                    pass2_labels = [
                        lb for lb in labels
                        if lb.function_id in pass2_ids
                    ]
                    print(f"\n--- Ensemble pass 2: bug_first mode "
                          f"({len(pass2_labels)}/{len(labels)} functions) ---",
                          flush=True)
                    bf_results, bf_dirs = _run_audit(
                        pass2_labels, source_dirs,
                        model=model, out_dir=bf_out,
                        full_source_dirs=full_source_dirs,
                        mode="bug_first",
                        joern_server=joern_srv,
                        max_workers=full_workers,
                    )
                else:
                    print("  All functions confident clean — skipping pass 2",
                          flush=True)
                    bf_results = []
                    bf_dirs = []
                _checkpoint_write(bf_ckpt, bf_results)
                print(f"  Bug-first pass complete "
                      f"({len(bf_results)} results, checkpointed)",
                      flush=True)
            else:
                print("  Bug-first pass: resuming from checkpoint",
                      flush=True)
                bf_dirs = [bf_out] if bf_out.is_dir() else []

        run_dirs = sec_dirs + bf_dirs
    finally:
        _stop_shared_joern(joern_srv)

    # --- Merge at the result level ---
    merged_cached = _checkpoint_read(merged_ckpt)
    if merged_cached is not None:
        print("  Resuming from merge checkpoint", flush=True)
        merged_results = merged_cached
    else:
        sec_by_id = {r["function_id"]: r for r in sec_results}
        bf_by_id = {r["function_id"]: r for r in bf_results}
        all_ids = set(sec_by_id) | set(bf_by_id)

        merged_results: List[Dict[str, Any]] = []
        sec_only_wins = 0
        bf_only_wins = 0
        agree_count = 0
        demoted_count = 0

        for fid in sorted(all_ids):
            sec_r = sec_by_id.get(fid)
            bf_r = bf_by_id.get(fid)

            if sec_r and bf_r:
                sec_rank = _STATUS_RANK.get(sec_r["actual"], 0)
                bf_rank = _STATUS_RANK.get(bf_r["actual"], 0)
                higher_status = (
                    sec_r["actual"] if sec_rank >= bf_rank
                    else bf_r["actual"]
                )

                use_max = True
                if (
                    higher_status in ("suspicious", "finding")
                    and not (sec_rank >= 3 and bf_rank >= 3)
                ):
                    sec_ev = sec_r.get("evidence_tool", "")
                    bf_ev = bf_r.get("evidence_tool", "")
                    has_evidence = (
                        _has_any_mechanical_evidence(sec_ev)
                        or _has_any_mechanical_evidence(bf_ev)
                    )
                    if not has_evidence:
                        use_max = False

                if not use_max:
                    higher = sec_r if sec_rank >= bf_rank else bf_r
                    winner = dict(higher)
                    if winner["actual"] == "finding":
                        winner["actual"] = "suspicious"
                    winner["ensemble_source"] = "disagree_demoted"
                    winner["security_actual"] = sec_r["actual"]
                    winner["bug_first_actual"] = bf_r["actual"]
                    demoted_count += 1
                elif bf_rank > sec_rank:
                    winner = dict(bf_r)
                    winner["ensemble_source"] = "bug_first"
                    winner["security_actual"] = sec_r["actual"]
                    bf_only_wins += 1
                elif sec_rank > bf_rank:
                    winner = dict(sec_r)
                    winner["ensemble_source"] = "security"
                    winner["bug_first_actual"] = bf_r["actual"]
                    sec_only_wins += 1
                else:
                    winner = dict(sec_r)
                    winner["ensemble_source"] = "both_agree"
                    agree_count += 1

                winner["match"] = _status_matches(
                    winner["expected"], winner["actual"],
                )
                merged_results.append(winner)
            elif sec_r:
                merged_results.append(dict(sec_r))
            else:
                merged_results.append(dict(bf_r))

        sec_cost = sum(r.get("cost_usd", 0) for r in sec_results)
        bf_cost = sum(r.get("cost_usd", 0) for r in bf_results)

        print("\n--- Ensemble merge ---", flush=True)
        print(f"  Security wins: {sec_only_wins}", flush=True)
        print(f"  Bug-first wins: {bf_only_wins}", flush=True)
        print(f"  Agree: {agree_count}", flush=True)
        print(f"  Demoted: {demoted_count}", flush=True)
        print(f"  Security cost: ${sec_cost:.4f}", flush=True)
        print(f"  Bug-first cost: ${bf_cost:.4f}", flush=True)

        _checkpoint_write(merged_ckpt, merged_results)

    # --- Phase 2: classify security impact ---
    findings = [r for r in merged_results
                if r["actual"] in ("finding", "suspicious")]
    if findings:
        print(f"\n--- Phase 2: classifying {len(findings)} finding(s) ---",
              flush=True)
        try:
            phase2_cost = _run_phase2_classify(findings, model=model)
            print(f"  Phase 2 cost: ${phase2_cost:.4f}", flush=True)
        except Exception:
            logger.error("Phase 2 classification failed", exc_info=True)
            print("  Phase 2 classification failed (continuing)", flush=True)

        # Phase 2 quality-finding suppression: demote non-security quality
        # findings to clean — they are real defects but not exploitable.
        # Exception: findings backed by mechanical evidence (SMT, sarif,
        # prefilter) are not suppressed — the tool confirmed the defect.
        suppressed = 0
        for r in merged_results:
            if (
                r.get("phase2_classification") == "quality_finding"
                and not r.get("phase2_is_security")
                and r["actual"] in ("finding", "suspicious")
                and r.get("phase2_primitive", "none") == "none"
            ):
                ev = r.get("evidence_tool", "")
                if _is_verification_evidence(ev):
                    continue
                r["actual"] = "clean"
                r["phase2_suppressed"] = True
                r["match"] = _status_matches(r["expected"], r["actual"])
                suppressed += 1
        if suppressed:
            print(f"  Phase 2 suppressed: {suppressed} quality finding(s) "
                  f"demoted to clean", flush=True)

    # --- File-level over-alert dampening (#4) ---
    _dampened = _dampen_file_pileup_dicts(merged_results)
    if _dampened:
        print(f"  File-level dampening: {_dampened} pile-up finding(s) "
              f"demoted", flush=True)

    # --- Phase 2b: chain detection ---
    quality_findings = [
        r for r in merged_results
        if r["actual"] in ("finding", "suspicious")
        and r.get("phase2_classification") == "quality_finding"
    ]
    if len(quality_findings) >= 2:
        print(f"\n--- Phase 2b: chain detection on {len(quality_findings)} "
              f"quality finding(s) ---", flush=True)
        try:
            chains = _run_phase2b_chains(
                quality_findings, merged_results,
                out_dir=base_out, model=model,
            )
            if chains:
                print(f"  Chains found: {len(chains)}", flush=True)
                for c in chains:
                    print(f"    {c['bug_a']} + {c['bug_b']} "
                          f"-> {c.get('primitive', '?')}", flush=True)
            else:
                print("  No chains confirmed", flush=True)
        except Exception:
            logger.error("Phase 2b chain detection failed", exc_info=True)
            print("  Phase 2b failed (continuing)", flush=True)

    return merged_results, run_dirs


def _run_phase2_classify(
    findings: List[Dict[str, Any]],
    *,
    model: str = "",
) -> float:
    """Run Phase 2 security classification on merged findings."""
    from core.llm.client import LLMClient
    from core.audit.security_classifier import CLASSIFICATION_SCHEMA

    client = LLMClient()
    kwargs: Dict[str, Any] = {"task_type": "audit"}
    if model:
        try:
            mc = client.config.config_for_model(model)
            kwargs = {"model_config": mc}
        except (ValueError, AttributeError):
            pass

    total_cost = 0.0
    for r in findings:
        fid = r["function_id"]
        hyp = r.get("hypothesis", "")
        prompt = (
            f"Given this verified defect:\n"
            f"  Function: {fid}\n"
            f"  Bug: {hyp}\n"
            f"  Status: {r['actual']}\n\n"
            f"Is this defect security-impacting? Consider trust boundaries, "
            f"attacker reachability, and CIA impact."
        )
        try:
            response = client.generate_structured(
                prompt,
                CLASSIFICATION_SCHEMA,
                system_prompt=(
                    "You are a security impact classifier. Given a "
                    "verified code defect, decide whether it has security "
                    "implications or is purely a quality issue."
                ),
                **kwargs,
            )
            result = response.result if hasattr(response, "result") else {}
            cost = response.cost if hasattr(response, "cost") else 0.0
            total_cost += cost
        except Exception:
            logger.warning("Phase 2 failed for %s", fid, exc_info=True)
            result = {"classification": "quality_finding", "is_security": False}

        r["phase2_classification"] = result.get("classification", "quality_finding")
        r["phase2_is_security"] = result.get("is_security", False)
        r["phase2_primitive"] = result.get("primitive", "none")
        cls_tag = result.get("classification", "?")
        print(f"  {fid} -> {cls_tag}", flush=True)

    return total_cost


def _run_phase2b_chains(
    quality_findings: List[Dict[str, Any]],
    all_results: List[Dict[str, Any]],
    *,
    out_dir: Optional[Path] = None,
    model: str = "",
) -> List[Dict[str, Any]]:
    """Run Phase 2b chain detection on quality findings.

    Builds a call graph from the audit log entries and looks for
    connected quality-bug pairs.
    """
    from core.llm.client import LLMClient
    from core.audit.chain_detector import CHAIN_SCHEMA

    client = LLMClient()
    kwargs: Dict[str, Any] = {"task_type": "audit"}
    if model:
        try:
            mc = client.config.config_for_model(model)
            kwargs = {"model_config": mc}
        except (ValueError, AttributeError):
            pass

    # Build adjacency from audit log caller/callee data
    graph: Dict[str, set] = {}
    for r in all_results:
        fid = r["function_id"]
        neighbours = graph.setdefault(fid, set())
        # The audit log entries may carry callers/callees
        for c in r.get("callers", []):
            if isinstance(c, dict) and c.get("file") and c.get("name"):
                n = f"{c['file']}:{c['name']}"
                neighbours.add(n)
                graph.setdefault(n, set()).add(fid)
        for c in r.get("callees", []):
            if isinstance(c, dict) and c.get("file") and c.get("name"):
                n = f"{c['file']}:{c['name']}"
                neighbours.add(n)
                graph.setdefault(n, set()).add(fid)

    # Find connected quality-bug pairs
    candidates = []
    seen = set()
    for i, a in enumerate(quality_findings):
        a_id = a["function_id"]
        for b in quality_findings[i + 1:]:
            b_id = b["function_id"]
            pair = tuple(sorted([a_id, b_id]))
            if pair in seen:
                continue
            if b_id in graph.get(a_id, set()):
                candidates.append((a, b))
                seen.add(pair)

    if not candidates:
        return []

    chains = []
    for a, b in candidates:
        prompt = (
            f"These bugs were found on the same call path:\n\n"
            f"Bug A: {a['function_id']}\n"
            f"  Hypothesis: {a.get('hypothesis', '')}\n\n"
            f"Bug B: {b['function_id']}\n"
            f"  Hypothesis: {b.get('hypothesis', '')}\n\n"
            f"Do these bugs compose into a security issue that "
            f"neither bug represents alone?"
        )
        try:
            response = client.generate_structured(
                prompt,
                CHAIN_SCHEMA,
                system_prompt=(
                    "You are a security analyst. Given two verified code "
                    "defects on the same call path, decide whether they "
                    "compose into a security vulnerability."
                ),
                **kwargs,
            )
            result = response.result if hasattr(response, "result") else {}
        except Exception:
            logger.warning("Chain eval failed for %s + %s",
                           a["function_id"], b["function_id"],
                           exc_info=True)
            continue

        if result.get("is_chain"):
            chains.append({
                "bug_a": a["function_id"],
                "bug_b": b["function_id"],
                "chain_description": result.get("chain_description", ""),
                "primitive": result.get("primitive", ""),
                "confidence": result.get("confidence", "medium"),
            })

    return chains


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run /audit calibration corpus",
    )
    parser.add_argument(
        "--class", dest="bug_class", default=None,
        help="Run only one bug class (e.g. aliasing, lifecycle)",
    )
    parser.add_argument(
        "--label", dest="label_ids", action="append", default=[],
        help="Run only these labels by function_id (repeatable)",
    )
    parser.add_argument(
        "--splice", type=Path, default=None,
        help="Splice partial results back into this full results file "
             "(overwrites matching function_ids, keeps the rest)",
    )
    parser.add_argument(
        "--model", action="append", default=[],
        help="LLM model to use (repeatable for cross-model comparison; "
             "default: orchestrator default)",
    )
    parser.add_argument(
        "--fetch", action="store_true",
        help="Fetch/update pinned sources before running",
    )
    parser.add_argument(
        "--out", type=Path, default=None,
        help="Output directory for the audit run",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("corpus-results.json"),
        help="Path for the results JSON (default: corpus-results.json)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Load and verify labels without running audit",
    )
    parser.add_argument(
        "--probe", action="store_true",
        help="Lightweight LLM probe mode: test prompting without the full "
             "audit pipeline.  Uses the same system prompt, strategy primers, "
             "and review schema as /audit but skips orchestrator, mechanical "
             "tools, and refinement loops",
    )
    parser.add_argument(
        "--max-tokens", type=int, default=8192,
        help="Maximum output tokens for --probe mode (default: 8192)",
    )
    parser.add_argument(
        "--domain-model", type=Path, default=None,
        help="Directory containing domain-model.json from /understand --study "
             "(injected into probe context when set)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Save LLM reasoning alongside results for diagnosis",
    )
    parser.add_argument(
        "--scope", choices=["excerpt", "full", "quick"], default="excerpt",
        help="Source scope: excerpt (labelled files only, default), "
             "full (entire repo), quick (skip repos with >5k source files)",
    )
    parser.add_argument(
        "--mode",
        choices=["security", "bug_first", "quality", "ensemble"],
        default="ensemble",
        help="Review mode: security, bug_first, quality, or ensemble "
             "(run security + bug_first, merge, Phase 2 + 2b; default)",
    )
    args = parser.parse_args(argv)

    from .label import load_all_labels

    labels = load_all_labels(bug_class=args.bug_class)

    if args.label_ids:
        id_set = set(args.label_ids)
        labels = [lb for lb in labels if lb.function_id in id_set]

    if not labels:
        print("No labels found.", file=sys.stderr)
        return 1

    print(f"Loaded {len(labels)} label(s)", end="")
    if args.bug_class:
        print(f" (class: {args.bug_class})", end="")
    if args.label_ids:
        print(f" (ids: {len(args.label_ids)})", end="")
    print()

    source_dirs = _resolve_source_dirs(labels, do_fetch=args.fetch)
    errors = _verify_labels(labels, source_dirs)
    if errors:
        print(f"{len(errors)} label verification error(s):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        if not args.dry_run:
            return 1

    if args.dry_run:
        print("Dry run — labels verified, not running audit.")
        for label in labels:
            print(f"  {label.function_id} ({label.bug_class}) "
                  f"expected={label.expected_status}")
        return 0

    # --- scope filtering ---
    if args.scope == "quick":
        labels, skipped_repos = _filter_quick_repos(labels, source_dirs)
        if not labels:
            print("No labels remaining after quick filter.")
            return 1
        print(f"Quick scope: {len(labels)} label(s) remaining "
              f"({len(skipped_repos)} repo(s) skipped)")

    models = args.model if args.model else [""]

    run_tag = str(int(time.time()))
    excerpt_dirs = None
    with _corpus_project_context(run_tag):
        if args.probe:
            t0 = time.monotonic()
            results = []
            for mdl in models:
                label_text = mdl or "default"
                print(f"\nProbe mode (model: {label_text})...",
                      flush=True)
                run_results = _run_probe(
                    labels, source_dirs,
                    model=mdl,
                    max_tokens=args.max_tokens,
                    domain_model_dir=args.domain_model,
                )
                results.extend(run_results)
            wall_s = time.monotonic() - t0
            run_dirs = []

            if len(models) > 1:
                _print_cross_model_summary(results, models)
        else:
            model = models[0]
            mode = args.mode
            print(f"Running audit (model: {model or 'default'}, "
                  f"mode: {mode})...", flush=True)

            audit_dirs = source_dirs
            if args.scope == "excerpt":
                excerpt_dirs = _build_excerpt_tree(labels, source_dirs)
                audit_dirs = excerpt_dirs

            t0 = time.monotonic()
            try:
                if mode == "ensemble":
                    results, run_dirs = _run_ensemble_audit(
                        labels, audit_dirs,
                        model=model, out_dir=args.out,
                        full_source_dirs=source_dirs if excerpt_dirs else None,
                    )
                else:
                    results, run_dirs = _run_audit(
                        labels, audit_dirs,
                        model=model, out_dir=args.out,
                        full_source_dirs=source_dirs if excerpt_dirs else None,
                        mode=mode,
                    )
            finally:
                if excerpt_dirs:
                    for d in excerpt_dirs.values():
                        shutil.rmtree(str(d), ignore_errors=True)
            wall_s = time.monotonic() - t0

    args.output.parent.mkdir(parents=True, exist_ok=True)

    if args.splice and args.splice.is_file():
        raw = json.loads(args.splice.read_text())
        base = raw["results"] if isinstance(raw, dict) and "results" in raw else raw
        partial_ids = {r["function_id"] for r in results}
        spliced = [r for r in base if r["function_id"] not in partial_ids]
        spliced.extend(results)
        spliced.sort(key=lambda r: r["function_id"])
        results = spliced
        print(f"\nSpliced {len(partial_ids)} partial results into "
              f"{args.splice} ({len(results)} total)")

    total_llm_s = sum(r.get("duration_s", 0.0) for r in results)
    meta = {
        "wall_s": round(wall_s, 1),
        "llm_s": round(total_llm_s, 1),
        "cost_usd": round(sum(r.get("cost_usd", 0.0) for r in results), 4),
        "model": ", ".join(m or "default" for m in models),
        "count": len(results),
    }
    _write_results(results, args.output, meta=meta)
    print(f"\nResults written to {args.output}")

    try:
        from core.audit.learning import extract_fp_patterns, save_corrections
        fp_patterns = extract_fp_patterns(results)
        if fp_patterns:
            corrections_dir = args.output.parent
            save_corrections(fp_patterns, corrections_dir)
            print(f"\nLearning loop: {len(fp_patterns)} FP pattern(s) extracted")
            for p in fp_patterns:
                print(f"  - {p['category']}: {p['count']} FPs")
    except Exception:
        logger.debug("learning loop extraction failed", exc_info=True)

    if args.debug and run_dirs:
        _save_debug(results, run_dirs, args.output)

    print()
    model_label = meta["model"]
    print(_format_summary(results, wall_s, model_label))

    return 0


if __name__ == "__main__":
    sys.exit(main())
