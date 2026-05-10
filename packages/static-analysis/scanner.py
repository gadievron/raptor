#!/usr/bin/env python3
"""Automated Code Security Agent (Enhanced)
- Accepts a repo path or Git URL
- Supports --policy-groups (comma-separated list) to select rule categories
- Runs Semgrep across selected local rule directories IN PARALLEL
- Optionally runs CodeQL when --codeql is provided; requires codeql CLI and query packs
- Produces SARIF outputs and optional merged SARIF with deduplication
- Includes progress reporting and comprehensive metrics
- The output of this could be consumed by RAPTOR or other tools for further analysis for finding bugs/security issues
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, List, Optional, Tuple

# Add parent directory to path for imports
# packages/static-analysis/scanner.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[2]))

from core.json import save_json
from core.config import RaptorConfig
from core.run.output import unique_run_suffix
from core.run.safe_io import safe_run_mkdir
from core.logging import get_logger
from core.git import clone_repository
from core.sarif.parser import generate_scan_metrics, merge_sarif, validate_sarif
from core.hash import sha256_bytes, sha256_tree
from packages import semgrep as semgrep_pkg

logger = get_logger()


def run(cmd, cwd=None, timeout=RaptorConfig.DEFAULT_TIMEOUT, env=None,
        target=None, output=None, proxy_hosts=None, caller_label=None):
    """Execute a command in a network-isolated sandbox and return results.

    When `target` and `output` are supplied, Landlock is engaged — the
    child may read anywhere (Landlock default) but may only write to
    `output` and `/tmp`.

    Network policy:
      - Default (proxy_hosts=None): block_network=True at the user-ns
        layer. Child sees no interfaces at all.
      - proxy_hosts=[...] set: route outbound via the RAPTOR egress
        proxy with a hostname allowlist. Caller specifies which hosts
        are needed (`semgrep.dev` for registry pack fetches,
        `github.com`/`gitlab.com` for git clone, etc.). UDP blocked,
        DNS resolution delegated to the proxy. Net surface is strictly
        narrower than plain block_network=False and strictly wider
        than block_network=True.
    """
    from core.sandbox import run as sandbox_run
    net_kwargs = (
        {"use_egress_proxy": True, "proxy_hosts": list(proxy_hosts),
         "caller_label": caller_label or "scanner"}
        if proxy_hosts else
        {"block_network": True}
    )
    # tool_paths: speculative best-guess bind set so mount-ns isolation
    # can engage. For Python tools we need (a) the script's bin dir
    # and (b) the interpreter's stdlib dir at sys.prefix/lib/pythonX.Y.
    #
    # Outcome depends on the operator's install layout:
    #
    #   /usr/bin/semgrep (system install): cmd[0] already in mount
    #     tree, helper returns []; mount-ns engages cleanly, full
    #     isolation, silent.
    #
    #   ~/.local/bin/semgrep (pip --user) or /opt/homebrew/bin
    #     (brew): helper returns [bin_dir, stdlib_dir]; mount-ns
    #     tries with these. If semgrep then exec's native deps not
    #     in the bind set (semgrep-core, etc.), context.py's
    #     speculative-C retry catches the 126/empty-stderr and
    #     falls back to Landlock-only. Workflow proceeds; debug-
    #     level diagnostic only.
    tool_paths = _compute_python_tool_paths(cmd)
    p = sandbox_run(
        cmd,
        target=target,
        output=output,
        cwd=cwd,
        env=env or RaptorConfig.get_safe_env(),
        text=True,
        capture_output=True,
        timeout=timeout,
        tool_paths=tool_paths or None,
        **net_kwargs,
    )
    return p.returncode, p.stdout, p.stderr


def _compute_python_tool_paths(cmd) -> list:
    """Best-guess bind dirs for a Python-tool sandbox call.

    Reads cmd[0]'s shebang to find the interpreter, then computes:
      - script's bin dir (so cmd[0] resolves)
      - interpreter's bin dir (often same dir)
      - interpreter's stdlib dir, derived from interpreter path +
        version (e.g. /home/USER/bin/python3.13 →
        /home/USER/lib/python3.13)

    All paths are absolute. Skips dirs that already lie under a
    standard mount-ns bind prefix (/usr, /lib, etc.) — no point
    asking for a bind that's already there.

    Returns [] when cmd is empty, the shebang can't be read, or
    the layout doesn't match a recognisable Python install.
    Speculative: a wrong guess is caught by context.py's
    speculative-C retry (re-runs without tool_paths if the call
    exits 126/127 with empty stderr).
    """
    import re
    import sys
    from pathlib import Path
    if not cmd:
        return []
    cmd0 = cmd[0]
    # Prefix-skip set — paths already in the mount-ns bind tree.
    _SYS_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/etc/", "/bin/", "/sbin/")
    def _interesting(p: str) -> bool:
        return p and not any(p == s.rstrip("/") or p.startswith(s)
                             for s in _SYS_PREFIXES)
    paths = set()
    # 1. Script's bin dir.
    if Path(cmd0).is_absolute():
        bin_dir = str(Path(cmd0).resolve().parent)
        if _interesting(bin_dir):
            paths.add(bin_dir)
    # 2. Read shebang to find the interpreter.
    interp = None
    try:
        with open(cmd0, "rb") as f:
            first_line = f.readline().decode("utf-8", errors="ignore").strip()
        if first_line.startswith("#!"):
            interp = first_line[2:].split()[0]
    except (OSError, IndexError, UnicodeDecodeError):
        pass
    # 3. Interpreter's bin dir + stdlib dir.
    # CRITICAL: use the UNRESOLVED interp path for stdlib computation,
    # NOT Path.resolve(). Python's sys.prefix is computed from the path
    # used to invoke the interpreter (i.e. sys.executable, which equals
    # the unresolved shebang path). For an interpreter at
    # /home/U/bin/python3.13 that's a symlink to /usr/bin/python3.13,
    # Python sets sys.prefix=/home/U and looks for stdlib at
    # /home/U/lib/python3.13. If we bind-mount the resolved location
    # (/usr/lib/python3.13 — already in mount tree) Python won't find
    # its stdlib because it's looking at sys.prefix-relative path.
    # The bin dir IS still added via Path.resolve() (so symlink targets
    # outside the mount tree get added too), but stdlib derivation
    # MUST follow the unresolved path.
    if interp and Path(interp).is_absolute() and Path(interp).is_file():
        # Bin dir for the interpreter. Add both the resolved AND
        # unresolved bin dirs so we cover the full symlink chain.
        for p in {str(Path(interp).parent), str(Path(interp).resolve().parent)}:
            if _interesting(p):
                paths.add(p)
        # Extract version from interpreter name. Try the SHEBANG name
        # first (typically `python3.13` — version-stamped); fall back
        # to the resolved name if the shebang name lacks a version.
        candidate_names = [Path(interp).name, Path(interp).resolve().name]
        ver = None
        for name in candidate_names:
            m = re.match(r"python(\d+\.\d+)", name)
            if m:
                ver = m.group(1)
                break
        if ver:
            # Stdlib at sys.prefix/lib/pythonX.Y where sys.prefix is
            # derived from the UNRESOLVED interp path (Python's view).
            stdlib = Path(interp).parent.parent / "lib" / f"python{ver}"
            if stdlib.is_dir() and _interesting(str(stdlib)):
                paths.add(str(stdlib))
    return sorted(paths)


def run_single_semgrep(
    name: str,
    config: str,
    repo_path: Path,
    out_dir: Path,
    timeout: int,
    progress_callback: Optional[Callable] = None
) -> Tuple[str, bool]:
    """
    Run a single Semgrep scan.

    Returns:
        Tuple of (sarif_path, success)
    """
    def sanitize_name(name: str) -> str:
        # Strict allowlist: alphanumeric + dash + underscore +
        # dot. Pre-fix only `/` and `:` were replaced — but
        # `name` is the policy-pack name from
        # `RaptorConfig.BASELINE_SEMGREP_PACKS` /
        # `POLICY_GROUP_TO_SEMGREP_PACK` (operator can extend
        # via `--policy-groups`), and the sanitised result
        # becomes part of an output FILE PATH. Any other shell
        # / filesystem-special character (`*`, `?`, `[`, `]`,
        # `\\`, space, NUL, newline, control bytes) flowed
        # straight into `out_dir / f"semgrep_{suffix}.sarif"`.
        # Concrete failure: a custom policy pack named with a
        # space (e.g. `--policy-groups "my pack"`) produced
        # `semgrep_my pack.sarif` — a path with embedded
        # whitespace that subsequent `find` / `glob` calls
        # mishandled (split on whitespace, missing the second
        # half).
        import re as _re
        # Replace any non-allowed char with underscore. Preserve
        # the legacy `/` → `_` and `:` → `_` mapping (those are
        # both in the disallowed set, so they get replaced anyway).
        return _re.sub(r'[^A-Za-z0-9._-]', '_', name)

    suffix = sanitize_name(name)
    sarif = out_dir / f"semgrep_{suffix}.sarif"
    json_out = out_dir / f"semgrep_{suffix}.json"
    stderr_log = out_dir / f"semgrep_{suffix}.stderr.log"
    exit_file = out_dir / f"semgrep_{suffix}.exit"

    logger.debug(f"Starting Semgrep scan: {name}")

    if progress_callback:
        progress_callback(f"Scanning with {name}")

    # Build the semgrep argv via packages/semgrep/. Sandbox engagement,
    # HOME redirect, and registry-pack proxy hosts remain scanner concerns
    # below — packages/semgrep/ is pure invocation logic.
    # Resolve binary explicitly to avoid broken-venv installations.
    semgrep_cmd = shutil.which("semgrep") or "/opt/homebrew/bin/semgrep"
    cmd = semgrep_pkg.build_cmd(
        repo_path,
        config,
        json_output_path=json_out,
        rule_timeout=RaptorConfig.SEMGREP_RULE_TIMEOUT,
        semgrep_bin=semgrep_cmd,
    )

    # Create clean environment without venv contamination or dangerous vars.
    # `VIRTUAL_ENV` and `PYTHONPATH` are now stripped by
    # `get_safe_env()` itself (DANGEROUS_ENV_VARS); the local
    # strips were redundant.
    clean_env = RaptorConfig.get_safe_env()
    # Remove venv from PATH
    if 'PATH' in clean_env:
        path_parts = clean_env['PATH'].split(':')
        path_parts = [p for p in path_parts if 'venv' not in p.lower() and '/bin/pysemgrep' not in p]
        clean_env['PATH'] = ':'.join(path_parts)

    # Redirect HOME into the run's out_dir so semgrep's two stateful
    # files — semgrep.log (operational log) and settings.yml (metrics
    # opt-in, empty after first write) — land inside the sandbox
    # output rather than polluting the user's real ~/.semgrep.
    # semgrep 1.79.0 does NOT persistently cache registry packs on
    # disk — every invocation fetches the pack YAML from semgrep.dev
    # regardless of HOME / cache dir — so the redirect costs us
    # nothing (there's no cache to lose across scans). PR #196 ships
    # pack YAMLs under engine/semgrep/rules/registry-cache/ and
    # rewrites `p/security-audit` → local path BEFORE semgrep's
    # registry client runs — post-#196 the fetch path is cold.
    semgrep_home = out_dir / ".semgrep_home"
    semgrep_home.mkdir(parents=True, exist_ok=True)
    clean_env['HOME'] = str(semgrep_home)

    # Registry packs ("p/xxx", "category/xxx") fetch YAML from semgrep.dev
    # on every invocation — semgrep has no persistent on-disk cache. A slow
    # or stalled registry fetch otherwise consumes the full SEMGREP_TIMEOUT
    # (15 min) per pack, and at MAX_SEMGREP_WORKERS=4 can eat the whole
    # 30-min agentic budget for one bad network moment. Bound the per-pack
    # cost with a tighter ceiling so a stuck fetch drops that pack and the
    # remaining packs still run. Local rule directories keep the longer
    # timeout because they do real scan work without network.
    is_registry_pack = config.startswith("p/") or config.startswith("category/")
    effective_timeout = min(timeout, RaptorConfig.SEMGREP_PACK_TIMEOUT) if is_registry_pack else timeout

    try:
        # Engage Landlock via target + output. Writes pinned to out_dir
        # and /tmp. Reads Landlock-default-wide (semgrep is a
        # RAPTOR-chosen trusted tool, not attacker-controlled code).
        # Network: route via the egress proxy with the resolved
        # allowlist — UDP blocked, hostname-allowlisted,
        # resolved-IP-screened by the proxy's is_global check.
        # Allowlist pulled from ._proxy_hosts (override → calibrate
        # → static default) so operators on Semgrep self-hosted /
        # corporate registry mirrors can override without source
        # edits. See packages/static-analysis/_proxy_hosts.py.
        #
        # ``static-analysis`` is hyphenated → not importable as a
        # Python package; scanner.py runs as ``__main__`` via
        # subprocess. Load the helper via importlib at call time
        # to match the existing convention (see tests under
        # packages/static-analysis/tests/ for the same pattern).
        import importlib.util as _importlib_util
        _ph_path = Path(__file__).parent / "_proxy_hosts.py"
        _ph_spec = _importlib_util.spec_from_file_location(
            "static_analysis_proxy_hosts", _ph_path,
        )
        _ph = _importlib_util.module_from_spec(_ph_spec)
        _ph_spec.loader.exec_module(_ph)
        rc, so, se = run(
            cmd, timeout=effective_timeout, env=clean_env,
            target=str(repo_path), output=str(out_dir),
            proxy_hosts=_ph.proxy_hosts_for_semgrep(),
            caller_label="scanner-semgrep",
        )

        # Validate output
        if not so or not so.strip():
            logger.warning(f"Semgrep scan '{name}' produced empty output")
            so = '{"runs": []}'

        # Explicit `encoding="utf-8"` on all three writes. Pre-fix
        # bare `write_text(...)` used `locale.getpreferredencoding()`
        # which returns cp1252/latin-1 on some hosts. Semgrep's SARIF
        # output is UTF-8 by spec; writing it back in cp1252 would
        # mojibake non-ASCII rule descriptions and snippet text. The
        # downstream SARIF parser then either failed schema validation
        # OR silently fed mojibake into LLM analysis prompts.
        # `errors="replace"` belt-and-braces against a stray non-UTF-8
        # byte sequence in the semgrep stdout (shouldn't happen but
        # we don't want a single bad byte to crash the write).
        sarif.write_text(so, encoding="utf-8", errors="replace")
        stderr_log.write_text(se or "", encoding="utf-8", errors="replace")
        exit_file.write_text(str(rc), encoding="utf-8")

        # Validate SARIF — tri-state result:
        #   True  → full schema validation passed
        #   False → load failed or schema rejected the structure
        #   None  → basic shape OK but full schema check couldn't run
        #           (jsonschema not installed, schema file missing)
        # Treat None as trust-with-warning rather than rejection;
        # the basic-shape check (load + version + runs field) is
        # already strict enough to catch malformed semgrep output.
        is_valid = validate_sarif(sarif)
        if is_valid is False:
            logger.warning(f"Semgrep scan '{name}' produced invalid SARIF")
        elif is_valid is None:
            logger.debug(
                f"Semgrep scan '{name}': SARIF basic shape OK but full "
                "schema validation skipped (jsonschema or schema file unavailable)"
            )

        success = rc in (0, 1) and is_valid is not False
        logger.debug(f"Completed Semgrep scan: {name} (exit={rc}, valid={is_valid})")

        return str(sarif), success

    except Exception as e:
        logger.error(f"Semgrep scan '{name}' failed: {e}")
        # Write empty SARIF on error. Same encoding posture as the
        # success path above — explicit UTF-8 so the downstream
        # parser sees a consistent byte shape regardless of host
        # locale.
        sarif.write_text('{"runs": []}', encoding="utf-8")
        stderr_log.write_text(str(e), encoding="utf-8", errors="replace")
        exit_file.write_text("-1", encoding="utf-8")
        return str(sarif), False


def semgrep_scan_parallel(
    repo_path: Path,
    rules_dirs: List[str],
    out_dir: Path,
    timeout: int = RaptorConfig.SEMGREP_TIMEOUT,
    progress_callback: Optional[Callable] = None
) -> List[str]:
    """
    Run Semgrep scans in parallel for improved performance.

    Args:
        repo_path: Path to repository to scan
        rules_dirs: List of rule directory paths
        out_dir: Output directory for results
        timeout: Timeout per scan
        progress_callback: Optional callback for progress updates

    Returns:
        List of SARIF file paths
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build config list with BOTH local rules AND standard packs for each category
    configs: List[Tuple[str, str]] = []
    added_packs = set()  # Track which standard packs we've added to avoid duplicates

    # Add local rules + corresponding standard packs for each specified category
    for rd in rules_dirs:
        rd_path = Path(rd)
        if rd_path.exists():
            category_name = rd_path.name

            # Add local rules for this category
            configs.append((f"category_{category_name}", str(rd_path)))

            # Add corresponding standard pack if available
            if category_name in RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK:
                pack_name, pack_id = RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK[category_name]
                if pack_id not in added_packs:
                    resolved = RaptorConfig.get_semgrep_config(pack_id)
                    configs.append((pack_name, resolved))
                    added_packs.add(pack_id)
                    logger.debug(f"Added standard pack for {category_name}: {resolved}")
        else:
            logger.warning(f"Rule directory not found: {rd_path}")

    # Add baseline packs (unless already added)
    for pack_name, pack_identifier in RaptorConfig.BASELINE_SEMGREP_PACKS:
        if pack_identifier not in added_packs:
            configs.append((pack_name, RaptorConfig.get_semgrep_config(pack_identifier)))
            added_packs.add(pack_identifier)

    logger.info(f"Starting {len(configs)} Semgrep scans in parallel (max {RaptorConfig.MAX_SEMGREP_WORKERS} workers)")
    logger.info(f"  - Local rule directories: {len([c for c in configs if c[0].startswith('category_')])}")
    logger.info(f"  - Standard/baseline packs: {len([c for c in configs if not c[0].startswith('category_')])}")

    # Run scans in parallel
    sarif_paths: List[str] = []
    failed_scans: List[str] = []

    with ThreadPoolExecutor(max_workers=RaptorConfig.MAX_SEMGREP_WORKERS) as executor:
        future_to_config = {
            executor.submit(
                run_single_semgrep,
                name,
                config,
                repo_path,
                out_dir,
                timeout,
                progress_callback
            ): (name, config)
            for name, config in configs
        }

        completed = 0
        total = len(future_to_config)

        for future in as_completed(future_to_config):
            name, config = future_to_config[future]
            completed += 1

            try:
                sarif_path, success = future.result()
                sarif_paths.append(sarif_path)

                if not success:
                    failed_scans.append(name)

                if progress_callback:
                    progress_callback(f"Completed {completed}/{total} scans")

            except Exception as exc:
                logger.error(f"Semgrep scan '{name}' raised exception: {exc}")
                failed_scans.append(name)

    if failed_scans:
        logger.warning(f"Failed scans: {', '.join(failed_scans)}")

    logger.info(f"Completed {len(sarif_paths)} scans ({len(failed_scans)} failed)")
    return sarif_paths


def semgrep_scan_sequential(
    repo_path: Path,
    rules_dirs: List[str],
    out_dir: Path,
    timeout: int = RaptorConfig.SEMGREP_TIMEOUT
) -> List[str]:
    """Sequential scanning fallback for debugging."""
    out_dir.mkdir(parents=True, exist_ok=True)
    sarif_paths: List[str] = []

    # Build config list with BOTH local rules AND standard packs for each category
    configs: List[Tuple[str, str]] = []
    added_packs = set()  # Track which standard packs we've added to avoid duplicates

    # Add local rules + corresponding standard packs for each specified category
    for rd in rules_dirs:
        rd_path = Path(rd)
        if rd_path.exists():
            category_name = rd_path.name

            # Add local rules for this category
            configs.append((f"category_{category_name}", str(rd_path)))

            # Add corresponding standard pack if available
            if category_name in RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK:
                pack_name, pack_id = RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK[category_name]
                if pack_id not in added_packs:
                    resolved = RaptorConfig.get_semgrep_config(pack_id)
                    configs.append((pack_name, resolved))
                    added_packs.add(pack_id)

    # Add baseline packs (unless already added)
    for pack_name, pack_identifier in RaptorConfig.BASELINE_SEMGREP_PACKS:
        if pack_identifier not in added_packs:
            configs.append((pack_name, RaptorConfig.get_semgrep_config(pack_identifier)))
            added_packs.add(pack_identifier)

    for idx, (name, config) in enumerate(configs, 1):
        logger.info(f"Running scan {idx}/{len(configs)}: {name}")
        sarif_path, success = run_single_semgrep(name, config, repo_path, out_dir, timeout)
        sarif_paths.append(sarif_path)

    return sarif_paths


def run_codeql(
    repo_path: Path,
    out_dir: Path,
    languages: Optional[List[str]] = None,
    build_command: Optional[str] = None,
) -> List[str]:
    """Delegate CodeQL analysis to packages/codeql/agent.py.

    Pre-unification this module shipped its own ~80-LOC WIP CodeQL
    runner alongside the proper one in `packages/codeql/`. The two
    diverged: the in-tree runner had no auto-detection (operator
    had to hard-code the language list), no build-system detection
    or synthesis (compiled C/C++ projects without a Makefile got
    silent extraction failures), no content-addressed DB cache, no
    target-repo trust check, no language alias normalisation
    (PR #448), and a hard-coded query-dir path that broke if the
    operator wasn't standing in repo root. The packages/codeql/
    runner has all of those.

    The two paths converge here: scanner.py invokes the proper
    agent as a subprocess (mirroring how raptor_agentic.py runs it
    at line 743). Output naming is identical — the agent writes
    `codeql_<lang>.sarif` per detected language under `out_dir`,
    matching the previous in-tree runner's convention so downstream
    consumers (SARIF merge, coverage records) are unchanged.

    Args:
        repo_path: Repository to scan.
        out_dir: Directory for SARIF + report outputs.
        languages: Explicit language list. None ⇒ auto-detect
            (recommended; the agent picks up everything in the
            repo and skips empty languages, vs the pre-unification
            "always create cpp/java/python/go DBs whether the repo
            has those files or not" approach).
        build_command: Optional CodeQL build command override
            (e.g. for compiled languages with non-standard layouts).

    Returns:
        List of absolute SARIF paths the agent wrote. Empty on any
        failure (logged); never raises.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    if shutil.which("codeql") is None:
        logger.warning("codeql CLI not on PATH; skipping CodeQL stage")
        return []

    # repo root → packages/codeql/agent.py. scanner.py lives at
    # packages/static-analysis/scanner.py so parents[2] is repo root.
    script_root = Path(__file__).resolve().parents[2]
    agent_script = script_root / "packages" / "codeql" / "agent.py"
    if not agent_script.exists():
        logger.warning(
            f"codeql agent script missing at {agent_script}; skipping CodeQL stage"
        )
        return []

    cmd = [
        sys.executable,
        str(agent_script),
        "--repo", str(repo_path),
        "--out", str(out_dir),
    ]
    if languages:
        cmd.extend(["--languages", ",".join(languages)])
    if build_command:
        cmd.extend(["--build-command", build_command])

    logger.info(f"Delegating CodeQL stage to {agent_script.name}")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=3600,
        )
    except subprocess.TimeoutExpired:
        logger.warning("codeql agent timed out after 3600s; skipping")
        return []
    except OSError as e:
        logger.warning(f"failed to invoke codeql agent: {e}")
        return []

    if proc.returncode != 0:
        # Surface the agent's stderr tail so the operator can see
        # WHY the run failed — language detection miscount, build
        # synthesis failure, trust-check rejection. Same truncation
        # rationale as before — codeql error output can run
        # thousands of lines.
        stderr_tail = (proc.stderr or proc.stdout or "").strip()
        if len(stderr_tail) > 2000:
            stderr_tail = "..." + stderr_tail[-2000:]
        logger.warning(
            f"codeql agent exited rc={proc.returncode}. "
            f"Last stderr: {stderr_tail or '<empty>'}"
        )
        # Don't return early — the agent may have produced partial
        # SARIFs (one language succeeded, another failed). Glob and
        # return whatever's there.

    # Glob for the agent's SARIF outputs. Naming matches the old
    # in-tree runner so downstream code (SARIF merge, coverage
    # records, _classify_artifact) needs no changes.
    sarif_paths = sorted(str(p) for p in out_dir.glob("codeql_*.sarif"))
    return sarif_paths


def _sarif_has_findings(sarif_path: Path) -> bool:
    """Return True iff the SARIF file contains at least one result.

    Failures (missing file, unparseable JSON) return False — callers treat
    "unknown" the same as "empty" because the goal is opportunistic cleanup.
    """
    try:
        data = json.loads(sarif_path.read_text())
    except Exception:
        return False
    for run_obj in data.get("runs", []) or []:
        if run_obj.get("results"):
            return True
    return False


def cleanup_per_pack_artifacts(out_dir: Path) -> int:
    """Remove redundant per-pack semgrep files after combined.sarif is written.

    Per-pack files (semgrep_<suffix>.{exit,json,sarif,stderr.log}) are
    intermediate: combined.sarif is the canonical post-merge artefact, and
    scan_metrics.json captures the per-run accounting. Keep the minimum
    needed for post-mortem of failed packs.

    Cleanup rules (per pack):
      - Always remove: .exit, .json, empty .stderr.log
      - On exit==0: also remove .sarif
      - On exit!=0: keep .exit, keep non-empty .stderr.log, keep .sarif if
        it has findings; delete the .sarif if it is empty/zero-results
        (still redundant — combined.sarif holds those results too)

    Strict glob (semgrep_*.{exit,json,sarif,stderr.log}) and os.unlink
    only — never follow symlinks or recurse.

    Returns the number of files removed.
    """
    removed = 0
    # Group by suffix using a strict glob set.
    suffixes: set = set()
    for ext in (".exit", ".json", ".sarif", ".stderr.log"):
        for p in out_dir.glob(f"semgrep_*{ext}"):
            # glob does not follow symlinks for matching, but the resolved
            # entry might still be one — defend with is_symlink check.
            if p.is_symlink() or not p.is_file():
                continue
            name = p.name[len("semgrep_"):-len(ext)]
            if name:
                suffixes.add(name)

    for suffix in suffixes:
        exit_file = out_dir / f"semgrep_{suffix}.exit"
        json_file = out_dir / f"semgrep_{suffix}.json"
        sarif_file = out_dir / f"semgrep_{suffix}.sarif"
        stderr_file = out_dir / f"semgrep_{suffix}.stderr.log"

        # Read exit code BEFORE any deletion.
        exit_code: Optional[int]
        try:
            exit_code = int(exit_file.read_text().strip())
        except Exception:
            exit_code = None

        success = exit_code == 0

        # Always delete: .json (intermediate machine output)
        for victim in (json_file,):
            try:
                if victim.is_file() and not victim.is_symlink():
                    os.unlink(victim)
                    removed += 1
            except FileNotFoundError:
                pass
            except OSError as e:
                logger.debug(f"cleanup: could not remove {victim}: {e}")

        # Empty stderr — always delete
        try:
            if (stderr_file.is_file() and not stderr_file.is_symlink()
                    and stderr_file.stat().st_size == 0):
                os.unlink(stderr_file)
                removed += 1
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.debug(f"cleanup: could not stat/remove {stderr_file}: {e}")

        if success:
            # On success, .exit and .sarif are both redundant (combined.sarif
            # is canonical and metrics record the success).
            for victim in (exit_file, sarif_file):
                try:
                    if victim.is_file() and not victim.is_symlink():
                        os.unlink(victim)
                        removed += 1
                except FileNotFoundError:
                    pass
                except OSError as e:
                    logger.debug(f"cleanup: could not remove {victim}: {e}")
        else:
            # Failed pack: keep .exit. Keep .sarif only if it has findings;
            # otherwise it is redundant noise (an empty {"runs":[]} stub).
            if sarif_file.is_file() and not sarif_file.is_symlink():
                if not _sarif_has_findings(sarif_file):
                    try:
                        os.unlink(sarif_file)
                        removed += 1
                    except OSError as e:
                        logger.debug(
                            f"cleanup: could not remove {sarif_file}: {e}"
                        )

    if removed:
        logger.info(
            f"Cleaned up {removed} redundant per-pack scan files in {out_dir}"
        )
    return removed


def _count_sarif_results(sarif_data) -> int:
    """Return the total number of results across runs in a parsed SARIF dict.

    Tolerates malformed shapes — non-dict / non-list members count as zero
    rather than raising. This is a provenance signal, not a validator.
    """
    if not isinstance(sarif_data, dict):
        return 0
    total = 0
    for run_obj in sarif_data.get("runs", []) or []:
        if not isinstance(run_obj, dict):
            continue
        results = run_obj.get("results") or []
        if isinstance(results, list):
            total += len(results)
    return total


def _pack_provenance_from_sarif(sarif_path: Path, out_dir: Path) -> dict:
    """Compute provenance for one per-pack SARIF.

    MUST be called before cleanup_per_pack_artifacts() runs, because
    cleanup deletes the per-pack SARIF / .exit / .stderr.log it depends on.

    Returns a dict with keys:
        tool, name, exit, findings, sarif_sha256, stderr_size_bytes
    Missing-file and parse failures degrade to safe defaults rather
    than raising — provenance is best-effort.
    """
    p = Path(sarif_path)
    stem = p.stem  # e.g. "semgrep_category_auth" or "codeql_cpp"
    if stem.startswith("semgrep_"):
        tool = "semgrep"
        name = stem[len("semgrep_"):]
    elif stem.startswith("codeql_"):
        tool = "codeql"
        name = stem[len("codeql_"):]
    else:
        tool = "unknown"
        name = stem

    # Hash + size + findings — read bytes once.
    try:
        raw = p.read_bytes()
        sarif_sha256 = sha256_bytes(raw)
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            data = None
        findings = _count_sarif_results(data) if data is not None else 0
    except OSError:
        # Missing (FileNotFoundError) or unreadable (EACCES, EIO, …)
        # — best-effort provenance, leave hash empty.
        sarif_sha256 = ""
        findings = 0

    # Exit code: only semgrep packs write a .exit file. CodeQL only emits
    # a SARIF on rc==0 (run_codeql appends only on success), so 0 is
    # accurate when we can see the SARIF.
    if tool == "semgrep":
        exit_file = out_dir / f"{stem}.exit"
        try:
            exit_code = int(exit_file.read_text().strip())
        except (OSError, ValueError):
            exit_code = -1
    else:
        exit_code = 0

    # Stderr size: again, semgrep-specific. CodeQL doesn't emit one in
    # the per-pack pattern; report 0.
    stderr_log = out_dir / f"{stem}.stderr.log"
    try:
        stderr_size = stderr_log.stat().st_size
    except (OSError, FileNotFoundError):
        stderr_size = 0

    return {
        "tool": tool,
        "name": name,
        "exit": exit_code,
        "findings": findings,
        "sarif_sha256": sarif_sha256,
        "stderr_size_bytes": stderr_size,
    }


def _compose_verification_manifest(
    sarif_inputs, combined_sarif: Path, out_dir: Path,
) -> dict:
    """Build the verification.json provenance manifest.

    Computes per-pack hashes from the per-pack SARIFs while they're still
    on disk — caller MUST invoke this before cleanup_per_pack_artifacts().
    """
    packs = [_pack_provenance_from_sarif(Path(p), out_dir) for p in sarif_inputs]

    combined: dict = {"path": combined_sarif.name}
    try:
        raw = combined_sarif.read_bytes()
        combined["sha256"] = sha256_bytes(raw)
        combined["size_bytes"] = len(raw)
    except FileNotFoundError:
        combined["sha256"] = ""
        combined["size_bytes"] = 0

    return {
        "schema_version": 1,
        "combined_sarif": combined,
        "packs": packs,
    }


def main():
    ap = argparse.ArgumentParser(description="RAPTOR Automated Code Security Agent with parallel scanning")
    ap.add_argument("--repo", required=True, help="Path or Git URL")
    # Argparse accepts BOTH the hyphenated (`--policy-version`,
    # `--policy-groups`) and underscore (`--policy_version`,
    # `--policy_groups`) forms. The hyphenated form is canonical
    # — matches the rest of the CLI surface (`--no-sandbox`,
    # `--audit-verbose`) and POSIX convention. Underscore form
    # retained as alias because docs/scripts in the wild used
    # the underscore variant before this PR; removing them
    # would break operator workflows that hard-coded the old
    # spelling.
    ap.add_argument(
        "--policy-version", "--policy_version",
        default=RaptorConfig.DEFAULT_POLICY_VERSION,
        dest="policy_version",
    )
    ap.add_argument(
        "--policy-groups", "--policy_groups",
        default=RaptorConfig.DEFAULT_POLICY_GROUPS,
        dest="policy_groups",
        help="Comma-separated list of rule group names (e.g. crypto,secrets,injection,auth,all)",
    )
    ap.add_argument(
        "--codeql", action="store_true",
        help="Run CodeQL stage. Delegates to packages/codeql/agent.py — the "
             "same engine /codeql uses (auto-language-detection, build "
             "synthesis, content-addressed DB cache, trust check). Off by "
             "default to keep /scan fast; use --no-codeql to assert opt-out.",
    )
    ap.add_argument(
        "--no-codeql", action="store_true",
        help="Explicitly disable the CodeQL stage. Takes precedence over "
             "--codeql. Useful in scripts that want a guaranteed Semgrep-only "
             "scan regardless of what defaults change in future.",
    )
    ap.add_argument(
        "--languages",
        help="Comma-separated language list for CodeQL (e.g. cpp,java). "
             "Operator-friendly aliases (c, c++, js, ts, c#, kt, py) are "
             "normalised. Default: auto-detect, which only creates DBs for "
             "languages actually present in the repo.",
    )
    ap.add_argument(
        "--build-command",
        help="Override CodeQL's build command for compiled languages. "
             "Forwarded to packages/codeql/agent.py --build-command.",
    )
    ap.add_argument("--keep", action="store_true", help="Keep temp working directory")
    ap.add_argument("--sequential", action="store_true", help="Disable parallel scanning (for debugging)")
    ap.add_argument("--out", default=None, help="Output directory (from lifecycle). Overrides auto-generated path.")

    from core.sandbox import add_cli_args, apply_cli_args
    add_cli_args(ap)
    args = ap.parse_args()
    apply_cli_args(args, parser=ap)

    start_time = time.time()
    tmp = Path(tempfile.mkdtemp(prefix="raptor_auto_"))
    repo_path = None

    logger.info(f"Starting automated code security scan")
    logger.info(f"Repository: {args.repo}")
    logger.info(f"Policy version: {args.policy_version}")
    logger.info(f"Policy groups: {args.policy_groups}")

    try:
        # Acquire repository
        if args.repo.startswith(("http://", "https://", "git@")):
            repo_path = tmp / "repo"
            clone_repository(args.repo, repo_path)
        else:
            repo_path = Path(args.repo).resolve()
            if not repo_path.exists():
                raise RuntimeError(f"repository path does not exist: {repo_path}")

        # Determine local rule directories
        groups = [g.strip() for g in args.policy_groups.split(",") if g.strip()]
        rules_base = RaptorConfig.SEMGREP_RULES_DIR
        _EXCLUDED_RULE_DIRS = {"registry-cache"}
        if "all" in groups:
            rules_dirs = [
                str(p) for p in sorted(rules_base.iterdir())
                if p.is_dir() and p.name not in _EXCLUDED_RULE_DIRS
            ]
        else:
            valid, unknown = [], []
            for g in groups:
                p = rules_base / g
                if g in _EXCLUDED_RULE_DIRS:
                    logger.warning(f"Policy group '{g}' is reserved and cannot be used directly")
                elif p.is_dir():
                    valid.append(str(p))
                else:
                    unknown.append(g)
            if unknown:
                logger.warning(f"Unknown policy groups (no rule directory found): {', '.join(unknown)}")
            rules_dirs = valid

        logger.info(f"Using {len(rules_dirs)} rule directories")

        # Output directory: use --out if provided (lifecycle), otherwise generate
        if args.out:
            out_dir = Path(args.out)
        else:
            repo_name = repo_path.name
            # Collision-prevention via unique_run_suffix — see core/run/output.py.
            out_dir = RaptorConfig.get_out_dir() / f"scan_{repo_name}_{unique_run_suffix('_')}"
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        safe_run_mkdir(out_dir)

        # Make record_denial calls (proxy events, generic Landlock
        # denials) write to THIS subprocess's out_dir. Without this,
        # active_run_dir is None → record_denial is no-op → events
        # silently dropped. The lifecycle hook in raptor.py wires
        # this for top-level invocations; for the agentic flow,
        # scanner.py runs as a subprocess and must wire it itself.
        # summarize_and_write at end-of-main converts the JSONL to
        # sandbox-summary.json.
        from core.sandbox.summary import set_active_run_dir
        set_active_run_dir(out_dir)

        # Manifest
        logger.info("Computing repository hash...")
        repo_hash = sha256_tree(repo_path)

        manifest = {
            "agent": "auto_codesec",
            "version": "2.0.0",  # Updated version with parallel scanning
            "repo_path": str(repo_path),
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "input_hash": repo_hash,
            "policy_version": args.policy_version,
            "policy_groups": groups,
            "parallel_scanning": not args.sequential,
        }
        save_json(out_dir / "scan-manifest.json", manifest)

        # Semgrep stage - Use parallel scanning by default
        logger.info("Starting Semgrep scans...")
        if args.sequential:
            # Fallback to sequential for debugging
            logger.warning("Sequential scanning enabled (slower)")
            semgrep_sarifs = semgrep_scan_sequential(repo_path, rules_dirs, out_dir)
        else:
            semgrep_sarifs = semgrep_scan_parallel(repo_path, rules_dirs, out_dir)

        # CodeQL stage (optional). --no-codeql takes precedence —
        # script-friendly so a default-flip from "off" to "on" can
        # be opted out of without code changes.
        codeql_sarifs = []
        run_codeql_stage = args.codeql and not args.no_codeql
        if run_codeql_stage:
            languages = (
                [s.strip() for s in args.languages.split(",") if s.strip()]
                if args.languages else None  # None ⇒ agent auto-detects
            )
            codeql_sarifs = run_codeql(
                repo_path, out_dir,
                languages=languages,
                build_command=args.build_command,
            )

        # Merge SARIFs if more than one
        sarif_inputs = semgrep_sarifs + codeql_sarifs
        merged = out_dir / "combined.sarif"
        if sarif_inputs:
            logger.info(f"Merging {len(sarif_inputs)} SARIF files...")
            try:
                merged_data = merge_sarif([str(p) for p in sarif_inputs])
                save_json(merged, merged_data)
                logger.info(f"Merged SARIF created: {merged}")
            except Exception as e:
                logger.warning(f"SARIF merge failed, using individual files: {e}")
                (out_dir / "sarif_merge.stderr.log").write_text(str(e))

        # Generate metrics
        logger.info("Generating scan metrics...")
        metrics = generate_scan_metrics(sarif_inputs)
        save_json(out_dir / "scan_metrics.json", metrics)

        logger.info(f"Scan complete: {metrics['total_findings']} findings in {metrics['total_files_scanned']} files")

        # Write coverage records and derive total_files_scanned from them
        try:
            from core.coverage.record import (
                build_from_semgrep, build_from_codeql, write_record, load_records,
            )
            # Semgrep coverage — find JSON outputs alongside SARIFs
            for sarif_path in semgrep_sarifs:
                json_path = Path(sarif_path).with_suffix(".json")
                if json_path.exists():
                    record = build_from_semgrep(
                        out_dir, json_path,
                        rules_applied=groups if groups else [str(Path(r).name) for r in rules_dirs],
                    )
                    if record:
                        write_record(out_dir, record, tool_name="semgrep")
                        break  # one record covers all (paths.scanned is cumulative)

            # CodeQL coverage — from SARIF artifacts
            for sarif_path in codeql_sarifs:
                record = build_from_codeql(Path(sarif_path))
                if record:
                    write_record(out_dir, record, tool_name="codeql")
                    break  # one record per run

            # Derive total_files_scanned from coverage records — these are
            # the canonical source of what was examined (not SARIF artifacts,
            # which Semgrep doesn't populate).
            all_covered = set()
            for rec in load_records(out_dir):
                all_covered.update(rec.get("files_examined", []))
            if all_covered:
                metrics["total_files_scanned"] = len(all_covered)
                save_json(out_dir / "scan_metrics.json", metrics)
        except Exception as e:
            logger.debug(f"Coverage record write failed (non-fatal): {e}")

        # Provenance manifest. MUST be composed BEFORE cleanup runs,
        # because cleanup deletes most of the per-pack SARIFs we hash.
        try:
            verification = _compose_verification_manifest(
                sarif_inputs, merged, out_dir,
            )
        except Exception as e:
            logger.debug(f"verification manifest compose failed (non-fatal): {e}")
            verification = {
                "schema_version": 1,
                "combined_sarif": {"path": merged.name, "sha256": "", "size_bytes": 0},
                "packs": [],
            }

        # Per-pack file cleanup. Runs AFTER combined.sarif and
        # scan_metrics.json are finalised. The merged SARIF is canonical;
        # per-pack semgrep_*.{exit,json,sarif,stderr.log} files are
        # intermediate. Keep only what's useful for post-mortem of failed
        # packs (exit code + non-empty stderr + sarif-with-findings).
        try:
            cleanup_per_pack_artifacts(out_dir)
        except Exception as e:
            logger.debug(f"Per-pack cleanup failed (non-fatal): {e}")

        save_json(out_dir / "verification.json", verification)

        duration = time.time() - start_time
        logger.info(f"Total scan duration: {duration:.2f}s")

        # Print coverage summary if checklist exists
        try:
            from core.coverage.summary import compute_summary, format_summary
            cov = compute_summary(out_dir)
            if cov:
                print()
                print(format_summary(cov))
                print()
        except Exception:
            pass

        result = {
            "status": "ok",
            "manifest": manifest,
            "metrics": metrics,
            "duration": duration,
        }
        print(json.dumps(result, indent=2))
        # Aggregate any tracer-emitted .sandbox-denials.jsonl into
        # sandbox-summary.json. The lifecycle hook lives in raptor.py
        # / raptor_agentic.py for top-level invocations — neither
        # covers THIS subprocess's out_dir when scanner.py is invoked
        # as a child of agentic. Without this call, audit JSONL
        # produced inside scanner subprocess (when mount-ns + tracer
        # actually engage for some Semgrep call) would orphan in
        # out_dir/.sandbox-denials.jsonl. No-op if no JSONL was
        # written (the common case today, since Semgrep hits B
        # fallback via Landlock-only).
        try:
            from core.sandbox.summary import summarize_and_write
            summarize_and_write(out_dir)
        except Exception as _e:
            logger.debug("summarize_and_write at end of scanner.py: "
                         "%s", _e, exc_info=True)
        sys.exit(0)
    finally:
        if not args.keep:
            try:
                shutil.rmtree(tmp)
            except Exception:
                pass


if __name__ == "__main__":
    main()
