"""Track file reads for coverage — test-only Python reimplementation.

The production hook is plugins/coverage/libexec/raptor-hook-read (bash,
runs async via PostToolUse plugin). This module reimplements the same
logic in Python so test_record.py can exercise coverage tracking
in-process without shelling out to the bash hook.

Not used in production. Extension list must stay in sync with the
extension case statement in raptor-hook-read.
"""

import json
import os
import time
import sys
from pathlib import Path

if __name__ == "__main__":
    # Script mode: the repo root must come from RAPTOR_DIR (launcher-
    # provided) — the path-safety rule forbids deriving it from
    # __file__. Production consumers import this module as a package
    # (or use the bash twin) and never hit this branch.
    if "RAPTOR_DIR" not in os.environ:
        sys.exit("RAPTOR_DIR is not set — cannot resolve the repo root")
    sys.path.insert(0, os.environ["RAPTOR_DIR"])

MANIFEST_NAME = ".reads-manifest"

_SOURCE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".h", ".cpp", ".hpp",
    ".cc", ".cxx", ".java", ".go", ".rs", ".rb", ".php", ".cs",
    ".swift", ".kt", ".scala", ".sh", ".bash", ".zsh",
    ".zig", ".nim", ".cr", ".sol", ".dart", ".m", ".mm", ".lua",
    ".pl", ".pm", ".jl", ".ex", ".exs", ".erl", ".hrl",
    ".fs", ".fsi", ".fsx", ".ml", ".mli",
    ".clj", ".cljs", ".cljc", ".groovy", ".gradle",
    ".r", ".hs", ".elm", ".vue", ".svelte", ".astro",
    ".tf", ".tofu", ".nix",
})


def _find_active_run():
    """Find the run directory this session's read should attribute to.

    PRIMARY: the session RUN LEDGER — the hook process inherits the
    launcher-exported RAPTOR_SESSION_PID (env-only resolution is sound
    here because the hook runs inside claude's own environment), and
    the ledger names exactly the runs this session started. Each
    candidate is validated: absolute control-char-free path, a
    self-authenticating `.raptor-run.json` with status=running
    (project dirs are NOT enumerated, so --out and standalone runs
    work), and the run's recorded session_pid equals ours (a run
    resumed BY ANOTHER SESSION no longer belongs to us). Newest valid
    live run wins; when none validates we attribute NOTHING — never
    the global heuristic in-session.

    FALLBACK (no session env — pre-series launchers, bare invocations):
    the historical machine-global route via the .active symlink and
    the newest-running-run scan, unchanged.

    Returns (run_dir, target) or (None, None). The read filter comes
    from the run's own recorded target_path (absent = no filter),
    matching the bash twin (plugins/coverage/libexec/raptor-hook-read
    — keep the two in lock-step).
    """
    session_pid = os.environ.get("RAPTOR_SESSION_PID", "")
    if session_pid.isdigit():
        return _find_session_run(int(session_pid))
    return _find_global_run()


def _find_session_run(session_pid):
    try:
        ledger = (Path.home() / ".local" / "share" / "raptor"
                  / "sessions.d" / f"{session_pid}.run")
        if ledger.stat().st_size > 512 * 1024:
            return None, None  # over the reader budget — like sessions
        text = ledger.read_text(encoding="utf-8")
    except OSError:
        return None, None
    candidates = []
    # Split on "\n" ONLY: str.splitlines() eats "\r" as a separator,
    # which made the CRLF guard below unreachable — the bash twin
    # (while read) keeps the "\r" in the field and drops the line.
    for line in text.split("\n"):
        if "\r" in line:
            continue  # CRLF lines: the bash twin drops them too
        parts = line.split(" ", 3)
        if parts and parts[0] == "pin":
            # Writer invariant: run records render BEFORE pin records,
            # so nothing below a pin line is a run record. The bash
            # twin early-stops here too; without this the twins
            # diverge on a (writer-bug) running-after-pin line.
            break
        if len(parts) != 4 or parts[0] != "running":
            continue
        epoch, run_dir = parts[1], parts[3]
        if (not run_dir.startswith("/") or not run_dir.isprintable()
                or not epoch.isascii() or not epoch.isdigit()):
            continue
        epoch_i = int(epoch)
        if epoch_i >= 2 ** 63:
            continue  # the bash twin's integer test rejects these
        if epoch_i > int(time.time()) + 86400:
            # A skewed-ahead-clock record would out-compete every
            # legitimate run in the newest-running selection until it
            # terminates; the ledger writer clamps these on rewrite,
            # readers skip them meanwhile.
            continue
        candidates.append((epoch_i, run_dir))
    # Newest first; ties keep FILE ORDER (stable sort on the epoch
    # key only) — the bash twin takes the first-listed record on
    # equal epochs, and two runs in one wall-clock second are real.
    candidates.sort(key=lambda c: -c[0])
    for _epoch, run_dir in candidates:
        d = Path(run_dir)
        try:
            meta_path = d / ".raptor-run.json"
            if meta_path.stat().st_size > 1_048_576:
                continue  # attacker-influenced file — never slurp GBs
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        if not isinstance(meta, dict) or meta.get("status") != "running":
            continue
        # String-compare like the bash twin: a metadata writer that
        # stringifies session_pid must not diverge the two consumers.
        if str(meta.get("session_pid")) != str(session_pid):
            continue  # resumed by (or belonging to) another session
        target = meta.get("target_path")
        if not isinstance(target, str):
            target = ""  # typed corruption: attribute without a filter
        elif target and not os.path.isdir(
                os.path.dirname(os.path.realpath(target)) or "/"):
            # Parity with the bash twin's realpath semantics: it
            # FAILS (filter cleared, attribute unfiltered) only when
            # a PARENT component is missing; a missing leaf resolves
            # fine there and keeps the filter. Matching exactly —
            # divergence either way silently changes what a session's
            # reads attribute to.
            target = ""
        return str(d), target
    return None, None


def _find_global_run():
    """Legacy machine-global discovery (no-session fallback only)."""
    active_link = Path.home() / ".raptor" / "projects" / ".active"
    if not active_link.is_symlink():
        return None, None

    try:
        link_target = os.readlink(active_link)
        if not link_target or "/" in link_target or ".." in link_target:
            return None, None
        if link_target.startswith("."):
            return None, None
        project_file = active_link.parent / link_target
        if not project_file.exists():
            return None, None

        data = json.loads(project_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None, None
        project_dir = data.get("output_dir", "")
        target = data.get("target", "")
        if not project_dir or not Path(project_dir).is_dir():
            return None, None

        # Newest running run; stat races skipped per-entry.
        entries = []
        for d in Path(project_dir).iterdir():
            if not d.is_dir() or d.name.startswith((".", "_")):
                continue
            try:
                mtime = d.stat().st_mtime
            except OSError:
                continue
            entries.append((mtime, d))
        for _mtime, d in sorted(entries, key=lambda t: t[0], reverse=True):
            meta_file = d / ".raptor-run.json"
            try:
                # Same 1 MiB gate as the session-ledger lane above —
                # the metadata file is attacker-influenced and this
                # legacy walk must never slurp GBs either.
                if meta_file.stat().st_size > 1_048_576:
                    continue
                meta_text = meta_file.read_text(encoding="utf-8")
            except OSError:
                continue
            try:
                meta = json.loads(meta_text)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(meta, dict):
                continue
            if meta.get("status") == "running":
                return str(d), target

    except (OSError, json.JSONDecodeError, KeyError, TypeError, AttributeError):
        pass

    return None, None


def main() -> None:
    # Find active run via project symlink
    run_dir, target = _find_active_run()
    if not run_dir:
        return

    target = target or ""

    # Read hook payload from stdin. Cap at 1 MB before parsing.
    # Pre-fix `json.load(sys.stdin)` was unbounded — a hostile
    # hook payload (or a Claude Code bug feeding the wrong fd)
    # could pipe gigabytes of data and OOM the hook. Real Read-
    # tool payloads are <2 KB (file_path + cwd + small metadata);
    # 1 MB is a 500x safety margin while bounding pathological
    # input.
    _MAX_STDIN_BYTES = 1 * 1024 * 1024
    try:
        _stdin_text = sys.stdin.read(_MAX_STDIN_BYTES + 1)
    except (OSError, ValueError):
        return
    if len(_stdin_text) > _MAX_STDIN_BYTES:
        return
    try:
        payload = json.loads(_stdin_text or "{}")
    except (json.JSONDecodeError, ValueError):
        return

    file_path = (payload.get("tool_input") or {}).get("file_path", "")
    if not file_path:
        return

    # Reject paths with NUL or line-terminator characters. The
    # manifest is line-delimited, so a `file_path` containing `\n`
    # (a hostile hook payload, or a rare-but-legal filesystem entry
    # name on platforms that allow newlines) splits into multiple
    # manifest entries — downstream parsers see fictitious paths.
    # NUL gets truncated by various C-level readers (the kernel,
    # some Python file APIs in 3.13+) producing a different path
    # than what the hook reported. Reject either up-front rather
    # than corrupting the manifest.
    if "\x00" in file_path or "\n" in file_path or "\r" in file_path:
        return

    # Skip non-source files — and directories named like one (the
    # bash twin has the explicit [ -d ] guard; keep parity).
    dot = file_path.rfind(".")
    if dot == -1 or file_path[dot:].lower() not in _SOURCE_EXTENSIONS:
        return
    if os.path.isdir(file_path):
        return

    # Skip files outside the target directory (path-level check, not string prefix).
    # Substitute `file_path` with the symlink-resolved real path so
    # the manifest records the canonical inventory path. Pre-fix the
    # original (possibly symlinked) `file_path` was written, so when
    # an operator's editor opened `target/symlink_to_handler.py`, the
    # manifest carried that symlink name — but the inventory was
    # built from real files, so the downstream lookup against
    # `symlink_to_handler.py` returned no match and the coverage
    # mark was lost. Recording the realpath fixes the join.
    # Parity with the bash hook's realpath: it FAILS (drops the read)
    # when a PARENT component is missing — recording such paths made
    # phantom manifest entries the inventory join then discarded.
    try:
        _resolved_fp = os.path.realpath(file_path)
        if not os.path.isdir(os.path.dirname(_resolved_fp) or "/"):
            return
    except (OSError, ValueError):
        return

    if target:
        try:
            # Resolve symlinks and check proper path containment
            resolved = _resolved_fp
            resolved_target = os.path.realpath(target)
            prefix = resolved_target + os.sep
            if not resolved.startswith(prefix) and resolved != resolved_target:
                return
            file_path = resolved
        except (OSError, ValueError):
            return

    # Append to manifest with O_NOFOLLOW. Pre-fix `open(..., "a")`
    # followed any symlink at the manifest path — if an attacker
    # (or a careless test fixture) planted a symlink at
    # `<run_dir>/<MANIFEST_NAME>` pointing elsewhere, our writes
    # went to the symlink target. ELOOP from the kernel when the
    # path is a symlink → fall through to the OSError except and
    # silently skip.
    try:
        manifest_path = os.path.join(run_dir, MANIFEST_NAME)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(manifest_path, flags, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(file_path + "\n")
    except OSError:
        pass


if __name__ == "__main__":
    main()
