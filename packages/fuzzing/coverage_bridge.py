"""Per-function fuzz coverage bridge (fuzz → audit).

The audit priority scorer, gap computation, and review context all
accept ``coverage-fuzz.json`` — three consumers, historically zero
producers. This module is the producer: after a fuzz campaign, when the
target was built with gcov instrumentation (``.gcno`` files present),
it replays the AFL queue/crash corpus against the instrumented binary,
collects per-function liveness via ``gcov -f``, and writes
``coverage-fuzz.json`` into the run directory where /audit's sibling-
run discovery already looks.

Emitted schema satisfies BOTH existing consumer shapes:

* ``files_examined`` — flat file list (``core.audit.priority.
  load_fuzz_coverage`` file-level "was this file fuzzed at all" set);
* ``files.{path}.functions.{name}`` — per-function records
  (``core.audit.loaders.fuzz_coverage_for`` /
  ``core.audit.gaps._fuzz_info_for``) carrying ``reached``,
  ``iterations``, ``crashes`` and ``harness``.

Degrades gracefully: no gcov instrumentation → no file, no error. All
subprocess execution is injectable for tests (no target execution in
CI).
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.json import save_json
from core.sandbox import SandboxSetupError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

logger = logging.getLogger(__name__)

COVERAGE_FUZZ_FILE = "coverage-fuzz.json"

# Replay is bounded: the queue can hold tens of thousands of inputs and
# each replay is a full target execution.
MAX_REPLAY_INPUTS = 200
_REPLAY_TIMEOUT_S = 5
_GCOV_TIMEOUT_S = 60

# Cap on captured tool output. gcov -f -t reports are proportional to
# source size (low MB at the extreme); anything past the cap is
# adversarial and gets truncated before parsing.
_MAX_CAPTURE_BYTES = 4 * 1024 * 1024

_FUNC_RE = re.compile(r"^Function '(.+)'$")
_FILE_RE = re.compile(r"^File '(.+)'$")
_LINES_RE = re.compile(r"^Lines executed:([\d.]+)% of \d+")


def _default_runner(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    stdin_bytes: bytes | None = None,
    timeout: int = _REPLAY_TIMEOUT_S,
) -> subprocess.CompletedProcess:
    """Run a target-replay or gcov command inside the sandbox.

    Corpus replay executes the UNTRUSTED fuzz target on attacker-derived
    crash/queue bytes — the same trust boundary as the afl-showmap path
    in ``afl_runner``, which runs under ``core.sandbox.run`` with the
    network denied. Mirror it: namespace/Landlock isolation,
    ``block_network=True``, writes confined to the build dir (the
    replay must flush ``.gcda`` counters there), reads limited to the
    tool/binary and corpus-input parents.

    Capture is bounded: replay stdout/stderr is discarded outright
    (nothing consumes it, and a hostile target could otherwise balloon
    memory through ``capture_output``); gcov's parsed report is
    truncated at ``_MAX_CAPTURE_BYTES``.
    """
    from core.sandbox import run as _sandbox_run

    workdir = Path(cwd) if cwd else Path.cwd()
    readable = {str(Path(cmd[0]).resolve().parent)}
    for arg in cmd[1:]:
        try:
            p = Path(arg)
            if p.is_file():
                readable.add(str(p.resolve().parent))
        except OSError:
            continue

    is_gcov = Path(cmd[0]).name == "gcov"
    proc = _sandbox_run(
        cmd,
        block_network=True,
        target=str(workdir),
        output=str(workdir),
        readable_paths=sorted(readable),
        cwd=str(workdir),
        input=stdin_bytes,
        stdout=subprocess.PIPE if is_gcov else subprocess.DEVNULL,
        stderr=subprocess.PIPE if is_gcov else subprocess.DEVNULL,
        timeout=timeout,
        check=False,
        caller_label="fuzz-coverage-bridge",
        sanitise_host_fingerprint=True,
    )
    for stream in ("stdout", "stderr"):
        data = getattr(proc, stream, None)
        if isinstance(data, (bytes, str)) and len(data) > _MAX_CAPTURE_BYTES:
            setattr(proc, stream, data[:_MAX_CAPTURE_BYTES])
    return proc


def find_corpus_inputs(
    out_dir: Path,
    *,
    max_inputs: int = MAX_REPLAY_INPUTS,
) -> list[Path]:
    """Collect AFL queue + crash inputs from a fuzz run directory.

    Crash inputs first (they exercise the interesting paths), then
    queue entries, bounded by ``max_inputs``.
    """
    out_dir = Path(out_dir)
    inputs: list[Path] = []
    seen: set[Path] = set()

    def _add_dir(d: Path) -> None:
        if not d.is_dir():
            return
        for f in sorted(d.iterdir()):
            if len(inputs) >= max_inputs:
                return
            if not f.is_file() or f.name == "README.txt":
                continue
            rp = f.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            inputs.append(f)

    afl_dir = out_dir / "afl"
    # The AFL runner writes merged_crashes under its own output dir
    # (<out>/afl/merged_crashes) — a bare <out>/merged_crashes is
    # tolerated for operator-staged inputs but never produced.
    _add_dir(out_dir / "merged_crashes")
    _add_dir(afl_dir / "merged_crashes")
    if afl_dir.is_dir():
        for inst in sorted(afl_dir.iterdir()):
            _add_dir(inst / "crashes")
        for inst in sorted(afl_dir.iterdir()):
            _add_dir(inst / "queue")
    # libFuzzer campaigns keep their working corpus and artifacts
    # under <out>/libfuzzer/ — without this branch they replayed zero
    # inputs and the bridge's coverage came only from stale counters.
    libfuzzer_dir = out_dir / "libfuzzer"
    if libfuzzer_dir.is_dir():
        _add_dir(libfuzzer_dir / "crashes")
        _add_dir(libfuzzer_dir / "corpus")
    return inputs


def has_gcov_instrumentation(build_dir: Path) -> bool:
    """True when compile-time gcov artifacts (``.gcno``) exist."""
    build_dir = Path(build_dir)
    if not build_dir.is_dir():
        return False
    try:
        return next(build_dir.rglob("*.gcno"), None) is not None
    except OSError:
        return False


def replay_corpus(
    binary: Path,
    inputs: Iterable[Path],
    *,
    input_mode: str = "file",
    build_dir: Path | None = None,
    runner: Callable = _default_runner,
) -> int:
    """Replay corpus inputs against the instrumented binary.

    ``input_mode`` mirrors the AFL runner's notion: ``"file"`` passes
    the input path as argv (the ``@@`` convention), anything else
    feeds bytes on stdin. Returns the number of successful replays.
    Individual replay failures (crashes included — crashing inputs
    still flush partial coverage on modern gcc) are survivable.
    """
    binary = Path(binary)
    replayed = 0
    for inp in inputs:
        try:
            if input_mode == "file":
                runner(
                    [str(binary), str(inp)],
                    cwd=build_dir,
                    timeout=_REPLAY_TIMEOUT_S,
                )
            else:
                runner(
                    [str(binary)],
                    cwd=build_dir,
                    stdin_bytes=inp.read_bytes(),
                    timeout=_REPLAY_TIMEOUT_S,
                )
            replayed += 1
        except (subprocess.TimeoutExpired, OSError):
            continue
        except SandboxSetupError:
            # Sandbox isolation could not engage — fail loud rather
            # than silently skipping every input (mirrors the
            # afl-showmap sibling; the orchestrator surfaces this as
            # a bridge failure and no unsandboxed replay happens).
            raise
        except Exception:
            logger.debug("replay failed for %s", inp, exc_info=True)
            continue
    return replayed


def parse_gcov_function_report(text: str) -> dict[str, dict[str, bool]]:
    """Parse ``gcov -f`` stdout into ``{file: {function: reached}}``.

    gcov emits per-function blocks (``Function 'name'`` followed by a
    ``Lines executed:`` line) and then the owning ``File 'path'``
    block. Functions are attributed to the next ``File`` line seen.
    """
    result: dict[str, dict[str, bool]] = {}
    pending: dict[str, bool] = {}
    current_name: str | None = None
    is_function = False

    for raw in text.splitlines():
        line = raw.strip()
        m = _FUNC_RE.match(line)
        if m:
            current_name = m.group(1)
            is_function = True
            continue
        m = _FILE_RE.match(line)
        if m:
            file_path = m.group(1)
            if pending:
                bucket = result.setdefault(file_path, {})
                for fn, reached in pending.items():
                    bucket[fn] = bucket.get(fn, False) or reached
                pending = {}
            current_name = None
            is_function = False
            continue
        m = _LINES_RE.match(line)
        if m and is_function and current_name is not None:
            pending[current_name] = float(m.group(1)) > 0.0
            current_name = None
            is_function = False
    return result


def collect_gcov_function_coverage(
    build_dir: Path,
    *,
    source_root: Path | None = None,
    runner: Callable = _default_runner,
) -> dict[str, dict[str, bool]]:
    """Run ``gcov -f`` over every ``.gcda`` and merge per-function
    liveness, keyed by source path (relative to ``source_root`` when
    the path resolves inside it)."""
    build_dir = Path(build_dir)
    merged: dict[str, dict[str, bool]] = {}
    gcda_files = sorted(build_dir.rglob("*.gcda"))
    if not gcda_files:
        return merged

    for gcda in gcda_files:
        try:
            proc = runner(
                ["gcov", "-f", "-t", str(gcda)],
                cwd=gcda.parent,
                timeout=_GCOV_TIMEOUT_S,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        except SandboxSetupError:
            raise  # fail loud — see replay_corpus
        except Exception:
            logger.debug("gcov failed for %s", gcda, exc_info=True)
            continue
        stdout = proc.stdout
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        parsed = parse_gcov_function_report(stdout or "")
        for file_path, funcs in parsed.items():
            key = _normalise_source_path(
                file_path, gcda.parent, source_root,
            )
            bucket = merged.setdefault(key, {})
            for fn, reached in funcs.items():
                bucket[fn] = bucket.get(fn, False) or reached
    return merged


def _normalise_source_path(
    file_path: str,
    gcov_cwd: Path,
    source_root: Path | None,
) -> str:
    """Make gcov's file path relative to the source root when possible."""
    if source_root is None:
        return file_path
    try:
        p = Path(file_path)
        if not p.is_absolute():
            p = (gcov_cwd / p).resolve()
        return str(p.relative_to(Path(source_root).resolve()))
    except (ValueError, OSError):
        return file_path


def build_fuzz_coverage(
    function_coverage: dict[str, dict[str, bool]],
    *,
    iterations: int = 0,
    crashes: int = 0,
    crash_functions: set[str] | None = None,
    harness: str = "afl",
) -> dict[str, Any]:
    """Assemble the combined ``coverage-fuzz.json`` document.

    ``iterations`` is the campaign's total executions, attributed to
    reached functions (the demotion gate downstream asks "was this
    function exercised a lot and never crashed"). Unreached functions
    carry ``reached: False`` and zero iterations — the boost signal
    ("fuzzing can't see it, audit should"). Campaign-level crashes are
    only attributed per-function via ``crash_functions`` (from crash
    triage); unattributed crashes stay in ``meta``.
    """
    crash_functions = crash_functions or set()
    files: dict[str, Any] = {}
    files_examined: list[str] = []
    for file_path in sorted(function_coverage):
        funcs = function_coverage[file_path]
        entry: dict[str, Any] = {}
        any_reached = False
        for name in sorted(funcs):
            reached = bool(funcs[name])
            any_reached = any_reached or reached
            entry[name] = {
                "reached": reached,
                "iterations": iterations if reached else 0,
                "crashes": crashes if name in crash_functions else 0,
                "harness": harness,
            }
        files[file_path] = {"functions": entry}
        if any_reached:
            files_examined.append(file_path)

    # tool/timestamp make this a first-class coverage record: without
    # them core.coverage.record.load_records skipped the file entirely,
    # so fuzz runtime coverage never reached the durable store or the
    # coverage summary's runtime category. functions_analysed carries
    # the reached functions so the store gets function-precise
    # runtime-tested marks (the registry classifies "fuzz" as runtime;
    # audit gap suppression is llm/analysed-gated, so fuzz reach never
    # counts as review).
    return {
        "tool": "fuzz",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": files_examined,
        "functions_analysed": [
            {"file": file_path, "function": name}
            for file_path, data in sorted(files.items())
            for name, info in sorted(data["functions"].items())
            if info["reached"]
        ],
        "files": files,
        "meta": {
            "producer": "raptor-fuzz",
            "generated_at": int(time.time()),
            "total_execs": iterations,
            "campaign_crashes": crashes,
            "harness": harness,
        },
    }


def write_fuzz_coverage(out_dir: Path, coverage: dict[str, Any]) -> Path:
    """Write ``coverage-fuzz.json`` into the run directory."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / COVERAGE_FUZZ_FILE
    save_json(path, coverage)
    return path


def emit_fuzz_coverage(
    out_dir: Path,
    *,
    binary: Path,
    source_root: Path | None = None,
    input_mode: str = "file",
    iterations: int = 0,
    crashes: int = 0,
    crash_functions: set[str] | None = None,
    build_dir: Path | None = None,
    max_inputs: int = MAX_REPLAY_INPUTS,
    harness: str = "afl",
    runner: Callable = _default_runner,
) -> Path | None:
    """End-to-end producer: replay corpus, collect gcov, write file.

    Returns the written path, or None when the target carries no gcov
    instrumentation (the common case — degrade silently) or nothing
    was collected.
    """
    binary = Path(binary)
    # Env-build campaigns hand a source DIRECTORY as the target path.
    # A directory cannot be replayed, and defaulting build_dir to its
    # PARENT would rglob the operator's surrounding tree — a sibling
    # project's gcov artifacts would then masquerade as this
    # campaign's coverage.
    if not binary.is_file():
        logger.debug(
            "fuzz coverage bridge: %s is not an executable file "
            "(directory/env-build target) — skipping", binary,
        )
        return None
    build_dir = Path(build_dir) if build_dir else binary.parent
    if not has_gcov_instrumentation(build_dir):
        logger.debug(
            "fuzz coverage bridge: no .gcno under %s — skipping",
            build_dir,
        )
        return None

    # Start replay from zeroed counters: .gcda files accumulate across
    # every execution of the instrumented binary (build-time test
    # suites, previous bridge runs), and gcov merges them — leftover
    # counters would be attributed to THIS campaign. The .gcno graph
    # files stay; the target recreates .gcda on first replay.
    removed = 0
    for gcda in build_dir.rglob("*.gcda"):
        try:
            gcda.unlink()
            removed += 1
        except OSError:
            logger.debug("could not remove stale counter %s", gcda)
    if removed:
        logger.info(
            "fuzz coverage bridge: cleared %d pre-existing .gcda "
            "counter file(s) under %s", removed, build_dir,
        )

    inputs = find_corpus_inputs(out_dir, max_inputs=max_inputs)
    if inputs:
        replayed = replay_corpus(
            binary,
            inputs,
            input_mode=input_mode,
            build_dir=build_dir,
            runner=runner,
        )
        logger.info(
            "fuzz coverage bridge: replayed %d/%d corpus inputs",
            replayed,
            len(inputs),
        )

    function_coverage = collect_gcov_function_coverage(
        build_dir, source_root=source_root, runner=runner,
    )
    if not function_coverage:
        logger.debug("fuzz coverage bridge: gcov produced no data")
        return None

    coverage = build_fuzz_coverage(
        function_coverage,
        iterations=iterations,
        crashes=crashes,
        crash_functions=crash_functions,
        harness=harness,
    )
    path = write_fuzz_coverage(out_dir, coverage)
    n_reached = sum(
        1
        for f in coverage["files"].values()
        for rec in f["functions"].values()
        if rec["reached"]
    )
    n_total = sum(
        len(f["functions"]) for f in coverage["files"].values()
    )
    logger.info(
        "fuzz coverage bridge: %d/%d functions reached across %d files "
        "→ %s",
        n_reached,
        n_total,
        len(coverage["files"]),
        path,
    )
    return path


# ── binary-target coverage (no source instrumentation) ─────────────

#: Per-trace-file size cap and total-dump/address caps: the fuzz out
#: dir is target-writable during a campaign, so a hostile target can
#: plant arbitrarily large "traces".
MAX_TRACE_FILE_BYTES = 64 * 1024 * 1024
MAX_TRACE_FILES = 20
MAX_TRACE_ADDRESSES = 2_000_000


def find_pc_dumps(out_dir: Path) -> list[Path]:
    """PC-trace artifacts a fuzz run may have produced or an operator
    dropped in: drcov logs (DynamoRIO/Frida) and sancov dumps.
    Oversized files are skipped with a log line; at most
    ``MAX_TRACE_FILES`` are returned."""
    out_dir = Path(out_dir)
    dumps: list[Path] = []
    for pattern in ("**/*.drcov", "**/drcov*.log", "**/*.sancov"):
        dumps.extend(out_dir.glob(pattern))
    kept = []
    for dump in sorted(set(dumps)):
        try:
            if dump.stat().st_size > MAX_TRACE_FILE_BYTES:
                logger.warning(
                    "PC trace %s over %d MiB — skipped",
                    dump, MAX_TRACE_FILE_BYTES >> 20,
                )
                continue
        except OSError:
            continue
        kept.append(dump)
        if len(kept) >= MAX_TRACE_FILES:
            logger.warning(
                "PC trace count capped at %d — remaining dumps "
                "ignored", MAX_TRACE_FILES,
            )
            break
    return kept


def _span_hits(pcs, spans, starts) -> int:
    """How many PCs land inside checklist function ranges."""
    import bisect
    n = 0
    for pc in pcs:
        i = bisect.bisect_right(starts, pc) - 1
        if i >= 0 and spans[i][0] <= pc <= spans[i][1]:
            n += 1
    return n


#: Base-inference bounds: sample cap keeps the vote O(sample x spans);
#: the quorum and validated-hit dominance keep a noise-built base from
#: being trusted (a wrong base would attribute coverage to functions
#: that never ran, which downstream reads as reviewed-adjacent signal).
_BASE_SAMPLE_CAP = 800
_BASE_VOTE_QUORUM = 8
_BASE_CANDIDATES = 5
_BASE_HIT_DOMINANCE = 1.25
_PAGE = 0x1000
#: Spans wider than this take no part in base voting: function sizes
#: ride the attacker-controlled symtab, and one forged multi-GiB span
#: would turn the per-(pc, span) interval walk into a CPU/memory sink
#: (millions of page candidates per pair). Real functions fit easily.
_BASE_VOTE_MAX_SPAN = 256 * _PAGE
#: Hit-validation sample for candidate SELECTION; the winner is then
#: re-scored on the full PC set once.
_BASE_VALIDATE_CAP = 200_000


def _base_candidates(pcs, spans) -> list:
    """Vote page-aligned base candidates for a PIE module's PCs.

    sancov dumps carry runtime addresses with no module map; for a
    PIE binary under ASLR they miss every file-relative checklist
    range. The true base B satisfies ``pc - B in [start, end]`` for
    the function containing each PC, so every (pc, span) pair votes
    for the page-aligned values of ``pc - end .. pc - start``. Raw
    vote counts alone cannot be trusted: regularly spaced function
    layouts produce harmonic aliases one page off the true base —
    the caller validates candidates by actual rebased hit-rate.
    Returns up to _BASE_CANDIDATES quorum-reaching candidates.
    """
    from collections import Counter
    sample = sorted(pcs)
    if len(sample) > _BASE_SAMPLE_CAP:
        stride = -(-len(sample) // _BASE_SAMPLE_CAP)
        sample = sample[::stride][:_BASE_SAMPLE_CAP]
    votes: Counter = Counter()
    for pc in sample:
        for start, end, _name in spans:
            if end - start >= _BASE_VOTE_MAX_SPAN:
                continue  # forged-size defence — see constant note
            lo = pc - end
            hi = pc - start
            if hi < 0:
                continue
            b = (lo + _PAGE - 1) & ~(_PAGE - 1)
            while b <= hi:
                if b > 0:
                    votes[b] += 1
                b += _PAGE
    return [b for b, n in votes.most_common(_BASE_CANDIDATES)
            if n >= _BASE_VOTE_QUORUM]


def _resolve_sancov_view(pcs, spans, starts):
    """Pick the usable interpretation of a sancov PC set.

    Returns ``(addresses, inferred_base)``. Direct (file-relative)
    view wins when it lands; otherwise a per-trace base inference is
    attempted — per-trace because every dump comes from its own
    process with its own ASLR base. The rebased view is accepted only
    when it strictly beats the direct view and reaches at least three
    distinct functions; anything weaker keeps the honest no-signal
    behaviour.
    """
    direct = _span_hits(pcs, spans, starts)
    if direct >= max(1, len(pcs) // 4):
        return pcs, None
    # An intra-module shift is not a load base: a file-relative dump
    # whose checklist covers only part of the module would otherwise
    # vote its own out-of-checklist PCs into a small bogus "base" that
    # re-attributes coverage to functions that never ran. A real PIE
    # load base sits beyond the module's file-address extent.
    min_base = spans[-1][1] + 1
    sample = sorted(pcs)
    if len(sample) > _BASE_VALIDATE_CAP:
        stride = -(-len(sample) // _BASE_VALIDATE_CAP)
        sample = sample[::stride][:_BASE_VALIDATE_CAP]
    scored = []
    for base in _base_candidates(pcs, spans):
        if base < min_base:
            continue
        shifted = [pc - base for pc in sample]
        scored.append((_span_hits(shifted, spans, starts), base))
    scored.sort(reverse=True)
    if not scored:
        return pcs, None
    _sample_hits, base = scored[0]
    rebased = {pc - base for pc in pcs}
    rehits = _span_hits(rebased, spans, starts)
    # The rebased view must clear the SAME evidence bar the direct
    # view is held to — merely beating a failed direct view is how
    # partial-checklist dumps got misattributed.
    if rehits <= direct or rehits < max(3, len(pcs) // 4):
        return pcs, None
    # Validated-hit dominance over the runner-up candidate: harmonic
    # aliases of regular layouts survive the vote but lose on actual
    # range hits; a near-tie means ambiguity — refuse, don't guess.
    if len(scored) > 1 and _sample_hits < scored[1][0] * _BASE_HIT_DOMINANCE:
        return pcs, None
    import bisect
    funcs = set()
    for pc in rebased:
        i = bisect.bisect_right(starts, pc) - 1
        if i >= 0 and spans[i][0] <= pc <= spans[i][1]:
            funcs.add(spans[i][2])
    if len(funcs) < 3:
        return pcs, None
    return rebased, base


def emit_binary_fuzz_coverage(
    out_dir: Path,
    *,
    binary: Path,
    checklist: dict | None = None,
    iterations: int = 0,
    crashes: int = 0,
    harness: str = "afl",
) -> Path | None:
    """Fuzz coverage for BINARY targets: PC traces → function map.

    Uninstrumented binaries have no gcov; what a fuzz run can produce
    (QEMU/Frida modes) or an operator can drop in are PC traces —
    drcov or sancov dumps. Those PCs map onto the binary checklist's
    address ranges (the same coordinate system the coverage store
    uses for ``binary:`` items), yielding the per-function
    ``coverage-fuzz.json`` the audit's priority scorer and the store
    already consume. Returns None when there are no traces or no
    binary checklist to map onto — never guesses.
    """
    from core.coverage.collect import parse_drcov, parse_sancov

    out_dir = Path(out_dir)
    binary = Path(binary)

    if checklist is None:
        checklist = _load_binary_checklist(out_dir)
    file_entry = _binary_file_entry(checklist, binary)
    if file_entry is None:
        logger.debug(
            "binary fuzz coverage: no binary checklist for %s — skipping",
            binary,
        )
        return None

    dumps = find_pc_dumps(out_dir)
    if not dumps:
        logger.debug("binary fuzz coverage: no PC traces under %s", out_dir)
        return None

    # PC → containing checklist function, via address ranges.
    spans = []
    for item in file_entry.get(
            "items", file_entry.get("functions", [])) or []:
        addr = item.get("address")
        if addr is None:
            continue
        size = item.get("size") or 0
        spans.append((addr, addr + max(size - 1, 0), item.get("name")))
    spans.sort()
    if not spans:
        return None
    starts = [sp[0] for sp in spans]

    addresses: set[int] = set()
    inferred_bases: dict[str, str] = {}
    for dump in dumps:
        try:
            if dump.suffix == ".sancov":
                pcs = set(parse_sancov(dump))
                if pcs:
                    usable, base = _resolve_sancov_view(
                        pcs, spans, starts,
                    )
                    if base is not None:
                        inferred_bases[dump.name] = hex(base)
                        logger.info(
                            "sancov trace %s: inferred PIE base %#x "
                            "(per-trace — each dump has its own "
                            "ASLR base)", dump.name, base,
                        )
                    addresses.update(usable)
            else:
                # drcov: {module_path: {base, offsets}} with
                # module-relative offsets. Keep only the analysed
                # binary's module and try both interpretations
                # (loaded-base + offset for the runtime view, bare
                # offset for PIE file-relative traces) — the
                # checklist range mapping below drops whichever set
                # misses.
                modules = parse_drcov(dump)
                for mod_path, info in modules.items():
                    if Path(mod_path).name != binary.name:
                        continue
                    base = info.get("base") or 0
                    offsets = set(info.get("offsets") or ())
                    if not offsets:
                        continue
                    # One interpretation per trace: rebased
                    # (runtime view) vs bare file-relative offsets.
                    # Unioning them falsely credits functions whose
                    # checklist address happens to collide with the
                    # OTHER interpretation, so keep whichever set
                    # actually lands in the checklist ranges.
                    rebased = {off + base for off in offsets}
                    if base and spans:
                        addresses.update(
                            rebased
                            if _span_hits(rebased, spans, starts)
                            >= _span_hits(offsets, spans, starts)
                            else offsets
                        )
                    else:
                        addresses.update(rebased)
        except Exception:  # noqa: BLE001 — one bad trace must not kill the rest
            logger.debug("unparseable PC trace: %s", dump, exc_info=True)
        if len(addresses) > MAX_TRACE_ADDRESSES:
            logger.warning(
                "PC address set capped at %d — remaining traces "
                "ignored", MAX_TRACE_ADDRESSES,
            )
            break
    if not addresses:
        return None

    import bisect
    reached: dict[str, int] = {}
    for pc in addresses:
        i = bisect.bisect_right(starts, pc) - 1
        if i >= 0 and spans[i][0] <= pc <= spans[i][1]:
            name = spans[i][2]
            reached[name] = reached.get(name, 0) + 1

    if not reached:
        return None

    path_key = file_entry.get("path")
    doc = {
        "tool": "fuzz",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": [path_key],
        "functions_analysed": [
            {"file": path_key, "function": name} for name in sorted(reached)
        ],
        "files": {
            path_key: {
                "functions": {
                    name: {
                        "reached": True,
                        "pcs": count,
                        "iterations": iterations,
                        "crashes": crashes,
                        "harness": harness,
                    }
                    for name, count in sorted(reached.items())
                },
            },
        },
        "meta": {
            "producer": "raptor-fuzz",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_execs": iterations,
            "campaign_crashes": crashes,
            "harness": harness,
            "representation": "pc_trace",
            "trace_files": [str(d) for d in dumps[:20]],
            "pcs_total": len(addresses),
            "inferred_pie_bases": inferred_bases,
        },
    }
    out_path = out_dir / "coverage-fuzz.json"
    save_json(out_path, doc)
    logger.info(
        "binary fuzz coverage: %d PCs over %d trace file(s) → %d/%d "
        "checklist functions reached",
        len(addresses), len(dumps), len(reached), len(spans),
    )
    return out_path


def _load_binary_checklist(out_dir: Path) -> dict | None:
    import json as _json
    for cand in (out_dir / "checklist.json", out_dir.parent / "checklist.json"):
        if cand.is_file():
            try:
                cl = _json.loads(cand.read_text())
            except (OSError, ValueError):
                continue
            if cl.get("target_kind") == "binary":
                return cl
    return None


def _binary_file_entry(checklist: dict | None, binary: Path) -> dict | None:
    if not checklist:
        return None
    try:
        from core.inventory.binary_builder import binary_path_key
        wanted = binary_path_key(binary)
    except ImportError:
        wanted = f"binary:{Path(binary).stem}"
    for fe in checklist.get("files", []):
        if fe.get("path") == wanted:
            return fe
    return None
