"""Fidelity-3 preprocessor translation view for /audit.

Runs the real C preprocessor (``gcc -E`` preferred, bare ``cpp`` as
fallback) on a single translation unit and parses the GCC linemarkers
(``# <lineno> "<file>" <flags>``) in the output to build a line map
from the expanded ("fidelity-3") view back to original-file
coordinates.  This is the top rung of the translation-view fidelity
ladder in :mod:`core.inventory.translation_view` — fidelity < 3 blanks
dead arms in-memory with an identity line map; fidelity 3 is the
preprocessor's own output, where the line map is real and may point
into *other* files (headers) under the target root.

Three consumers:

* the expanded view of a whole TU with its line map;
* the expanded text of one function's line range mapped back to
  original coordinates;
* macro-defined function recovery — function definitions that only
  exist post-expansion (generated via macros) returned with
  original-file line attribution so they can feed the inventory.
  Whole categories of code never reach the LLM today because a
  ``DEFINE_HANDLER(name)``-style definition is invisible pre-expansion.

Design constraints (the scanned repo is UNTRUSTED — same posture as
:mod:`core.audit.compiler_sweep`):

* NOTHING from the repo may execute.  No build system is invoked; the
  preprocessor is run directly on exactly one TU and include paths are
  derived mechanically from the directory layout (bounded walk, capped,
  symlinks not followed) via the same helper compiler_sweep uses.
* The preprocessor parses hostile input, so the invocation goes
  through ``core.sandbox.context.run`` with ``block_network=True`` plus
  Landlock target/output confinement.  If the sandbox cannot be
  imported the module refuses to run the preprocessor unsandboxed.
* Preprocess failure (missing generated headers, exotic dialects) is a
  graceful degraded result — ``ok=False`` with the reason — never an
  exception that kills the pipeline and never a fabricated view.
* Only lines mapping back to files under the target root are
  attributable; system-header expansion is noise and is excluded from
  every downstream matching surface (its map entries are ``None``).
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.run.scratch import scratch_dir

from ._util import safe_join
from .compiler_sweep import _derive_include_dirs

logger = logging.getLogger(__name__)

_PREPROCESS_TIMEOUT_S = 60
_PROBE_TIMEOUT_S = 30
_MAX_EXPANDED_BYTES = 16 * 1024 * 1024

_C_SUFFIXES = frozenset({".c", ".h"})
_CXX_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".C", ".hh", ".hpp", ".hxx"})

# C keywords / common non-definition tokens that must never be reported
# as recovered function names.
_C_KEYWORDS = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "default",
    "return", "sizeof", "goto", "break", "continue", "typedef",
    "struct", "union", "enum", "static", "extern", "inline", "const",
    "volatile", "register", "restrict", "void", "int", "char", "long",
    "short", "float", "double", "signed", "unsigned", "defined",
    "_Static_assert", "alignof", "_Alignof", "asm", "__asm__",
    "namespace", "template", "class", "operator", "new", "delete",
    "throw", "catch", "try", "using", "decltype",
})


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class ExpandedView:
    """Fidelity-3 view of one translation unit.

    ``line_map`` is a tuple parallel to ``text.split("\\n")`` — entry
    ``i`` describes expanded line ``i + 1``.  Each entry is either
    ``(original_file_rel, original_line)`` for lines attributable to a
    file under the target root, or ``None`` for system-header /
    builtin expansion (excluded from all downstream matching).
    """

    ok: bool
    file_path: str
    fidelity: int = 3
    text: str = ""
    line_map: tuple = ()
    tool: str = ""
    errors: list = field(default_factory=list)

    def lines(self) -> list:
        return self.text.split("\n") if self.text else []

    def origin_of(self, expanded_line: int) -> tuple | None:
        """(original_file_rel, original_line) for a 1-indexed expanded
        line, or None when out of range / not attributable."""
        idx = expanded_line - 1
        if 0 <= idx < len(self.line_map):
            return self.line_map[idx]
        return None


@dataclass
class FunctionExpansion:
    """Expanded text of one function's original line range.

    ``lines`` is a list of ``(original_line, expanded_text)`` pairs in
    expanded-view order, restricted to lines that map back to the
    requested file and range.
    """

    ok: bool
    file_path: str
    line_start: int
    line_end: int
    lines: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join(t for _ln, t in self.lines)


@dataclass(frozen=True)
class MacroDefinedFunction:
    """A function definition that only exists post-expansion.

    ``file``/``line`` attribute the definition back to the original
    source coordinates (the macro-invocation site), relative to the
    target root.
    """

    name: str
    file: str
    line: int
    signature: str = ""

    def to_checklist_item(self) -> dict:
        """Checklist-item-shaped dict (see core.inventory.extractors)."""
        return {
            "name": self.name,
            "kind": "function",
            "line_start": self.line,
            "line_end": self.line,
            "signature": self.signature,
            "checked_by": [],
            "macro_defined": True,
        }


# ---------------------------------------------------------------------------
# Toolchain probing (once per process, cached)
# ---------------------------------------------------------------------------

_PROBE_LOCK = threading.Lock()
_PROBE_CACHE: dict = {}


def _reset_probe_cache() -> None:
    """Test hook: forget probe results (e.g. after monkeypatching which)."""
    with _PROBE_LOCK:
        _PROBE_CACHE.clear()


def _safe_env() -> dict | None:
    try:
        from core.config import RaptorConfig
        return RaptorConfig.get_safe_env()
    except ImportError:
        return None


def _probe_ok(argv: list) -> bool:
    """Check the preprocessor accepts ``-E`` on RAPTOR-chosen input.

    Probe input is ``/dev/null`` (no repo content), so a plain
    subprocess with the safe env is the right trust level — the
    sandbox is reserved for the real run, which parses hostile source.
    """
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, check=False,
            timeout=_PROBE_TIMEOUT_S, env=_safe_env(),
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _preprocessor_for(is_cxx: bool) -> list | None:
    """Return the preprocessor argv prefix for the TU kind, or None.

    C: ``gcc -E -x c`` preferred, bare ``cpp`` fallback.
    C++: ``g++ -E -x c++`` preferred, ``gcc -E -x c++`` fallback.
    """
    key = "cxx" if is_cxx else "c"
    with _PROBE_LOCK:
        if key in _PROBE_CACHE:
            return _PROBE_CACHE[key]

    result: list | None = None
    if is_cxx:
        candidates = []
        gxx = shutil.which("g++")
        if gxx:
            candidates.append([gxx, "-E", "-x", "c++"])
        gcc = shutil.which("gcc")
        if gcc:
            candidates.append([gcc, "-E", "-x", "c++"])
    else:
        candidates = []
        gcc = shutil.which("gcc")
        if gcc:
            candidates.append([gcc, "-E", "-x", "c"])
        cpp = shutil.which("cpp")
        if cpp:
            candidates.append([cpp, "-x", "c"])
    for cand in candidates:
        if _probe_ok([*cand, os.devnull]):
            result = cand
            break

    with _PROBE_LOCK:
        _PROBE_CACHE[key] = result
    return result


# ---------------------------------------------------------------------------
# Macro configuration → -D/-U flags
# ---------------------------------------------------------------------------

_DEFINE_NAME_RE = re.compile(r"^[A-Za-z_]\w*$")
_FLAG_RE = re.compile(r"^-[DU]")


def _has_control_chars(value: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in value)


def _macro_flags(macro_config: Any) -> list:
    """Convert a macro configuration into validated ``-D``/``-U`` argv.

    Accepts either :class:`core.build.macro_config.MacroConfig` (duck-
    typed: ``.defined`` dict + ``.undefined`` iterable) or a plain
    iterable of ``-DNAME[=VALUE]`` / ``-UNAME`` strings.  Entries that
    fail validation are dropped with a debug log — never raise, never
    pass through control characters.  The argv is list-based and the
    run is sandboxed, so validation here defends the flag surface
    (nothing can smuggle a separate option in) rather than a shell.
    """
    if macro_config is None:
        return []

    flags: list = []

    def _add_define(name: str, value: str | None) -> None:
        if not _DEFINE_NAME_RE.match(name or ""):
            logger.debug("preprocessor_view: dropping invalid define name %r", name)
            return
        if value is None or value == "" or value == "1":
            flags.append(f"-D{name}")
            return
        if _has_control_chars(value):
            logger.debug("preprocessor_view: dropping define %r (control chars)", name)
            return
        flags.append(f"-D{name}={value}")

    def _add_undef(name: str) -> None:
        if not _DEFINE_NAME_RE.match(name or ""):
            logger.debug("preprocessor_view: dropping invalid undef name %r", name)
            return
        flags.append(f"-U{name}")

    defined = getattr(macro_config, "defined", None)
    undefined = getattr(macro_config, "undefined", None)
    if isinstance(defined, dict) or undefined is not None:
        for name in sorted(defined or {}):
            _add_define(name, (defined or {}).get(name))
        for name in sorted(undefined or ()):
            _add_undef(name)
        return flags

    if isinstance(macro_config, (list, tuple)) or (
        isinstance(macro_config, Iterable) and not isinstance(macro_config, str)
    ):
        for raw in macro_config:
            if not isinstance(raw, str) or not _FLAG_RE.match(raw):
                logger.debug("preprocessor_view: dropping macro flag %r", raw)
                continue
            body = raw[2:]
            if raw.startswith("-U"):
                _add_undef(body)
            elif "=" in body:
                name, _, value = body.partition("=")
                _add_define(name, value)
            else:
                _add_define(body, None)
        return flags

    logger.debug("preprocessor_view: unsupported macro_config %r", type(macro_config))
    return []


# ---------------------------------------------------------------------------
# Linemarker parsing
# ---------------------------------------------------------------------------

# GCC linemarker: `# <lineno> "<file>" <flags...>` — flags optional.
_LINEMARKER_RE = re.compile(r'^#\s+(\d+)\s+"((?:[^"\\]|\\.)*)"(?:[ \t\d]*)$')


def _unescape_marker_path(raw: str) -> str:
    """Undo GCC's escaping of ``\\`` and ``"`` in marker filenames."""
    if "\\" not in raw:
        return raw
    out = []
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == "\\" and i + 1 < len(raw):
            out.append(raw[i + 1])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


class _OriginResolver:
    """Resolve marker filenames → attributable target-relative paths.

    ``None`` for builtins (``<built-in>``, ``<command-line>``, ...),
    for anything outside the target root (system headers), and for
    paths that fail to resolve.  Memoised per view build.
    """

    def __init__(self, target_root: Path, workdir: Path):
        self._root = os.path.realpath(target_root)
        self._workdir = workdir
        self._cache: dict = {}

    def resolve(self, marker_file: str) -> str | None:
        if marker_file in self._cache:
            return self._cache[marker_file]
        rel: str | None = None
        if marker_file and not marker_file.startswith("<"):
            p = Path(marker_file)
            if not p.is_absolute():
                p = self._workdir / p
            try:
                real = os.path.realpath(p)
            except OSError:
                real = ""
            if real == self._root:
                rel = "."
            elif real.startswith(self._root + os.sep):
                rel = os.path.relpath(real, self._root).replace(os.sep, "/")
        self._cache[marker_file] = rel
        return rel


def _parse_linemarked_output(
    output: str, target_root: Path, workdir: Path,
) -> tuple:
    """Split preprocessor output into (text, line_map).

    Marker lines are removed from the view; every remaining line gets a
    parallel map entry — ``(file_rel, line)`` when attributable to the
    target root, else ``None``.
    """
    resolver = _OriginResolver(target_root, workdir)
    out_lines: list = []
    line_map: list = []
    cur_file: str | None = None
    cur_line = 0
    for raw in output.split("\n"):
        m = _LINEMARKER_RE.match(raw)
        if m:
            cur_line = int(m.group(1))
            cur_file = resolver.resolve(_unescape_marker_path(m.group(2)))
            continue
        out_lines.append(raw)
        if cur_file is not None and cur_line > 0:
            line_map.append((cur_file, cur_line))
        else:
            line_map.append(None)
        cur_line += 1
    return "\n".join(out_lines), tuple(line_map)


# ---------------------------------------------------------------------------
# Public API (a): whole-TU expanded view
# ---------------------------------------------------------------------------


def _degraded(file_path: str, msg: str, *, tool: str = "") -> ExpandedView:
    logger.debug("preprocessor_view degraded for %s: %s", file_path, msg)
    return ExpandedView(ok=False, file_path=file_path, tool=tool, errors=[msg])


def expand_translation_unit(
    *,
    target_path: Path,
    file_path: str,
    macro_config: Any = None,
    out_dir: Path | None = None,
) -> ExpandedView:
    """Run the preprocessor on one TU and return the fidelity-3 view.

    Args:
        target_path: Root of the (untrusted) target codebase.
        file_path: Relative path to the translation unit.
        macro_config: Optional macro configuration — either a
            :class:`core.build.macro_config.MacroConfig` or an iterable
            of ``-DNAME[=VALUE]`` / ``-UNAME`` strings.
        out_dir: Run output directory — scratch space and the
            sandbox's writable surface.  A temp dir is used when None.

    Returns:
        ExpandedView.  ``ok=False`` (degraded, never an exception, never
        a fabricated view) on preprocess failure, missing tools, missing
        sandbox, non-C/C++ TU, or path escape.
    """
    target_path = Path(target_path)
    full_path = safe_join(target_path, file_path)
    if full_path is None:
        return _degraded(file_path, f"path escapes target: {file_path}")
    if not full_path.is_file():
        return _degraded(file_path, f"file not found: {full_path}")

    suffix = full_path.suffix
    is_c = suffix in _C_SUFFIXES
    is_cxx = suffix in _CXX_SUFFIXES or suffix == ".C"
    if not (is_c or is_cxx):
        return _degraded(
            file_path, f"not a C/C++ translation unit: {suffix or '<no suffix>'}",
        )

    pre = _preprocessor_for(is_cxx)
    if pre is None:
        return _degraded(
            file_path, "no C preprocessor available (need gcc, g++ or cpp)",
        )

    include_dirs = _derive_include_dirs(target_path, full_path.parent)
    include_flags = [f"-I{d}" for d in include_dirs]
    macro_flags = _macro_flags(macro_config)

    scratch_root = str(out_dir) if out_dir else None
    with scratch_dir("preproc_view_", dir=scratch_root) as workdir:
        out_file = workdir / "expanded.i"
        cmd = [
            *pre, *macro_flags, *include_flags,
            str(full_path), "-o", str(out_file),
        ]

        try:
            from core.sandbox.context import run as sandbox_run
        except ImportError:
            # The preprocessor parses hostile source — never run it
            # unsandboxed.
            return _degraded(
                file_path,
                "core.sandbox unavailable — refusing to run the "
                "preprocessor on untrusted source without isolation",
                tool=Path(pre[0]).name,
            )

        try:
            proc = sandbox_run(
                cmd,
                block_network=True,
                target=str(target_path),
                output=str(workdir),
                cwd=str(workdir),
                capture_output=True,
                text=True,
                timeout=_PREPROCESS_TIMEOUT_S,
                caller_label="audit-preprocessor-view",
            )
        except subprocess.TimeoutExpired:
            return _degraded(
                file_path,
                f"preprocessor timed out ({_PREPROCESS_TIMEOUT_S}s)",
                tool=Path(pre[0]).name,
            )
        except (subprocess.SubprocessError, OSError, ValueError, TypeError) as exc:
            return _degraded(
                file_path,
                f"preprocessor invocation failed: {exc}",
                tool=Path(pre[0]).name,
            )

        if proc.returncode != 0:
            # Missing generated headers, dialect gaps, etc.  Degrade,
            # never fabricate a view from partial output.
            stderr = (proc.stderr or "").strip()
            first = "; ".join(stderr.splitlines()[:3]) or f"exit code {proc.returncode}"
            return _degraded(
                file_path,
                f"preprocess failed — no fidelity-3 view: {first}",
                tool=Path(pre[0]).name,
            )

        try:
            if out_file.stat().st_size > _MAX_EXPANDED_BYTES:
                return _degraded(
                    file_path,
                    f"expanded output exceeds {_MAX_EXPANDED_BYTES} bytes",
                    tool=Path(pre[0]).name,
                )
            output = out_file.read_text(errors="replace")
        except OSError as exc:
            return _degraded(
                file_path,
                f"could not read preprocessor output: {exc}",
                tool=Path(pre[0]).name,
            )

        text, line_map = _parse_linemarked_output(output, target_path, workdir)
        return ExpandedView(
            ok=True,
            file_path=file_path,
            text=text,
            line_map=line_map,
            tool=Path(pre[0]).name,
        )


# ---------------------------------------------------------------------------
# Public API (b): one function's expanded range
# ---------------------------------------------------------------------------


def expand_function(
    *,
    target_path: Path,
    file_path: str,
    line_start: int,
    line_end: int,
    macro_config: Any = None,
    out_dir: Path | None = None,
    view: ExpandedView | None = None,
) -> FunctionExpansion:
    """Expanded text of one function's original line range.

    Selects expanded-view lines whose origin maps back to *file_path*
    within ``[line_start, line_end]``, keeping original coordinates.
    Pass a pre-built *view* to avoid re-preprocessing the same TU.
    """
    if view is None:
        view = expand_translation_unit(
            target_path=target_path,
            file_path=file_path,
            macro_config=macro_config,
            out_dir=out_dir,
        )
    if not view.ok:
        return FunctionExpansion(
            ok=False, file_path=file_path,
            line_start=line_start, line_end=line_end,
            errors=list(view.errors),
        )

    tu_rel = file_path.replace(os.sep, "/")
    selected: list = []
    for idx, entry in enumerate(view.line_map):
        if entry is None:
            continue
        origin_file, origin_line = entry
        if origin_file != tu_rel:
            continue
        if line_start and origin_line < line_start:
            continue
        if line_end and origin_line > line_end:
            continue
        selected.append((origin_line, view.lines()[idx]))

    return FunctionExpansion(
        ok=True, file_path=file_path,
        line_start=line_start, line_end=line_end,
        lines=selected,
    )


# ---------------------------------------------------------------------------
# Public API (c): macro-defined function recovery
# ---------------------------------------------------------------------------

# A C function-definition shape in fully-expanded text.  Deliberately
# conservative: return-type tokens, a name, a parameter list without
# nested parens/braces, then an opening brace.  Macro expansion puts a
# whole generated definition on one physical line, which this matches.
_FUNC_DEF_RE = re.compile(
    r"(?m)^[ \t]*(?:[A-Za-z_]\w*[ \t\*]+)+"
    r"([A-Za-z_]\w*)[ \t]*\(([^;{}()]*)\)[ \t\r\n]*\{"
)


def _definition_exists_pre_expansion(name: str, original_text: str) -> bool:
    """Does *original_text* already contain a definition-shaped
    occurrence of *name* before preprocessing?"""
    pat = re.compile(
        rf"(?<!\w){re.escape(name)}\s*\([^;{{}}()]*\)\s*\{{",
    )
    return bool(pat.search(original_text))


def recover_macro_defined_functions(
    *,
    target_path: Path,
    file_path: str,
    macro_config: Any = None,
    out_dir: Path | None = None,
    view: ExpandedView | None = None,
) -> list:
    """Function definitions that only exist post-expansion.

    Returns a list of :class:`MacroDefinedFunction` with original-file
    line attribution (the macro-invocation site).  Only definitions on
    attributable lines (files under the target root) are considered —
    system-header expansion never surfaces here.  Degraded/failed views
    return ``[]``: absence of a view is never treated as evidence.
    """
    target_path = Path(target_path)
    if view is None:
        view = expand_translation_unit(
            target_path=target_path,
            file_path=file_path,
            macro_config=macro_config,
            out_dir=out_dir,
        )
    if not view.ok or not view.text:
        return []

    # Precompute expanded-line offsets for offset → line lookup.
    line_offsets: list = [0]
    for line in view.text.split("\n"):
        line_offsets.append(line_offsets[-1] + len(line) + 1)

    import bisect

    original_cache: dict = {}

    def _original_text(rel: str) -> str:
        if rel not in original_cache:
            resolved = safe_join(target_path, rel)
            try:
                original_cache[rel] = (
                    resolved.read_text(errors="replace") if resolved else ""
                )
            except OSError:
                original_cache[rel] = ""
        return original_cache[rel]

    recovered: list = []
    seen: set = set()
    for m in _FUNC_DEF_RE.finditer(view.text):
        name = m.group(1)
        if name in _C_KEYWORDS or name.lower() in _C_KEYWORDS:
            continue
        # Attribute the definition to the line holding the name itself
        # (the match can start on an earlier line for multi-line heads).
        name_line = bisect.bisect_right(line_offsets, m.start(1)) - 1
        origin = view.origin_of(name_line + 1)
        if origin is None:
            continue
        origin_file, origin_line = origin
        original = _original_text(origin_file)
        if not original:
            continue
        if _definition_exists_pre_expansion(name, original):
            continue
        key = (name, origin_file, origin_line)
        if key in seen:
            continue
        seen.add(key)
        sig = view.lines()[name_line].strip()
        recovered.append(MacroDefinedFunction(
            name=name,
            file=origin_file,
            line=origin_line,
            signature=sig[:200],
        ))

    recovered.sort(key=lambda r: (r.file, r.line, r.name))
    return recovered


# ---------------------------------------------------------------------------
# Inventory feed: checklist augmentation
# ---------------------------------------------------------------------------

# Cheap textual prefilter: an ALL_CAPS macro invocation at column 0
# (the classic ``DEFINE_HANDLER(foo)`` definition-generator shape).
# Files without it are skipped without spawning the preprocessor.
_MACRO_INVOCATION_RE = re.compile(r"(?m)^[A-Z_][A-Z0-9_]{2,}\s*\(")

_AUGMENT_FILE_CAP = 50


def augment_checklist_with_macro_functions(
    checklist: dict,
    target_path: Path,
    *,
    macro_config: Any = None,
    out_dir: Path | None = None,
    scope: Any = None,
    max_files: int = _AUGMENT_FILE_CAP,
) -> int:
    """Add macro-defined functions to a checklist in place.

    Walks the checklist's C/C++ TU entries (``.c`` and C++ TU suffixes;
    headers are covered via the TUs that include them), prefilters to
    files whose raw text shows a definition-generator-shaped macro
    invocation, recovers macro-defined functions and appends them as
    checklist items (``macro_defined: true``).  Bounded by *max_files*
    preprocessor runs.  Returns the number of items added.  Best-effort
    throughout — a failure on one file never aborts the pass.
    """
    scope_tuple = None
    if scope:
        scope_tuple = (scope,) if isinstance(scope, str) else tuple(scope)

    target_path = Path(target_path)
    by_path: dict = {}
    for fe in checklist.get("files") or []:
        p = fe.get("path", "")
        if p:
            by_path[p] = fe

    tu_suffixes = frozenset({".c"}) | (_CXX_SUFFIXES - {".hh", ".hpp", ".hxx"})
    added = 0
    budget = max_files
    for path in by_path:
        if budget <= 0:
            break
        if scope_tuple and not path.startswith(scope_tuple):
            continue
        if Path(path).suffix not in tu_suffixes:
            continue
        resolved = safe_join(target_path, path)
        if resolved is None or not resolved.is_file():
            continue
        try:
            raw = resolved.read_text(errors="replace")
        except OSError:
            continue
        if not _MACRO_INVOCATION_RE.search(raw):
            continue
        budget -= 1
        try:
            recovered = recover_macro_defined_functions(
                target_path=target_path,
                file_path=path,
                macro_config=macro_config,
                out_dir=out_dir,
            )
        except Exception:
            logger.debug(
                "macro recovery failed for %s", path, exc_info=True,
            )
            continue
        for rec in recovered:
            dest = by_path.get(rec.file)
            if dest is None:
                continue
            items = dest.setdefault("items", [])
            if any(it.get("name") == rec.name for it in items):
                continue
            items.append(rec.to_checklist_item())
            added += 1

    if added:
        logger.info(
            "preprocessor_view: recovered %d macro-defined function(s)", added,
        )
    return added
