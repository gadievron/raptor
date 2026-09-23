"""
core/security/codeql_trust.py

Trust check for target-repo CodeQL pack files.

Called before invoking ``codeql database create`` against an untrusted
repo. Returns True if the caller should refuse to dispatch.

**Distinct from cc_trust.** Claude Code config files
(``.claude/settings.json``, ``.mcp.json``) go through ``cc_trust``;
this module is the parallel check for the codeql side.

**Defense-in-depth, not an active channel.** Verified against CLI
2.26.3 under RAPTOR's exact invocation (``database create
--language=<lang> --source-root=<repo> --build-mode=none``, no pack
search flags): the CLI does NOT consume repo-tree pack config at
create time — planted ``qlpack.yml`` files (root, nested, dotted-dir)
are read only as ordinary source data (TRAP/YAML extraction, source
archive, line count); a bogus ``extractor:`` and a ``buildCommand:``
canary produce no resolution, no execution, no log mention; directory
symlinks are never traversed at all; ``.github/codeql/
codeql-config.yml`` is consumed by the GitHub Action (or an explicit
``--codescanning-config``), not by this invocation; caller cwd
placement changes nothing (codeql launches its own children with
cwd=source-root regardless). The gate stays because pack semantics
are version-mobile and the scan is cheap. It becomes load-bearing
again if ANY of these change:
  - a target-repo-derived value reaches any codeql flag that steers
    extractor/pack/config resolution — ``--search-path`` /
    ``--additional-packs`` / ``--codescanning-config`` (every quoted
    runtime site is pinned with value provenance by
    ``.github/tests/test_codeql_pack_resolution_pins.py``), and the
    same class includes ``--extractor-option(-file)`` and
    ``--extra-tracing-config`` (unused anywhere today);
  - a codeql CLI upgrade adds create-time workspace/pack discovery —
    mechanically reminded: the version-anchor test fails once the
    host CLI outruns ``PACK_PROBE_VERIFIED_CLI``; re-run
    ``core/security/scripts/codeql-pack-probe`` and bump the anchor
    on a clean pass;
  - RAPTOR ever writes per-user codeql config (``~/.config/codeql/
    config`` or ``CODEQL_CONFIG_FILE``): it injects default flags —
    including the class above — into EVERY invocation. The env route
    is already stripped by ``get_safe_env``; the file route needs a
    HOME write, which an untrusted repo cannot do;
  - traced builds are a DIFFERENT channel: build execution is either
    operator-consented (the ``build`` trust marker / traced-build
    flag) or loudly disclosed for languages with no buildless mode —
    and a running build system subsumes anything a pack file could
    add.
For the same reason the walk's documented boundaries (directory
symlinks listed-never-entered; dotted dirs pruned except
``.github``) are accepted blind spots, not bypasses: codeql itself
resolves nothing through them at create time.

Files inspected:
    codeql-pack.yml         (recursive walk, capped)
    qlpack.yml              (recursive walk, capped)
    .github/codeql/codeql-config.yml

Blocking fields in ``codeql-pack.yml`` / ``qlpack.yml``:
    extractor:                     ANY value (codeql may exec this)
    dependencies.<name>            non-canonical (not ``codeql/...``)
    defaultSuiteFile               path-traversing value (escapes pack)
    buildCommand                   subprocess invocation
    setup / preCompileScript /
    postCompileScript              subprocess invocation
    structural: symlink, oversized, malformed → block

Blocking fields in ``codeql-config.yml``:
    packs.<lang>[]                 non-canonical pack reference
    queries[].uses                 external repo / URL reference
    manualBuildSteps / setup       subprocess invocation
    pack-cache                     ANY value (in-repo pack source)
    structural: symlink, oversized, malformed → block

Trust override: same module-flag pattern as cc_trust. ``--trust-repo``
sets it once at entry-point argparse time; this module reads it via
``check_repo_codeql_trust(trust_override=None)``. Deliberately NOT
driven by an env var (target repos can inject env via the build
system; trust must come from explicit operator intent).
"""

from __future__ import annotations

import errno
import logging
import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from core.security.capped_read import read_capped

try:
    import yaml
except ImportError:  # pragma: no cover — yaml is a hard dep elsewhere
    yaml = None

try:
    # Shared hostile-YAML mechanisms (one home, not re-derived here):
    # the quote-blind flow-depth pre-bound refuses loader-stack
    # overflow BEFORE the parser sees the text, and
    # PARSE_ESCAPE_ERRORS names the exception classes that escape
    # PyYAML's own error type on hostile input (RecursionError from
    # deep nesting, ValueError from CPython digit limits).
    from packages.sca._yaml_fast import MAX_FLOW_DEPTH as _MAX_FLOW_DEPTH
    from packages.sca._yaml_fast import _flow_depth_exceeded
    from packages.sca.parsers._base import PARSE_ESCAPE_ERRORS as _YAML_ESCAPE_ERRORS
except ImportError:  # pragma: no cover — packages/ ships beside core/
    # Partial install: the load sites fail CLOSED (uninspectable →
    # blocking finding), never open and never a crash.
    _MAX_FLOW_DEPTH = 0
    _flow_depth_exceeded = None  # type: ignore[assignment]
    _YAML_ESCAPE_ERRORS = (RecursionError, ValueError)

_logger = logging.getLogger(__name__)


if yaml is not None:
    class _AliasRefusingSafeLoader(yaml.SafeLoader):
        """SafeLoader that refuses aliases (and with them merge keys).

        Pack files have no legitimate use for anchors/aliases, and an
        alias chain (``aN: &aN [*a(N-1),*a(N-1)]``) amplifies a
        ~600-byte file into a 2^depth-node graph: ``safe_load`` shares
        the aliased nodes cheaply, and the scanner's later ``str()``
        on an aliased value materialises the full expansion —
        OOM-killing the trust gate in the operator's process BEFORE
        the verdict the gate exists to produce. Refusal surfaces as a
        ``YAMLError``, which the load sites already treat as the
        malformed-YAML blocking finding (fail closed, loud reason).

        Pure-Python ``SafeLoader`` base deliberately: ``CSafeLoader``
        composes in C where this hook never runs, and the pure loader
        turns deep-nesting stack abuse into a catchable
        ``RecursionError`` instead of a native stack overflow.
        """

        def compose_node(self, parent, index):  # type: ignore[no-untyped-def]
            if self.check_event(yaml.events.AliasEvent):
                raise yaml.YAMLError(
                    "YAML alias refused (anchor/alias amplification — "
                    "pack files have no legitimate use for aliases)"
                )
            return super().compose_node(parent, index)


def _load_untrusted_yaml(raw: bytes):  # type: ignore[no-untyped-def]
    """Bounded ``safe_load`` for attacker-supplied pack/config YAML.

    Returns the loaded document; raises ``yaml.YAMLError`` on every
    refusal (flow depth, aliases) so call sites keep their single
    malformed-YAML fail-closed path. Callers must also catch
    ``_YAML_ESCAPE_ERRORS`` — deep-nesting shapes below the pre-bound
    can still surface as ``RecursionError`` from the pure-Python
    loader.
    """
    if _flow_depth_exceeded is None:  # pragma: no cover — partial install
        raise yaml.YAMLError(
            "yaml hostile-input guards unavailable (partial install) — "
            "refusing to inspect"
        )
    # Pre-scan on a lenient decode; the PARSE feed stays the original
    # bytes so encoding strictness (ReaderError on bad UTF-8 → the
    # blocking malformed-YAML path) is unchanged.
    if _flow_depth_exceeded(raw.decode("utf-8", errors="replace")):
        raise yaml.YAMLError(
            f"flow nesting deeper than {_MAX_FLOW_DEPTH} — refusing to "
            "load (deep flow nesting overflows the YAML loader stack)"
        )
    return yaml.load(raw, Loader=_AliasRefusingSafeLoader)


def _scalar_or_shape_finding(
    fs: FileScan, label: str, val: object,
) -> str | None:
    """Type gate before any ``str()`` on an attacker-chosen value.

    Returns the value as ``str`` when it is a plain scalar; otherwise
    appends a blocking ``(unrecognised shape)`` finding WITHOUT
    stringifying the container (belt beside the alias refusal: no
    code path materialises an attacker-shaped graph into a string)
    and returns None.
    """
    if val is None:
        # A null slot (``codeql/cpp-all:`` — dep with no version) is a
        # legitimate scalar absence, not an attacker container.
        return ""
    if isinstance(val, (str, int, float, bool)):
        return str(val)
    fs.findings.append(Finding(
        f"{label} (unrecognised shape)",
        f"({type(val).__name__} value)",
        True,
    ))
    return None


# ---------------------------------------------------------------------------
# Process-wide trust override
# ---------------------------------------------------------------------------

_trust_override_set = False


def set_trust_override(val: bool) -> None:
    """Set process-wide trust override. Call once from each entry point
    that parses ``--trust-repo``. Idempotent."""
    global _trust_override_set
    _trust_override_set = bool(val)


# ---------------------------------------------------------------------------
# Finding / FileScan dataclasses (parallel to cc_trust)
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """One labelled row in the per-file findings table."""
    label: str
    value: str
    blocking: bool


@dataclass
class FileScan:
    """Findings for one inspected file."""
    path: Path
    findings: list[Finding] = field(default_factory=list)

    def has_blocking(self) -> bool:
        return any(f.blocking for f in self.findings)


# ---------------------------------------------------------------------------
# Constants + helpers
# ---------------------------------------------------------------------------

# The newest codeql CLI release on which core/security/scripts/
# codeql-pack-probe verified that `database create` consumes no
# repo-tree pack config (the module docstring's defense-in-depth
# premise). The version-anchor test
# (.github/tests/test_codeql_cli_version_anchor.py) fails when the
# host CLI is newer at major.minor granularity: re-run the probe;
# bump this on exit 0; a probe exit 1 means the gate became
# load-bearing — revisit the docstring and walk boundaries instead.
PACK_PROBE_VERIFIED_CLI = "2.26.3"

# packages/codeql/.. — three levels up from this file.
_RAPTOR_DIR = Path(__file__).resolve().parents[2]

# 1 MiB cap on pack files. Real codeql-pack.yml files are <10 KiB; the
# cap exists to bound the YAML parser's memory exposure.
_MAX_CONFIG_BYTES = 1_048_576

# Bound the recursive walk on pathological repos (vendored monorepos
# with thousands of nested pack files). 200 hits + early break is
# enough to catch any realistic pack layout while keeping the walk
# bounded.
_MAX_PACK_FILES = 200

# U+2028/U+2029 line-separators slip past Cc/Cf categories but
# render as newlines in terminals — strip them so output can't be
# split by an attacker-supplied label.
# Escaped spellings (matching cc_trust._EXTRA_STRIP): the literal
# characters are invisible in an editor, so a reviewer cannot tell
# the set from a pair of ordinary quoted blanks — and an accidental
# "cleanup" to real spaces would silently disable the defence while
# corrupting every space in sanitised output.
_EXTRA_STRIP = frozenset({"\u2028", "\u2029"})

# CodeQL's canonical (Microsoft-authored) pack namespace. Anything
# outside this namespace is third-party and may carry custom
# extractors / queries.
_CANONICAL_PACK_PREFIX = "codeql/"

# Pack name after the canonical namespace: alnum start, then the
# characters CodeQL pack names actually use. Deliberately excludes
# ``/`` (a second path segment) and a leading ``.`` so shapes like
# ``codeql/../evil-pack`` or ``codeql/.hidden`` can never pass as
# canonical — a bare ``startswith`` prefix test accepted those.
_CANONICAL_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _is_canonical_pack_ref(ref: str) -> bool:
    """True iff ``ref`` is a well-formed ``codeql/<name>[@version][:path]``.

    The version part (after ``@``) is not validated — it never names a
    filesystem path — but the name must be a single sane path segment
    with no traversal, and the optional suite path (after ``:``, the
    codeql-config pack syntax) must stay inside the pack (relative, no
    ``..`` segments).
    """
    if not ref.startswith(_CANONICAL_PACK_PREFIX):
        return False
    rest = ref[len(_CANONICAL_PACK_PREFIX):]
    rest, _, suite_path = rest.partition(":")
    name = rest.split("@", 1)[0]
    if _CANONICAL_NAME_RE.fullmatch(name) is None or ".." in name:
        return False
    if suite_path and (
        suite_path.startswith("/")
        or ".." in suite_path.split("/")
    ):
        return False
    return True


def _safe(s: str) -> str:
    """Strip Unicode control/format chars and line/paragraph separators.
    Same defence as cc_trust._safe — see that docstring for the threat
    model (ANSI escapes, Trojan Source bidi, zero-width chars)."""
    return "".join(
        c if c == "\t" or (
            c not in _EXTRA_STRIP
            and unicodedata.category(c) not in ("Cc", "Cf")
        ) else "?"
        for c in s
    )


def _truncate(s: str, limit: int = 80) -> str:
    safe = _safe(s)
    return safe[:limit] + "..." if len(safe) > limit else safe


def _mask(s: str, keep: int = 8) -> str:
    """Render a command-bearing config value without echoing it.

    Scan output lands on stdout and from there in retained CI logs;
    extractor / build-hook command lines can embed credentials in
    their arguments. Keep a short identifying prefix, redact the
    tail, show the length. Mirrors cc_trust._mask.
    """
    safe = _safe(s)
    if not safe:
        return "(empty)"
    # A prefix of a value no longer than ``keep`` IS the value —
    # fully redact rather than echo it whole.
    prefix = safe[:keep] if 0 < keep < len(safe) else ""
    return f"{prefix}*** ({len(safe)} chars)"


def _path_present(p: Path) -> bool:
    # os.lstat, not pathlib exists()/is_symlink(): their OSError
    # behavior is version-dependent (≤3.12 raises, 3.13+ swallows to
    # False), and False on a probe error waved an uninspectable
    # config file through as absent.
    try:
        os.lstat(p)
        return True
    except OSError as e:
        if e.errno in (errno.ENOENT, errno.ENOTDIR):
            return False
        # EACCES/EIO/...: something is there in a form the probe
        # cannot see. Report present — the per-file scanner then
        # reads it, and an unreadable file is a blocking
        # "oversized/unreadable" finding.
        return True


def _read_capped(path: Path) -> bytes | None:
    """Read up to ``_MAX_CONFIG_BYTES``; delegates the hardened
    open/read to :func:`core.security.capped_read.read_capped`."""
    return read_capped(path, _MAX_CONFIG_BYTES)


# ---------------------------------------------------------------------------
# Per-file scanners
# ---------------------------------------------------------------------------


def _scan_pack_file(path: Path) -> FileScan:
    """Scan a ``codeql-pack.yml`` or ``qlpack.yml``."""
    fs = FileScan(path=path)
    raw = _read_capped(path)
    if raw is None:
        fs.findings.append(
            Finding("oversized/unreadable", _truncate(str(path), 120), True)
        )
        return fs
    if yaml is None:                                    # pragma: no cover
        fs.findings.append(
            Finding("yaml unavailable", "cannot inspect", True)
        )
        return fs
    try:
        doc = _load_untrusted_yaml(raw)
    except (yaml.YAMLError, *_YAML_ESCAPE_ERRORS) as e:
        fs.findings.append(
            Finding("malformed YAML", _truncate(str(e), 120), True)
        )
        return fs
    if not isinstance(doc, dict):
        fs.findings.append(
            Finding("non-dict YAML", _truncate(str(type(doc).__name__), 60), True)
        )
        return fs

    # extractor: ANY value flags for review — codeql may exec this
    # binary/script during DB build. The path is relative to the pack;
    # an attacker-supplied repo could point it anywhere inside the
    # source root.
    if doc.get("extractor"):
        extractor = _scalar_or_shape_finding(fs, "extractor", doc["extractor"])
        if extractor is not None:
            fs.findings.append(
                Finding("extractor", _mask(extractor), True)
            )

    # dependencies: only the canonical ``codeql/`` namespace is allowed
    # without manual review. Third-party packs may bring their own
    # extractors / queries.
    #
    # Codeql's schema names a dict[name->version] but YAML is permissive
    # and we've seen real packs in the wild use a flat list form
    # (``dependencies: ['name@version', ...]``). Handle both — if the
    # ``dependencies`` key is present at all and isn't an empty value,
    # walk every entry. An attacker who can write the pack chooses the
    # form, so we have to inspect both.
    deps = doc.get("dependencies")
    dep_specs: list[tuple[str, str]] = []
    if isinstance(deps, dict):
        for n, v in deps.items():
            name = _scalar_or_shape_finding(fs, "dependency name", n)
            if name is None:
                continue
            ver = _scalar_or_shape_finding(fs, f"dependency {_truncate(name, 60)}", v)
            dep_specs.append((name, ver if ver is not None else ""))
    elif isinstance(deps, list):
        for item in deps:
            name = _scalar_or_shape_finding(fs, "dependency entry", item)
            if name is not None:
                dep_specs.append((name, ""))
    elif deps not in (None, {}, []):
        _scalar_or_shape_finding(fs, "dependencies", deps)
    for n, v in dep_specs:
        if not _is_canonical_pack_ref(n):
            label = f"{n}: {v}" if v else n
            fs.findings.append(
                Finding("non-canonical dep", _truncate(label, 120), True)
            )

    # defaultSuiteFile: relative path to a query suite that codeql will
    # compile + run by default. An attacker-controlled suite can pull
    # in arbitrary queries (which then compile arbitrary QL — extension
    # functions, file I/O via standard library, etc.). Path traversal
    # via ``../`` could also reference suites outside the pack.
    suite = doc.get("defaultSuiteFile")
    if suite:
        s = _scalar_or_shape_finding(fs, "defaultSuiteFile", suite)
        if s is not None and (".." in s or s.startswith("/")):
            fs.findings.append(
                Finding("defaultSuiteFile (escapes pack)",
                        _truncate(s, 120), True)
            )

    # buildCommand / setup hooks — pack-level subprocess invocation.
    # These keys aren't part of the formal codeql-pack schema today,
    # but conservative blocking guards against future schema growth
    # AND against custom/forked codeql distributions.
    for key in ("buildCommand", "setup",
                "preCompileScript", "postCompileScript"):
        if doc.get(key):
            val = _scalar_or_shape_finding(fs, key, doc[key])
            if val is not None:
                fs.findings.append(Finding(key, _mask(val), True))

    return fs


def _scan_codeql_config(path: Path) -> FileScan:
    """Scan a ``.github/codeql/codeql-config.yml``."""
    fs = FileScan(path=path)
    raw = _read_capped(path)
    if raw is None:
        fs.findings.append(
            Finding("oversized/unreadable", _truncate(str(path), 120), True)
        )
        return fs
    if yaml is None:                                    # pragma: no cover
        fs.findings.append(
            Finding("yaml unavailable", "cannot inspect", True)
        )
        return fs
    try:
        doc = _load_untrusted_yaml(raw)
    except (yaml.YAMLError, *_YAML_ESCAPE_ERRORS) as e:
        fs.findings.append(
            Finding("malformed YAML", _truncate(str(e), 120), True)
        )
        return fs
    if not isinstance(doc, dict):
        fs.findings.append(
            Finding("non-dict YAML", _truncate(str(type(doc).__name__), 60), True)
        )
        return fs

    # packs: dict-by-language OR flat list of pack-spec strings.
    # Canonical = ``codeql/<name>``; anything else is third-party.
    packs = doc.get("packs")
    if packs:
        flat: list[str] = []
        if isinstance(packs, dict):
            for refs in packs.values():
                if isinstance(refs, list):
                    flat.extend(str(r) for r in refs if isinstance(r, str))
                elif isinstance(refs, str):
                    flat.append(refs)
        elif isinstance(packs, list):
            flat = [str(r) for r in packs if isinstance(r, str)]
        for ref in flat:
            if not _is_canonical_pack_ref(ref):
                fs.findings.append(
                    Finding("non-canonical pack", _truncate(ref, 120), True)
                )

    # queries: list of {uses: ...} OR string entries. External repo
    # references (``owner/repo`` or URL) bring in arbitrary queries
    # that can abuse extension functions during analysis.
    queries = doc.get("queries")
    if queries:
        entries = queries if isinstance(queries, list) else [queries]
        for e in entries:
            raw_uses = e.get("uses", "") if isinstance(e, dict) else e
            uses = _scalar_or_shape_finding(fs, "queries entry", raw_uses)
            if uses is None:
                continue
            # External: any path containing ``/`` that isn't a relative
            # local reference (``./`` or ``../``).
            if "/" in uses and not uses.startswith(("./", "../")):
                fs.findings.append(
                    Finding("external queries", _truncate(uses, 120), True)
                )

    # manualBuildSteps / setup — subprocess invocation directives.
    for key in ("manualBuildSteps", "setup"):
        if doc.get(key):
            val = _scalar_or_shape_finding(fs, key, doc[key])
            if val is not None:
                fs.findings.append(Finding(key, _mask(val), True))

    # pack-cache: redirects codeql's pack download cache to a custom
    # location. Used legitimately for offline / air-gapped builds, but
    # an attacker-supplied repo could point it at a writable in-repo
    # path pre-stocked with malicious pack content; codeql then
    # "downloads" (i.e. reads) packs from there. Block any value —
    # operator must opt in via --trust-repo if they need it.
    if doc.get("pack-cache"):
        val = _scalar_or_shape_finding(fs, "pack-cache", doc["pack-cache"])
        if val is not None:
            fs.findings.append(
                Finding("pack-cache", _truncate(val, 120), True)
            )

    return fs


# ---------------------------------------------------------------------------
# Top-level scan
# ---------------------------------------------------------------------------


def _scan_repo(resolved_path: str) -> tuple[tuple[FileScan, ...], bool]:
    """Pure scan: returns (scans, any_blocking). Deliberately NOT
    cached. The pack-file set comes from a recursive walk, so no cheap
    fingerprint can prove freshness (a qlpack.yml written deep in the
    tree between two checks would not change any fixed-location stat,
    and a top-level-mtime heuristic misses nested additions entirely) —
    a per-process cache therefore reintroduces the TOCTOU the trust
    gate exists to close: the same process runs untrusted target code
    that can write pack files after the first check. Re-scanning is
    affordable: the check fires once per ``codeql database create``
    (packages/codeql/database_manager.py), and two rglob passes are
    noise next to a DB build measured in minutes. The pack-file-cap
    warning fires on every call, which is at most once per DB create."""
    target = Path(resolved_path)
    # Skip RAPTOR's own repo — RAPTOR ships codeql packs under
    # packages/llm_analysis/codeql_packs/ that would always flag
    # if scanned. Operator running RAPTOR against itself is
    # implicitly trusted.
    if target == _RAPTOR_DIR:
        return ((), False)

    # Walk for pack files. ``pathlib``'s ``**`` follows directory
    # symlinks on every Python before 3.13, so a hostile repo shipping
    # ``dir -> /`` (or a symlink loop) would walk the HOST filesystem
    # at this pre-CodeQL trust gate — unbounded wall time, and
    # out-of-repo qlpack.yml files surfacing as "repo" findings. Walk
    # with ``os.walk(followlinks=False)`` instead: symlinked
    # directories are listed but never entered. Dotted dirs (``.git``,
    # ``.claude/worktrees``) are pruned at walk time except
    # ``.github``, which holds codeql-config.yml legitimately — the
    # same set the old post-match filter skipped (and pruned matches
    # never counted toward the cap). Entries NAMED like a pack file
    # that are symlinks or directories stay in the match set: the
    # per-file scan below marks them blocking (symlink / unreadable),
    # exactly as before. The cap is applied PER PATTERN so a flood of
    # one filename cannot starve enumeration of the other.
    pack_files: list[Path] = []
    capped = False
    # Walk errors are collected, never swallowed: os.walk's default is
    # to skip an unlistable directory silently, so an unreadable (or
    # mid-walk vanishing) subtree yielded a verdict computed from a
    # knowably-incomplete enumeration — the same shape the pack-file
    # cap already treats as blocking below.
    walk_errors = 0

    def _on_walk_error(e: OSError) -> None:
        nonlocal walk_errors
        walk_errors += 1
        # Debug-tier locator (first few only): helps an operator find
        # root-owned or damaged leftovers without a manual find. The
        # blocking finding itself stays a count + fixed text — dir
        # names from the walk are repo-controlled bytes.
        if walk_errors <= 5:
            _logger.debug(
                "codeql trust: pack enumeration error: %s",
                _safe(_truncate(str(getattr(e, "filename", None) or e),
                                200)))

    pattern_names = ("codeql-pack.yml", "qlpack.yml")
    counts = dict.fromkeys(pattern_names, 0)
    try:
        for dirpath, dirnames, filenames in os.walk(
            target, followlinks=False, onerror=_on_walk_error,
        ):
            dirnames[:] = sorted(
                d for d in dirnames
                if not d.startswith(".") or d == ".github"
            )
            entries = set(filenames).union(dirnames)
            for name in pattern_names:
                if name not in entries:
                    continue
                if counts[name] >= _MAX_PACK_FILES:
                    capped = True
                    continue
                pack_files.append(Path(dirpath) / name)
                counts[name] += 1
    except OSError:
        walk_errors += 1

    if capped:
        _logger.warning(
            "CodeQL trust: pack-file scan capped at %d files per "
            "pattern in %s — additional pack files were NOT inspected; "
            "treating the incomplete scan as blocking.",
            _MAX_PACK_FILES, target,
        )

    config_path = target / ".github" / "codeql" / "codeql-config.yml"
    if _path_present(config_path):
        pack_files.append(config_path)

    if not pack_files and not capped and not walk_errors:
        return ((), False)

    scans: list[FileScan] = []
    for path in pack_files:
        # Guarded: pathlib is_symlink() raises on probe errors on
        # ≤3.12. Unprobeable → not a symlink here; the per-file scan
        # below then blocks on the unreadable content.
        try:
            _is_link = path.is_symlink()
        except OSError:
            _is_link = False
        if _is_link:
            fs = FileScan(path=path)
            try:
                tgt = str(path.readlink())
            except OSError:
                tgt = "<unreadable>"
            fs.findings.append(Finding("symlink", _truncate(tgt, 120), True))
            scans.append(fs)
            continue
        if path.name == "codeql-config.yml":
            scanned = _scan_codeql_config(path)
        else:
            scanned = _scan_pack_file(path)
        if scanned.findings:
            scans.append(scanned)

    if capped:
        # Fail closed: a verdict computed from a knowably-incomplete
        # enumeration is not a verdict. Reaching the cap becomes a
        # blocking finding — same shape as a malformed pack file — so
        # the operator sees exactly why the gate refused and can
        # override deliberately (--trust-repo / the project's `config`
        # trust marker) after looking at the concrete findings above.
        # This is an operational gate outcome, not a code verdict:
        # nothing here is persisted to journals or cross-run stores,
        # so a later trusted re-run starts clean.
        capped_scan = FileScan(path=target)
        capped_scan.findings.append(Finding(
            "scan_capped",
            f"more than {_MAX_PACK_FILES} pack files per pattern; "
            "enumeration incomplete — uninspected pack files remain",
            True,
        ))
        scans.append(capped_scan)

    if walk_errors:
        # Same fail-closed shape as scan_capped: an enumeration that
        # skipped subtrees is not a verdict. Unreadable dirs can flip
        # readable between this check and `codeql database create`
        # (the mode-flip variant of the TOCTOU the no-cache docstring
        # describes), so "couldn't look" must not read as "clean".
        err_scan = FileScan(path=target)
        err_scan.findings.append(Finding(
            "scan_incomplete",
            f"{walk_errors} directory error(s) during pack-file "
            "enumeration (unreadable or vanished dirs) — uninspected "
            "subtrees remain",
            True,
        ))
        scans.append(err_scan)

    any_blocking = any(s.has_blocking() for s in scans)
    return (tuple(scans), any_blocking)


def check_repo_codeql_trust(
    repo_path: str,
    trust_override: bool | None = None,
) -> bool:
    """Check target repo for unsafe CodeQL pack config. Returns True if
    DB creation should be refused.

    ``trust_override``:
        None   → read the module-level flag (set by ``set_trust_override``).
                 Production default.
        True   → force trust (warn but never block). Tests, callers with
                 context the module flag doesn't capture.
        False  → force strict. Tests, hard-enforcement code paths.
    """
    if not repo_path:
        return False
    if trust_override is None:
        trust_override = _trust_override_set
    # A SUPPLIED repo the checker cannot resolve or stat is refused,
    # not waved through: these lanes previously returned "clean", but
    # that verdict had examined nothing — a vanished (TOCTOU),
    # mistyped, or pathological path skipped the gate entirely while
    # the caller went on to run `codeql database create` against the
    # same spelling. The trust override downgrades to warn-and-proceed
    # exactly like a real finding. Mirrors cc_trust's gate.
    try:
        resolved = str(Path(repo_path).resolve())
        os.stat(resolved)
    except (ValueError, OSError) as e:
        reason = getattr(e, "strerror", None) or type(e).__name__
        shown = _truncate(_safe(repo_path), limit=200)
        if trust_override:
            print(f"raptor: cannot examine {shown} for CodeQL pack "
                  f"config ({_safe(str(reason))}) — proceeding "
                  f"(trust override active)")
            return False
        print(f"raptor: cannot examine {shown} for CodeQL pack "
              f"config ({_safe(str(reason))}) — treating as dangerous")
        return True
    scans, any_blocking = _scan_repo(resolved)
    if scans:
        target = Path(resolved)
        _render_scan_report(target, scans, any_blocking, trust_override)
    return any_blocking and not trust_override


def _render_scan_report(
    target: Path,
    scans: tuple[FileScan, ...],
    any_blocking: bool,
    trust_override: bool,
) -> None:
    """Pure rendering — separated from ``_scan_repo`` so the scan stays
    side-effect free."""
    safe_target = _safe(str(target))
    if any_blocking:
        if trust_override:
            print(f"raptor: {safe_target} has dangerous CodeQL pack config "
                  f"(trust override active):")
        else:
            print(f"raptor: {safe_target} has dangerous CodeQL pack config:")
    else:
        print(f"raptor: {safe_target} has CodeQL pack config:")

    for fs in scans:
        try:
            rel = fs.path.relative_to(target)
        except ValueError:
            rel = fs.path
        print(f"  {_safe(str(rel))}")
        if not fs.findings:
            continue
        label_w = max(len(f.label) for f in fs.findings) + 2
        for f in fs.findings:
            print(f"    {f.label:<{label_w}}{f.value}")


__all__ = [
    "FileScan",
    "Finding",
    "check_repo_codeql_trust",
    "set_trust_override",
]
