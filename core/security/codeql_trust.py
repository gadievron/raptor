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
import stat
from pathlib import Path

from core.security._trust_common import (
    _DIR_OBSERVE_FLAGS,
    _FD_OBSERVE_FLAGS,
    GIT_LINK_MAX_BYTES,
    RAPTOR_DIR as _RAPTOR_DIR,
    FileScan,
    Finding,
    is_registered_worktree_of_self as _is_registered_worktree_of_self,
    mask as _mask,
    open_supplied_target,
    read_git_link,
    read_trust_config as _read_capped,
    render_scan_report,
    resolve_supplied_target,
    safe_text as _safe,
    supplied_target_diverged,
    truncate as _truncate,
)

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


# Finding / FileScan result shapes ship from the shared trust-gate
# helper layer (core/security/_trust_common.py), re-exported here for
# this gate's callers (see __all__).


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

# Bound the recursive walk on pathological repos (vendored monorepos
# with thousands of nested pack files). 200 hits + early break is
# enough to catch any realistic pack layout while keeping the walk
# bounded.
_MAX_PACK_FILES = 200

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


# _safe / _truncate / _mask (sanitise, bound, redact — the display
# path every attacker-influencable value rides through), the U+2028/
# U+2029 strip set, and _RAPTOR_DIR (repo-root self-scan skip) live in
# the shared trust-gate helper layer; see core/security/
# _trust_common.py for the threat model.

# Operator-facing subject for this gate's shared renderer / resolve
# gate — names what was scanned.
_SCAN_SUBJECT = "CodeQL pack config"


# ---------------------------------------------------------------------------
# Self-recognition: registered worktrees of RAPTOR's own repo
# ---------------------------------------------------------------------------

# The recognition proof (trusted-side registry enumeration + the
# bidirectional link check, fail closed everywhere) lives in the shared
# trust-gate helper layer — core/security/_trust_common.py,
# ``is_registered_worktree_of_self`` — so BOTH gates (this one and
# cc_trust) run the SAME code and a fix lands once; the divergence
# tripwire (test_trust_gate_crosspin.py) pins the identity. The gate's
# own module-level ``_RAPTOR_DIR`` is passed at each call site, so the
# existing monkeypatch seam keeps working. The aliases below keep the
# historical names importable from this module
# (test_codeql_trust_self_worktree.py imports _GIT_LINK_MAX_BYTES).
_GIT_LINK_MAX_BYTES = GIT_LINK_MAX_BYTES
_read_git_link = read_git_link


# ---------------------------------------------------------------------------
# Per-file scanners
# ---------------------------------------------------------------------------


def _scan_pack_file(
    path: Path,
    *,
    read_name: str | None = None,
    dir_fd: int | None = None,
) -> FileScan:
    """Scan a ``codeql-pack.yml`` or ``qlpack.yml``.

    ``path`` is the DISPLAY path (findings, report rendering). When
    ``dir_fd`` is given the bytes are read via ``read_name`` RELATIVE
    to that already-open directory fd (openat semantics) — the walk's
    live dirfd — so the content observation binds to the directory
    identity the walk enumerated, never to a re-walk of the display
    spelling. Without ``dir_fd`` the display path itself is read
    (direct test calls on standalone files).
    """
    fs = FileScan(path=path)
    src = Path(read_name) if (dir_fd is not None and read_name) else path
    raw = _read_capped(src, dir_fd=dir_fd)
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


def _scan_codeql_config(
    path: Path,
    *,
    read_name: str | None = None,
    dir_fd: int | None = None,
) -> FileScan:
    """Scan a ``.github/codeql/codeql-config.yml``.

    ``path``/``read_name``/``dir_fd`` contract as in
    :func:`_scan_pack_file`: display path, plus an optional
    fd-anchored read of ``read_name`` relative to ``dir_fd``.
    """
    fs = FileScan(path=path)
    src = Path(read_name) if (dir_fd is not None and read_name) else path
    raw = _read_capped(src, dir_fd=dir_fd)
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
    #
    # Accepted asymmetry, recorded: ``./local`` and single-segment
    # in-repo suite refs pass while external refs block, though an
    # in-repo suite wields the same arbitrary-QL power. Latent by
    # construction — RAPTOR only ever runs ``database create``, which
    # does not execute the config's query suites; the packs/extractor
    # arms above cover what CREATE does consult. If a consumer ever
    # runs ``database analyze`` with a repo config, in-repo query
    # refs must start blocking too.
    queries = doc.get("queries")
    if queries:
        entries = queries if isinstance(queries, list) else [queries]
        for e in entries:  # type: ignore[misc]
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


def _scan_repo(
    resolved_path: str,
    *,
    target_fd: int | None,
) -> tuple[tuple[FileScan, ...], bool]:
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
    warning fires on every call, which is at most once per DB create.

    ``target_fd`` is the caller's held observation fd on the target
    (see :func:`check_repo_codeql_trust`): the self-recognition gate
    borrows it, so the trusted-self verdict binds to the same inode
    the caller's divergence bracket checks — no second target open for
    a swap to re-aim between the gate and the bracket — and the pack
    WALK below runs on that same fd (``os.fwalk(dir_fd=...)``), so
    enumeration and every per-file read are anchored to the held inode
    too: a spelling re-aimed mid-scan can neither hide pack files from
    the walk nor substitute the bytes it reads. Required (no default):
    a call site that forgot the fd would silently fall back to the
    gate's own-open shape — the spelling re-walk the held-fd protocol
    exists to remove. With ``target_fd=None`` (tests exercising
    cap/parse behaviour) the scan opens its own observation fd so the
    one fd-anchored code path runs either way.
    """
    target = Path(resolved_path)
    # Skip RAPTOR's own repo — RAPTOR ships codeql packs under
    # packages/llm_analysis/codeql_packs/ that would always flag
    # if scanned. Operator running RAPTOR against itself is
    # implicitly trusted. A git worktree of RAPTOR itself (e.g. a
    # pristine source-only checkout used as an audit target) is the
    # same trust domain — recognised strictly from RAPTOR's OWN
    # worktree registry plus a bidirectional link check, fail closed
    # (_is_registered_worktree_of_self).
    if (target == _RAPTOR_DIR
            or _is_registered_worktree_of_self(
                target, _RAPTOR_DIR, target_fd=target_fd)):
        return ((), False)

    # Walk for pack files, ANCHORED to the held observation fd:
    # ``os.fwalk(".", dir_fd=...)`` enumerates from the held inode (fd
    # semantics throughout — fwalk opens every subdirectory relative to
    # its parent's fd), and each matched entry is classified and read
    # through the live ``dirfd`` the walk yields, so neither the
    # enumeration nor a single content read ever re-walks the target
    # SPELLING. A double swap (decoy in after the held open, original
    # back before the final divergence bracket) that steered the old
    # ``os.walk(target)`` at the decoy's content now observes only the
    # held inode. This pre-CodeQL trust gate faces hostile repos: one
    # shipping ``dir -> /`` (or a symlink loop) must never steer the
    # walk across the HOST filesystem — ``follow_symlinks=False``
    # (fwalk's default) keeps that refusal explicit: symlinked
    # directories are listed but never entered (fwalk confirms each
    # descent by samestat against the pre-descent lstat). Dotted dirs
    # (``.git``, ``.claude/worktrees``) are pruned at walk time except
    # ``.github``, which holds codeql-config.yml legitimately — the
    # same set the old post-match filter skipped (and pruned matches
    # never counted toward the cap). Entries NAMED like a pack file
    # that are symlinks or directories stay in the match set: the
    # per-file scan marks them blocking (symlink / unreadable), exactly
    # as before. The cap is applied PER PATTERN so a flood of one
    # filename cannot starve enumeration of the other.
    scans: list[FileScan] = []
    capped = False
    # Walk errors are collected, never swallowed: fwalk's default is
    # to skip an unlistable directory silently, so an unreadable (or
    # mid-walk vanishing) subtree yielded a verdict computed from a
    # knowably-incomplete enumeration — the same shape the pack-file
    # cap already treats as blocking below. A platform without
    # ``os.fwalk`` (or without dir_fd support under it) lands in the
    # same lane: no enumeration is not a clean enumeration —
    # fail-closed, never a fallback to a spelling re-walk.
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

    def _scan_matched(display: Path, name: str, dirfd: int) -> None:
        """Classify and scan one matched entry THROUGH the live
        directory fd: lstat and readlink relative to ``dirfd`` for the
        symlink finding, capped read relative to ``dirfd`` for the
        content — the display path is never re-opened."""
        try:
            is_link = stat.S_ISLNK(os.lstat(name, dir_fd=dirfd).st_mode)
        except (OSError, NotImplementedError):
            # Unprobeable → not a symlink here; the capped read below
            # settles it fail-closed (unreadable → blocking finding).
            is_link = False
        if is_link:
            fs = FileScan(path=display)
            try:
                tgt = os.fsdecode(os.readlink(name, dir_fd=dirfd))
            except (OSError, NotImplementedError):
                tgt = "<unreadable>"
            fs.findings.append(Finding("symlink", _truncate(tgt, 120), True))
            scans.append(fs)
            return
        if name == "codeql-config.yml":
            scanned = _scan_codeql_config(display, read_name=name,
                                          dir_fd=dirfd)
        else:
            scanned = _scan_pack_file(display, read_name=name, dir_fd=dirfd)
        if scanned.findings:
            scans.append(scanned)

    def _config_component_fd(parent_fd: int, name: str,
                             display: Path) -> int | None:
        """Open one directory component of the codeql-config location
        relative to ``parent_fd`` (O_NOFOLLOW | O_DIRECTORY). None when
        the component is absent (no finding) or refused (blocking
        finding appended): a SYMLINKED component is a blocking finding
        in its own right — the config's consumers resolve the path
        themselves, so a link vetted-by-following here could be
        re-aimed after the check (same doctrine as the cc gate's
        symlinked ``.claude``); an unprobeable/unopenable component is
        fail-closed unreadable, never absent."""
        try:
            st = os.lstat(name, dir_fd=parent_fd)
        except OSError as e:
            if e.errno in (errno.ENOENT, errno.ENOTDIR):
                return None
            fs = FileScan(path=display)
            fs.findings.append(Finding(
                "oversized/unreadable", _truncate(str(display), 120), True))
            scans.append(fs)
            return None
        except NotImplementedError:
            fs = FileScan(path=display)
            fs.findings.append(Finding(
                "oversized/unreadable", _truncate(str(display), 120), True))
            scans.append(fs)
            return None
        if stat.S_ISLNK(st.st_mode):
            fs = FileScan(path=display)
            try:
                tgt = os.fsdecode(os.readlink(name, dir_fd=parent_fd))
            except (OSError, NotImplementedError):
                tgt = "<unreadable>"
            fs.findings.append(Finding("symlink", _truncate(tgt, 120), True))
            scans.append(fs)
            return None
        if not stat.S_ISDIR(st.st_mode):
            # A regular file where a directory component would be:
            # nothing the config location can denote — absent, exactly
            # as the historical ENOTDIR probe reported.
            return None
        try:
            return os.open(name, _DIR_OBSERVE_FLAGS, dir_fd=parent_fd)
        except (OSError, NotImplementedError):
            fs = FileScan(path=display)
            fs.findings.append(Finding(
                "oversized/unreadable", _truncate(str(display), 120), True))
            scans.append(fs)
            return None

    pattern_names = ("codeql-pack.yml", "qlpack.yml")
    counts = dict.fromkeys(pattern_names, 0)

    own_fd: int | None = None
    walk_fd = target_fd
    if walk_fd is None:
        # Test lane (target_fd=None): open our own observation fd so
        # the fd-anchored walk below is the only code path. Unopenable
        # → no enumeration → the walk-error lane blocks below.
        try:
            own_fd = os.open(resolved_path, _FD_OBSERVE_FLAGS)
        except OSError:
            own_fd = None
        walk_fd = own_fd

    try:
        if walk_fd is None or not hasattr(os, "fwalk"):
            walk_errors += 1
        else:
            try:
                for dirpath, dirnames, filenames, dirfd in os.fwalk(
                    ".", onerror=_on_walk_error, follow_symlinks=False,
                    dir_fd=walk_fd,
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
                        _scan_matched(target / dirpath / name, name, dirfd)
                        counts[name] += 1
            except (OSError, NotImplementedError):
                # A non-directory target lands here on the walk's first
                # open (ENOTDIR), same lane as the historical walk's
                # top-level error.
                walk_errors += 1

        if capped:
            _logger.warning(
                "CodeQL trust: pack-file scan capped at %d files per "
                "pattern in %s — additional pack files were NOT "
                "inspected; treating the incomplete scan as blocking.",
                _MAX_PACK_FILES, target,
            )

        # codeql-config.yml at its one fixed location, probed through
        # the held fd component by component (never a path re-walk of
        # the spelling): ``.github`` and ``.github/codeql`` must be
        # real directories reached O_NOFOLLOW-relative to the held
        # root, then the file itself is classified and read relative
        # to the innermost fd.
        if walk_fd is not None:
            gh_display = target / ".github"
            gh_fd = _config_component_fd(walk_fd, ".github", gh_display)
            if gh_fd is not None:
                cq_display = gh_display / "codeql"
                try:
                    cq_fd = _config_component_fd(gh_fd, "codeql", cq_display)
                finally:
                    os.close(gh_fd)
                if cq_fd is not None:
                    try:
                        cfg_absent = False
                        try:
                            os.lstat("codeql-config.yml", dir_fd=cq_fd)
                        except OSError as e:
                            cfg_absent = e.errno in (errno.ENOENT,
                                                     errno.ENOTDIR)
                            # Any other probe error: present-but-
                            # unprobeable — the scan below settles it
                            # fail-closed.
                        except NotImplementedError:
                            pass
                        if not cfg_absent:
                            _scan_matched(
                                cq_display / "codeql-config.yml",
                                "codeql-config.yml", cq_fd)
                    finally:
                        os.close(cq_fd)
    finally:
        if own_fd is not None:
            os.close(own_fd)

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
    # Fail-closed resolve+stat gate (shared helper layer): a SUPPLIED
    # repo the checker cannot resolve or stat is refused, not waved
    # through — the caller would otherwise go on to run `codeql
    # database create` against the same spelling. The trust override
    # downgrades to warn-and-proceed.
    resolved, refuse = resolve_supplied_target(
        repo_path, trust_override, subject=_SCAN_SUBJECT)
    if resolved is None:
        return refuse
    # Held observation fd (shared helper layer): the self-recognition
    # gate borrows it, the pack WALK enumerates and reads through it
    # (``os.fwalk(dir_fd=...)`` — see ``_scan_repo``), and the
    # refuse-only divergence bracket below compares the final spelling
    # against its identity, so the verdict a consumer acts on is bound
    # to one observed inode end to end. On a platform whose os lacks
    # dir_fd support the gate's back-link reads raise
    # NotImplementedError inside its catch-all → not-self → the scan
    # RUNS and its fd-anchored walk blocks fail-closed (walk-error
    # lane), never falling back to a spelling re-walk; the exact
    # ``target == _RAPTOR_DIR`` skip needs no dir_fd and survives.
    target_fd, refuse = open_supplied_target(
        resolved, trust_override, subject=_SCAN_SUBJECT)
    if target_fd is None:
        return refuse
    try:
        scans, any_blocking = _scan_repo(resolved, target_fd=target_fd)
        if scans:
            target = Path(resolved)
            # Rendering (core.security._trust_common.render_scan_report)
            # stays separated from ``_scan_repo`` so the scan stays
            # side-effect free.
            render_scan_report(target, scans, any_blocking, trust_override,
                               subject=_SCAN_SUBJECT)
        # Refuse-only identity bracket: conjunctive, runs after the
        # scan and the rendering — it can refuse a clean verdict whose
        # target was swapped mid-scan, never wave anything through.
        if supplied_target_diverged(
                target_fd, resolved, trust_override, _SCAN_SUBJECT):
            return True
        return any_blocking and not trust_override
    finally:
        os.close(target_fd)


__all__ = [
    "FileScan",
    "Finding",
    "check_repo_codeql_trust",
    "set_trust_override",
]
