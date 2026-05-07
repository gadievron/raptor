#!/usr/bin/env python3
"""Bridge between raptor and raptor-sca for agentic and sandboxed runs.

Provides:

  - :func:`_find_sca_agent` — discover the raptor-sca entry point.
    Returns the resolved path to ``packages/sca/agent.py`` in the
    raptor-sca tree, or ``None`` if raptor-sca is not installed.

  - :func:`run_sca_subprocess` — launch raptor-sca as a sandboxed
    subprocess with egress routed through the proxy.  The hostname
    allowlist is :data:`packages.sca.SCA_ALLOWED_HOSTS`.

Used by ``raptor_agentic.py`` Phase 1b::

    from packages.sca.agent import _find_sca_agent, run_sca_subprocess
    agent = _find_sca_agent()
    if agent:
        rc, stdout, stderr = run_sca_subprocess(agent, target, out, ...)

And by the raptor-side ``packages/sca/__init__.py`` for the canonical
host list (the old basic-scan functions are retained for backward compat
with existing tests).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
# Use defusedxml for parsing target-repo XML files. Stdlib's
# `xml.etree.ElementTree` is vulnerable to XXE / billion-laughs /
# decompression-bomb attacks when fed adversarial XML — the SCA
# pipeline reads XML files from untrusted target repositories
# (operator's pom.xml may have been crafted by an attacker via
# a malicious dependency, supply-chain compromise, or a deliberately
# poisoned target). defusedxml.ElementTree wraps the same API but
# disables external entity resolution, blocks billion-laughs, and
# caps recursion. ImportError fallback keeps SCA working in
# environments where defusedxml isn't installed (with a runtime
# warning that XML parsing is using the unsafe stdlib).
try:
    import defusedxml.ElementTree as ET  # type: ignore[import-not-found]
    _DEFUSED_XML = True
except ImportError:
    import xml.etree.ElementTree as ET
    _DEFUSED_XML = False
from pathlib import Path
from typing import List, Optional, Sequence

from core.json import load_json, save_json
from core.run.safe_io import safe_run_mkdir

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# raptor-sca discovery
# ---------------------------------------------------------------------------

# Search order for the raptor-sca agent entry point. The worktree
# location is the most common dev layout; the sibling directory covers
# a standalone checkout.  Paths are relative to the raptor repo root.
_SCA_AGENT_CANDIDATES = (
    # git worktree at ../raptor-sca
    Path(__file__).resolve().parents[2] / ".." / "raptor-sca" / "packages" / "sca" / "agent.py",  # noqa: E501
    # same-repo feature branch (packages/sca/agent.py IS the agent)
    # — when feat/sca merges to main, this file is replaced by the
    #   full agent; until then, a marker file signals the real one.
    Path(__file__).resolve().parents[2] / "packages" / "sca" / "_sca_agent_marker",
)


def _find_sca_agent() -> Optional[Path]:
    """Discover the raptor-sca subprocess agent.

    Returns the resolved path to the raptor-sca agent entry point, or
    ``None`` when raptor-sca is not installed.  The agent is the
    ``packages/sca/agent.py`` script in the raptor-sca tree — NOT this
    file (which is the raptor-side bridge).
    """
    # Explicit override — useful for CI or custom layouts.
    # Run the same content check we apply to the auto-discovered
    # candidates (the `from packages.sca import SCA_ALLOWED_HOSTS`
    # import is a discriminator). Pre-fix the env-override path
    # only checked `is_file()`, so an operator pointing
    # RAPTOR_SCA_AGENT at the WRONG file (e.g. an old `agent.py`
    # from a sibling project, this bridge file itself, or a
    # placeholder script with the wrong shape) silently launched
    # subprocess that didn't have the SCA-agent contract — leading
    # to confusing "no SCA findings" / opaque crash output. The
    # content check makes a wrong override fail loud at discovery
    # time with a clear log line.
    env_path = os.environ.get("RAPTOR_SCA_AGENT")
    if env_path:
        p = Path(env_path).resolve()
        if not p.is_file():
            logger.warning("RAPTOR_SCA_AGENT=%s does not exist — ignoring", env_path)
        else:
            try:
                text = p.read_text(encoding="utf-8")
            except OSError:
                logger.warning(
                    "RAPTOR_SCA_AGENT=%s could not be read — ignoring",
                    env_path,
                )
            else:
                if "from packages.sca import SCA_ALLOWED_HOSTS" in text:
                    return p
                logger.warning(
                    "RAPTOR_SCA_AGENT=%s does not look like a raptor-sca "
                    "agent (missing SCA_ALLOWED_HOSTS import) — ignoring",
                    env_path,
                )

    for candidate in _SCA_AGENT_CANDIDATES:
        resolved = candidate.resolve()
        if resolved.is_file() and resolved.name == "agent.py":
            # Quick sanity: the real raptor-sca agent imports
            # packages.sca.api, not core.json.  Check for the
            # SCA_ALLOWED_HOSTS import to distinguish it from this file.
            try:
                text = resolved.read_text(encoding="utf-8")
                if "from packages.sca import SCA_ALLOWED_HOSTS" in text:
                    return resolved
            except OSError:
                pass

    return None


# ---------------------------------------------------------------------------
# Sandboxed subprocess launch
# ---------------------------------------------------------------------------

def run_sca_subprocess(
    agent_path: Path,
    target: Path,
    output_dir: Path,
    *,
    sandbox_args: Sequence[str] = (),
    env: Optional[dict] = None,
    timeout: int = 600,
    writable_paths: Optional[Sequence[Path]] = None,
) -> tuple:
    """Run the raptor-sca agent as a sandboxed subprocess.

    Uses :func:`core.sandbox.run` with ``use_egress_proxy=True`` so the
    child's outbound HTTPS is funnelled through the in-process proxy
    with :data:`packages.sca.SCA_ALLOWED_HOSTS` as the hostname
    allowlist.  Landlock confines writes to ``output_dir``.

    Args:
        writable_paths: Additional directories the agent needs write
            access to. Pre-fix the agent could ONLY write to
            ``output_dir`` — but raptor-sca's resolver subprocesses
            (pip-compile, `npm install --package-lock-only`,
            `mvn dependency:resolve`) need to write into their own
            scratch dirs (`~/.cache/pip`, `~/.npm`, `~/.m2`) and
            many also need to populate a `.venv/` next to the target
            manifest. Pre-fix the resolver hit Landlock EACCES on
            those dirs and silently fell back to "no resolution"
            (treating every dep as unconstrained / not-pinned),
            producing inflated false-positive SCA reports. Pass the
            cache dirs and per-resolver scratch dirs here so the
            agent has the writable surface it actually needs.

    Returns ``(returncode, stdout, stderr)``.
    """
    from core.config import RaptorConfig
    from core.sandbox import run as sandbox_run
    from packages.sca import SCA_ALLOWED_HOSTS

    cmd: list = [
        sys.executable, str(agent_path),
        "--repo", str(target),
        "--out", str(output_dir),
        *sandbox_args,
    ]

    # `output` is the canonical-write location; additional writable
    # paths are layered via the sandbox's `writable_paths` kwarg.
    # Empty / None tuple is harmless to sandbox_run.
    extra_writable = (
        tuple(str(p) for p in writable_paths) if writable_paths else ()
    )

    result = sandbox_run(
        cmd,
        use_egress_proxy=True,
        proxy_hosts=list(SCA_ALLOWED_HOSTS),
        caller_label="sca-agent",
        target=str(target),
        output=str(output_dir),
        writable_paths=extra_writable,
        # `env if env is not None else ...` — pre-fix `env or` was
        # truthy-tested, so an EXPLICIT `env={}` (caller's signal
        # "spawn with empty env") got replaced with the default
        # safe env because `{}` is falsy. The empty-env intent
        # was silently overridden — sandbox children inherited
        # the caller-default RAPTOR env when caller had
        # specifically asked for nothing. Explicit None check
        # preserves the caller's `{}` choice.
        env=env if env is not None else RaptorConfig.get_safe_env(),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


# ---------------------------------------------------------------------------
# Legacy basic-scan functions (retained for backward compat with tests)
# ---------------------------------------------------------------------------

def get_out_dir() -> Path:
    base = os.environ.get("RAPTOR_OUT_DIR")
    return Path(base).resolve() if base else Path("out").resolve()


# Vendored / cache / build directories whose dependency manifests
# describe TRANSITIVE deps already covered by the top-level
# manifest, OR are vendored copies whose pin-shape doesn't reflect
# the actual project's intent. Including them in SCA produces
# noisy reports (the same `react@17.0.2` flagged 30x because every
# transitive dep also depends on it) and breaks fix recommendations
# (an "upgrade `lodash` to 4.17.21" suggestion against a
# vendored-by-someone-else lodash isn't actionable).
_VENDOR_DIR_NAMES = frozenset({
    "node_modules", "vendor", ".venv", "venv", "__pycache__",
    ".tox", "dist", "build", "target", ".gradle", ".mvn",
    "site-packages", "bower_components", ".bundle", "Pods",
    ".cache", ".idea", ".vscode",
})


def find_dependency_files(root: Path) -> List[Path]:
    candidates = []
    for pat in ['pom.xml', 'build.gradle', 'package.json',
                'requirements.txt', 'pyproject.toml']:
        for p in root.rglob(pat):
            # Skip if any path component is a vendor / cache dir.
            # Pre-fix `rglob` walked into node_modules and friends,
            # picking up every transitive dep's package.json,
            # multiplying the SCA report by orders of magnitude
            # (a typical npm project has 1000+ nested
            # package.json files, each producing duplicate /
            # not-actionable advisories).
            try:
                rel_parts = p.relative_to(root).parts
            except ValueError:
                rel_parts = p.parts
            if any(part in _VENDOR_DIR_NAMES for part in rel_parts[:-1]):
                continue
            # Reject symlinks (file or any parent dir). `rglob`
            # follows symlinks by default on Python < 3.13 — a
            # symlink under the target repo pointing OUT to e.g.
            # `/etc` or to a shared workspace directory could
            # introduce dependency files we'd then parse and
            # report as if they belonged to this repo. Two failure
            # modes:
            #   1. Operator-visible noise: shared workspace
            #      `requirements.txt` flagged against the wrong
            #      project, fix recommendations applied to the
            #      wrong tree.
            #   2. Confused-deputy disclosure: parser output
            #      goes into LLM prompts for triage; symlinks
            #      to /etc/* would leak host filesystem layout.
            try:
                if p.is_symlink():
                    continue
                # Walk up the parents to root, refusing if any
                # intermediate directory is a symlink (the file
                # itself may not be a symlink even when reached
                # through a symlinked parent).
                parent = p.parent
                walked_through_symlink = False
                while parent != root and parent.parent != parent:
                    if parent.is_symlink():
                        walked_through_symlink = True
                        break
                    parent = parent.parent
                if walked_through_symlink:
                    continue
            except OSError:
                continue
            candidates.append(p)
    return candidates


_PARSE_POM_WARNED_UNSAFE = False


def parse_pom(p):
    global _PARSE_POM_WARNED_UNSAFE
    if not _DEFUSED_XML and not _PARSE_POM_WARNED_UNSAFE:
        # Warn once per process — operator should know they're
        # parsing untrusted XML with the stdlib parser. Logging
        # here rather than at import to avoid the warning when
        # SCA isn't actually invoked.
        try:
            from core.logging import get_logger
            get_logger("sca.agent").warning(
                "defusedxml not installed — pom.xml parsing falls back to "
                "xml.etree.ElementTree which is vulnerable to XXE / "
                "billion-laughs in adversarial XML. `pip install defusedxml` "
                "to enable safe parsing."
            )
        except Exception:
            pass
        _PARSE_POM_WARNED_UNSAFE = True
    try:
        tree = ET.parse(p)
        root = tree.getroot()
        # Try both XPath shapes: namespaced (Maven 4.0.0 schema —
        # `xmlns="http://maven.apache.org/POM/4.0.0"` declared) and
        # bare (no xmlns). Pre-fix only the namespaced path was
        # tried, so namespace-less POMs (older Maven projects,
        # hand-written POMs, some Spring Boot generated POMs that
        # omit xmlns, custom build tooling output) returned an
        # empty `[]` deps list — SCA silently reported zero
        # dependencies. The bare-XPath fallback covers the
        # missing-xmlns case without breaking the schema-conforming
        # path.
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
        deps = []
        # Determine which shape this POM uses by checking root tag.
        # ElementTree namespaces appear in tags as
        # `{http://maven.apache.org/POM/4.0.0}project`; bare POMs
        # are just `project`. Iterating both yields zero noise
        # because each POM matches exactly one shape.
        is_namespaced = root.tag.startswith('{')
        if is_namespaced:
            iter_xpath = './/m:dependency'
            child = lambda d, k: d.find(f'm:{k}', ns)
            findall_kwargs = (iter_xpath, ns)
            properties_xpath = './/m:properties'
        else:
            iter_xpath = './/dependency'
            child = lambda d, k: d.find(k)
            findall_kwargs = (iter_xpath,)
            properties_xpath = './/properties'

        # Property-substitution map. Maven POMs frequently use
        # `${prop.name}` references in version (and sometimes
        # groupId/artifactId) fields, with the actual value
        # defined in a `<properties>` section. Pre-fix the parser
        # returned the literal `${spring.version}` string as the
        # version, which OSV lookups can't resolve to a CVE
        # search — false-negative on every property-substituted
        # version.
        props = {}
        properties_node = root.find(*((properties_xpath, ns) if is_namespaced
                                      else (properties_xpath,)))
        if properties_node is not None:
            for prop in properties_node:
                # Strip namespace from tag if present.
                tag = prop.tag
                if tag.startswith('{'):
                    tag = tag.split('}', 1)[1]
                if prop.text:
                    props[tag] = prop.text.strip()

        def resolve(value):
            """Substitute `${prop}` references; bounded recursion
            so circular `${a}=${b}, ${b}=${a}` definitions can't
            spin forever."""
            if value is None:
                return None
            for _ in range(8):  # 8 levels of indirection is plenty.
                m = re.search(r'\$\{([^}]+)\}', value)
                if not m:
                    break
                key = m.group(1)
                if key not in props or props[key] == value:
                    break
                value = value.replace(m.group(0), props[key])
            return value

        for d in root.findall(*findall_kwargs):
            g = child(d, 'groupId')
            a = child(d, 'artifactId')
            v = child(d, 'version')
            s = child(d, 'scope')
            deps.append({
                'group': resolve(g.text) if g is not None else None,
                'artifact': resolve(a.text) if a is not None else None,
                'version': resolve(v.text) if v is not None else None,
                # `scope` (compile/test/provided/runtime/system/import)
                # lets downstream consumers filter test-only deps
                # the way devDependencies are filtered for npm.
                # Default is `compile` per Maven spec.
                'scope': (s.text.strip() if s is not None and s.text else 'compile'),
            })
        return deps
    except Exception as e:
        return {'error': str(e)}


def parse_requirements(p, _seen=None):
    """Parse a pip requirements.txt-style file.

    Pre-fix issues addressed here:
      * **Line continuations.** A single requirement can span
        multiple lines via trailing `\\` (`pkg \\` newline
        `--hash=sha256:...`). Pre-fix `splitlines()` returned
        each fragment as a separate "dep" entry — `pkg \\` and
        `--hash=sha256:...` showed up as two unrelated
        requirements, the latter being garbage.
      * **`-r other.txt` includes.** Real requirements files
        commonly chain via `-r requirements-dev.txt` or
        `--requirement other.txt`. Pre-fix those lines were
        recorded verbatim as "deps" — SCA reported `-r
        other.txt` as a literal package name, then OSV lookups
        for it failed silently. Recursively parse the included
        file (with cycle detection via `_seen`) so the chained
        deps surface in the report.
      * **Inline comments.** `pkg==1.0  # pin for CVE-XYZ`
        kept the trailing comment as part of the version
        spec; OSV lookups treated `1.0  # pin for CVE-XYZ` as
        the version. Strip everything after the first
        whitespace-prefixed `#`.
    """
    deps: List[str] = []
    if _seen is None:
        _seen = set()
    real = p.resolve(strict=False)
    if real in _seen:
        return deps
    _seen.add(real)
    try:
        # `encoding='utf-8-sig'` strips a leading BOM if present.
        # Pre-fix `read_text()` (default utf-8) preserved the BOM
        # as `﻿` at the start of the first logical line —
        # the BOM is whitespace-class to .strip() but NOT stripped
        # by it, so the first dep ended up as `'﻿requests==2.31.0'`
        # which OSV lookups failed on. Common in Windows-edited
        # requirements.txt and generated files from `pip-compile`
        # in some toolchains. utf-8-sig handles "BOM if present,
        # plain utf-8 otherwise" without breaking BOM-less files.
        text = p.read_text(encoding="utf-8-sig")
    except OSError:
        return deps
    except UnicodeDecodeError:
        # Fallback: preserve old behaviour for non-utf8 files
        # (defensive — pip itself rejects non-utf8 requirements
        # since pip 22.2, but legacy files might exist).
        try:
            text = p.read_text(errors="replace")
        except OSError:
            return deps

    # Join continuations: trailing `\` on a stripped-of-trailing-
    # whitespace line means "next physical line is part of this
    # logical line". Process character-by-character to avoid
    # corner cases with embedded backslashes in URLs.
    logical_lines: List[str] = []
    buf = ""
    for raw in text.splitlines():
        # If buf is mid-continuation, prepend to current line.
        if buf:
            raw = buf + raw
            buf = ""
        # Detect continuation: line ends with `\` (not preceded
        # by another `\` to escape it). Drop the trailing `\`
        # and stash for the next iteration.
        stripped_right = raw.rstrip()
        if stripped_right.endswith("\\") and not stripped_right.endswith("\\\\"):
            buf = stripped_right[:-1]
            continue
        logical_lines.append(raw)
    if buf:
        logical_lines.append(buf)

    for ln in logical_lines:
        # Strip inline comments (` #` or leading `#`).
        # Don't strip `#` inside the requirement (e.g. URL fragments)
        # — only when preceded by whitespace.
        hash_idx = -1
        in_quoted = False
        for i, ch in enumerate(ln):
            if ch in ("'", '"'):
                in_quoted = not in_quoted
            elif ch == '#' and not in_quoted and (i == 0 or ln[i - 1] in (' ', '\t')):
                hash_idx = i
                break
        if hash_idx >= 0:
            ln = ln[:hash_idx]
        ln = ln.strip()
        if not ln:
            continue

        # `-r path` / `--requirement path` recursive include.
        for prefix in ('-r ', '--requirement ', '--requirement='):
            if ln.startswith(prefix):
                included = ln[len(prefix):].strip().strip('"').strip("'")
                # Resolve relative to the parent file's directory.
                included_path = (p.parent / included).resolve(strict=False)
                if included_path.exists():
                    deps.extend(parse_requirements(included_path, _seen))
                break
        else:
            # `-c constraints.txt` is a constraints file (NOT a
            # dep itself, just version pinning hints) — recurse
            # to surface its pins as deps for SCA purposes.
            for prefix in ('-c ', '--constraint ', '--constraint='):
                if ln.startswith(prefix):
                    included = ln[len(prefix):].strip().strip('"').strip("'")
                    included_path = (p.parent / included).resolve(strict=False)
                    if included_path.exists():
                        deps.extend(parse_requirements(included_path, _seen))
                    break
            else:
                deps.append(ln)
    return deps


def parse_package_json(p):
    try:
        obj = load_json(p)
        if obj is None:
            return {'error': 'failed to parse JSON'}
        # Pre-fix only `dependencies` (the production deps) was
        # read. npm / yarn / pnpm projects also use:
        #   * `devDependencies` — test/build tooling, often
        #     consumed in CI flows that DO ship to production
        #     when build artifacts are baked in.
        #   * `peerDependencies` — declared API requirements
        #     that get installed by consumers; advisories on
        #     these still affect the project surface.
        #   * `optionalDependencies` — installed when present;
        #     CVEs apply when they ARE installed.
        # SCA reports ought to surface advisories on all four.
        # `dep_type` annotation lets downstream consumers
        # filter (e.g. "skip dev-only deps for production
        # severity scoring") without re-parsing.
        deps_out = []
        for dep_type, key in (
            ("runtime", "dependencies"),
            ("dev", "devDependencies"),
            ("peer", "peerDependencies"),
            ("optional", "optionalDependencies"),
        ):
            section = obj.get(key)
            if isinstance(section, dict):
                for name, version in section.items():
                    deps_out.append({
                        "name": name,
                        "version": version,
                        "dep_type": dep_type,
                    })
        return deps_out
    except Exception as e:
        return {'error': str(e)}


def main():
    ap = argparse.ArgumentParser(description='RAPTOR SCA Agent')
    ap.add_argument('--repo', required=True)
    # `parse_known_args` so callers (raptor.py orchestrator,
    # `/agentic --sca`, future wrappers) can pass `--out`,
    # `--project`, `--max-cost`, etc. without crashing this
    # subcommand. Pre-fix `parse_args()` raised SystemExit on
    # any unknown arg, breaking the wrapping orchestrator that
    # passes through standard RAPTOR run-lifecycle flags. The
    # extras are silently dropped here — they're either
    # consumed by the wrapper (--out, --project) before this
    # subcommand sees argv, or genuinely irrelevant to SCA
    # (`--no-exploits`).
    args, _unknown = ap.parse_known_args()
    repo = Path(args.repo).resolve()
    if not repo.exists():
        raise SystemExit('repo not found')

    out = {
        'files': [],
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    for p in find_dependency_files(repo):
        entry = {'path': str(p)}
        if p.name == 'pom.xml':
            entry['deps'] = parse_pom(p)
        elif p.name == 'requirements.txt':
            entry['deps'] = parse_requirements(p)
        elif p.name == 'package.json':
            entry['deps'] = parse_package_json(p)
        else:
            entry['note'] = 'unsupported parser'
        out['files'].append(entry)

    out_dir = get_out_dir()
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    safe_run_mkdir(out_dir)
    save_json(out_dir / 'sca.json', out)
    print(json.dumps({'status': 'ok', 'files_found': len(out['files'])}))


if __name__ == '__main__':
    main()
