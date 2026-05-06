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
import sys
import time
import xml.etree.ElementTree as ET
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
    env_path = os.environ.get("RAPTOR_SCA_AGENT")
    if env_path:
        p = Path(env_path).resolve()
        if p.is_file():
            return p
        logger.warning("RAPTOR_SCA_AGENT=%s does not exist — ignoring", env_path)

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
) -> tuple:
    """Run the raptor-sca agent as a sandboxed subprocess.

    Uses :func:`core.sandbox.run` with ``use_egress_proxy=True`` so the
    child's outbound HTTPS is funnelled through the in-process proxy
    with :data:`packages.sca.SCA_ALLOWED_HOSTS` as the hostname
    allowlist.  Landlock confines writes to ``output_dir``.

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

    result = sandbox_run(
        cmd,
        use_egress_proxy=True,
        proxy_hosts=list(SCA_ALLOWED_HOSTS),
        caller_label="sca-agent",
        target=str(target),
        output=str(output_dir),
        env=env or RaptorConfig.get_safe_env(),
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


def find_dependency_files(root: Path) -> List[Path]:
    candidates = []
    for pat in ['pom.xml', 'build.gradle', 'package.json',
                'requirements.txt', 'pyproject.toml']:
        for p in root.rglob(pat):
            candidates.append(p)
    return candidates


def parse_pom(p):
    try:
        tree = ET.parse(p)
        root = tree.getroot()
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
        deps = []
        for d in root.findall('.//m:dependency', ns):
            g = d.find('m:groupId', ns)
            a = d.find('m:artifactId', ns)
            v = d.find('m:version', ns)
            deps.append({
                'group': g.text if g is not None else None,
                'artifact': a.text if a is not None else None,
                'version': v.text if v is not None else None,
            })
        return deps
    except Exception as e:
        return {'error': str(e)}


def parse_requirements(p):
    deps = []
    for ln in p.read_text().splitlines():
        ln = ln.strip()
        if not ln or ln.startswith('#'):
            continue
        deps.append(ln)
    return deps


def parse_package_json(p):
    try:
        obj = load_json(p)
        if obj is None:
            return {'error': 'failed to parse JSON'}
        deps = obj.get('dependencies', {})
        return [{'name': k, 'version': v} for k, v in deps.items()]
    except Exception as e:
        return {'error': str(e)}


def main():
    ap = argparse.ArgumentParser(description='RAPTOR SCA Agent')
    ap.add_argument('--repo', required=True)
    args = ap.parse_args()
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
