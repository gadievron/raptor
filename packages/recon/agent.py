#!/usr/bin/env python3
"""RAPTOR Recon Agent (safe, read-only)
- Accepts repo path or git URL
- Clones shallowly if URL (no credentials, no network if disabled)
- Produces out/recon.json with simple inventory: file counts, languages by extension
- Produces scan-manifest.json (input_hash, timestamp, agent meta)
"""
import argparse, json, os, shutil, sys, tempfile, time
from pathlib import Path

# Setup path for core module imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.json import save_json
from core.git import clone_repository
from core.hash import sha256_tree


def get_out_dir() -> Path:
    base = os.environ.get("RAPTOR_OUT_DIR")
    return Path(base).resolve() if base else Path("out").resolve()

# Cap on inventory traversal — bounded so a target with
# millions of files (or symlink loops we somehow descended
# despite followlinks=False) can't exhaust the agent's
# memory/time budget.
_INVENTORY_FILE_CAP = 200_000


def inventory(path: Path):
    counts = {}
    langs = {}
    total_files = 0
    truncated = False
    # `os.walk(followlinks=False)` instead of `path.rglob("*")`:
    #   * `rglob` follows symlinks by default on Python < 3.13.
    #     A symlink loop in a target repo (vendored deps with
    #     circular includes, intentionally-malicious target
    #     planted by an attacker) hung the recon agent
    #     indefinitely.
    #   * `os.walk(followlinks=False)` short-circuits at the
    #     symlink without entering its target.
    # Hard cap at _INVENTORY_FILE_CAP enforces termination
    # even on loop-free pathological trees.
    import os
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        for name in filenames:
            total_files += 1
            if total_files > _INVENTORY_FILE_CAP:
                truncated = True
                break
            p = Path(dirpath) / name
            ext = p.suffix.lower()
            counts[ext] = counts.get(ext, 0) + 1
            # coarse language mapping
            if ext in ['.java', '.kt']:
                langs['java'] = langs.get('java', 0) + 1
            elif ext in ['.py']:
                langs['python'] = langs.get('python', 0) + 1
            elif ext in ['.go']:
                langs['go'] = langs.get('go', 0) + 1
            elif ext in ['.js', '.ts']:
                langs['javascript'] = langs.get('javascript', 0) + 1
            elif ext in ['.rb']:
                langs['ruby'] = langs.get('ruby', 0) + 1
            elif ext in ['.cs']:
                langs['csharp'] = langs.get('csharp', 0) + 1
        if truncated:
            break
    result = {
        'file_count': total_files,
        'ext_counts': counts,
        'language_counts': langs,
    }
    if truncated:
        result['truncated_at'] = _INVENTORY_FILE_CAP
    return result

def main():
    ap = argparse.ArgumentParser(description='RAPTOR Recon Agent - safe inventory')
    ap.add_argument('--repo', required=True, help='Path or git URL')
    ap.add_argument('--keep', action='store_true', help='Keep temp repo if cloned')
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix='raptor_recon_'))
    repo_path = None
    try:
        if args.repo.startswith('http://') or args.repo.startswith('https://') or args.repo.startswith('git@'):
            repo_path = tmp / 'repo'
            clone_repository(args.repo, repo_path, depth=1)
        else:
            repo_path = Path(args.repo).resolve()
            if not repo_path.exists():
                # Raise FileNotFoundError instead of SystemExit.
                # Pre-fix `raise SystemExit(...)` worked when the
                # agent was invoked as a standalone script from
                # the shell, but when imported and invoked by
                # other Python code (orchestrator, test suite,
                # programmatic wrappers) SystemExit terminated
                # the calling process — surprising and hard to
                # catch at the call site without an explicit
                # `try: ... except SystemExit:`. FileNotFoundError
                # is the standard exception type for this
                # condition, can be caught uniformly via
                # `except OSError`, and keeps the standalone-
                # script case working (uncaught exceptions
                # produce the same operator-visible behaviour).
                raise FileNotFoundError(f"Repository path does not exist: {repo_path}")

        out_dir = get_out_dir()
        out_dir.mkdir(parents=True, exist_ok=True)

        manifest = {
            'agent': 'raptor.recon',
            'version': '1.0.0',
            'repo_path': str(repo_path),
            'timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            # Use very large max_file_size to disable limit (backward compatibility with old behavior)
            # Chunk size doesn't affect hash result, only reading efficiency
            'input_hash': sha256_tree(repo_path, max_file_size=10**12, chunk_size=8192)
        }
        save_json(out_dir / 'scan-manifest.json', manifest)

        inv = inventory(repo_path)
        save_json(out_dir / 'recon.json', {'manifest': manifest, 'inventory': inv})

        print(json.dumps({'status':'ok','manifest':manifest,'inventory':inv}, indent=2))
    finally:
        if not args.keep:
            try:
                shutil.rmtree(tmp)
            except Exception:
                pass

if __name__ == '__main__':
    main()
