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

def safe_clone(url: str, dest: Path):
    clone_repository(url, dest, depth=1)
    return dest

def inventory(path: Path):
    counts = {}
    langs = {}
    total_files = 0
    for p in path.rglob("*"):
        if p.is_file():
            total_files += 1
            ext = p.suffix.lower()
            counts[ext] = counts.get(ext,0) + 1
            # coarse language mapping
            if ext in ['.java','.kt']:
                langs['java'] = langs.get('java',0)+1
            elif ext in ['.py']:
                langs['python'] = langs.get('python',0)+1
            elif ext in ['.go']:
                langs['go'] = langs.get('go',0)+1
            elif ext in ['.js','.ts']:
                langs['javascript'] = langs.get('javascript',0)+1
            elif ext in ['.rb']:
                langs['ruby'] = langs.get('ruby',0)+1
            elif ext in ['.cs']:
                langs['csharp'] = langs.get('csharp',0)+1
    return {'file_count': total_files, 'ext_counts': counts, 'language_counts': langs}

def main():
    ap = argparse.ArgumentParser(description='RAPTOR Recon Agent - safe inventory')
    ap.add_argument('--repo', required=True, help='Path or git URL')
    ap.add_argument('--keep', action='store_true', help='Keep temp repo if cloned')
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix='raptor_recon_'))
    repo_path = None
    try:
        if args.repo.startswith('http://') or args.repo.startswith('https://') or args.repo.startswith('git@'):
            repo_path = safe_clone(args.repo, tmp / 'repo')
        else:
            repo_path = Path(args.repo).resolve()
            if not repo_path.exists():
                raise SystemExit('Repository path does not exist')

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
