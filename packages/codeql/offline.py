"""Prepare, import, and check an operator-owned CodeQL airgap kit."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import shlex
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, os.environ['RAPTOR_DIR'])

from core.atomic_fs import write_text_atomically  # noqa: E402
from core.config import RaptorConfig  # noqa: E402
from core.json import dumps_canonical  # noqa: E402
from core.security.capped_read import read_capped  # noqa: E402

ROOT = RaptorConfig.REPO_ROOT
LANGUAGES = ('cpp', 'csharp', 'go', 'java', 'javascript', 'python', 'ruby', 'rust', 'swift')
MODES = ('standard', 'iris', 'curated')
MAX_FILES = 100_000
MAX_BYTES = 8 * 1024**3
LOCK = 'codeql-pack.lock.yml'


def _bootstrap():
    return runpy.run_path(str(ROOT / '.devcontainer/codeql-bootstrap.py'))


def _offline():
    return RaptorConfig.CODEQL_OFFLINE


def _record(source: Path, destination: Path | None = None):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024**3:
            raise ValueError(f'not a bounded regular file: {source}')
        digest = hashlib.sha256()
        size = 0
        output = None
        if destination is not None:
            destination.parent.mkdir(parents=True, exist_ok=True)
            output = destination.open('xb')
        try:
            while block := stream.read(1024 * 1024):
                size += len(block)
                if size > 2 * 1024**3:
                    raise ValueError(f'file grew beyond limit: {source}')
                digest.update(block)
                if output is not None:
                    output.write(block)
        finally:
            if output is not None:
                output.close()
        return {'sha256': digest.hexdigest(), 'size': size}


def _tree(root: Path, *, copy_to: Path | None = None, source=False):
    """Inventory regular files without following symlinks; optionally copy bytes."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f'not a real directory: {root}')
    records = {}
    total = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            if (Path(current) / name).is_symlink():
                raise ValueError(f'symlink in transfer tree: {Path(current) / name}')
        if source:
            dirs[:] = [d for d in dirs if d not in ('.codeql', '.git')]
        for name in sorted(files):
            if source and (name == LOCK or name.endswith(('.qlx', '.bqrs'))):
                continue
            path = Path(current) / name
            rel = path.relative_to(root).as_posix()
            record = _record(path, copy_to / rel if copy_to else None)
            records[rel] = record
            total += record['size']
            if len(records) > MAX_FILES or total > MAX_BYTES:
                raise ValueError('transfer tree exceeds file/byte budget')
    return records


def _catalog(root: Path, languages, modes):
    packs = []
    for lang in languages:
        for mode, rel in [('iris', f'packages/llm_analysis/codeql_packs/{lang}-queries'),
                          ('curated', f'engine/codeql/queries/{lang}')]:
            if mode in modes and (root / rel / 'qlpack.yml').is_file():
                packs.append(rel)
    return packs


def _cache_directory(root: Path, parts=()):
    """Never follow cache-directory symlinks or write through shared parents."""
    current = root
    for name in (None, *parts):
        if name is not None:
            current = current / name
        current.mkdir(exist_ok=True, mode=0o700)
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022):
            raise ValueError(f'cache directory must be user-owned and not writable by others: {current}')
    return current


def _run(cli, args, *, network, paths=()):
    command = [str(cli), *map(str, args)]
    if network:
        env = RaptorConfig.get_safe_env(preserve_proxy=True)
        p = subprocess.run(command, capture_output=True, text=True, timeout=900, env=env)
    else:
        from core.sandbox import run
        cache = next(str(arg).split('=', 1)[1] for arg in args if str(arg).startswith('--common-caches='))
        readonly = [str(path) for path in paths if str(path) != cache]
        p = run(command, block_network=True, output=cache,
                tool_paths=[str(Path(cli).parent), *readonly],
                capture_output=True, text=True, timeout=600, caller_label='codeql-offline-check')
    if p.returncode:
        raise RuntimeError(f"CodeQL {' '.join(map(str, args[:3]))} failed: {(p.stderr or p.stdout or '')[-4000:]}")
    return p.stdout


def _check(cli, cache, root, languages, modes, packs):
    print('Resolving installed standard packs', flush=True)
    output = _run(cli, ['resolve', 'packs', '--format=json', f'--common-caches={cache}'],
                  network=False, paths=[cache])
    found = {}
    for step in json.loads(output).get('steps', []):
        for scan in step.get('scans', []):
            found.update(scan.get('found', {}))
    for lang in languages:
        for kind in ('all', 'queries'):
            name = f'codeql/{lang}-{kind}'
            if name not in found:
                raise RuntimeError(f'offline pack unavailable: {name}')
        if 'standard' in modes:
            print(f'Checking standard suite: {lang}', flush=True)
            suite = f'codeql/{lang}-queries:codeql-suites/{lang}-security-and-quality.qls'
            _run(cli, ['resolve', 'queries', suite, f'--common-caches={cache}'], network=False, paths=[cache])
    for rel in packs:
        print(f'Checking query pack: {rel}', flush=True)
        _run(cli, ['query', 'compile', '--check-only', '--threads=2', '--ram=2048',
                   f'--common-caches={cache}', root / rel], network=False, paths=[cache, root / rel])


def prepare(output: Path, languages, modes):
    if _offline():
        raise RuntimeError('prepare needs a connected machine; unset RAPTOR_CODEQL_OFFLINE')
    if output.exists() or output.is_symlink():
        raise ValueError(f'output already exists: {output}')
    output.parent.mkdir(parents=True, exist_ok=True)
    boot = _bootstrap()
    asset, digest, size = boot['_asset']()
    print(f"Preparing CodeQL {boot['VERSION']} for {','.join(languages)} ({','.join(modes)})", flush=True)
    with tempfile.TemporaryDirectory(prefix='.codeql-offline-', dir=output.parent) as temporary:
        work = Path(temporary)
        kit = work / 'kit'
        kit.mkdir()
        bundle = kit / asset
        boot['_download'](bundle, asset, digest, size)
        cli = boot['ensure_installed'](force=True, local_archive=bundle)
        cache = work / 'cache'
        cache.mkdir()
        staged = work / 'source'
        packs = _catalog(ROOT, languages, modes)
        provenance = {}
        for rel in packs:
            print(f'Resolving dependencies: {rel}', flush=True)
            original = ROOT / rel
            target = staged / rel
            target.mkdir(parents=True)
            sources = _tree(original, copy_to=target, source=True)
            old_lock = _record(original / LOCK) if (original / LOCK).exists() else None
            if old_lock:
                _record(original / LOCK, target / LOCK)
            _run(cli, ['pack', 'install', '--mode=use-lock', f'--common-caches={cache}', target], network=True)
            lock = target / LOCK
            if not lock.is_file():
                raise RuntimeError(f'no dependency lock generated for {rel}')
            _record(lock, kit / 'locks' / rel / LOCK)
            provenance[rel] = {'sources': sources, 'original_lock': old_lock}
        print('Checking selected packs with network connections denied', flush=True)
        _check(cli, cache, staged, languages, modes, packs)
        if (cache / 'packages').exists():
            (cache / 'packages').rename(kit / 'packages')
        inventory = _tree(kit)
        metadata = {'schema_version': 1, 'codeql_version': boot['VERSION'], 'asset': asset,
                    'languages': list(languages), 'modes': list(modes), 'packs': provenance, 'files': inventory}
        manifest = dumps_canonical(metadata)
        (kit / 'manifest.json').write_text(manifest, encoding='utf-8')
        os.replace(kit, output)
    checksum = hashlib.sha256(manifest.encode()).hexdigest()
    print(f'Prepared {output}\nManifest SHA-256: {checksum}\nTransfer the directory and retain this hash for import.')
    return checksum


def _load_kit(kit, expected):
    if kit.is_symlink() or not kit.is_dir():
        raise ValueError('offline kit must be a real directory')
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('expected a 64-character manifest SHA-256')
    raw = read_capped(kit / 'manifest.json', 32 * 1024**2, raise_on_refusal=True)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('offline manifest SHA-256 mismatch')
    data = json.loads(raw)
    if (not isinstance(data, dict) or type(data.get('schema_version')) is not int
            or data['schema_version'] != 1):
        raise ValueError('unsupported offline manifest')
    if (not isinstance(data.get('languages'), list) or not data['languages']
            or set(data['languages']) - set(LANGUAGES)
            or not isinstance(data.get('modes'), list) or not data['modes']
            or set(data['modes']) - set(MODES)):
        raise ValueError('invalid offline language/mode selection')
    allowed = set(_catalog(ROOT, data['languages'], data['modes']))
    if set(data.get('packs', {})) != allowed:
        raise ValueError('offline kit does not match this checkout\'s selected local packs')
    files = data.get('files')
    if not isinstance(files, dict) or len(files) > MAX_FILES:
        raise ValueError('invalid offline file inventory')
    for name in files:
        path = PurePosixPath(name)
        if (path.is_absolute() or '..' in path.parts or '\\' in name or str(path) != name
                or any(ord(char) < 32 or ord(char) == 127 for char in name)):
            raise ValueError('unsafe offline inventory path')
        if name == data.get('asset'):
            continue
        if name.startswith('locks/') and name in {'locks/' + rel + '/' + LOCK for rel in allowed}:
            continue
        if (len(path.parts) < 5 or path.parts[0] != 'packages'
                or not all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}', part)
                           for part in path.parts[1:4])
                or '/'.join(path.parts[:4]) + '/qlpack.yml' not in files):
            raise ValueError(f'unexpected offline inventory file: {name}')
    actual = _tree(kit)
    actual.pop('manifest.json', None)
    if actual != files:
        missing = sorted(set(files) - set(actual))
        unexpected = sorted(set(actual) - set(files))
        changed = sorted(name for name in set(files) & set(actual) if files[name] != actual[name])
        details = '; '.join(f'{label}: {", ".join(names[:3])}' for label, names in
                            (('missing', missing), ('unexpected', unexpected), ('changed', changed)) if names)
        raise ValueError('offline kit files differ from the verified manifest; ' + details)
    boot = _bootstrap()
    asset, digest, size = boot['_asset']()
    if data['codeql_version'] != boot['VERSION'] or data['asset'] != asset:
        raise ValueError('offline kit targets a different pinned CodeQL release or architecture')
    if files.get(asset) != {'sha256': digest, 'size': size}:
        raise ValueError('offline bundle does not match the repository\'s pinned archive')
    for rel, info in data['packs'].items():
        if _tree(ROOT / rel, source=True) != info['sources']:
            raise ValueError(f'query sources changed since preparation: {rel}')
        current = _record(ROOT / rel / LOCK) if (ROOT / rel / LOCK).exists() else None
        prepared = files.get('locks/' + rel + '/' + LOCK)
        if prepared is None or current not in (None, info['original_lock'], prepared):
            raise ValueError(f'dependency lock changed since preparation: {rel}')
    return boot, data


def import_kit(kit: Path, expected: str):
    boot, data = _load_kit(kit, expected)
    # Stage verified bytes privately so a transfer directory changed during
    # import cannot redirect writes or replace code after the inventory check.
    cache = Path.home() / '.codeql'
    _cache_directory(cache)
    fd = os.open(cache / '.raptor-offline.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'w') as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise ValueError('offline import lock must be a regular file')
        fcntl.flock(lock, fcntl.LOCK_EX)
        _import_verified(kit, expected, boot, data, cache)


def _import_verified(kit, expected, boot, data, cache):
    with tempfile.TemporaryDirectory(prefix='.offline-import-', dir=cache) as temporary:
        staged = Path(temporary)
        for name, expected_record in data['files'].items():
            if _record(kit / name, staged / name) != expected_record:
                raise ValueError(f'offline file changed during import: {name}')
        boot['ensure_installed'](force=True, local_archive=staged / data['asset'])
        # Import only immutable pack-version directories; never copy auth or
        # unrelated caches and never overwrite a different existing version.
        packages = staged / 'packages'
        if packages.exists():
            for metadata in sorted(packages.glob('*/*/*/qlpack.yml')):
                source = metadata.parent
                relative = source.relative_to(packages)
                target = cache / 'packages' / relative
                _cache_directory(cache, ('packages', *relative.parts[:-1]))
                if target.exists() or target.is_symlink():
                    if _tree(target) != _tree(source):
                        raise ValueError(f'existing cached pack differs: {relative}')
                else:
                    os.replace(source, target)
        for rel in data['packs']:
            if _tree(ROOT / rel, source=True) != data['packs'][rel]['sources']:
                raise ValueError(f'query sources changed during import: {rel}')
            current = _record(ROOT / rel / LOCK) if (ROOT / rel / LOCK).exists() else None
            prepared = data['files']['locks/' + rel + '/' + LOCK]
            if current not in (None, data['packs'][rel]['original_lock'], prepared):
                raise ValueError(f'dependency lock changed during import: {rel}')
            content = read_capped(staged / 'locks' / rel / LOCK, 1024**2, raise_on_refusal=True)
            write_text_atomically(ROOT / rel / LOCK, content.decode('utf-8'))
    check(data['languages'], data['modes'])
    cli = boot['ensure_installed'](install=False)
    print('Imported and verified. Run these commands in the shell used for RAPTOR:')
    print('export CODEQL_CLI=' + shlex.quote(str(cli)))
    print('export PATH=' + shlex.quote(str(Path(cli).parent)) + ':"$PATH"')
    print('export RAPTOR_CODEQL_OFFLINE=1')


def check(languages, modes):
    boot = _bootstrap()
    cli = boot['ensure_installed'](install=False)
    cache = Path.home() / '.codeql'
    _cache_directory(cache)
    packs = _catalog(ROOT, languages, modes)
    _check(cli, cache, ROOT, languages, modes, packs)
    print('Offline check passed for languages=' + ','.join(languages) + ' modes=' + ','.join(modes))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare', help='download the pinned bundle and selected dependencies on a connected machine')
    prep.add_argument('--out', type=Path, required=True)
    imp = sub.add_parser('import', help='verify and import a transferred directory without network access')
    imp.add_argument('directory', type=Path)
    imp.add_argument('--sha256', required=True, help='manifest hash printed by prepare, retained separately')
    verify = sub.add_parser('check', help='resolve standard suites and check local queries with network denied')
    for command in (prep, verify):
        command.add_argument('--languages', nargs='+', choices=LANGUAGES, default=list(LANGUAGES))
        command.add_argument('--modes', nargs='+', choices=MODES, default=list(MODES))
    args = parser.parse_args(argv)
    try:
        if args.command == 'prepare':
            prepare(args.out.absolute(), args.languages, args.modes)
        elif args.command == 'import':
            import_kit(args.directory.absolute(), args.sha256)
        else:
            check(args.languages, args.modes)
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, RecursionError, subprocess.SubprocessError) as exc:
        from core.security.log_sanitisation import escape_nonprintable
        parser.exit(1, 'CodeQL offline setup failed: ' + escape_nonprintable(str(exc), preserve_newlines=True) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
