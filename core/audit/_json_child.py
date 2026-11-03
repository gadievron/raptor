"""Named SMT worker; source and vocabulary are data, never host read grants."""
import contextlib
import importlib
import importlib.util
from pathlib import Path
import resource
import sys


def _limit(resource_id, value):
    _, hard = resource.getrlimit(resource_id)
    if hard != resource.RLIM_INFINITY:
        value = min(value, hard)
    resource.setrlimit(resource_id, (value, value))


def _local_z3(tag, args, **options):
    # Compound SMT verbs call the same Z3 API. They already run under this
    # worker's hard bounds; never try to create a second nested sandbox.
    from core.audit.condition_smt import _z3_dispatch_json
    return _z3_dispatch_json({'tag': tag, 'args': args})


def main():
    # Linux enforces AS. macOS accepts it without a hard memory guarantee.
    _limit(resource.RLIMIT_AS, int(sys.argv[3]) * 1024 * 1024)
    _limit(resource.RLIMIT_CPU, int(sys.argv[4]))
    _limit(resource.RLIMIT_FSIZE, 16 * 1024 * 1024)
    root = Path(__file__).resolve().parents[2]
    # Admit only code subtrees, not ROOT/out or other installation state.
    # Explicit package specs avoid needing a directory-listing read grant
    # on the whole install root just to discover core and packages.
    for name in ('core', 'packages'):
        directory = root / name
        spec = importlib.util.spec_from_file_location(name, directory / '__init__.py',
                                                     submodule_search_locations=[str(directory)])
        if spec is None or spec.loader is None:
            return 1
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    from core.audit._json_protocol import ALLOWED_ENTRIES, MAX_REQUEST_BYTES, MAX_REPLY_BYTES, decode, encode
    entry = sys.argv[1]
    if entry not in ALLOWED_ENTRIES:
        return 1
    with contextlib.redirect_stdout(sys.stderr):
        # Already confined; no user hooks are executed by the parent.
        if sys.argv[2]:
            import site
            site.addsitedir(sys.argv[2])
        module, _, function = entry.rpartition(':')
        dispatch = getattr(importlib.import_module(module), function)
        from core.audit import condition_smt
        condition_smt._run_z3_child = _local_z3
        request = decode(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1), MAX_REQUEST_BYTES)
        result = dispatch(request)
        payload = encode(result, MAX_REPLY_BYTES)
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        sys.stderr.write('SMT worker failed: ' + type(exc).__name__ + '\n')
        raise SystemExit(1) from None
