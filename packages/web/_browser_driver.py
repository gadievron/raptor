"""Private executable for Playwright's driver transport; not a public CLI."""
import json
import os
from pathlib import Path
import sys


def run_driver(config, argv):
    from core.sandbox import run
    from core.sandbox.errors import SandboxSetupError
    if (len(argv) != 2 or argv[1] != 'run-driver'
            or Path(argv[0]).resolve() != Path(config['cli']).resolve()):
        raise ValueError('Unexpected Playwright driver arguments')
    if sys.platform == 'linux':
        if os.getuid() == 0:
            raise SandboxSetupError('Browser containment requires a non-root Linux operator')
        from core.sandbox.landlock import check_landlock_available, _get_landlock_abi
        if not check_landlock_available() or _get_landlock_abi() < 4:
            raise SandboxSetupError('Browser containment requires Landlock ABI 4+ on Linux')
    work = config['work']
    env = dict(PATH=os.defpath, HOME=str(Path(work)/'.home'),
               TMPDIR=work, TMP=work, TEMP=work, LANG='C.UTF-8',
               XDG_CONFIG_HOME=str(Path(work)/'.home/.config'),
               XDG_CACHE_HOME=str(Path(work)/'.home/.cache'))
    # Keep HOME on the granted work inode, rather than staging /tmp/.home
    # (the namespace tmpfs is deliberately outside the writable allowlist).
    for name in ('HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME'):
        Path(env[name]).mkdir(mode=0o700, parents=True, exist_ok=True)
    if config.get('browsers'):
        env['PLAYWRIGHT_BROWSERS_PATH'] = config['browsers']
    # Protocol annotations only: no credentials, user Node options or trust markers.
    for name in ('PW_LANG_NAME', 'PW_LANG_NAME_VERSION', 'PW_CLI_DISPLAY_VERSION'):
        if name in os.environ:
            env[name] = os.environ[name]
    result = run(['/usr/bin/env', 'TMPDIR='+work, 'TMP='+work, 'TEMP='+work,
                  config['node'], config['cli'], 'run-driver'],
                 profile='chromium', block_network=False,
                 target=work, output=work, writable_paths=[work],
                 restrict_reads=True, fake_home=False, exclude_tmp_baseline=True,
                 # Directory tool grants carry Landlock EXECUTE; file read grants do not.
                 tool_paths=[str(Path(config['node']).parent), str(Path(config['cli']).parent), *config['reads']],
                 allowed_tcp_ports=config['ports'], require_fresh_procfs=True,
                 env=env, strict_env=True, strip_trust_markers=True,
                 cwd=work, stdin=0, capture_output=False, start_new_session=True,
                 timeout=300, limits=dict(max_file_mb=128, cpu_seconds=120, nproc=256, nofile=4096, memory_mb=0),
                 caller_label='playwright-browser')
    return result.returncode


def main():
    # Isolated interpreter: bootstrap only the installed source root, before
    # any target input is read. The actual Node child receives no Python paths.
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    import core.startup.process_init  # noqa: F401
    from core.sandbox.errors import SandboxSetupError
    from core.security.log_sanitisation import sanitise_for_terminal
    try:
        # Parent-owned, private control file; never browser/target-derived.
        with (Path(sys.argv[1]) / 'driver.json').open('r', encoding='utf-8') as stream:  # raw-open: private launcher control file, outside child writable scope
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError('Browser launcher control exceeds budget')
        return run_driver(json.loads(raw), sys.argv[2:])
    except (Exception, SandboxSetupError) as error:
        print('Browser containment refused: ' + sanitise_for_terminal(str(error)[:2000], max_len=16384), file=sys.stderr)
        return 126


if __name__ == '__main__':
    raise SystemExit(main())
