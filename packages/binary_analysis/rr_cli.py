"""Contained reproduction and rr lifecycle commands for crash-analysis workflows."""
import argparse
import math
import subprocess
import sys

from core.security.log_sanitisation import sanitise_for_terminal
from core.sandbox import SandboxSetupError
from packages.binary_analysis.rr_record import record, pack, run_target
from packages.binary_analysis.rr_replay import replay


def _term(value):
    """Render captured target diagnostics without terminal controls or flooding."""
    text = value.decode(errors='replace') if isinstance(value, bytes) else str(value)
    omitted = max(0, len(text) - 65536)
    # LF is the only structural control retained; escape CR, ESC, bidi and tabs.
    rendered = '\n'.join(sanitise_for_terminal(line, max_len=4096)
                         for line in text[:65536].split('\n'))  # line-model: retain CR for visible escaping, not line matching
    if omitted:
        rendered += f'\n...[+{omitted} input chars omitted]\n'
    return rendered


def _seconds(value):
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError('timeout must be a finite positive number')
    return seconds


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    for name, description in (
            ('run', 'Reproduce with confined reads/writes; rr is not required'),
            ('record', 'Record an untrusted command in a dedicated workspace')):
        target = actions.add_parser(name, help=description)
        target.add_argument('--workspace', required=True)
        if name == 'run':
            target.add_argument('--sanitizer', action='store_true',
                                help='Allow sanitizer thread inspection under the debugger policy')
        if name == 'record':
            target.add_argument('--trace', required=True, help='New trace directory beneath workspace')
        target.add_argument('--cwd', help='Working directory beneath workspace; default is workspace')
        target.add_argument('--stdin', help='Regular input file beneath workspace; default is /dev/null')
        target.add_argument('--timeout', type=_seconds, default=120)
        target.add_argument('command', nargs=argparse.REMAINDER, help='Executable and arguments after --')
    packer = actions.add_parser('pack', help='Pack a trace with writes confined to that trace')
    packer.add_argument('--workspace', required=True)
    packer.add_argument('--trace', required=True)
    packer.add_argument('--timeout', type=_seconds, default=120)
    player = actions.add_parser('replay', help='Open contained interactive replay')
    player.add_argument('trace', nargs='?')
    player.add_argument('--timeout', type=_seconds, default=None)
    args = parser.parse_args(argv)
    try:
        if args.action in ('run', 'record'):
            command = args.command[1:] if args.command[:1] == ['--'] else args.command
            if not command:
                parser.error(args.action+' requires an executable after --')
            options = dict(input_file=args.stdin, cwd=args.cwd, timeout=args.timeout)
            if args.action == 'record':
                result = record(args.workspace, args.trace, command, **options)
            else:
                result = run_target(args.workspace, command, sanitizer=args.sanitizer, **options)
        elif args.action == 'pack':
            result = pack(args.workspace, args.trace, timeout=args.timeout)
        else:
            result = replay(args.trace, timeout=args.timeout)
        for stream, destination in ((result.stdout, sys.stdout), (result.stderr, sys.stderr)):
            if stream:
                destination.write(_term(stream))
        if args.action == 'record':
            if result.returncode:
                print(f'rr: recorder/target exited with status {result.returncode}', file=sys.stderr)
            if getattr(result, 'recording_verified', False) is True:
                print('rr: recording replay consistency check passed', file=sys.stderr)
                return 0
            print('rr: no verified recording is available; retained files are diagnostic only',
                  file=sys.stderr)
            return 1
        if result.returncode:
            print(f'rr {args.action} exited with status {result.returncode}', file=sys.stderr)
        # Exit 3 is reserved for setup refusal. Preserve target/tool status in
        # diagnostics without misclassifying an executed target's own exit 3.
        if result.returncode == 3:
            return 1
        return 128-result.returncode if result.returncode < 0 else result.returncode
    except SandboxSetupError as error:
        print(f'rr {args.action} refused: {sanitise_for_terminal(str(error), max_len=4096)}', file=sys.stderr)
        return 3
    except subprocess.TimeoutExpired:
        print(f'rr {args.action} timed out; any retained recording may be incomplete', file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError) as error:
        print(f'rr {args.action}: {sanitise_for_terminal(str(error), max_len=4096)}', file=sys.stderr)
        return 1
