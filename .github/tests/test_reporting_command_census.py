"""Source census follows report registration without importing commands."""
from pathlib import Path
import runpy

CENSUS = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "reporting_command_census.py"))["census"]
FLAGS = '''
def register(parser):
    parser.add_argument("--report-format")
    parser.add_argument("--report-output")
    parser.add_argument("--no-report", action="store_true")
'''


def _scan(tmp_path, source, *, helper=FLAGS):
    for name, text in {"core/report_args.py": helper, "packages/owned/cli.py": source}.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return {row["leaf_declaration"]: row for row in CENSUS(tmp_path) if row["source"] == "packages/owned/cli.py"}


def test_import_alias_and_literal_loop_register_only_selected_parser(tmp_path):
    rows = _scan(tmp_path, '''
import argparse
from core.report_args import register as report_options
def build():
    root = argparse.ArgumentParser(prog="owned")
    commands = root.add_subparsers()
    one = commands.add_parser("one"); two = commands.add_parser("two")
    alias = one
    for selected in (alias,):
        report_options(selected)
    return root
''')
    assert rows["owned"]["declaration_kind"] == "container"
    assert rows["one"]["status"] == "common flags registered"
    assert rows["two"]["status"] == "domain interface retained"


def test_root_parser_inherits_flags_from_fragment_and_commands_are_never_imported(tmp_path):
    marker = tmp_path / "must-not-run"
    rows = _scan(tmp_path, f'''
from pathlib import Path
from argparse import ArgumentParser as Parser
from core.report_args import register
Path({str(marker)!r}).write_text("not authorised")
def build():
    common = Parser(add_help=False)
    parser = Parser(prog="standalone", parents=[common])
    register(common)
    return parser
''')
    assert not marker.exists()
    assert rows["standalone"]["declaration_kind"] == "root"
    assert rows["standalone"]["status"] == "common flags registered"


def test_keyword_only_helper_parameter_does_not_register_other_argument(tmp_path):
    helper = FLAGS.replace("register(parser)", "register(other, *, parser)")
    rows = _scan(tmp_path, '''
import argparse
from core.report_args import register
one = argparse.ArgumentParser(prog="one")
two = argparse.ArgumentParser(prog="two")
register(two, parser=one)
''', helper=helper)
    assert rows["one"]["status"] == "common flags registered"
    assert rows["two"]["status"] == "domain interface retained"


def test_rebinding_helper_parameter_does_not_grant_caller_coverage(tmp_path):
    helper = 'import argparse\n' + FLAGS.replace('    parser.add_argument("--report-format")',
                                                             '    parser = argparse.ArgumentParser()\n    parser.add_argument("--report-format")')
    rows = _scan(tmp_path, '''
import argparse
from core.report_args import register
one = argparse.ArgumentParser(prog="one")
register(one)
''', helper=helper)
    assert rows["one"]["status"] == "domain interface retained"


def test_recursive_helpers_without_flag_evidence_do_not_grant_coverage(tmp_path):
    rows = _scan(tmp_path, '''
import argparse
from core.report_args import first
one = argparse.ArgumentParser(prog="one")
first(one)
''', helper='''
def first(parser):
    second(parser)
def second(parser):
    first(parser)
''')
    assert rows["one"]["status"] == "domain interface retained"


def test_helper_chain_through_relative_import(tmp_path):
    path = tmp_path / "packages" / "owned" / "local.py"
    path.parent.mkdir(parents=True)
    path.write_text('from core.report_args import register\ndef local(parser):\n    register(parser)\n')
    rows = _scan(tmp_path, '''
import argparse
from .local import local
one = argparse.ArgumentParser(prog="one")
local(one)
''')
    assert rows["one"]["status"] == "common flags registered"


def test_class_parser_declaration_is_source_evidence_not_a_helper(tmp_path):
    rows = _scan(tmp_path, '''
import argparse
from core.report_args import register
class Holder:
    parser = argparse.ArgumentParser(prog="owned-static")
    register(parser)
''')
    assert rows["owned-static"]["scope"] == "Holder"
    assert rows["owned-static"]["status"] == "common flags registered"


def test_post_loop_alias_does_not_register_every_sibling(tmp_path):
    rows = _scan(tmp_path, '''
import argparse
from core.report_args import register
one = argparse.ArgumentParser(prog="one")
two = argparse.ArgumentParser(prog="two")
for chosen in (one, two):
    alias = chosen
register(alias)
''')
    assert rows["one"]["status"] == "domain interface retained"


def test_callable_argument_shadowing_import_is_not_registration_proof(tmp_path):
    rows = _scan(tmp_path, '''
import argparse
from core.report_args import register
def build(register):
    one = argparse.ArgumentParser(prog="one")
    register(one)
''')
    assert rows["one"]["status"] == "domain interface retained"
