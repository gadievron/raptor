"""CLI launch review covers aliases, command builders and shell delegates."""


from pathlib import Path

import pytest

from core.testing.cli_launch_inventory import process_sites, shell_routes


@pytest.mark.parametrize("source", [
    "import subprocess\nsubprocess.run(['libexec/raptor-threat-model', 'show'])",
    "import subprocess as sp\nsp.Popen(['libexec/raptor-threat-model', 'show'])",
    "from subprocess import run as launch\nlaunch(['libexec/raptor-threat-model', 'show'])",
    "import subprocess\nlaunch = subprocess.run\nlaunch(['libexec/raptor-threat-model', 'show'])",
    "import subprocess as sp\ngetattr(sp, 'run')(['libexec/raptor-threat-model', 'show'])",
    "__import__('subprocess').run(['libexec/raptor-threat-model', 'show'])",
    "import importlib\nimportlib.import_module('subprocess').run(['libexec/raptor-threat-model', 'show'])",
])
def test_aliases_cannot_hide_a_router(source):
    sites = process_sites("tests/test_router.py", source)
    assert len(sites) == 1
    assert "libexec/raptor-threat-model" in sites[0]["command_references"]


def test_dynamic_dispatch_remains_visible_for_review():
    sites = process_sites("tests/test_router.py", """
import subprocess as sp
getattr(sp, operation)(command)
""")
    assert len(sites) == 1
    assert sites[0]["callees"] == ["subprocess.<dynamic>"]


def test_shared_command_builder_is_followed():
    sites = process_sites("tests/test_router.py", """
import subprocess as sp
ROOT = 'checkout/libexec'
def command():
    return [ROOT + '/raptor-threat-model', 'build', '--help']
def helper():
    return sp.run(command())
""")
    assert len(sites) == 1
    assert sites[0]["scope"] == "helper"
    assert "checkout/libexec" in sites[0]["command_references"]
    assert "/raptor-threat-model" in sites[0]["command_references"]


def test_inline_python_and_transitive_shell_delegate_stay_visible():
    sites = process_sites("tests/test_router.py", """
import subprocess
code = "import runpy; runpy.run_path('libexec/raptor-build-checklist', run_name='__main__')"
subprocess.run(['python3', '-c', code])
""")
    assert "raptor-build-checklist" in " ".join(sites[0]["command_references"])
    routes = shell_routes("libexec/raptor-threat-model", '''#!/bin/sh
exec "$RAPTOR_DIR/libexec/raptor-agentic" --threat-model-only "$@"
''')
    assert routes["delegates"] == [("raptor-agentic", "")]


def test_location_and_whitespace_do_not_change_the_contract_signature():
    first = process_sites("tests/test_router.py", "import subprocess\nsubprocess.run(['x'])")[0]
    second = process_sites("tests/test_router.py", "import subprocess\n\nsubprocess.run( ['x'] )")[0]
    assert first["signature"] == second["signature"]


def test_new_calls_through_shared_launch_helpers_remain_visible():
    source = '''
import subprocess
COMMAND = ['libexec/raptor-threat-model', 'show']
def launch(args):
    return subprocess.run(args)
def wrapper():
    return launch(COMMAND)
wrapper()
'''
    sites = process_sites("tests/test_router.py", source)
    assert {site["scope"] for site in sites} == {"launch", "wrapper", ""}
    assert any("libexec/raptor-threat-model" in site["command_references"] for site in sites)


def test_imported_helper_alias_cannot_hide_a_new_cli_caller():
    sites = process_sites("tests/test_router.py", '''
from tests.shared import launch as run
run(['libexec/raptor-threat-model', 'show'])
''', launch_helpers={"tests.shared.launch"})
    assert len(sites) == 1
    assert sites[0]["callees"] == ["tests.shared.launch"]


@pytest.mark.parametrize("source,callee", [
    ("import os\nos.execv('libexec/raptor-audit', ['raptor-audit'])", "os.execv"),
    ("import asyncio as a\na.create_subprocess_exec('libexec/raptor-audit')", "asyncio.create_subprocess_exec"),
    ("import runpy as r\nr.run_path('libexec/raptor-audit')", "runpy.run_path"),
    ("from importlib.machinery import SourceFileLoader as Loader\nLoader('cli', 'libexec/raptor-audit')", "importlib.machinery.SourceFileLoader"),
    ("loader.exec_module(module)", "loader.exec_module"),
])
def test_alternative_execution_apis_require_review(source, callee):
    sites = process_sites("tests/test_router.py", source)
    assert len(sites) == 1
    assert sites[0]["callees"] == [callee]


@pytest.mark.slow
def test_repository_launch_contracts_are_closed():
    import hashlib
    import json
    import subprocess
    from collections import Counter

    from core.testing.cli_launch_inventory import inventory, source_witnesses

    root = Path(__file__).resolve().parents[3]
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=root, capture_output=True, text=True, check=True, timeout=30,
    )
    paths = sorted(set(listed.stdout.splitlines()))
    catalogue = json.loads((Path(__file__).parent / "data/cli_launch_contracts.json").read_text())
    rows = inventory(root, paths)
    actual = Counter((row["path"], row["scope"], row["signature"]) for row in rows)
    expected = Counter()
    contracts = {"standalone", "owned-custom-launch", "owned-session-or-refusal",
                 "owned-in-process", "non-cli-probe"}
    for record in catalogue["sites"]:
        assert record["contract"] in contracts
        assert record["purpose"].strip()
        expected[(record["path"], record["scope"], record["signature"])] += record["count"]
    unclassified, retired = actual - expected, expected - actual
    assert not unclassified, f"unreviewed process/helper/loader launches: {list(unclassified)[:20]}"
    assert not retired, f"removed or changed launch contracts need reconciliation: {list(retired)[:20]}"
    witnessed = source_witnesses(root, paths, rows)
    assert set(witnessed) == set(catalogue["sources"]), "launch environment/helper dependencies changed; review their owners"
    changed = [path for path, digest in catalogue["sources"].items()
               if not (root / path).is_file()
               or hashlib.sha256((root / path).read_bytes()).hexdigest() != digest]
    assert not changed, f"launch command/environment producers changed; review contracts: {changed[:20]}"
    routers = {}
    for path in paths:
        if not path.startswith(("bin/", "libexec/", "plugins/", ".claude/hooks/")):
            continue
        candidate = root / path
        if not candidate.is_file():
            continue
        try:
            source = candidate.read_text()
        except UnicodeError:
            continue
        if source.startswith("#!") and ("bash" in source.splitlines()[0] or "/sh" in source.splitlines()[0]):
            route = shell_routes(path, source)
            if route["delegates"] or route["modules"]:
                routers[path] = hashlib.sha256(candidate.read_bytes()).hexdigest()
    assert routers == catalogue["shell_routers"], "shell routing changed; review transitive Python launch ownership"


def test_environment_factory_without_its_own_spawn_is_a_source_witness(tmp_path):
    from core.testing.cli_launch_inventory import source_witnesses

    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "env.py").write_text("def child_env():\n    return {}\n")
    source = "from tests.env import child_env\nimport subprocess\nsubprocess.run(['python3', 'libexec/raptor-audit'], env=child_env())\n"
    (tests / "test_cli.py").write_text(source)
    paths = ["tests/env.py", "tests/test_cli.py"]
    rows = process_sites("tests/test_cli.py", source)
    first = source_witnesses(tmp_path, paths, rows)
    assert set(first) == set(paths)
    (tests / "env.py").write_text("import os\ndef child_env():\n    return dict(os.environ)\n")
    second = source_witnesses(tmp_path, paths, rows)
    assert first["tests/env.py"] != second["tests/env.py"]
    assert first["tests/test_cli.py"] == second["tests/test_cli.py"]


def test_duplicate_helper_calls_on_one_line_are_counted_separately():
    sites = process_sites("tests/test_router.py", '''
import subprocess
def launch(args):
    return subprocess.run(args)
launch(['x']); launch(['x'])
''')
    assert len(sites) == 3
    callers = [site for site in sites if site["scope"] == ""]
    assert len(callers) == 2
    assert callers[0]["signature"] == callers[1]["signature"]
    assert callers[0]["column"] != callers[1]["column"]


@pytest.mark.parametrize("caller", [
    "from tests.m_bridge import bridge\nbridge(['x']); bridge(['x'])\n",
    "import tests.m_bridge as module\nmodule.bridge(['x']); module.bridge(['x'])\n",
    "from tests.m_bridge import bridge as imported\nalias = imported\nalias(['x']); alias(['x'])\n",
    "import tests.m_bridge as module\ngetattr(module, 'bridge')(['x']); getattr(module, 'bridge')(['x'])\n",
])
def test_inventory_rechecks_transitive_callers_only(tmp_path, monkeypatch, caller):
    from collections import Counter

    from core.testing import cli_launch_inventory as module

    sources = {
        "tests/a_router.py": caller,
        "tests/m_bridge.py": (
            "from tests.z_sink import launch\n"
            "def bridge(args):\n    return launch(args)\n"
        ),
        "tests/z_sink.py": (
            "import subprocess\n"
            "def launch(args):\n    return subprocess.run(args)\n"
        ),
        "tests/unrelated.py": "def ordinary():\n    return str(42)\nordinary()\n",
    }
    for path, source in sources.items():
        target = tmp_path / path
        target.parent.mkdir(exist_ok=True)
        target.write_text(source)

    # Compare every row, including duplicate call sites, with the original
    # exhaustive fixed point rather than an expected row-count shortcut.
    helpers = set()
    while True:
        expected = [row for path, source in sorted(sources.items())
                    for row in process_sites(path, source, launch_helpers=helpers)]
        discovered = {
            row["path"][:-3].replace("/", ".") + "." + row["scope"]
            for row in expected if row["scope"]
        }
        if discovered <= helpers:
            break
        helpers.update(discovered)

    calls = Counter()
    analyse = module._process_sites

    def record(path, source, **kwargs):
        calls[path] += 1
        return analyse(path, source, **kwargs)

    monkeypatch.setattr(module, "_process_sites", record)
    actual = module.inventory(tmp_path, list(reversed(sources)))
    assert actual == expected
    assert calls == {
        "tests/a_router.py": 2,
        "tests/m_bridge.py": 2,
        "tests/z_sink.py": 1,
        "tests/unrelated.py": 1,
    }
    assert len([row for row in actual if row["path"] == "tests/a_router.py"]) == 2


def test_inventory_does_not_reuse_analysis_across_source_changes(tmp_path):
    from core.testing.cli_launch_inventory import inventory

    path = tmp_path / "test_change.py"
    path.write_text("import subprocess\nsubprocess.run(['first'])\n")
    first = inventory(tmp_path, [path.name])
    path.write_text("import subprocess\nsubprocess.run(['second'])\n")
    second = inventory(tmp_path, [path.name])
    assert first[0]["command_references"] == ["first"]
    assert second[0]["command_references"] == ["second"]
    assert first[0]["signature"] != second[0]["signature"]
    path.write_text("def broken(\n")
    with pytest.raises(SyntaxError):
        inventory(tmp_path, [path.name])
