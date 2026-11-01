"""PHP socket CRLF sanitizers must establish a value contract, not a name."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_RULE = _ROOT / "rules/php/crlf-injection.yaml"
_FIXTURES = _ROOT / "tests/fixtures"
_RULE_ID = "raptor.php.crlf-injection.socket-write"

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")


def _scan(tmp_path, targets, *, timeout=180):
    generated = all(target.parent == tmp_path for target in targets)
    if generated and shutil.which("git") is not None:
        # A tiny project avoids Semgrep's expensive discovery fallback for
        # generated targets outside the checkout. No commit is necessary.
        for args in (["git", "init", "-q"], ["git", "add", "--", *[p.name for p in targets]]):
            subprocess.run(args, cwd=tmp_path, capture_output=True, text=True,
                           timeout=20, check=True)
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics", "off",
         "--disable-version-check", "--json", *map(str, targets)],
        env={**os.environ, "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
             "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log")},
        cwd=tmp_path if generated else None,
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    scanned = {Path(path).name for path in data.get("paths", {}).get("scanned", [])}
    assert scanned == {target.name for target in targets}, data.get("paths")
    actual = {target.name: [] for target in targets}
    for result in data["results"]:
        assert result["check_id"].endswith(_RULE_ID), result["check_id"]
        actual[Path(result["path"]).name].append(result["start"]["line"])
    expected = {
        target.name: [i for i, line in enumerate(target.read_text().splitlines(), 1)
                      if "// crlf-finding" in line]
        for target in targets
    }
    assert any(expected.values()), "non-vacuity: at least one marked vulnerable sink"
    actual = {name: sorted(lines) for name, lines in actual.items()}
    differences = {
        target.name: {
            "missed": [i for i in expected[target.name] if i not in actual[target.name]],
            "unexpected": [i for i in actual[target.name] if i not in expected[target.name]],
        } for target in targets
    }
    assert actual == expected, f"Semgrep {data.get('version')}: {differences}"


@pytest.mark.wall_budget(30)  # Real Semgrep 1.177 scan exceeded 10s; retain the PR sentinel.
def test_positive_fixture_findings_match_marked_socket_writes(tmp_path):
    # The existing negative-fixture gate checks crlf_socket_neg.php.
    # Keep this default-tier sentinel to one file: witness every positive
    # sink, including the former no-op-replace miss, without a duplicate scan.
    _scan(tmp_path, [_FIXTURES / "crlf_socket_pos.php"], timeout=25)


@pytest.mark.slow  # Nightly installs the pinned Semgrep used for the mutation matrix.
def test_replacement_contracts_and_taint_preservation(tmp_path):
    unsafe = {
        "unrelated_replace": r"$v = str_replace('x', 'y', $_GET['x']);",
        "cr_only": r'''$v = str_replace("\r", '', $_GET['x']);''',
        "lf_only": r'''$v = str_replace("\n", '', $_GET['x']);''',
        "pair_only": r'''$v = str_replace("\r\n", '', $_GET['x']);''',
        "single_quoted_escapes": r"$v = str_replace(['\r', '\n'], '', $_GET['x']);",
        "mixed_quotes": r'''$v = str_replace(["\r", '\n'], '', $_GET['x']);''',
        "literal_backslashes": r'''$v = str_replace(["\\r", "\\n"], '', $_GET['x']);''',
        "replacement_reintroduces_lf": r'''$v = str_replace(["\r", "\n"], "\n", $_GET['x']);''',
        "replacement_array_reintroduces_cr": r'''$v = str_replace(["\r", "\n"], ["\r", ''], $_GET['x']);''',
        "dynamic_replacement": r'''$v = str_replace(["\r", "\n"], $_GET['replacement'], $_GET['x']);''',
        "interpolated_replacement": r'''$r = $_GET['replacement']; $v = str_replace(["\r", "\n"], "$r", $_GET['x']);''',
        "regex_noop": r"$v = preg_replace('/unrelated/', '', $_GET['x']);",
        "regex_cr_only": r"$v = preg_replace('/\r/', '', $_GET['x']);",
        "regex_pair_only": r"$v = preg_replace('/\r\n/', '', $_GET['x']);",
        "regex_anchored": r"$v = preg_replace('/^[\r\n]+/', '', $_GET['x']);",
        "regex_positive_limit": r"$v = preg_replace('/[\r\n]+/', '', $_GET['x'], 1);",
        "regex_zero_limit": r"$v = preg_replace('/[\r\n]+/', '', $_GET['x'], 0);",
        "regex_dynamic_limit": r"$n = $_GET['limit']; $v = preg_replace('/[\r\n]+/', '', $_GET['x'], $n);",
        "regex_reintroduces_lf": r'''$v = preg_replace('/[\r\n]+/', "\n", $_GET['x']);''',
        "regex_backreference": r"$v = preg_replace('/[\r\n]+/', '$0', $_GET['x']);",
        "regex_literal_backslashes": r"$v = preg_replace('/[\\\\r\\\\n]+/', '', $_GET['x']);",
        "unrelated_subject": r'''$v = $_GET['x']; str_replace(["\r", "\n"], '', 'fixed');''',
        "original_subject_remains_tainted": r'''$v = $_GET['x']; $clean = str_replace(["\r", "\n"], '', $v);''',
        "alias_of_original_remains_tainted": r'''$original = $_GET['x']; $v = $original; $clean = preg_replace('/[\r\n]+/', '', $original);''',
        "sanitized_then_tainted": r'''$v = str_replace(["\r", "\n"], '', $_GET['x']); $v .= $_GET['suffix'];''',
        "conditional_sanitization": r'''$v = $_GET['x']; if ($_GET['clean']) { $v = str_replace(["\r", "\n"], '', $v); }''',
        "nested_partial_strip": r'''$v = str_replace("\r", '', str_replace("\n", "\n", $_GET['x']));''',
    }
    safe = {
        "strip_array": r'''$v = str_replace(["\r", "\n"], '', $_GET['x']);''',
        "strip_reverse": r'''$v = str_replace(["\n", "\r"], '', $_GET['x']);''',
        "safe_space": r'''$v = str_replace(["\r", "\n"], ' ', $_GET['x']);''',
        "long_array_syntax": r'''$v = str_replace(array("\r", "\n"), '', $_GET['x']);''',
        "count_output": r'''$v = str_replace(["\r", "\n"], '', $_GET['x'], $count);''',
        "replacement_array": r'''$v = str_replace(["\r", "\n"], ['', ' '], $_GET['x']);''',
        "nested_both_orders": r'''$v = str_replace("\r", '', str_replace("\n", ' ', $_GET['x']));''',
        "nested_reverse": r'''$v = str_replace("\n", '', str_replace("\r", '', $_GET['x']));''',
        "regex_class": r"$v = preg_replace('/[\r\n]/', '', $_GET['x']);",
        "regex_class_plus": r"$v = preg_replace('/[\r\n]+/', '', $_GET['x']);",
        "regex_reverse": r"$v = preg_replace('/[\n\r]+/', ' ', $_GET['x']);",
        "regex_other_delimiter": r"$v = preg_replace('~[\r\n]+~', '', $_GET['x']);",
        "regex_unlimited": r"$v = preg_replace('/[\r\n]+/', '', $_GET['x'], -1);",
        "regex_count_output": r"$v = preg_replace('/[\r\n]+/', '', $_GET['x'], -1, $count);",
        "safe_result_alias": r'''$clean = str_replace(["\r", "\n"], '', $_GET['x']); $v = $clean;''',
        "numeric": r"$v = intval($_GET['x']);",
        "encoded": r"$v = rawurlencode($_GET['x']);",
    }
    source = ["<?php"]
    for cases, expected_finding in ((unsafe, True), (safe, False)):
        for name, body in cases.items():
            source.extend([f"function {name}($socket) {{", f"    {body}",
                           "    socket_write($socket, $v);" + (" // crlf-finding" if expected_finding else ""),
                           "}"])
    # Sanitizer matching must not suppress a sink nested in an argument.
    source.extend(["function nested_sink($socket) {",
                   r'''    str_replace(["\r", "\n"], '', socket_write($socket, $_GET['x'])); // crlf-finding''',
                   "}", "function assigned_nested_sink($socket) {",
                   r'''    $safe = str_replace(["\r", "\n"], '', socket_write($socket, $_GET['x'])); // crlf-finding''',
                   "}"])
    target = tmp_path / "contracts.php"
    target.write_text("\n".join(source) + "\n")
    _scan(tmp_path, [target])


@pytest.mark.slow  # Executed on the pinned tool in nightly.
def test_mutated_arguments_and_reference_aliases(tmp_path):
    target = tmp_path / "mutations.php"
    target.write_text(r'''<?php
function reference_alias($socket) {
    $raw = $_GET['x']; $alias =& $raw;
    $safe = str_replace(["\r", "\n"], '', $raw);
    socket_write($socket, $alias); // crlf-finding
}
function mutated_limit($socket) {
    $limit = -1; $limit = 1;
    $safe = preg_replace('/[\r\n]+/', '', $_GET['x'], $limit);
    socket_write($socket, $safe); // crlf-finding
}
function mutated_search($socket) {
    $search = ["\r", "\n"]; $search = ['x', 'y'];
    $safe = str_replace($search, '', $_GET['x']);
    socket_write($socket, $safe); // crlf-finding
}
function mutated_replacement($socket) {
    $replacement = ''; $replacement = $_GET['replacement'];
    $safe = preg_replace('/[\r\n]+/', $replacement, $_GET['x']);
    socket_write($socket, $safe); // crlf-finding
}
function dynamic_pattern($socket) {
    $pattern = $_GET['pattern'];
    $safe = preg_replace($pattern, '', $_GET['x']);
    socket_write($socket, $safe); // crlf-finding
}
function result_retainted($socket) {
    $safe = preg_replace('/[\r\n]+/', '', $_GET['x']);
    $alias = $safe; $alias = $_GET['other'];
    socket_write($socket, $alias); // crlf-finding
}
''')
    _scan(tmp_path, [target])


@pytest.mark.slow  # Live namespace/name matching is exercised on the nightly pin.
def test_shadowed_functions_and_builtin_scope(tmp_path):
    targets = []
    for name, arguments, signature, returned, braced in [
        ("str_replace", r'''["\r", "\n"], '', $_GET['x']''', "$a, $b, $value", "$value", False),
        ("preg_replace", r"'/[\r\n]+/', '', $_GET['x']", "$a, $b, $value", "$value", True),
        ("rawurlencode", "$_GET['x']", "$value", "$value", False),
        ("intval", "$_GET['x']", "$value", "$value", True),
    ]:
        opening = f"namespace Application_{name} {{" if braced else f"namespace Application_{name};"
        declaration = f"function {name}({signature}) {{ return {returned}; }}"
        if name == "str_replace":
            declaration = declaration.replace("str_replace", "StR_RePlAcE")
        source = ["<?php", opening, "function unrelated() {}", "function shadow($socket) {",
                  f"    $value = {name}({arguments});",
                  "    socket_write($socket, $value); // crlf-finding", "}",
                  declaration, "function builtin($socket) {",
                  f"    $value = {chr(92)}{name}({arguments});",
                  "    socket_write($socket, $value);", "}"]
        if braced:
            source.append("}")
        target = tmp_path / f"shadow_{name}.php"
        target.write_text("\n".join(source) + "\n")
        targets.append(target)
    ordinary = tmp_path / "ordinary.php"
    ordinary.write_text(r'''<?php
namespace OrdinaryApplication;
function safe_fallback($socket) {
    $value = str_replace(["\r", "\n"], '', $_GET['x']);
    socket_write($socket, $value);
}
class LocalCleaner {
    public function str_replace($a, $b, $value) { return $value; }
    public function send($socket) {
        $value = str_replace(["\r", "\n"], '', $_GET['x']);
        socket_write($socket, $value);
    }
}
''')
    targets.append(ordinary)
    multiple = tmp_path / "multiple_namespaces.php"
    multiple.write_text(r'''<?php
namespace Before;
function clean_before($socket) {
    $value = str_replace(["\r", "\n"], '', $_GET['x']);
    socket_write($socket, $value); // safe
}
namespace Shadow;
function str_replace($a, $b, $value) { return $value; }
function bad($socket) {
    $value = str_replace(["\r", "\n"], '', $_GET['x']);
    socket_write($socket, $value); // crlf-finding
}
namespace After;
function clean_after($socket) {
    $value = str_replace(["\r", "\n"], '', $_GET['x']);
    socket_write($socket, $value); // safe
}
''')
    targets.append(multiple)
    _scan(tmp_path, targets)
