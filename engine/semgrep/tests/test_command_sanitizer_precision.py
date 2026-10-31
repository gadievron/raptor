"""Quoting a result must not hide command execution in its arguments."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_RULE = Path(__file__).resolve().parents[1] / "rules/injection/command-taint.yaml"
_RULE_ID = "raptor.injection.command.taint.python"


@pytest.mark.slow  # Real Semgrep startup approaches the default-tier wall budget.
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_quoting_only_sanitizes_its_result(tmp_path):
    source = """import os
import shlex
import subprocess
os.system(input())  # unsafe
shlex.quote(os.system(input()))  # unsafe
shlex.join([os.popen(input()).read()])  # unsafe
shlex.quote(subprocess.check_output(input(), shell=True))  # unsafe
os.system("echo " + shlex.quote(input()))
os.system(shlex.join(["echo", input()]))
quoted = shlex.quote(input())
os.system("echo " + quoted)
os.system(shlex.quote(input()) + input())  # unsafe
joined = shlex.join(["echo", input()])
os.system(joined)
alias = quoted
os.system("echo " + alias)
quoted = input()
os.system("echo " + quoted)  # unsafe
joined += input()
os.system(joined)  # unsafe
nested = shlex.quote(os.system(input()))  # unsafe
"""
    target = tmp_path / "commands.py"
    target.write_text(source)
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", str(target)],
        env={**os.environ, "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
             "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log")},
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    assert all(r["check_id"].endswith(_RULE_ID) for r in data["results"])
    expected = {i for i, line in enumerate(source.splitlines(), 1) if "# unsafe" in line}
    actual = {r["start"]["line"] for r in data["results"]}
    assert actual == expected, f"Semgrep {data.get('version')}: {actual=} {expected=}"


_VALUE_SANITIZER_CASES = [
        ("eval.py", "injection/eval-taint.yaml", "raptor.injection.eval.taint.python", """
import ast
ast.literal_eval(eval(input()))  # unsafe
ast.literal_eval(input())
"""),
        ("sql.py", "injection/sql-concat.yaml", "raptor.injection.sql.taint.python", """
int(db.execute(input()))  # unsafe
db.execute("SELECT " + str(int(input())))
"""),
        ("path.py", "filesystem/path-traversal.yaml", "raptor.files.path_traversal.taint.python", """
import os
os.path.basename(open(input()).read())  # unsafe
open(os.path.basename(input()))
"""),
        ("joined.py", "python/python-security.yaml", "raptor.python.path-join-traversal", """
import os
os.path.basename(open(input()).read())  # unsafe
open(os.path.basename(input()))
"""),
        ("regex.py", "injection/regex-dos.yaml", "raptor.injection.regex-dos.taint.python", """
import re
re.escape(re.compile(input()).pattern)  # unsafe
re.compile(re.escape(input()))
"""),
        ("html.py", "injection/xss.yaml", "raptor.injection.xss.taint.python", """
import html
html.escape(HttpResponse(input()))  # unsafe
HttpResponse(html.escape(input()))
"""),
        ("shell.php", "php/argument-injection.yaml", "raptor.php.argument-injection.exec-family", """<?php
escapeshellarg(system($_GET['cmd'])); // unsafe
system("echo " . escapeshellarg($_GET['arg']));
intval(exec($_GET['cmd'])); // unsafe
"""),
        ("mongo.js", "injection/nosql-taint.yaml", "raptor.injection.nosql.taint.javascript", """
mongoSanitize(collection.findOne(req.body)); // unsafe
collection.findOne(mongoSanitize(req.body));
"""),
        ("Output.java", "injection/xss.yaml", "raptor.injection.xss.taint.java", """
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
class Output {
  String render(HttpServletRequest request) {
    return org.owasp.encoder.Encode.forHtml(request.getParameter("p"));
  }
  void write(HttpServletRequest request,
             HttpServletResponse response) throws Exception {
    org.owasp.encoder.Encode.forHtml(response.getWriter().printf(request.getParameter("p"))); // unsafe
    response.getWriter().println(org.owasp.encoder.Encode.forHtml(request.getParameter("p")));
  }
}
"""),
    ]


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
@pytest.mark.parametrize("name, config, rule_id, source", _VALUE_SANITIZER_CASES,
                         ids=[case[0] for case in _VALUE_SANITIZER_CASES])
def test_value_sanitizers_preserve_nested_sinks_across_rule_families(
    tmp_path, name, config, rule_id, source,
):
    """Scan each fixture with its own rule family to bound analysis work."""
    target = tmp_path / name
    target.write_text(source)
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(_RULE.parents[1] / config),
         "--metrics", "off", "--disable-version-check", "--jobs", "1",
         "--json", str(target)],
        env={**os.environ, "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
             "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log")},
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    expected = {i for i, line in enumerate(source.splitlines(), 1)
                if "// unsafe" in line or "# unsafe" in line}
    assert expected, name
    actual = {r["start"]["line"] for r in data["results"]
              if r["check_id"].endswith(rule_id)}
    assert actual == expected, (name, rule_id, data.get("version"), actual, expected)
