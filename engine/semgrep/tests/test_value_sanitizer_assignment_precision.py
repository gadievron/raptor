"""Assigned sanitizer results stay clean without clearing raw aliases or nested sinks."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

_RULES = Path(__file__).resolve().parents[1] / "rules"
_CASES = [
    ("LdapAssignments.java", "injection/ldap-taint.yaml", "raptor.injection.ldap.taint.java", '''
import javax.servlet.http.HttpServletRequest;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import org.owasp.esapi.ESAPI;
class LdapAssignments {
  void scan(HttpServletRequest req, DirContext ctx, SearchControls sc) throws Exception {
    String raw = req.getParameter("uid");
    String safe = ESAPI.encoder().encodeForLDAP(raw);
    ctx.search("base", safe, sc);
    String alias = safe;
    ctx.search("base", alias, sc);
    ctx.search("base", raw, sc); // unsafe
    safe = req.getParameter("again");
    ctx.search("base", safe, sc); // unsafe
    String nested = ESAPI.encoder().encodeForLDAP(ctx.search("base", req.getParameter("nested"), sc).toString()); // unsafe
  }
}
'''),
    ("XPathAssignments.java", "injection/xpath-taint.yaml", "raptor.injection.xpath.taint.java", '''
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import org.owasp.esapi.ESAPI;
class XPathAssignments {
  void scan(HttpServletRequest req, XPath xp) throws Exception {
    String raw = req.getParameter("id");
    String safe = ESAPI.encoder().encodeForXPath(raw);
    xp.compile("/employee[@id='" + safe + "']");
    String alias = safe;
    xp.compile("/employee[@id='" + alias + "']");
    xp.compile(raw); // unsafe
    safe = req.getParameter("again");
    xp.compile(safe); // unsafe
    String nested = ESAPI.encoder().encodeForXPath(xp.compile(req.getParameter("nested")).toString()); // unsafe
  }
}
'''),
    ("HtmlAssignments.java", "injection/xss.yaml", "raptor.injection.xss.taint.java", '''
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;
class HtmlAssignments {
  void scan(HttpServletRequest req, HttpServletResponse response) throws Exception {
    String raw = req.getParameter("text");
    String safe = Encode.forHtml(raw);
    response.getWriter().println(safe);
    String alias = safe;
    response.getWriter().println(alias);
    response.getWriter().println(raw); // unsafe
    safe = req.getParameter("again");
    response.getWriter().println(safe); // unsafe
    String nested = Encode.forHtml(response.getWriter().printf(req.getParameter("nested")).toString()); // unsafe
  }
}
'''),
    ("arguments.php", "php/argument-injection.yaml", "raptor.php.argument-injection.exec-family", '''<?php
function assigned_arguments() {
    $raw = $_GET['file'];
    $safe = escapeshellarg($raw);
    exec("echo " . $safe);
    $alias = $safe;
    exec("echo " . $alias);
    exec($raw); // unsafe
    $safe = $_GET['again'];
    exec($safe); // unsafe
    $nested = escapeshellarg(exec($_GET['nested'])); // unsafe
}
'''),
    ("attributes.php", "php/attr-xss.yaml", "raptor.php.attr-xss.attr-context", '''<?php
function assigned_attributes() {
    $raw = $_GET['title'];
    $safe = htmlspecialchars($raw, ENT_QUOTES);
    echo "<span title='" . $safe . "'>x</span>";
    $alias = $safe;
    echo "<span title='" . $alias . "'>x</span>";
    echo "<span title='" . $raw . "'>x</span>"; // unsafe
    $safe = $_GET['again'];
    echo "<span title='" . $safe . "'>x</span>"; // unsafe
    $nested = htmlspecialchars(print("<span title='" . $_GET['nested'] . "'>x</span>"), ENT_QUOTES); // unsafe
}
'''),
    ("includes.php", "php/include-injection.yaml", "raptor.php.include-injection.request-path", '''<?php
function assigned_includes() {
    $raw = $_GET['page'];
    $safe = basename($raw);
    include 'modules/' . $safe;
    $alias = $safe;
    include 'modules/' . $alias;
    include $raw; // unsafe
    $safe = $_GET['again'];
    include $safe; // unsafe
    $nested = basename(include $_GET['nested']); // unsafe
}
'''),
]


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
@pytest.mark.parametrize("name,config,rule_id,source", _CASES, ids=[case[0] for case in _CASES])
def test_assignment_sanitizers_keep_exact_value_boundaries(tmp_path, name, config, rule_id, source):
    target = tmp_path / name
    target.write_text(source)
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(_RULES / config), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", str(target)],
        env={**os.environ, "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
             "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log")},
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    expected = {line for line, text in enumerate(source.splitlines(), 1) if "// unsafe" in text}
    assert len(expected) == 3
    actual = {result["start"]["line"] for result in data["results"]
              if result["check_id"].endswith(rule_id)}
    assert actual == expected, (name, data.get("version"), actual, expected)
