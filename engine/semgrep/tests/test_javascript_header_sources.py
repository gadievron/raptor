"""Header dot access and bracket access share request-source semantics."""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from core.audit.tests._live_transport import run_pinned_subprocess

_RULES = Path(__file__).resolve().parents[1] / "rules"
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed")]

# Keep each family paired with its actual sink and exact native rule id.
_CASES = [('deserialisation/unsafe-deserialize.yaml', 'raptor.deserialisation.unsafe.javascript.serialize-eval', 'eval({s});'), ('injection/command-taint-multi.yaml', 'raptor.injection.command.taint.javascript', 'child_process.exec({s});'), ('injection/header-injection.yaml', 'raptor.injection.header-injection.taint.javascript', 'res.setHeader("X-Result", {s});'), ('injection/log-injection.yaml', 'raptor.injection.log-injection.taint.javascript', 'console.log({s});'), ('injection/nosql-taint.yaml', 'raptor.injection.nosql.taint.javascript', 'collection.find({s});'), ('injection/regex-dos.yaml', 'raptor.injection.regex-dos.taint.javascript', 'new RegExp({s});'), ('injection/ssti-taint.yaml', 'raptor.injection.ssti.taint.javascript', 'ejs.render({s});'), ('injection/xss.yaml', 'raptor.injection.xss.taint.javascript', 'res.send({s});'), ('javascript/js-security.yaml', 'raptor.js.path-traversal', 'fs.readFile({s}, callback);'), ('sinks/open-redirect.yaml', 'raptor.web.open-redirect.taint.javascript', 'res.redirect({s});'), ('sinks/ssrf.yaml', 'raptor.web.ssrf.taint.javascript', 'fetch({s});'), ('web/prototype-pollution-implementation.yaml', 'raptor.web.prototype-pollution.deep-set.javascript', 'target[{s}]["value"] = 1;'), ('web/prototype-pollution.yaml', 'raptor.web.prototype-pollution.taint.javascript', 'lodash.merge(target, {s});')]


@pytest.mark.parametrize("extension", ["js", "ts"])
@pytest.mark.parametrize("config,rule_id,sink", _CASES, ids=[row[0] for row in _CASES])
def test_header_property_sources(tmp_path, config, rule_id, sink, extension):
    sources = [
        ('req.headers["host"]', True),
        ('req.headers.host', True),
        ('request.headers.host', True),
        ('local.headers.host', False),
        ('"constant"', False),
    ]
    lines = []
    expected = set()
    for index, (source, reports) in enumerate(sources):
        lines.append(f"function case_{index}(req, request, local) {{")
        lines.append("  " + sink.replace("{s}", source))
        if reports:
            expected.add(len(lines))
        lines.append("}")
    target = tmp_path / f"cases.{extension}"
    target.write_text("\n".join(lines) + "\n")
    proc = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(_RULES / config), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", str(target)],
        timeout=180, context="JavaScript header source parity", skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(path).name for path in data["paths"]["scanned"]} == {target.name}
    actual = {row["start"]["line"] for row in data["results"]
              if row["check_id"].endswith(rule_id)}
    assert actual == expected, (rule_id, data.get("version"), actual, expected)
