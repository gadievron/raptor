"""Express headers and Koa body properties share request-source semantics."""
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
_CASES = [('deserialisation/unsafe-deserialize.yaml',
  'raptor.deserialisation.unsafe.javascript.serialize-eval',
  'eval({s});',
  True),
 ('injection/command-taint-multi.yaml',
  'raptor.injection.command.taint.javascript',
  'child_process.exec({s});',
  True),
 ('injection/header-injection.yaml',
  'raptor.injection.header-injection.taint.javascript',
  'res.setHeader("X-Result", {s});',
  True),
 ('injection/log-injection.yaml',
  'raptor.injection.log-injection.taint.javascript',
  'console.log({s});',
  True),
 ('injection/nosql-taint.yaml',
  'raptor.injection.nosql.taint.javascript',
  'collection.find({s});',
  True),
 ('injection/regex-dos.yaml',
  'raptor.injection.regex-dos.taint.javascript',
  'new RegExp({s});',
  True),
 ('injection/ssti-taint.yaml', 'raptor.injection.ssti.taint.javascript', 'ejs.render({s});', True),
 ('injection/xss.yaml', 'raptor.injection.xss.taint.javascript', 'res.send({s});', True),
 ('javascript/js-security.yaml', 'raptor.js.path-traversal', 'fs.readFile({s}, callback);', True),
 ('sinks/open-redirect.yaml',
  'raptor.web.open-redirect.taint.javascript',
  'res.redirect({s});',
  True),
 ('sinks/ssrf.yaml', 'raptor.web.ssrf.taint.javascript', 'fetch({s});', True),
 ('web/prototype-pollution-implementation.yaml',
  'raptor.web.prototype-pollution.deep-set.javascript',
  'target[{s}]["value"] = 1;',
  False),
 ('web/prototype-pollution.yaml',
  'raptor.web.prototype-pollution.taint.javascript',
  'lodash.merge(target, {s});',
  True)]


@pytest.mark.parametrize("extension", ["js", "ts"])
@pytest.mark.parametrize("config,rule_id,sink,koa_body", _CASES, ids=[row[0] for row in _CASES])
def test_header_property_sources(tmp_path, config, rule_id, sink, koa_body, extension):
    sources = [
        ('req.headers["host"]', True),
        ('req.headers.host', True),
        ('request.headers.host', True),
        ('req.get("host")', True),
        ('req.header("host")', True),
        ('request.get("host")', True),
        ('request.header("host")', True),
        ('local.get("host")', False),
        ('local.header("host")', False),
        ('local.headers.host', False),
        ('"constant"', False),
    ]
    # The deep-set implementation rule declares Express sources only.
    if koa_body:
        sources.extend([
            ('ctx.request.query.value', True),
            ('ctx.request.query["value"]', True),
            ('context.request.query.value', True),
            ('c.request.query["value"]', True),
            ('ctx.response.query.value', False),
            ('local.request.query.value', False),
            ('ctx.request.body["value"]', True),
            ('ctx.request.body.value', True),
            ('context.request.body.value', True),
            ('c.request.body.value', True),
            ('ctx.get("host")', True),
            ('ctx.request.get("host")', True),
            ('context.get("host")', True),
            ('c.request.get("host")', True),
            ('ctx.header.host', True),
            ('ctx.header["host"]', True),
            ('ctx.headers.host', True),
            ('ctx.headers["host"]', True),
            ('ctx.request.header.host', True),
            ('ctx.request.header["host"]', True),
            ('ctx.request.headers.host', True),
            ('ctx.request.headers["host"]', True),
            ('context.headers.host', True),
            ('c.request.headers.host', True),
            ('ctx.response.headers.host', False),
            ('ctx.response.header["host"]', False),
            ('local.request.headers.host', False),
            ('ctx.response.get("host")', False),
            ('local.request.get("host")', False),
            ('local.request.body.value', False),
            ('"constant body"', False),
        ])
    cases = [(sink.replace("{s}", source), reports) for source, reports in sources]
    if config == "injection/nosql-taint.yaml":
        cases.extend([
            ("collection.find(req.query);", True),
            ("collection.find(req.params);", True),
            ("collection.find(request.query);", True),
            ("collection.find(request.params);", True),
            ("collection.find(req.body);", True),
            ("collection.find({}, req.query);", False),
            ("collection.find({}, req.params);", False),
            ("collection.find(req);", False),
            ("const query = req.query; collection.find(query);", True),
            ("const params = req.params; collection.find(params);", True),
            ("collection.find({...req.query});", True),
            ("collection.find({...req.params});", True),
            ("const data = req.query; collection.find(req);", False),
            ("collection.find(local.query);", False),
            ("collection.find(local.params);", False),
            ("collection.find({}, req.body);", False),
            ("collection.find(ctx.query);", True),
            ("collection.find(ctx.params);", True),
            ("collection.find(context.query);", True),
            ("collection.find(c.params);", True),
            ("collection.find(ctx.request.body);", True),
            ("collection.find({}, ctx.query);", False),
            ("collection.find({}, ctx.params);", False),
            ("collection.find(ctx);", False),
            ("const query = ctx.query; collection.find(query);", True),
            ("const params = ctx.params; collection.find(params);", True),
            ("collection.find({...ctx.query});", True),
            ("collection.find({...ctx.params});", True),
            ("const data = ctx.query; collection.find(ctx);", False),
            ("collection.find({}, ctx.request.body);", False),
        ])
    if config in ("injection/nosql-taint.yaml", "web/prototype-pollution.yaml"):
        cases.extend([
            (sink.replace("{s}", source), reports)
            for source, reports in [
                ("ctx.request.query", True),
                ("context.request.query", True),
                ("c.request.query", True),
                ("{...ctx.request.query}", True),
                ("ctx.response.query", False),
                ("local.request.query", False),
                ("local.query", False),
            ]
        ])
        cases.extend([
            ("const data = ctx.request.query; " + sink.replace("{s}", "data"), True),
            ("const data = ctx.request.query; " + sink.replace("{s}", "ctx"), False),
            ("const data = ctx.request.query; " + sink.replace("{s}", "ctx.request"), False),
        ])
    if config == "injection/nosql-taint.yaml":
        cases.append(("collection.find({}, ctx.request.query);", False))
    lines = []
    expected = set()
    for index, (body, reports) in enumerate(cases):
        lines.append(f"function case_{index}(req, request, local, ctx, context, c) {{")
        lines.append("  " + body)
        if reports:
            expected.add(len(lines))
        lines.append("}")
    target = tmp_path / f"cases.{extension}"
    target.write_text("\n".join(lines) + "\n")
    proc = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(_RULES / config), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", str(target)],
        timeout=180, context="JavaScript request property parity", skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(path).name for path in data["paths"]["scanned"]} == {target.name}
    actual = {row["start"]["line"] for row in data["results"]
              if row["check_id"].endswith(rule_id)}
    assert actual == expected, (rule_id, data.get("version"), actual, expected)
