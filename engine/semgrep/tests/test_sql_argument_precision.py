"""SQL text, rather than context, receiver or bound data, is the sink."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil

import pytest

from core.audit.tests._live_transport import run_pinned_subprocess

_RULES = Path(__file__).resolve().parents[1] / "rules"
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed")]

_MATRICES = {
    "python": ("injection/sql-concat.yaml", "raptor.injection.sql.taint.python", [
        ('cursor.execute(input())', True),
        ('cursor.executescript(input())', True),
        ('cursor.executescript("SELECT " + input())', True),
        ('sqlite3.connect(":memory:").executescript(input())', True),
        ('cursor.executescript("SELECT " + str(int(input())))', False),
        ('cursor = get_cursor(input())\ncursor.executescript("SELECT 1")', False),
        ('cursor.execute("SELECT ?", (cursor.executescript(input()),))', True),
        ('cursor.executescript("SELECT 1;")', False),
        ('cursor.execute(input(), ())', True),
        ('cursor.executemany(input(), [(1,)])', True),
        ('cursor.execute(query=input(), params=())', True),
        ('cursor.execute(params=(), query=input())', True),
        ('cursor.executemany(query=input(), params_seq=[(1,)])', True),
        ('cursor.executemany(params_seq=[(1,)], query=input())', True),
        ('cursor.execute(statement=sqlalchemy.text(input()), parameters={})', True),
        ('cursor.execute(parameters={}, statement=sqlalchemy.text(input()))', True),
        ('cursor.execute(query="SELECT %s", params=(input(),))', False),
        ('cursor.execute(params=(input(),), query="SELECT %s")', False),
        ('cursor.execute(parameters={"id": input()}, statement=sqlalchemy.text("SELECT :id"))', False),
        ('cursor.execute(query="SELECT " + str(int(input())))', False),
        ('int(cursor.execute(query=input()))', True),
        ('cursor.execute("SELECT ?", (input(),))', False),
        ('cursor.executemany("INSERT INTO t VALUES (?)", [(input(),)])', False),
        ('query = input()\ncursor.execute(query, {"id": 1})', True),
        ('cursor.execute(sqlalchemy.text(input()), {"id": 1})', True),
        ('int(cursor.execute(input(), (1,)))', True),
        ('cursor.execute("SELECT ?", (cursor.execute(input()),))', True),
        ('cursor = get_cursor(input())\ncursor.execute("SELECT 1")', False),
    ]),
    "go-concat": ("injection/sql-taint.yaml", "raptor.injection.sql.taint.go", [
        ('db.Query("SELECT * FROM t WHERE " + r.FormValue("sql"), 1)', True),
        ('db.Query("SELECT * FROM t WHERE " + strings.TrimSpace("id = ?"), r.FormValue("id"))', False),
        ('db.QueryContext(ctx, "SELECT * FROM t WHERE " + r.FormValue("sql"), 1)', True),
        ('ctx = context.WithValue(ctx, "trace", r.FormValue("trace"))\ndb.QueryContext(ctx, "SELECT " + strings.TrimSpace("1"), 1)', False),
        ('search.Query("asset " + r.FormValue("key"))', False),
        ('db.Query("SELECT " + r.FormValue("head") + " FROM t", 1)', True),
    ]),
    "go-format": ("go/go-security.yaml", "raptor.go.sql-sprintf-query", [
        ('db.Query(fmt.Sprintf("SELECT %s", r.FormValue("sql")), 1)', True),
        ('db.Query(fmt.Sprintf(`SELECT %s`, r.FormValue("sql")), 1)', True),
        ('db.Query(fmt.Sprintf(`  select %s`, r.FormValue("sql")), 1)', True),
        ('db.Query(fmt.Sprintf(`SELECT %s`, "1"), r.FormValue("id"))', False),
        ('search.Query(fmt.Sprintf(`selected items: %s`, r.FormValue("key")))', False),
        ('db.Query(fmt.Sprintf("SELECT %s", "1"), r.FormValue("id"))', False),
        ('ctx = context.WithValue(ctx, "trace", r.FormValue("trace"))\ndb.QueryContext(ctx, fmt.Sprintf("SELECT %s", "1"), 1)', False),
        ('db.QueryRow(r.FormValue("sql"), 1)', True),
        ('db.QueryContext(ctx, r.FormValue("sql"), 1)', True),
        ('db.QueryRowContext(ctx, r.FormValue("sql"), 1)', True),
        ('db.ExecContext(ctx, r.FormValue("sql"), 1)', True),
        ('db.QueryRow("SELECT ?", r.FormValue("id"))', False),
        ('db.QueryContext(ctx, "SELECT ?", r.FormValue("id"))', False),
        ('search.Query(fmt.Sprintf("selected items: %s", r.FormValue("key")))', False),
    ]),
    "javascript": ("injection/sql-taint.yaml", "raptor.injection.sql.taint.javascript", [
        ('connection.query("SELECT * FROM t WHERE " + req.query.sql, [1]);', True),
        ('connection.query("SELECT * FROM t WHERE " + clean("id = ?"), [req.query.id]);', False),
        ('connection.query("SELECT ?", [req.query.id]);', False),
        ('connection.query("SELECT " + req.query.head + " FROM t", [1]);', True),
        ('search.query("asset " + req.query.key);', False),
        ('connection.query(req.query.sql, [1]);', True),
        ('connection.execute(req.query.sql, [1]);', True),
    ]),
    "java": ("injection/sql-taint.yaml", "raptor.injection.sql.taint.java", [
        ('stmt.executeQuery(request.getParameter("sql"));', True),
        ('stmt.execute(request.getParameter("sql"), Statement.RETURN_GENERATED_KEYS);', True),
        ('stmt.executeUpdate(request.getParameter("sql"), new String[]{"id"});', True),
        ('stmt.execute("SELECT 1", Integer.parseInt(request.getParameter("flags")));', False),
        ('Statement selected = factory.forTenant(request.getParameter("tenant"));\nselected.execute("SELECT 1");', False),
        ('PreparedStatement p = conn.prepareStatement("SELECT ?");\np.setString(1, request.getParameter("data"));\np.execute();', False),
        ('conn.prepareStatement(request.getParameter("sql"), Statement.RETURN_GENERATED_KEYS);', True),
    ]),
}


for _accessor in (
    'request.GET.get("sql")', 'request.POST.get("sql")',
    'flask.request.args.get("sql")', 'flask.request.form.get("sql")',
    'os.environ.get("SQL_QUERY")',
):
    _MATRICES["python"][2].extend([
        (f'cursor.execute({_accessor})', True),
        (f'cursor.execute("SELECT ?", ({_accessor},))', False),
        (f'cursor.execute("SELECT " + str(int({_accessor})))', False),
    ])


for _accessor in (
    'request.GET.getlist("ids")', 'request.POST.getlist("ids")',
    'flask.request.args.getlist("ids")', 'flask.request.form.getlist("ids")',
):
    _MATRICES["python"][2].extend([
        (f'cursor.execute("SELECT " + ",".join({_accessor}))', True),
        (f'cursor.execute("SELECT ?", ({_accessor},))', False),
    ])
for _container in ('flask.request.args', 'flask.request.form'):
    _MATRICES["python"][2].extend([
        (f'cursor.execute("SELECT " + str({_container}.get("id", type=int)))', False),
        (f'cursor.execute("SELECT " + str({_container}.get("id", 0, int)))', False),
        (f'cursor.execute({_container}.get("sql", "SELECT 1"))', True),
        (f'cursor.execute({_container}.get("sql", default="SELECT 1"))', True),
    ])
    _MATRICES["python"][2].append((
        f'cursor.execute("SELECT " + str({_container}.getlist("ids", type=int)))', False,
    ))
    for _accessor in (
        f'{_container}.get(key="sql")',
        f'{_container}.get(key="sql", default="SELECT 1")',
        f'{_container}.get(default="SELECT 1", key="sql")',
    ):
        _MATRICES["python"][2].extend([
            (f'cursor.execute({_accessor})', True),
            (f'cursor.execute("SELECT ?", ({_accessor},))', False),
        ])
    _MATRICES["python"][2].append((
        f'cursor.execute("SELECT " + str({_container}.get(key="id", type=int)))', False,
    ))


for _accessor in (
    'flask.request.values["sql"]',
    'flask.request.values.get("sql")',
    'flask.request.values.get("sql", "SELECT 1")',
    'flask.request.values.get("sql", default="SELECT 1")',
    'flask.request.values.get(key="sql")',
    'flask.request.values.get(key="sql", default="SELECT 1")',
    'flask.request.values.get(default="SELECT 1", key="sql")',
):
    _MATRICES["python"][2].extend([
        (f'cursor.execute({_accessor})', True),
        (f'cursor.execute("SELECT ?", ({_accessor},))', False),
        (f'cursor.execute("SELECT " + str(int({_accessor})))', False),
    ])
for _container in ('flask.request.args', 'flask.request.form', 'flask.request.values'):
    _MATRICES["python"][2].extend([
        (f'cursor.execute("SELECT " + ",".join({_container}.getlist(key="ids")))', True),
        (f'cursor.execute("SELECT ?", ({_container}.getlist(key="ids"),))', False),
        (f'cursor.execute("SELECT " + str({_container}.getlist(key="ids", type=int)))', False),
    ])
_MATRICES["python"][2].extend([
    ('cursor.execute("SELECT " + ",".join(flask.request.values.getlist("ids")))', True),
    ('cursor.execute("SELECT ?", (flask.request.values.getlist("ids"),))', False),
    ('cursor.execute("SELECT " + str(flask.request.values.get("id", type=int)))', False),
    ('cursor.execute("SELECT " + str(flask.request.values.get("id", 0, int)))', False),
    ('cursor.execute("SELECT " + str(flask.request.values.get(key="id", type=int)))', False),
    ('cursor.execute("SELECT " + str(flask.request.values.getlist("ids", type=int)))', False),
])


_MATRICES["java-wrapper"] = (
    None, "raptor.generated.source-wrapper.sqli",
    [(body.replace("request.getParameter", "wrapper.grab"), finding)
     for body, finding in _MATRICES["java"][2]],
)


_MATRICES["javascript"][2].extend([
    ('connection.query({text: "SELECT $1", values: [req.query.id]});', False),
    ('connection.query({text: req.query.sql, values: [1]});', True),
    ('connection.query({values: [req.query.id], text: "SELECT $1"});', False),
    ('const text = "SELECT $1";\nconnection.query({text, values: [req.query.id]});', False),
    ('const text = req.query.sql;\nconnection.query({text, values: [1]});', True),
    ('connection.query({text: "SELECT " + req.query.head + " FROM t", values: [req.query.id]});', True),
    ('connection.query({query: req.query.sql});', True),
    ('search.query({text: req.query.sql, values: []});', False),
    ('connection.query({text: "SELECT $1", values: [connection.query(req.query.sql)]});', True),
    ('connection.query({text: "SELECT $1", values: [{id: req.query.id}]});', False),
    ('connection.query({text: "SELECT $1", values: ["SELECT " + req.query.id]});', False),
    ('connection.query(`SELECT ${req.query.sql}`);', True),
    ('connection.query(`SELECT $1`, [req.query.id]);', False),
    ('connection.query({text: `SELECT ${req.query.sql}`, values: [1]});', True),
    ('knex.raw(req.query.sql, [1]);', True),
    ('knex.raw("SELECT ?", [req.query.id]);', False),
    ('sequelize.query(req.query.sql, {bind: [1]});', True),
    ('sequelize.query("SELECT $1", {bind: [req.query.id]});', False),
    ('connection.prepare(req.query.sql);', True),
    ('connection.prepare("SELECT 1");', False),
    ('connection.query({text: "SELECT $1", values: [1], sql: req.query.sql});', True),
])
for _source in ('req.params.sql', 'req.body.sql', 'req.headers["x-query"]',
                'req.headers.host', 'request.headers.host',
                'ctx.query.sql', 'ctx.params.sql', 'ctx.request.body.sql', 'ctx.request.body["sql"]',
                'process.env.QUERY', 'process.argv[2]'):
    _MATRICES["javascript"][2].extend([
        (f'connection.query({_source});', True),
        (f'connection.query("SELECT $1", [{_source}]);', False),
    ])
# Whole Express query objects remain sources when spread into SQL options.
_MATRICES["javascript"][2].extend([
    ('connection.query({...req.query});', True),
    ('connection.query({text: "SELECT 1", ...req.query});', True),
    ('connection.query("SELECT $1", [{...req.query}]);', False),
    ('connection.query({text: "SELECT $1", values: [req.query]});', False),
    ('search.query({...req.query});', False),
    ('connection.query(req);', False),
    ('connection.query(local.headers.host);', False),
])

_MATRICES["typescript"] = (
    "injection/sql-taint.yaml", "raptor.injection.sql.taint.javascript",
    _MATRICES["javascript"][2],
)


@pytest.mark.parametrize("family", _MATRICES)
def test_sql_text_argument_is_the_sink(tmp_path, monkeypatch, family):
    config, rule_id, cases = _MATRICES[family]
    if family == "python":
        name = "cases.py"
        prefix = ["import sqlite3", "import sqlalchemy", "def get_cursor(tenant):",
                  "    return sqlite3.connect(':memory:').cursor()"]
        head, tail, indent = "def case_{index}(cursor):", "", "    "
    elif family.startswith("go-"):
        name = "cases.go"
        imports = '"context"; "database/sql"; "net/http"; ' + ('"strings"' if family == "go-concat" else '"fmt"')
        prefix = ["package example", "import (" + imports + ")", "type Search struct{}",
                  "func (*Search) Query(text string, args ...interface{}) {}"]
        head, tail, indent = "func case_{index}(r *http.Request, db *sql.DB, search *Search) {{", "}", "    "
    elif family in {"javascript", "typescript"}:
        name = "cases.ts" if family == "typescript" else "cases.js"
        prefix, head, tail, indent = [], "function case_{index}(req, connection, search) {{", "}", "  "
    else:
        name = "Cases.java"
        prefix = ["import java.sql.*;", "import javax.servlet.http.HttpServletRequest;",
                  "interface StatementFactory { Statement forTenant(String tenant); }", "class Cases {"]
        if family == "java-wrapper":
            prefix.insert(-1, "class RequestSource { private final HttpServletRequest request; "
                          "RequestSource(HttpServletRequest request) { this.request = request; } "
                          "String grab(String name) { return request.getParameter(name); } }")
        head = "void case_{index}(HttpServletRequest request, Statement stmt, Connection conn, StatementFactory factory, RequestSource wrapper) throws Exception {{" if family == "java-wrapper" else "void case_{index}(HttpServletRequest request, Statement stmt, Connection conn, StatementFactory factory) throws Exception {{"
        tail, indent = "}", "    "
    lines, expected = list(prefix), set()
    for index, (body, reports) in enumerate(cases):
        lines.append(head.format(index=index))
        if family.startswith("go-"):
            lines.extend([indent + "ctx := context.Background()", indent + "_ = ctx"])
        lines.extend(indent + line for line in body.splitlines())
        if reports:
            expected.add(len(lines))
        if tail:
            lines.append(tail)
    if family in ("java", "java-wrapper"):
        lines.append("}")
    target = tmp_path / name
    target.write_text("\n".join(lines) + "\n")
    monkeypatch.chdir(tmp_path)
    if family == "java-wrapper":
        from core.analysis.java_source_summaries import SourceSummary
        from packages.semgrep.source_wrapper_rules import generate_rules_yaml

        summary = SourceSummary(package="", owner="RequestSource", name="grab", arity=1,
                                signature="(String)", via="field")
        projected = generate_rules_yaml([summary])
        assert projected is not None
        rule_config = tmp_path / "source-wrappers.json"
        rule_config.write_text(projected)
    else:
        rule_config = _RULES / config
    proc = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(rule_config), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", str(target)],
        timeout=180, context="SQL argument precision", skip_signals=(9,),
        env={**os.environ, "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
             "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log")},
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(path).name for path in data["paths"]["scanned"]} == {name}
    assert expected, family
    actual = {row["start"]["line"] for row in data["results"] if row["check_id"].endswith(rule_id)}
    assert actual == expected, (family, data.get("version"), actual, expected)


@pytest.mark.parametrize("family", ["javascript", "typescript"])
def test_sql_query_option_sink_retention(tmp_path, monkeypatch, family):
    """Exercise sink admission without taint propagation masking unknown fields."""
    import yaml

    document = yaml.safe_load((_RULES / "injection/sql-taint.yaml").read_text())
    rule = next(row for row in document['rules'] if row['id'] == 'raptor.injection.sql.taint.javascript')
    generic = next(sink for sink in rule['pattern-sinks'] if any(
        row.get('metavariable-regex', {}).get('metavariable') == '$DBOBJ'
        for row in sink.get('patterns', [])
    ))
    config = tmp_path / 'generic-sink-contract.json'
    config.write_text(json.dumps({'rules': [{
        'id': rule['id'], 'languages': rule['languages'],
        'message': 'owned generic sink contract', 'severity': 'WARNING',
        'options': rule['options'], 'patterns': generic['patterns'],
    }]}))
    cases = [('connection.query({text: "SELECT $1", values: [req.query.id]});', False),
     ('connection.query({values: [req.query.id], text: "SELECT $1"});', False),
     ('const text = "SELECT $1";\nconnection.query({text, values: [req.query.id]});', False),
     ('connection.query({text: req.query.sql, values: [1]});', True),
     ('connection.query({text: `SELECT ${req.query.sql}`, values: [1]});', True),
     ('connection.query({text: "SELECT $1", values: [1], ...req.query});', True),
     ('connection.query({...req.query, text: "SELECT $1", values: [1]});', True),
     ('connection.query({text: "SELECT $1", values: [1], [req.query.key]: req.query.sql});', True),
     ('connection.query({text: "SELECT $1", values: [1], [[req.query.key][0]]: req.query.sql});', True),
     ('connection.query({text: "SELECT $1", values: [1], sql: req.query.sql});', True),
     ('connection.query({text: "SELECT $1", values: [1], text: req.query.sql});', True),
     ('connection.query({text: req.query.sql, values: [1], text: "SELECT $1"});', True),
     ('connection.query({text: "SELECT $1", values: [1], get text() {return req.query.sql;}});', True),
     ('connection.query({text: "SELECT $1", values: [1], name: "cache"});', True),
     ('connection.query({query: req.query.sql, box: {text: "SELECT $1", values: [1]}});', True),
     ('connection.query({text: "SELECT $1", values: [1], sql: {text: "SELECT $1", values: '
      '[req.query.sql]}});',
      True),
     ('connection.query({text: "SELECT $1", values: [req.query.id], ...{}});', True),
     ('connection.query({text: "SELECT $1", values: [{id: req.query.id}]});', False),
     ('const options = {text: "SELECT $1", values: [req.query.id]};\nconnection.query(options);', True),
     ('const options = {text: "SELECT $1", values: [1]};\n'
      'options.text = req.query.sql;\n'
      'connection.query(options);',
      True)]
    monkeypatch.setitem(_MATRICES, family, (str(config), rule['id'], cases))
    test_sql_text_argument_is_the_sink(tmp_path, monkeypatch, family)
