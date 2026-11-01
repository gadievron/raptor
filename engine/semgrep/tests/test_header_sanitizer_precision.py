"""Header sanitizers must remove both controls without hiding raw aliases."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_RULE = Path(__file__).resolve().parents[1] / "rules/injection/header-injection.yaml"
pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")


def _cases(language):
    if language == "python":
        source = "input()"
        expressions = {
            "raw": source,
            "noop": r'''input().replace("\n", "\n").replace("\r", "\r")''',
            "reinject": r'''input().replace("\n", "").replace("\r", "\n")''',
            "limited": r'''input().replace("\n", "", 1).replace("\r", "", 1)''',
            "zero": r'''input().replace("\n", "", 0).replace("\r", "")''',
            "dynamic": r'''input().replace("\n", "").replace("\r", input())''',
            "encoded_replacement": r'''input().replace("\n", "").replace("\r", "\x0a")''',
            "raw_search": r'''input().replace(r"\n", "").replace(r"\r", "")''',
            "partial": r'''input().replace("\r\n", "")''',
            "safe_strip": r'''input().replace("\n", "").replace("\r", "")''',
            "safe_space": r'''input().replace('\r', ' ').replace('\n', ' ')''',
            "safe_normalize": r'''input().replace("\r", "\n").replace("\n", "")''',
            "safe_unlimited": r'''input().replace("\n", "", -1).replace("\r", "", -1)''',
            "safe_backslash": r'''input().replace("\n", "\\n").replace("\r", "\\r")''',
        }
        sink = 'response.headers["X-Value"] = value'
        header = ""
        signature = "def {name}(response):"
        end = ""
    elif language == "go":
        source = 'os.Getenv("VALUE")'
        expressions = {
            "raw": source,
            "noop": r'''strings.ReplaceAll(strings.ReplaceAll(os.Getenv("VALUE"), "\n", "\n"), "\r", "\r")''',
            "reinject": r'''strings.ReplaceAll(strings.ReplaceAll(os.Getenv("VALUE"), "\n", ""), "\r", "\n")''',
            "partial": r'''strings.ReplaceAll(os.Getenv("VALUE"), "\r\n", "")''',
            "dynamic": r'''strings.ReplaceAll(strings.ReplaceAll(os.Getenv("VALUE"), "\n", ""), "\r", os.Getenv("REPLACEMENT"))''',
            "encoded_replacement": r'''strings.ReplaceAll(strings.ReplaceAll(os.Getenv("VALUE"), "\n", ""), "\r", "\x0a")''',
            "raw_search": r'''strings.ReplaceAll(strings.ReplaceAll(os.Getenv("VALUE"), `\n`, ""), `\r`, "")''',
            "safe_strip": r'''strings.ReplaceAll(strings.ReplaceAll(os.Getenv("VALUE"), "\n", ""), "\r", "")''',
            "safe_normalize": r'''strings.ReplaceAll(strings.ReplaceAll(os.Getenv("VALUE"), "\r", "\n"), "\n", "")''',
            "safe_backslash": r'''strings.ReplaceAll(strings.ReplaceAll(os.Getenv("VALUE"), "\n", "\\n"), "\r", "\\r")''',
        }
        sink = 'w.Header().Set("X-Value", value)'
        header = 'package main\nimport ("os"; "strings"; "net/http")\n'
        signature = "func {name}(w http.ResponseWriter) {{"
        end = "}"
    elif language == "java":
        source = 'request.getParameter("value")'
        expressions = {
            "raw": source,
            "noop": source + r'''.replace("\n", "\n").replace("\r", "\r")''',
            "reinject": source + r'''.replace("\n", "").replace("\r", "\n")''',
            "dynamic": source + r'''.replace("\n", "").replace("\r", request.getParameter("replacement"))''',
            "encoded_replacement": source + r'''.replace("\n", "").replace("\r", "\012")''',
            "literal_search": source + r'''.replaceAll("[\\\\r\\\\n]", "")''',
            "backref": source + r'''.replaceAll("[\r\n]", "$0")''',
            "regex_reinject": source + r'''.replaceAll("[\\r\\n]", "\n")''',
            "safe_strip": source + r'''.replace("\n", "").replace("\r", "")''',
            "safe_normalize": source + r'''.replace("\r", "\n").replace("\n", "")''',
            "safe_regex": source + r'''.replaceAll("[\r\n]", " ")''',
            "safe_regex_escape": source + r'''.replaceAll("[\\r\\n]", "")''',
        }
        sink = 'response.setHeader("X-Value", value);'
        header = 'class Contracts {\n'
        signature = "void {name}(HttpServletRequest request, HttpServletResponse response) {{"
        end = "}"
    else:
        source = "req.query.value"
        expressions = {
            "raw": source,
            "noop": source + r'''.replace(/[\r\n]/g, '$&')''',
            "dynamic": source + r'''.replace(/[\r\n]/g, req.query.replacement)''',
            "encoded_replacement": source + r'''.replace(/[\r\n]/g, "\u000a")''',
            "literal_search": source + r'''.replace(/[\\r\\n]/g, "")''',
            "prefix": source + r'''.replace(/[\r\n]/g, "$`")''',
            "suffix": source + r'''.replace(/[\r\n]/g, "$'")''',
            "reinject": source + r'''.replace(/[\r\n]/g, "\n")''',
            "sticky": source + r'''.replace(/[\r\n]/gy, "")''',
            "nonglobal": source + r'''.replace(/[\r\n]/, "")''',
            "callback": source + r'''.replace(/[\r\n]/g, () => req.query.replacement)''',
            "safe_strip": source + r'''.replace(/[\r\n]/g, "")''',
            "safe_reverse": source + r'''.replace(/[\n\r]/g, " ")''',
            "safe_flags": source + r'''.replace(/[\r\n]/gi, "")''',
            "safe_chain": source + r'''.replace(/\n/g, "").replace(/\r/g, "")''',
            "safe_normalize": source + r'''.replace(/\r/g, "\n").replace(/\n/g, "")''',
            "safe_backslash": source + r'''.replace(/[\r\n]/g, "\\n")''',
        }
        sink = 'res.setHeader("X-Value", value);'
        header = ""
        signature = "function {name}(req, res) {{"
        end = "}"
    lines = [header]
    for name, expression in expressions.items():
        lines.append(signature.format(name=name))
        assignment = {"python": "value = ", "go": "value := ", "java": "String value = ", "javascript": "const value = "}[language]
        lines.append("    " + assignment + expression + (";" if language in {"java", "javascript"} else ""))
        marker = "" if name.startswith("safe_") else (" # header-finding" if language == "python" else " // header-finding")
        lines.extend(["    " + sink + marker, end])
    # A sanitizer result does not sanitize the original value or its aliases.
    lines.append(signature.format(name="raw_alias"))
    declaration = {"python": "raw = ", "go": "raw := ", "java": "String raw = ", "javascript": "const raw = "}[language]
    suffix = ";" if language in {"java", "javascript"} else ""
    lines.append("    " + declaration + source + suffix)
    clean = expressions["safe_strip"].replace(source, "raw")
    lines.append("    " + assignment + clean + suffix)
    if language == "go":
        lines.append("    _ = value")
    raw_sink = sink.replace("value", "raw")
    lines.extend(["    " + raw_sink + (" # header-finding" if language == "python" else " // header-finding"), end])
    marker = " # header-finding" if language == "python" else " // header-finding"
    lines.append(signature.format(name="safe_alias"))
    lines.append("    " + assignment + expressions["safe_strip"] + suffix)
    alias_declaration = assignment.replace("value", "alias")
    lines.append("    " + alias_declaration + "value" + suffix)
    lines.extend(["    " + sink.replace("value", "alias"), end])
    lines.append(signature.format(name="safe_direct"))
    lines.extend(["    " + sink.replace("value", expressions["safe_strip"]), end])
    if language in {"python", "javascript"}:
        lines.append(signature.format(name="nested_sink"))
        nested_sink = 'response.headers.set("X-Value", value)' if language == "python" else sink.rstrip(";")
        # The write happens before calling replace on its return value.
        nested = expressions["safe_strip"].replace(source, nested_sink.replace("value", source))
        lines.extend(["    " + assignment + nested + suffix + marker, end])
    lines.append(signature.format(name="recontaminated"))
    lines.append("    " + assignment.replace("const ", "let ") + expressions["safe_strip"] + suffix)
    lines.append("    value = value + " + source + suffix)
    lines.extend(["    " + sink + marker, end])
    lines.append(signature.format(name="conditional_strip"))
    lines.append("    " + assignment.replace("const ", "let ") + source + suffix)
    condition = {
        "python": "if input():",
        "go": 'if os.Getenv("CLEAN") != "" {',
        "java": 'if (request.getParameter("clean") != null) {',
        "javascript": "if (req.query.clean) {",
    }[language]
    lines.extend(["    " + condition, "        value = " + expressions["safe_strip"].replace(source, "value") + suffix])
    if language != "python":
        lines.append("    }")
    lines.extend(["    " + sink + marker, end])
    if language == "java":
        lines.append("}")
    return "\n".join(lines) + "\n"


# Nightly installs Semgrep and selects slow tests. A single batched scan
# covers every language; cold tool startup exceeded 20 seconds under load.
@pytest.mark.slow
def test_header_replacement_contracts(tmp_path):
    languages = [("python", "py"), ("go", "go"), ("java", "java"),
                 ("javascript", "js"), ("javascript", "ts")]
    targets = []
    for language, extension in languages:
        target = tmp_path / f"contracts.{extension}"
        target.write_text(_cases(language))
        targets.append(target)
    if shutil.which("git"):
        for args in (["git", "init", "-q"], ["git", "add", "--", *[p.name for p in targets]]):
            subprocess.run(args, cwd=tmp_path, capture_output=True, timeout=10, check=True)
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics", "off", "--disable-version-check",
         "--jobs", "1", "--json", *map(str, targets)], cwd=tmp_path,
        env={**os.environ, "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
             "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log"), "SEMGREP_ENABLE_VERSION_CHECK": "0"},
        capture_output=True, text=True, timeout=90, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(p).name for p in data["paths"]["scanned"]} == {p.name for p in targets}
    actual = {p.name: set() for p in targets}
    for result in data["results"]:
        assert "raptor.injection.header-injection.taint." in result["check_id"]
        actual[Path(result["path"]).name].add(result["start"]["line"])
    expected = {p.name: {i for i, line in enumerate(p.read_text().splitlines(), 1)
                         if "header-finding" in line} for p in targets}
    assert all(expected.values()), "every language must have positive witnesses"
    assert all(any("safe_" in line for line in p.read_text().splitlines()) for p in targets)
    assert actual == expected, f"Semgrep {data.get('version')}: {actual} != {expected}"
