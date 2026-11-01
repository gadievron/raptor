"""Log sanitizers must remove both controls without hiding raw aliases."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_RULE = Path(__file__).resolve().parents[1] / "rules/injection/log-injection.yaml"
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
        sink = 'logging.info(value)'
        header = "import logging\n"
        signature = "def {name}():"
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
        sink = 'log.Print(value)'
        header = 'package main\nimport ("os"; "strings"; "log"; "log/slog"; "io")\n'
        signature = "func {name}() {{"
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
        sink = 'logger.info(value);'
        header = 'class Contracts {\n'
        signature = "void {name}(HttpServletRequest request, Logger logger) {{"
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
        sink = 'console.log(value);'
        header = ""
        signature = "function {name}(req, res) {{"
        end = "}"
    lines = [header]
    for name, expression in expressions.items():
        lines.append(signature.format(name=name))
        assignment = {"python": "value = ", "go": "value := ", "java": "String value = ", "javascript": "const value = "}[language]
        lines.append("    " + assignment + expression + (";" if language in {"java", "javascript"} else ""))
        marker = "" if name.startswith("safe_") else (" # log-finding" if language == "python" else " // log-finding")
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
    lines.extend(["    " + raw_sink + (" # log-finding" if language == "python" else " // log-finding"), end])
    marker = " # log-finding" if language == "python" else " // log-finding"
    lines.append(signature.format(name="safe_alias"))
    lines.append("    " + assignment + expressions["safe_strip"] + suffix)
    alias_declaration = assignment.replace("value", "alias")
    lines.append("    " + alias_declaration + "value" + suffix)
    lines.extend(["    " + sink.replace("value", "alias"), end])
    lines.append(signature.format(name="safe_direct"))
    lines.extend(["    " + sink.replace("value", expressions["safe_strip"]), end])
    if language in {"python", "javascript"}:
        lines.append(signature.format(name="nested_sink"))
        nested_sink = 'logging.info(value)' if language == "python" else sink.rstrip(";")
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
    lines.append(_logging_contexts(language))
    if language == "java":
        lines.append("}")
    return "\n".join(lines) + "\n"

def _logging_contexts(language):
    """Raw formatting and escaping controls for the concrete API contracts."""
    if language == "python":
        return r'''
def raw_format():
    logging.info("User: %s", input()) # log-finding
    logging.warning("User: %s", input()) # log-finding
    logging.error("User: %s", input()) # log-finding
    logging.debug("User: %s", input()) # log-finding
    logging.critical("User: %s", input()) # log-finding
    logging.exception("User: %s", input()) # log-finding
    logging.info("User: %% %s", input()) # log-finding

def safe_format():
    logging.info("User: %r", input())
    logging.info("User: %a", input())
    logging.info("User: %%s", input())
    logging.info("User: %s", input().replace("\r", "").replace("\n", ""))

def format_reinjection():
    value = input().replace("\r", "").replace("\n", "\r")
    logging.info("User: %s", value) # log-finding
'''
    if language == "go":
        return r'''
func rawFormat() {
    log.Printf("User: %s", os.Getenv("USER")) // log-finding
    log.Fatalf("User: %s", os.Getenv("USER")) // log-finding
    log.Panicf("User: %v", os.Getenv("USER")) // log-finding
    log.Printf("User: %% %s", os.Getenv("USER")) // log-finding
    log.Printf("User: %%s", os.Getenv("USER")) // log-finding
    log.Printf("User", os.Getenv("USER")) // log-finding
    log.Printf("User: %d", os.Getenv("USER")) // log-finding
    log.Printf("User: %t", os.Getenv("USER")) // log-finding
    log.Println("User:", os.Getenv("USER")) // log-finding
    log.Print("User:", os.Getenv("USER"), "tail") // log-finding
}
func safeFormat() {
    log.Printf("User: %q", os.Getenv("USER"))
    log.Printf("User: %x", os.Getenv("USER"))
    log.Printf("User: %X", os.Getenv("USER"))
    log.Printf("User: %T", os.Getenv("USER"))
    log.Printf("User: %s", strings.ReplaceAll(strings.ReplaceAll(os.Getenv("USER"), "\r", ""), "\n", ""))
}
func safeStructured() {
    slog.Info(os.Getenv("USER"))
    slog.Warn(os.Getenv("USER"))
    slog.Error(os.Getenv("USER"))
    slog.Debug(os.Getenv("USER"))
    slog.Info("User", "value", os.Getenv("USER"))
    slog.New(slog.NewTextHandler(io.Discard, nil)).Info(os.Getenv("USER"))
    slog.New(slog.NewJSONHandler(io.Discard, nil)).Info(os.Getenv("USER"))
}
'''
    if language == "java":
        return r'''
void rawFormat(HttpServletRequest request, Logger logger) {
    logger.info("User: {}", request.getParameter("value")); // log-finding
    logger.warn("User: {}", request.getParameter("value")); // log-finding
    logger.error("User: {}", request.getParameter("value")); // log-finding
    logger.debug("User: {}", request.getParameter("value")); // log-finding
    logger.trace("User: {}", request.getParameter("value")); // log-finding
}
void safeFormat(HttpServletRequest request, Logger logger) {
    logger.info("User", request.getParameter("value"));
    logger.info("User: \\{}", request.getParameter("value"));
    logger.info("User: {}", request.getParameter("value").replace("\r", "").replace("\n", ""));
}
'''
    return r'''
function rawFormat(req) {
    console.log("User: %s", req.query.value); // log-finding
    console.info("User: %s", req.query.value); // log-finding
    console.warn("User: %s", req.query.value); // log-finding
    console.error("User: %s", req.query.value); // log-finding
    console.debug("User: %s", req.query.value); // log-finding
    console.log("User:", req.query.value); // log-finding
    console.log("User: %%s", req.query.value); // log-finding
    console.log("User: %% %s", req.query.value); // log-finding
}
function safeFormat(req) {
    console.log("User: %j", req.query.value);
    console.log("User: %d", req.query.value);
    console.log("User: %s", req.query.value.replace(/[\r\n]/g, ""));
}
function formatReinjection(req) {
    const value = req.query.value.replace(/[\r\n]/g, "$&");
    console.log("User: %s", value); // log-finding
}
'''


# Nightly installs Semgrep and selects slow tests. A single batched scan
# covers every language; cold tool startup exceeded 20 seconds under load.
@pytest.mark.slow
def test_log_replacement_contracts(tmp_path):
    languages = [("python", "py"), ("go", "go"), ("java", "java"),
                 ("javascript", "js"), ("javascript", "ts")]
    targets = []
    for language, extension in languages:
        target = tmp_path / f"contracts.{extension}"
        target.write_text(_cases(language))
        targets.append(target)
    _scan_targets(tmp_path, targets)


def _scan_targets(tmp_path, targets, *, columns=False):
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
        assert "raptor.injection.log-injection.taint." in result["check_id"]
        actual[Path(result["path"]).name].add((result["start"]["line"], result["start"]["col"]) if columns else result["start"]["line"])
    if columns:
        expected = {p.name: set() for p in targets}
        for target in targets:
            for number, line in enumerate(target.read_text().splitlines(), 1):
                if 'format-find:' not in line:
                    continue
                code, names = line.split('format-find:', 1)
                for name in filter(None, map(str.strip, names.split(','))):
                    expected[target.name].add((number, code.rindex(name) + 1))
    else:
        expected = {p.name: {i for i, line in enumerate(p.read_text().splitlines(), 1)
                             if "log-finding" in line} for p in targets}
    assert all(expected.values()), "every language must have positive witnesses"
    if not columns:
        assert all(any("safe_" in line for line in p.read_text().splitlines()) for p in targets)
    assert actual == expected, f"Semgrep {data.get('version')}: {actual} != {expected}"


def _format_cases(language):
    """Each marker names exact argument ranges, including mixed safe/raw calls."""
    if language == "python":
        cases = {
            "mixed_first": ('logging.info("%s %r", raw1, raw2)', ['raw1']),
            "mixed_second": ('logging.info("%r %s", raw1, raw2)', ['raw2']),
            "three": ('logging.info("%r %s %a", raw1, raw2, raw3)', ['raw2']),
            "four": ('logging.info("%r %s %a %s", raw1, raw2, raw3, raw4)', ['raw2', 'raw4']),
            "all_encoded": ('logging.info("%r %a", raw1, raw2)', []),
            "extra_error": ('logging.info("%s", raw1, raw2)', []),
            "missing_error": ('logging.info("%s %s", raw1)', []),
            "zero_precision": ('logging.info("%.0s %r", raw1, raw2)', []),
            "width": ('logging.info("%10s %.0s", raw1, raw2)', ['raw1']),
            "precision": ('logging.info("%.1s %r", raw1, raw2)', ['raw1']),
            "character": ('logging.info("%.0c %r", raw1, raw2)', ['raw1']),
            "percent": ('logging.info("%%s %r %s", raw1, raw2)', ['raw2']),
            "numeric": ('logging.info("%d %s", 42, raw2)', ['raw2']),
            "bad_numeric": ('logging.info("%d %s", "42", raw2)', []),
            "keyword_arguments": ('logging.info("%s %r", raw1, raw2, extra={"tag": "fixed"})', ['raw1']),
            "invalid_flag": (r'logging.info(r"%\s %r", raw1, raw2)', []),
            "format_alias": ('fmt = "%s %r"\nlogging.info(fmt, raw1, raw2)', ['raw1']),
            "mutated_safe": ('fmt = "%s %s"\nfmt = "%r %r"\nlogging.info(fmt, raw1, raw2)', []),
            "mutated_raw": ('fmt = "%r %r"\nfmt = "%r %s"\nlogging.info(fmt, raw1, raw2)', ['raw2']),
            "input_alias": ('alias = raw1\nlogging.info("%s %r", alias, raw2)', ['alias']),
            "mapping_one": ('logging.info("%(first)s", {"first": raw1, "unused": raw2})', ['raw1']),
            "mapping_repeat": ('logging.info("%(first)r %(first)s", {"first": raw1})', ['raw1']),
            "mapping_mixed": ('logging.info("%(first)s %(second)r", {"first": raw1, "second": raw2})', ['raw1']),
            "mapping_second": ('logging.info("%(first)r %(second)s", {"first": raw1, "second": raw2})', ['raw2']),
            "mapping_safe": ('logging.info("%(first)r %(second)a", {"first": raw1, "second": raw2})', []),
            "mapping_unused": ('logging.info("%(used)s", {"used": "fixed", "unused": raw1})', []),
            "mapping_missing": ('logging.info("%(first)s %(missing)s", {"first": raw1})', []),
            "mapping_overwritten": ('logging.info("%(first)s", {"first": raw1, "first": "fixed"})', []),
            "mapping_alias": ('fmt = "%(first)s %(second)r"\nlogging.info(fmt, {"first": raw1, "second": raw2})', ['raw1']),
            "mapping_percent": ('logging.info("%%(first)s", {"first": raw1})', []),
            "mapping_sanitized": ('clean = raw1.replace("\\r", "").replace("\\n", "")\nlogging.info("%(first)s", {"first": clean})', []),
        }
        header, signature, end, decl = 'import logging\n', 'def {name}():', '', lambda i: f'raw{i} = input()'
    elif language == "go":
        cases = {
            "mixed_first": ('log.Printf("%s %q", raw1, raw2)', ['raw1']),
            "mixed_second": ('log.Printf("%q %s", raw1, raw2)', ['raw2']),
            "three": ('log.Printf("%q %s %X", raw1, raw2, raw3)', ['raw2']),
            "four": ('log.Printf("%q %s %x %s", raw1, raw2, raw3, raw4)', ['raw2', 'raw4']),
            "encoded": ('log.Printf("%q %X %T", raw1, raw2, raw3)', []),
            "extra": ('log.Printf("%q", raw1, raw2)', ['raw2']),
            "missing": ('log.Printf("%q %s", raw1)', []),
            "type_error": ('log.Printf("%q %d", raw1, raw2)', ['raw2']),
            "empty": ('log.Printf("", raw1)', ['raw1']),
            "literal_percent": ('log.Printf("%%s", raw1)', ['raw1']),
            "format_alias": ('fmt := "%q %s"\nlog.Printf(fmt, raw1, raw2)', ['raw2']),
            "mutated_safe": ('fmt := "%s %s"\nfmt = "%q %q"\nlog.Printf(fmt, raw1, raw2)', []),
            "indexed_second": ('log.Printf("%[2]s", raw1, raw2)', ['raw2']),
            "indexed_first": ('log.Printf("%[2]q %[1]s", raw1, raw2)', ['raw1']),
            "indexed_repeat": ('log.Printf("%[2]q %[2]s", raw1, raw2)', ['raw2']),
            "indexed_unused": ('log.Printf("%[2]q", raw1, raw2, raw3)', []),
            "indexed_fourth": ('log.Printf("%[4]s %[2]q", raw1, raw2, raw3, raw4)', ['raw4']),
            "indexed_bad_other": ('log.Printf("%[9]s %[2]s", raw1, raw2)', ['raw2']),
            "indexed_alias": ('fmt := "%[2]s"\nlog.Printf(fmt, raw1, raw2)', ['raw2']),
        }
        header, signature, end = 'package main\nimport ("log"; "os")\n', 'func {name}() {{', '}'
        decl = lambda i: f'raw{i} := os.Getenv("RAW{i}"); _ = raw{i}'
    elif language == "java":
        cases = {
            "second": ('logger.info("{} {}", raw1, raw2);', ['raw1', 'raw2']),
            "three": ('logger.info("{} {} {}", raw1, raw2, raw3);', ['raw1', 'raw2', 'raw3']),
            "four": ('logger.info("{} {} {} {}", raw1, raw2, raw3, raw4);', ['raw1', 'raw2', 'raw3', 'raw4']),
            "unused": ('logger.info("{}", "fixed", raw2);', []),
            "extra": ('logger.info("{} {}", "fixed", raw2, raw3);', ['raw2']),
            "missing": ('logger.info("{} {} {}", raw1);', ['raw1']),
            "literal": ('logger.info("fixed", raw1, raw2);', []),
            "escaped_literal": (r'logger.info("\\{}", raw1);', []),
            "escaped_alias": (r'String fmt = "\\{}";' + '\nlogger.info(fmt, raw1);', []),
            "format_alias": ('String fmt = "{} {}";\nlogger.info(fmt, "fixed", raw2);', ['raw2']),
            "mutated_safe": ('String fmt = "{} {}";\nfmt = "fixed";\nlogger.info(fmt, raw1, raw2);', []),
            "sanitized": ('String clean = raw1.replace("\\r", "").replace("\\n", "");\nlogger.info("{} {}", clean, raw2);', ['raw2']),
        }
        header, signature, end = 'class FormatCases {\n', 'void {name}(HttpServletRequest request, Logger logger) {{', '}'
        decl = lambda i: f'String raw{i} = request.getParameter("raw{i}");'
    else:
        cases = {
            "mixed_first": ('console.log("%s %j", raw1, raw2);', ['raw1']),
            "mixed_second": ('console.log("%j %s", raw1, raw2);', ['raw2']),
            "three": ('console.log("%j %s %d", raw1, raw2, raw3);', ['raw2']),
            "four": ('console.log("%j %s %o %s", raw1, raw2, raw3, raw4);', ['raw2', 'raw4']),
            "encoded": ('console.log("%j %d %o", raw1, raw2, raw3);', []),
            "css": ('console.log("%c %s", raw1, raw2);', ['raw2']),
            "extra": ('console.log("%j", raw1, raw2);', ['raw2']),
            "missing": ('console.log("%j %s", raw1);', []),
            "empty": ('console.log("", raw1, raw2);', ['raw1', 'raw2']),
            "unknown": ('console.log("%z", raw1, raw2);', ['raw1', 'raw2']),
            "escaped_percent": ('console.log("%%s %j", raw1, raw2);', ['raw2']),
            "format_alias": ('const fmt = "%j %s";\nconsole.log(fmt, raw1, raw2);', ['raw2']),
            "mutated_safe": ('let fmt = "%s %s";\nfmt = "%j %j";\nconsole.log(fmt, raw1, raw2);', []),
            "sanitized": ('const clean = raw1.replace(/[\\r\\n]/g, "");\nconsole.log("%s %s", clean, raw2);', ['raw2']),
        }
        header, signature, end = '', 'function {name}(req) {{', '}'
        decl = lambda i: f'const raw{i} = req.query.raw{i};'
    lines = [header]
    for name, (body, expected) in cases.items():
        lines.append(signature.format(name=name))
        lines.extend('    ' + decl(i) for i in range(1, 5))
        body_lines = body.splitlines()
        lines.extend('    ' + line for line in body_lines[:-1])
        marker = ' # ' if language == 'python' else ' // '
        lines.append('    ' + body_lines[-1] + marker + 'format-find: ' + ','.join(expected))
        lines.append(end)
    if language == 'java':
        lines.append('}')
    return '\n'.join(lines) + '\n'


@pytest.mark.slow
def test_format_arguments_follow_runtime_conversions(tmp_path):
    targets = []
    for language, extension in [("python", "py"), ("go", "go"), ("java", "java"),
                                ("javascript", "js"), ("javascript", "ts")]:
        target = tmp_path / f'formats.{extension}'
        target.write_text(_format_cases(language))
        targets.append(target)
    _scan_targets(tmp_path, targets, columns=True)
