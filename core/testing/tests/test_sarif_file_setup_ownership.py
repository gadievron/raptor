"""Exact SARIF file setup component, before parser execution."""

import ast
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import pytest

ROOT = Path(__file__).resolve().parents[3]
PINS = {
    "_result": "aa0779f3ce8f023ddfdadbcb645545e0e9665ad158ff7d23be8a0288c41a106d",
    "_extensions_shaped": "7d47544bfeacb3fb7ee6e123e3934260c92e6cc4dc23c7310cd344c3afb3cf8c",
    "test_extension_rule_severity_and_cwe_join": "1e45f558be92de2c616e17d55fea6adad6d67b5f116d685cc44b3325af95531f",
}


@pytest.mark.parametrize(
    "refusal", [False, True], ids=["serialized-boundary", "write-error"]
)
def test_sarif_file_setup_ownership(tmp_path, refusal):
    source = ROOT / "core/sarif/tests/test_sarif_parser.py"
    text = source.read_text()
    tree = ast.parse(text)
    cls = next(
        n
        for n in tree.body
        if isinstance(n, ast.ClassDef) and n.name == "TestExtensionRules"
    )
    result = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_result"
    )
    helper = next(
        n
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == "_extensions_shaped"
    )
    method = copy.deepcopy(
        next(
            n
            for n in cls.body
            if isinstance(n, ast.FunctionDef)
            and n.name == "test_extension_rule_severity_and_cwe_join"
        )
    )
    for n in [result, helper, method]:
        assert (
            hashlib.sha256(ast.get_source_segment(text, n).encode()).hexdigest()
            == PINS[n.name]
        )
    assert isinstance(method.body[1], ast.ImportFrom)
    method.body.pop(1)  # Setup component excludes the unused parser import.
    handles, writes = [], []
    failure = OSError("owned SARIF fixture first write refusal")

    class Handle:
        def __init__(self, stream):
            self.stream, self.name = stream, stream.name

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *exc):
            return self.stream.__exit__(*exc)

        def write(self, data):
            writes.append(data)
            if refusal:
                raise failure
            return self.stream.write(data)

        def __getattr__(self, key):
            return getattr(self.stream, key)

    def named(*args, **kwargs):
        assert kwargs.get("delete") is False and "dir" not in kwargs
        handle = Handle(tempfile.NamedTemporaryFile(*args, dir=tmp_path, **kwargs))
        handles.append(handle)
        return handle

    class ParserBoundary(Exception):
        pass

    parsed = []

    def forbidden(path):
        assert len(handles) == 1 and handles[0].stream.closed
        document = json.loads(path.read_text())
        rule = document["runs"][0]["tool"]["extensions"][0]["rules"][0]
        assert rule["id"] == "py/sql-injection"
        assert rule["defaultConfiguration"]["level"] == "error"
        assert rule["properties"]["tags"] == ["external/cwe/cwe-089"]
        parsed.append(document)
        raise ParserBoundary("serialized fixture before parser execution")

    ns = {
        "Path": Path,
        "tempfile": SimpleNamespace(NamedTemporaryFile=named),
        "json": json,
        "parse_sarif_findings": forbidden,
    }
    exec(
        compile(
            ast.Module(body=[result, helper, method], type_ignores=[]),
            str(source),
            "exec",
        ),
        ns,
    )
    case = unittest.TestCase()
    case._extensions_shaped = ns["_extensions_shaped"]
    try:
        with pytest.raises(OSError if refusal else ParserBoundary) as caught:
            ns[method.name](case)
        assert writes and len(handles) == 1
        assert (caught.value is failure) if refusal else len(parsed) == 1
        case.doCleanups()
        handle = handles[0]
        assert handle.stream.closed
        assert not Path(handle.name).exists(), "pathname survived unittest cleanup"
        (tmp_path / "observation.json").write_text(
            json.dumps(
                {
                    "write_refused": refusal,
                    "exception_identity": refusal,
                    "stream_closed": True,
                    "path_removed_after_unittest_cleanup": True,
                    "refusal": refusal,
                    "scope": "exact setup component only; parser import/execution excluded",
                }
            )
            + "\n"
        )
    finally:
        case.doCleanups()
        for handle in handles:
            handle.stream.close()
            Path(handle.name).unlink(missing_ok=True)
