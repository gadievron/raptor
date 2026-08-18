"""Tests for the audit → /fuzz dictionary/seed handoff (P39).

Stubbed: the constant/string extractors are patched — no tree-sitter,
no target scanning.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from core.audit.fuzz_handoff import (
    DICT_AFL_FILENAME,
    DICT_JSON_FILENAME,
    MAX_TOKENS,
    _afl_escape,
    _pack_constant,
    emit_fuzz_dict,
)


class _Const:
    def __init__(self, name, value, file="src/proto.h", line=3):
        self.name = name
        self.value = value
        self.file = file
        self.line = line


class _ConstTable:
    def __init__(self, unique):
        self.unique = unique


class _Lit:
    def __init__(self, value, context="comparison", is_template=False,
                 file="src/parse.c", line=7, function="parse"):
        self.value = value
        self.context = context
        self.is_template = is_template
        self.file = file
        self.line = line
        self.function = function


class _Table:
    def __init__(self, keys, table_type="switch"):
        self.keys = keys
        self.table_type = table_type


def _emit(tmp_path, *, constants=None, literals=None, tables=None,
          iris=None):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    src = target / "src"
    src.mkdir(exist_ok=True)
    (src / "parse.c").write_text("int parse(void) { return 0; }\n")
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    (out / "checklist.json").write_text(json.dumps({
        "files": [{"path": "src/parse.c", "functions": []}],
    }))
    if iris is not None:
        (out / "iris-taint-specs.json").write_text(json.dumps(iris))

    with patch(
        "core.audit.constant_resolution.build_unique_constants",
        return_value=_ConstTable(constants or {}),
    ), patch(
        "core.audit.ts_extract.extract_all_string_literals",
        return_value={"src/parse.c": literals or []},
    ), patch(
        "core.audit.ts_extract.extract_all_dispatch_tables",
        return_value={"src/parse.c": tables or []},
    ):
        result = emit_fuzz_dict(target, out)
    return result, out


class TestAflEscape:
    def test_printable_passthrough(self):
        assert _afl_escape(b"GET /") == "GET /"

    def test_quote_backslash_and_binary_escaped(self):
        assert _afl_escape(b'a"b\\c\x00') == 'a\\x22b\\x5cc\\x00'


class TestPackConstant:
    def test_minimal_widths(self):
        assert _pack_constant(0x1234) == b"\x34\x12"
        assert _pack_constant(0xDEADBEEF) == b"\xef\xbe\xad\xde"

    def test_negative(self):
        assert _pack_constant(-2) == b"\xfe"


class TestEmitFuzzDict:
    def test_writes_both_artifacts_with_provenance(self, tmp_path):
        result, out = _emit(
            tmp_path,
            constants={"MAGIC": _Const("MAGIC", 0xDEADBEEF)},
            literals=[
                _Lit("HELLO", context="comparison"),
                _Lit("%s%n", context="argument", is_template=True),
            ],
            tables=[_Table(["CMD_READ", "CMD_WRITE"])],
        )
        assert result == out / DICT_AFL_FILENAME

        doc = json.loads((out / DICT_JSON_FILENAME).read_text())
        assert doc["meta"]["producer"] == "raptor-audit"
        provs = [t["provenance"] for t in doc["tokens"]]
        assert any(p.startswith("constant:MAGIC=0xdeadbeef") for p in provs)
        assert any(p.startswith("string:comparison") for p in provs)
        assert any(p.startswith("format_string") for p in provs)
        assert any(p.startswith("dispatch:switch") for p in provs)

        afl = (out / DICT_AFL_FILENAME).read_text().splitlines()
        assert any(
            line.startswith("const_MAGIC=") and "\\xef\\xbe\\xad\\xde" in line
            for line in afl
        )
        assert 'dispatch_CMD_READ="CMD_READ"' in afl

    def test_small_constants_and_log_strings_excluded(self, tmp_path):
        result, out = _emit(
            tmp_path,
            constants={"ONE": _Const("ONE", 1)},
            literals=[_Lit("opened file", context="argument")],
        )
        assert result is None
        assert not (out / DICT_AFL_FILENAME).exists()

    def test_token_cap_and_dedupe(self, tmp_path):
        literals = [
            _Lit(f"token{i:04d}", context="switch_case")
            for i in range(MAX_TOKENS + 50)
        ]
        # A duplicate value must not appear twice.
        literals.append(_Lit("token0000", context="comparison"))
        result, out = _emit(tmp_path, literals=literals)
        assert result is not None
        doc = json.loads((out / DICT_JSON_FILENAME).read_text())
        assert len(doc["tokens"]) == MAX_TOKENS
        values = [t["value"] for t in doc["tokens"]]
        assert len(values) == len(set(values))

    def test_iris_specs_become_seed_hints(self, tmp_path):
        iris = [
            {"function": "write_frame", "file": "src/io.c", "role": "sink"},
            {"function": "read_frame", "file": "src/io.c", "role": "source"},
            {"function": "escape", "file": "src/io.c", "role": "sanitiser"},
        ]
        _result, out = _emit(
            tmp_path,
            literals=[_Lit("FRAME", context="comparison")],
            iris=iris,
        )
        doc = json.loads((out / DICT_JSON_FILENAME).read_text())
        hints = doc["seed_hints"]
        assert {h["function"] for h in hints} == {"write_frame", "read_frame"}
        assert all(h["provenance"] == "iris:taint-spec" for h in hints)

    def test_nothing_mined_writes_nothing(self, tmp_path):
        result, out = _emit(tmp_path)
        assert result is None
        assert not (out / DICT_JSON_FILENAME).exists()

    def test_never_raises(self, tmp_path):
        with patch(
            "core.audit.constant_resolution.build_unique_constants",
            side_effect=RuntimeError("boom"),
        ):
            assert emit_fuzz_dict(tmp_path, tmp_path / "missing") is None

    def test_orchestrator_emits_at_end_of_run(self):
        """Wiring guard: the orchestrator calls emit_fuzz_dict."""
        import inspect

        import core.audit.orchestrator as orch_mod

        src = inspect.getsource(orch_mod)
        assert "emit_fuzz_dict(config.target_path, config.out_dir)" in src
