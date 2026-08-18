"""_safe_eval node-allowlist tests for the sandbox host daemon.

The compute language is arithmetic/bit-ops over recv-derived bindings
(ints or raw bytes), byte slicing/indexing, and the p/u packing helpers
called by bare name. ``Attribute`` is deliberately NOT allowlisted:
nothing in the language needs dotted access, and admitting it opens
``p64.__globals__['os']``-shaped escape chains through an expression
built entirely from otherwise-allowlisted nodes. These tests pin both
sides — every documented-legitimate shape still evaluates, and the
escape shapes are rejected at parse-walk time (before any eval).
"""

from typing import ClassVar

import pytest

from core.sandbox._daemon import _safe_eval


class TestRejectedExpressions:
    """Escape-shaped expressions raise ValueError before evaluation."""

    @pytest.mark.parametrize("expr", [
        # Attribute-chain escapes — the __globals__ pivot.
        "p64.__globals__['os']",
        "p64.__globals__['os'].system('id')",
        "u64.__globals__",
        "int.__class__",
        "(1).__class__",
        "leak.__class__.__mro__",
        # Any dotted access at all — Attribute is not in the language.
        "leak.hex()",
        "x.real",
        # __import__ and other non-allowlisted callables.
        "__import__('os')",
        "__import__('os').system('id')",
        "getattr(int, '__subclasses__')",
        "eval('1')",
        "exec('x=1')",
        "open('/etc/passwd')",
        # Other disallowed node classes.
        "[1, 2]",
        "{1: 2}",
        "(1, 2)",
        "lambda: 1",
        "x if y else z",
        "[i for i in b]",
        "f'{x}'",
        "x and y",
        "x == y",
        "(x := 1)",
    ])
    def test_rejected(self, expr):
        with pytest.raises(ValueError, match="disallowed"):
            _safe_eval(expr, {"leak": b"\x41" * 16, "x": 1, "y": 2,
                              "z": 3, "b": b"ab"})

    def test_call_via_subscripted_callee_rejected(self):
        # Call whose func isn't a bare Name: getattr(node.func, "id")
        # is None -> disallowed call.
        with pytest.raises(ValueError, match="disallowed call"):
            _safe_eval("fns[0](1)", {"fns": None})


class TestAcceptedExpressions:
    """Every documented-legitimate compute shape still evaluates."""

    BINDINGS: ClassVar[dict] = {
        "libc_leak": 0x7F0000123456,
        "base": 0x400000,
        "leak": bytes(range(16)),
    }

    def _eval(self, expr):
        return _safe_eval(expr, dict(self.BINDINGS))

    def test_packing_helpers(self):
        assert self._eval("p64(0x41)") == b"\x41" + b"\x00" * 7
        assert self._eval("p32(0x41424344)") == b"\x44\x43\x42\x41"
        assert self._eval("p16(0x4142)") == b"\x42\x41"
        assert self._eval("u64(leak)") == int.from_bytes(
            self.BINDINGS["leak"][:8], "little")
        assert self._eval("u32(leak)") == int.from_bytes(
            self.BINDINGS["leak"][:4], "little")
        assert self._eval("u16(leak)") == int.from_bytes(
            self.BINDINGS["leak"][:2], "little")
        assert self._eval("int(42)") == 42

    def test_arithmetic_on_bindings(self):
        assert self._eval("libc_leak - 0x123456") == 0x7F0000000000
        assert self._eval("base + 0x10") == 0x400010
        assert self._eval("(base + 8) * 2") == 0x800010
        assert self._eval("base // 2") == 0x200000
        assert self._eval("base % 7") == 0x400000 % 7

    def test_bit_ops(self):
        assert self._eval("libc_leak & 0xFFF") == 0x456
        assert self._eval("base | 1") == 0x400001
        assert self._eval("base ^ base") == 0
        assert self._eval("1 << 12") == 4096
        assert self._eval("base >> 4") == 0x40000
        assert self._eval("-base") == -0x400000
        assert self._eval("~0") == -1

    def test_byte_slicing_and_indexing(self):
        # Slicing raw recv bytes is part of the language:
        # a bind_as capture that didn't parse as int stays bytes.
        assert self._eval("leak[8:16]") == bytes(range(8, 16))
        assert self._eval("u64(leak[8:16])") == int.from_bytes(
            bytes(range(8, 16)), "little")
        assert self._eval("leak[3]") == 3

    def test_composed_expression(self):
        got = self._eval("p64((u64(leak[0:8]) + 0x10) & ~0xF)")
        want = ((int.from_bytes(bytes(range(8)), "little") + 0x10)
                & ~0xF).to_bytes(8, "little")
        assert got == want

    def test_no_builtins_leak_into_namespace(self):
        # Even an allowlisted-node expression can't reach builtins:
        # bare names resolve only against bindings + helpers.
        with pytest.raises(NameError):
            _safe_eval("abs", {})
