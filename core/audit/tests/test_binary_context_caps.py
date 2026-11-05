"""Binary context caps bound rendering work while preserving ordered entries."""

import pytest

from core.audit import binary_context as context
from packages.ghidra.model import REDatabase, REFunction, REXref


def _database(incoming):
    functions = [REFunction(name=f"fn{i}", address=0x1000 + i * 0x100,
                            size=64, source_tool="ghidra", signature=f"void fn{i}(void)",
                            decompilation="\n".join(f"line {j}" for j in range(30)))
                 for i in range(41)]
    main = functions[0]
    refs = []
    for func in functions[1:]:
        ref = REXref(from_addr=func.address + 1 if incoming else main.address + 1,
                    to_addr=main.address if incoming else func.address, kind="call")
        refs.extend([ref, ref])
    return REDatabase(source_tool="ghidra", binary_path="/x/target.bin",
                      functions=functions, xrefs=refs), main


@pytest.mark.parametrize("incoming", [False, True], ids=["callees", "callers"])
def test_first_fifteen_unique_entries_bound_lookups(monkeypatch, incoming):
    db, main = _database(incoming)
    # Index construction remains complete; only rendering is capped.
    by_callee, by_caller = context._xref_call_adjacency(db)
    assert sum(map(len, by_callee.values())) == 80
    assert sum(map(len, by_caller.values())) == 80
    method = "function_containing_address" if incoming else "function_by_address"
    lookup = getattr(db, method)
    calls = []

    def counted(address):
        calls.append(address)
        return lookup(address)

    monkeypatch.setattr(db, method, counted)
    render = context._binary_callers if incoming else context._binary_callees
    records = render(db, main)
    assert len(calls) == 29  # Fourteen duplicate pairs, then the fifteenth unique entry.
    assert records == [dict(
        name=f"fn{i}", file="binary:target", line_start=0,
        address=0x1000 + i * 0x100, signature=f"void fn{i}(void)",
        **({} if incoming else {"source_snippet": "\n".join(f"line {j}" for j in range(20))}),
    ) for i in range(1, 16)]
    assert context._xref_call_adjacency(db) == (by_callee, by_caller)


def test_adjacency_keeps_reference_identity_order_and_append_invalidation():
    db, main = _database(False)
    incoming, outgoing = context._xref_call_adjacency(db)
    assert all(a is b for a, b in zip(outgoing[main.address], db.xrefs, strict=True))
    extra = REXref(from_addr=main.address + 2, to_addr=0x9999, kind="call")
    db.xrefs.append(extra)
    rebuilt_in, rebuilt_out = context._xref_call_adjacency(db)
    assert rebuilt_in is not incoming
    assert rebuilt_out[main.address][-1] is extra
    assert rebuilt_in[0x9999] == [extra]
