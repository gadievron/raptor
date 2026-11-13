"""Native symbol admission requires scalar Unicode names, not surrogates."""

from types import SimpleNamespace

import pytest

from core.smt_solver import bitvec
from core.smt_solver._validation import require_symbol_name


@pytest.mark.parametrize("code", [0xD800, 0xDBFF, 0xDC00, 0xDFFF])
@pytest.mark.parametrize("position", ["leading", "middle", "trailing"])
def test_surrogates_decline_before_native_symbol_factory(code, position, monkeypatch):
    char = chr(code)
    name = {"leading": char + "Value", "middle": "Val" + char + "ue",
            "trailing": "Value" + char}[position]
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid symbol reached a native factory")
    monkeypatch.setattr(bitvec, "z3", SimpleNamespace(BitVec=forbidden))
    with pytest.raises(ValueError, match="surrogate code points"):
        bitvec.mk_var(name, 8)


@pytest.mark.parametrize("name", ["Value", "value", "Value Other", "Value.Ω", "Value😀", ""])
def test_valid_names_keep_identity_at_the_constructor_seam(name, monkeypatch):
    seen, result = [], object()
    def construct(supplied, width):
        seen.append((supplied, width))
        return result
    monkeypatch.setattr(bitvec, "z3", SimpleNamespace(BitVec=construct))
    assert require_symbol_name(name) == name
    assert bitvec.mk_var(name, 8) is result
    assert seen == [(name, 8)]


@pytest.mark.parametrize("name", ["\x00Value", "Val\x00ue", "Value\x00"])
def test_existing_nul_refusal_is_unchanged(name):
    with pytest.raises(ValueError, match="NUL"):
        require_symbol_name(name)


def test_surrogate_pair_spelling_is_not_a_single_scalar_character():
    with pytest.raises(ValueError, match="surrogate code points"):
        require_symbol_name("\ud83d\ude00")
    assert require_symbol_name("😀") == "😀"
