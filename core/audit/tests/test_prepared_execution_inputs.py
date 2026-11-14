"""Exact byte custody controls for descriptive parent execution inputs."""

from core.audit import prepared_execution_inputs as parent_exec_inputs

from dataclasses import FrozenInstanceError
import os
import sys

import pytest

from core.audit.prepared_execution_inputs import InputsUnavailable, snapshot_parent_inputs


CAPS = dict(max_args=8, max_env=8, max_item_bytes=128, max_total_bytes=1024)


def snapshot(argv=None, environment=None, cwd="/owned/cwd", **caps):
    return snapshot_parent_inputs(["/compiler", "-c", "a.c"] if argv is None else argv,
                                  {"HOME": "/owned/home", "LANG": "C"} if environment is None else environment,
                                  cwd, **{**CAPS, **caps})


def test_exact_inputs_and_trusted_overlay_order_are_preserved_without_observation():
    env = {"HOME": "/attempt/home", "HTTP_PROXY": "http://owned.invalid", "LANG": "C"}
    result = snapshot(environment=env)
    args, consumed, cwd = result.exec_inputs()
    assert args == (b"/compiler", b"-c", b"a.c") and cwd == b"/owned/cwd"
    assert tuple(consumed.items()) == tuple((os.fsencode(k), os.fsencode(v)) for k, v in env.items())
    assert result.filesystem_encoding == sys.getfilesystemencoding()
    assert result.filesystem_errors == sys.getfilesystemencodeerrors()
    assert result.authenticated_build is False and result.observed_child_context is False
    with pytest.raises(FrozenInstanceError):
        result.cwd = b"/other"


def test_mutating_original_or_returned_environment_does_not_change_snapshot():
    argv, env = ["/compiler", "a.c"], {"A": "one"}
    result = snapshot(argv=argv, environment=env)
    before = result.sha256
    argv[1], env["A"] = "changed.c", "two"
    returned = result.exec_inputs()[1]
    returned[b"A"] = b"three"
    assert result.exec_inputs() == ((b"/compiler", b"a.c"), {b"A": b"one"}, b"/owned/cwd")
    assert result.sha256 == before


def test_utf8_and_surrogateescaped_material_use_actual_filesystem_encoding():
    raw = b"bad\xffname"
    escaped = os.fsdecode(raw)
    result = snapshot(argv=["/compiler", "caf\u00e9.c", escaped], environment={"K": escaped})
    assert result.argv == (b"/compiler", os.fsencode("caf\u00e9.c"), raw)
    assert result.environment == ((b"K", raw),)


@pytest.mark.parametrize("first,second", [(["/compiler", "ab", "c"], ["/compiler", "a", "bc"]),
                                         (["/compiler", ""], ["/compiler"])])
def test_argument_framing_distinguishes_equal_concatenations(first, second):
    assert snapshot(argv=first).sha256 != snapshot(argv=second).sha256


def test_environment_framing_and_order_are_exact_not_sorted():
    first = snapshot(environment={"A": "bc", "D": "e"})
    second = snapshot(environment={"Ab": "c", "D": "e"})
    reordered = snapshot(environment={"D": "e", "A": "bc"})
    assert len({first.sha256, second.sha256, reordered.sha256}) == 3


@pytest.mark.parametrize("bad", [None, 7, b"bytes", "nul\0x", "\ud800"])
def test_invalid_leaf_strings_or_encoding_refuse(bad):
    with pytest.raises(InputsUnavailable):
        snapshot(argv=["/compiler", bad])


@pytest.mark.parametrize("env", [{"": "x"}, {"A=B": "x"}, {"A": None}, {b"A": "x"}, {"A": "\0"}])
def test_ambiguous_or_invalid_environment_material_refuses(env):
    with pytest.raises(InputsUnavailable):
        snapshot(environment=env)


def test_encoded_environment_aliases_refuse_before_dict_collapse():
    normal = "\u00e9"
    # Under UTF-8 the ordinary roundtrip is identical; deliberately construct
    # the surrogateescaped spelling that encodes to those same UTF-8 bytes.
    alias = "".join(chr(0xDC00 + byte) for byte in os.fsencode(normal))
    with pytest.raises(InputsUnavailable, match="environment_name_ambiguous"):
        snapshot(environment={normal: "first", alias: "second"})


@pytest.mark.parametrize("argv,env,cwd", [([], {}, "/b"), (["relative"], {}, "/b"),
                                          (["/c"], {}, "relative"), (["/c"], [], "/b")])
def test_first_scope_rejects_empty_arguments_relative_execution_or_non_dict_environment(argv, env, cwd):
    with pytest.raises(InputsUnavailable):
        snapshot(argv=argv, environment=env, cwd=cwd)


@pytest.mark.parametrize("field", ["max_args", "max_env", "max_item_bytes", "max_total_bytes"])
@pytest.mark.parametrize("bad", [True, 0, -1, 1.5])
def test_budgets_are_explicit_positive_exact_integers(field, bad):
    with pytest.raises(InputsUnavailable):
        snapshot(**{field: bad})


def test_exact_payload_limit_and_count_limits_refuse_whole_snapshot():
    result = snapshot()
    assert snapshot(max_total_bytes=result.payload_bytes).sha256 == result.sha256
    with pytest.raises(InputsUnavailable, match="input_total_byte_budget"):
        snapshot(max_total_bytes=result.payload_bytes - 1)
    for caps in ({"max_args": 2}, {"max_env": 1}, {"max_item_bytes": 2}):
        with pytest.raises(InputsUnavailable):
            snapshot(**caps)


def test_utf8_byte_limit_is_not_character_limit():
    with pytest.raises(InputsUnavailable, match="input_item_byte_budget"):
        snapshot(argv=["/c", "\u00e9" * 5], max_item_bytes=8)


def test_string_and_container_subclasses_cannot_supply_custom_coercion():
    class Evil(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("custom encoding reached")

    class Env(dict):
        def items(self):
            raise AssertionError("custom environment iterator reached")

    with pytest.raises(InputsUnavailable):
        snapshot(argv=["/compiler", Evil("x")])
    with pytest.raises(InputsUnavailable):
        snapshot(environment=Env(A="x"))


def test_default_representation_does_not_disclose_raw_context():
    result = snapshot(argv=["/compiler", "owned-secret-argument"],
                      environment={"TOKEN": "owned-secret-environment"},
                      cwd="/owned-secret-directory")
    rendered = repr(result)
    assert "owned-secret" not in rendered and "TOKEN" not in rendered
    assert result.sha256 in rendered


def test_mutation_after_first_length_check_cannot_bypass_arg_count(monkeypatch):
    argv=["/owned/cc"]
    real_len=len
    mutated=False
    def length_then_mutate(value):
        nonlocal mutated
        observed=real_len(value)
        if value is argv and not mutated:
            mutated=True
            argv.extend(["", ""])
        return observed
    monkeypatch.setattr(parent_exec_inputs,"len",length_then_mutate,raising=False)
    with pytest.raises(parent_exec_inputs.InputsUnavailable,match="argument_count_unavailable"):
        parent_exec_inputs.snapshot_parent_inputs(argv,{},"/owned",max_args=1,max_env=1,max_item_bytes=64,max_total_bytes=128)


def test_cleared_arguments_between_count_checks_refuse_typed(monkeypatch):
    argv = ["/owned/cc"]
    real_len = len
    mutated = False

    def length_then_clear(value):
        nonlocal mutated
        observed = real_len(value)
        if value is argv and not mutated:
            mutated = True
            argv.clear()
        return observed

    monkeypatch.setattr(parent_exec_inputs, "len", length_then_clear, raising=False)
    with pytest.raises(InputsUnavailable, match="argument_count_unavailable"):
        snapshot(argv=argv)
