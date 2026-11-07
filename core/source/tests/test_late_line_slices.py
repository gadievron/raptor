"""Suffix slicing shares the exact raw and canonical LF contracts."""

import random

import pytest

from core.source.lines import join_lf_slice, slice_text, split_lines


@pytest.mark.parametrize("ending", [
    pytest.param("", id="unterminated"),
    pytest.param("\n", id="lf"),
    pytest.param("\r\n", id="crlf"),
    pytest.param("\n\r", id="cr-only-final-row"),
    pytest.param("\n\n", id="blank-final-row"),
    pytest.param("\r\r", id="double-cr"),
])
@pytest.mark.parametrize("start,end", [(130, 140), (300, 310), (480, 490), (511, 900), (512, 900), (900, 901)])
def test_late_raw_and_canonical_windows(ending, start, end):
    text = "\n".join(f"{i}: comment\v\f\x85\u2028\r " + "x" * 40 for i in range(512)) + ending
    assert join_lf_slice(text, start, end) == "\n".join(text.split("\n")[start:end])  # line-model: raw LF oracle includes CR and the trailing empty element
    assert slice_text(text, start + 1, end) == "\n".join(split_lines(text)[start:end])


def test_generated_suffix_bounds_and_empty_rows():
    rng = random.Random(1304)
    for _ in range(500):
        rows = [rng.choice(("", "row\r", "row\r\r", "x\v\f\x85\u2028", "x" * 80)) for _ in range(1000)]
        text = "\n".join(rows)
        start = rng.randrange(128, 1100)
        end = rng.choice((start, start + 1, start + 7, 1100, 10**100))
        assert join_lf_slice(text, start, end) == "\n".join(text.split("\n")[start:end])  # line-model: raw LF oracle, with Python slice clamping
        assert slice_text(text, start + 1, end) == "\n".join(split_lines(text)[start:end])


def test_string_adapter_keeps_split_and_slice_operations():
    seen = []

    class Text(str):
        def split(self, separator):
            seen.append(separator)
            return ["adapter"] * 200 + ["selected", "tail"]

    assert join_lf_slice(Text("unused" * 5000), 200, 201) == "selected"
    assert seen == ["\n"]


@pytest.mark.parametrize("shape", ["sparse_prefix", "dense_prefix", "no_sample_breaks"])
def test_density_estimate_never_defines_coordinates(shape):
    if shape == "sparse_prefix":
        rows = ["long row " * 500] * 10 + [""] * 1500
    elif shape == "dense_prefix":
        rows = [""] * 1500 + ["long row " * 500] * 10
    else:
        rows = ["long first row " * 2000] + ["row"] * 1500
    text = "\n".join(rows)
    for start in (129, 300, len(rows) - 3, len(rows) + 1):
        for end in (start + 3, len(rows) + 50):
            assert join_lf_slice(text, start, end) == "\n".join(rows[start:end])
            assert slice_text(text, start + 1, end) == "\n".join(split_lines(text)[start:end])
