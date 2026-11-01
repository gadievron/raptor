"""Wire-source, budget, inverted rejection, and consumer must agree."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

_RULE = Path(__file__).resolve().parents[1] / "rules/packet_length_inverted_guard.cocci"
pytestmark = pytest.mark.skipif(shutil.which("spatch") is None, reason="coccinelle not installed")


def _source(*, compare="n < left", before="", after="", budget="skb->len - off",
            read="skb", consume="skb", decode="ntohl(wire)", sink="direct"):
    call = (f"skb_to_sgvec({consume}, sg, off, n)" if sink == "direct" else
            f"rxgk_decrypt_skb(crypto, key, {consume}, &off, &n, &error)")
    return f'''int parse(struct sk_buff *skb, struct sk_buff *other) {{
 unsigned int off = 4, wire, n;
 unsigned int left = {budget};
 int ret, error;
 if (skb_copy_bits({read}, off, &wire, sizeof(wire)) < 0) goto bad;
 {before}
 n = {decode};
 if ({compare}) goto bad;
 {after}
 ret = {call};
 return ret;
 bad: return -1;
}}
'''


def _run(tmp_path, source):
    target = tmp_path / "packet.c"
    target.write_text(source)
    proc = subprocess.run(["spatch", "--sp-file", str(_RULE), str(target), "--no-show-diff"],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return [json.loads(line.removeprefix("COCCIRESULT:"))
            for line in (proc.stdout + proc.stderr).splitlines()
            if line.startswith("COCCIRESULT:")]


@pytest.mark.parametrize("sink", ["direct", "wrapper"])
def test_inverted_guard_reaches_range_consumer(tmp_path, sink):
    hits = _run(tmp_path, _source(sink=sink))
    assert len(hits) == 1
    assert hits[0]["rule"] == "packet_length_inverted_guard"


@pytest.mark.parametrize("changes", [
    {"compare": "n > left"},
    {"compare": "n >= left"},
    {"compare": "n < 16"},
    {"after": "if (n > left) goto bad;"},
    {"after": "if (n > skb->len - off) goto bad;"},
    {"before": "overwrite(&wire);"},
    {"before": "saved = &wire;"},
    {"after": "if (left < n) goto bad;"},
    {"after": "if (n != left) goto bad;"},
    {"after": "if (n <= left) return 0; else goto bad;"},
    {"after": "n = left;"},
    {"after": "n &= 15;"},
    {"after": "left = n;"},
    {"before": "left = 16;"},
    {"before": "wire = trusted_size;"},
    {"before": "skb = other;"},
    {"after": "skb = other;"},
    {"after": "if (validate(n, left)) goto bad;"},
    {"after": "if (validate_ptr(&n)) goto bad;"},
    {"before": "saved = &n;"},
    {"budget": "other->len - off"},
    {"budget": "16"},
    {"read": "other"},
    {"consume": "other"},
    {"decode": "trusted_length()"},
])
def test_near_misses_are_refused(tmp_path, changes):
    assert _run(tmp_path, _source(**changes)) == []


def test_correct_guard_before_inverted_guard_is_respected(tmp_path):
    text = _source().replace("if (n < left)", "if (n > left) goto bad;\n if (n < left)")
    assert _run(tmp_path, text) == []


def test_same_names_in_distinct_functions_do_not_join(tmp_path):
    source = _source().replace("ret = skb_to_sgvec(skb, sg, off, n);", "ret = 0;")
    source += "int neighbour(struct sk_buff *skb) { return skb_to_sgvec(skb, sg, off, n); }\n"
    assert _run(tmp_path, source) == []


def test_goto_can_be_an_acceptance_branch(tmp_path):
    text = _source().replace("goto bad;\n \n ret =", "goto accepted;\n return -1;\n accepted: ret =")
    assert "goto accepted" in text
    assert _run(tmp_path, text) == []


def test_abort_label_is_a_modeled_error_path(tmp_path):
    text = _source(sink="wrapper").replace(
        "bad: return -1;", "bad: ret = rxrpc_abort_conn(conn, skb, reason, -EPROTO, trace); goto out;\n out: return ret;")
    assert len(_run(tmp_path, text)) == 1


def test_same_named_conditional_definitions_do_not_join(tmp_path):
    first = _source().replace("ret = skb_to_sgvec(skb, sg, off, n);", "ret = 0;")
    second = "int parse(struct sk_buff *skb) { return skb_to_sgvec(skb, sg, off, n); }\n"
    assert _run(tmp_path, "#ifdef A\n" + first + "#else\n" + second + "#endif\n") == []


def test_reversed_comparison_and_nomark_consumer(tmp_path):
    text = _source(compare="left > n").replace("skb_to_sgvec(", "skb_to_sgvec_nomark(")
    assert len(_run(tmp_path, text)) == 1
