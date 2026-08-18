"""Tests for core.audit.parser_shape and its priority/gaps wiring.

The end-to-end fixture replays the slot-selection failure shape from a
scoped head-to-head audit: an external-format file whose ``static``
byte-walking decode workhorse (where the predicted finding lived) was
never scheduled while its thin exported siblings claimed the file's
review slots. The fixture is synthetic — generic names, no project
vocabulary — because the signals must be structural, not memorised.
"""

from __future__ import annotations

from types import SimpleNamespace

from core.audit.gaps import compute_gaps, truncate_gaps_to_budget
from core.audit.parser_shape import (
    LENGTH_ARITH_DENSITY_FLOOR,
    LENGTH_ARITH_SITES_FLOOR,
    ParserShape,
    parser_shape,
)
from core.audit.priority import (
    SCORE_LENGTH_ARITH,
    SCORE_PARSER_SHAPED,
    score_functions,
)

_BUF_PARAMS = [["in", "const unsigned char **"], ["keylen", "unsigned int"]]


class TestSignatureDetection:
    def test_byte_buffer_plus_length_param(self):
        shape = parser_shape("", parameters=_BUF_PARAMS, sloc=10)
        assert shape.byte_buffer_input

    def test_pointer_without_length_param_is_not_buffer_input(self):
        shape = parser_shape(
            "", parameters=[["hdr", "const unsigned char *"],
                            ["magic", "unsigned int"]], sloc=10,
        )
        assert not shape.byte_buffer_input

    def test_length_param_without_pointer_is_not_buffer_input(self):
        shape = parser_shape(
            "", parameters=[["bitlen", "unsigned int"], ["isdss", "int"]],
            sloc=10,
        )
        assert not shape.byte_buffer_input

    def test_no_parameters(self):
        assert not parser_shape("x = 1;", parameters=None).byte_buffer_input


class TestBodySignals:
    def test_cursor_advance(self):
        assert parser_shape("p += saltlen;", sloc=1).cursor_advance
        assert parser_shape("magic = *q++;", sloc=1).cursor_advance
        assert not parser_shape("total = a + b;", sloc=1).cursor_advance

    def test_length_arith_sites_counted(self):
        src = "if (keylen < 8) return NULL;\ninlen = keylen - 8;\n"
        shape = parser_shape(src, sloc=2)
        assert shape.length_arith_sites >= 2
        assert shape.length_arith_density > 0

    def test_error_path_sites_counted(self):
        src = "goto err;\nreturn NULL;\nreturn -1;\n"
        shape = parser_shape(src, sloc=3)
        assert shape.error_path_sites == 3

    def test_missing_source_degrades_to_signature(self):
        shape = parser_shape(None, parameters=_BUF_PARAMS, sloc=50)
        assert shape.byte_buffer_input
        assert not shape.cursor_advance
        assert shape.length_arith_sites == 0


class TestClassification:
    def test_buffer_walker_is_parser_shaped(self):
        src = "p += 8;\nif (keylen < 8)\n    goto err;\n"
        assert parser_shape(src, parameters=_BUF_PARAMS, sloc=3).parser_shaped

    def test_morphology_alone_never_classifies(self):
        # A "parse"-named function with no buffer signature and no
        # parser-API call stays unclassified — the weak signal only
        # corroborates a byte-buffer signature.
        shape = parser_shape("return opt;", name="parse_options", sloc=1)
        assert shape.name_morphology
        assert not shape.parser_shaped

    def test_taxonomy_parser_call_classifies(self):
        # yyparse is a PARSER_SEED_FUNCS member (stable seed set).
        shape = parser_shape("rc = yyparse();", name="run", sloc=1)
        assert shape.parser_api_call
        assert shape.parser_shaped

    def test_learned_boundary_transfer_classifies(self):
        vocab = SimpleNamespace(boundary_transfers=frozenset({"proj_pull"}))
        shape = parser_shape(
            "n = proj_pull(buf, cap);", name="drain", sloc=1,
            domain_vocab=vocab,
        )
        assert shape.parser_api_call

    def test_own_name_call_is_ignored(self):
        shape = parser_shape("return yyparse(x - 1);", name="yyparse", sloc=1)
        assert not shape.parser_api_call

    def test_never_raises_on_junk(self):
        shape = parser_shape("", name="", parameters=[[None, None], "x"],
                             sloc=0)
        assert isinstance(shape, ParserShape)


class TestScoreComponents:
    def _gap(self, shape_dict):
        return {
            "file": "a.c", "name": "f", "priority": 0, "sloc": 10,
            "metadata": {}, "parser_shape": shape_dict,
        }

    def test_parser_shaped_scores(self):
        base = score_functions([self._gap({})])[0]["priority_score"]
        boosted = score_functions(
            [self._gap({"parser_shaped": True})],
        )[0]["priority_score"]
        assert boosted - base == SCORE_PARSER_SHAPED

    def test_length_arith_floors_respected(self):
        below = score_functions([self._gap({
            "length_arith_sites": LENGTH_ARITH_SITES_FLOOR - 1,
            "length_arith_density": 1.0,
        })])[0]["priority_score"]
        above = score_functions([self._gap({
            "length_arith_sites": LENGTH_ARITH_SITES_FLOOR,
            "length_arith_density": LENGTH_ARITH_DENSITY_FLOOR,
        })])[0]["priority_score"]
        assert above - below == SCORE_LENGTH_ARITH

    def test_gap_without_shape_unchanged(self):
        gap = {"file": "a.c", "name": "f", "priority": 0, "sloc": 10,
               "metadata": {}}
        assert score_functions([gap])[0]["priority_score"] >= 0


# ── End-to-end fixture: the pvkfmt slot-selection shape ──────────────


def _exported_length_helper() -> list[str]:
    """~30-line exported helper (the previously-preferred small sibling)."""
    body = [
        "unsigned int blob_field_count(unsigned int bitlen, int isdss,",
        "                              int ispub)",
        "{",
        "    unsigned int fields = 0;",
        "    if (isdss) {",
        "        if (ispub)",
        "            fields = 1;",
        "        else",
        "            fields = 2;",
        "    } else {",
        "        if (ispub)",
        "            fields = 3;",
        "        else",
        "            fields = 7;",
        "    }",
        "    switch (fields) {",
        "    case 1:",
        "        return 20;",
        "    case 2:",
        "        return 24;",
        "    case 3:",
        "        return 28;",
        "    case 7:",
        "        return 52;",
        "    default:",
        "        break;",
        "    }",
        "    return 0;",
        "}",
    ]
    return body


def _exported_header_reader() -> list[str]:
    """~88-line exported header reader (the other preferred sibling)."""
    body = [
        "int blob_header_read(const unsigned char **in, unsigned int length,",
        "                     unsigned int *pmagic, unsigned int *pbitlen)",
        "{",
        "    const unsigned char *p = *in;",
        "    unsigned int bt, ver, reserved;",
        "    if (length < 16)",
        "        return 0;",
        "    bt = *p++;",
        "    ver = *p++;",
        "    reserved = read_two(&p);",
        "    if (reserved != 0)",
        "        return 0;",
        "    *pmagic = read_four(&p);",
        "    *pbitlen = read_four(&p);",
    ]
    # Pad with realistic checked-branch filler to ~88 lines.
    for i in range(16):
        body.extend([
            f"    if (bt == {i}) {{",
            f"        ver |= {i};",
            "        if (ver == 0)",
            "            return 0;",
            "    }",
        ])
    body.extend([
        "    *in = p;",
        "    return 1;",
        "}",
    ])
    return body


def _static_body_decoder() -> list[str]:
    """~94-line static decode workhorse (where the finding lived).

    No parse/decode morphology in the name; classification must come
    from the byte-buffer signature, cursor advances, length arithmetic,
    and error-path density.
    """
    body = [
        "static void *body_key_material(const unsigned char **in,",
        "                               unsigned int saltlen,",
        "                               unsigned int keylen)",
        "{",
        "    const unsigned char *p = *in;",
        "    unsigned char *enctmp = NULL;",
        "    unsigned char keybuf[20];",
        "    void *key = NULL;",
        "    int enctmplen, inlen;",
        "    unsigned char *q;",
        "    unsigned int magic;",
        "    if (saltlen) {",
        "        enctmp = alloc_bytes(keylen + 8);",
        "        if (enctmp == NULL)",
        "            goto err;",
        "        if (!derive_key(keybuf, sizeof(keybuf), p, saltlen))",
        "            goto err;",
        "        p += saltlen;",
        "        copy_bytes(enctmp, p, 8);",
        "        p += 8;",
        "        if (keylen < 8)",
        "            goto err;",
        "        inlen = keylen - 8;",
        "        q = enctmp + 8;",
        "        if (!stream_init(keybuf))",
        "            goto err;",
        "        if (!stream_update(q, &enctmplen, p, inlen))",
        "            goto err;",
        "        if (!stream_final(q + enctmplen, &enctmplen))",
        "            goto err;",
        "        magic = read_four((const unsigned char **)&q);",
        "        if (magic != 0xa400 && magic != 0xa500) {",
        "            q = enctmp + 8;",
        "            wipe_bytes(keybuf + 5, 11);",
        "            if (!stream_init(keybuf))",
        "                goto err;",
        "            if (!stream_update(q, &enctmplen, p, inlen))",
        "                goto err;",
        "            if (!stream_final(q + enctmplen, &enctmplen))",
        "                goto err;",
        "            magic = read_four((const unsigned char **)&q);",
        "            if (magic != 0xa400 && magic != 0xa500)",
        "                goto err;",
        "        }",
        "        p = enctmp;",
        "    }",
    ]
    for i in range(10):
        body.extend([
            f"    if (keylen > {4096 << (i % 3)})",
            "        goto err;",
            f"    inlen = inlen - {i % 4};",
            "    if (inlen < 0)",
            "        goto err;",
        ])
    body.extend([
        "    key = body_fields(&p, keylen);",
        "err:",
        "    release_bytes(enctmp);",
        "    return key;",
        "}",
    ])
    return body


def _pvkfmt_shape_fixture(tmp_path):
    """Write the fixture file; return (checklist, keys by role)."""
    fns = [
        ("blob_field_count", "extern",
         [["bitlen", "unsigned int"], ["isdss", "int"], ["ispub", "int"]],
         _exported_length_helper()),
        ("blob_header_read", "extern",
         [["in", "const unsigned char **"], ["length", "unsigned int"],
          ["pmagic", "unsigned int *"], ["pbitlen", "unsigned int *"]],
         _exported_header_reader()),
        ("body_key_material", "static",
         [["in", "const unsigned char **"], ["saltlen", "unsigned int"],
          ["keylen", "unsigned int"]],
         _static_body_decoder()),
    ]
    lines: list[str] = []
    items = []
    for name, visibility, params, body in fns:
        start = len(lines) + 1
        lines.extend(body)
        items.append({
            "name": name,
            "kind": "function",
            "line_start": start,
            "line_end": len(lines),
            "metadata": {"visibility": visibility, "parameters": params,
                         "return_type": "int"},
        })
        lines.append("")
    (tmp_path / "blob.c").write_text("\n".join(lines), encoding="utf-8")
    checklist = {
        "target_path": str(tmp_path),
        "files": [{"path": "blob.c", "language": "c", "items": items}],
    }
    return checklist


class TestPvkfmtShapeSlotSelection:
    """The buggy static decoder must outrank its exported siblings."""

    def _ordered_keys(self, tmp_path):
        checklist = _pvkfmt_shape_fixture(tmp_path)
        gaps = compute_gaps(checklist, [])
        gaps = score_functions(gaps)
        return gaps, [g["name"] for g in gaps]

    def test_decoder_is_parser_shaped_and_siblings_signals(self, tmp_path):
        gaps, _ = self._ordered_keys(tmp_path)
        by_name = {g["name"]: g for g in gaps}
        shape = by_name["body_key_material"].get("parser_shape") or {}
        assert shape.get("parser_shaped"), (
            "static byte-walking decoder not classified parser-shaped"
        )
        assert shape.get("length_arith_sites", 0) >= 2
        assert shape.get("error_path_sites", 0) >= 2
        helper_shape = by_name["blob_field_count"].get("parser_shape") or {}
        assert not helper_shape.get("parser_shaped"), (
            "length-table helper wrongly classified parser-shaped"
        )

    def test_decoder_outranks_previously_preferred_siblings(self, tmp_path):
        _, order = self._ordered_keys(tmp_path)
        decoder = order.index("body_key_material")
        assert decoder < order.index("blob_field_count"), order
        assert decoder < order.index("blob_header_read"), order

    def test_decoder_survives_budget_truncation(self, tmp_path):
        gaps, _ = self._ordered_keys(tmp_path)
        selected = truncate_gaps_to_budget(gaps, 2, None)
        assert "body_key_material" in {g["name"] for g in selected}
