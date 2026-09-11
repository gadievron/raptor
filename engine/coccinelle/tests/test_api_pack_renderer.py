"""Tests for engine.coccinelle.api_pack_renderer hardening.

Covers: pack-dir containment (Path.is_relative_to, not string prefix),
_idents container-type guard, fullmatch anchoring (no trailing-newline
tolerance), and the single authoritative marker predicate.
"""

from __future__ import annotations

import json
from pathlib import Path

from engine.coccinelle.api_pack_renderer import (
    _API_RE,
    _IDENT_RE,
    has_api_pack_marker,
    load_packs,
    render_text,
)


def _write_pack(packs_dir: Path, name: str = "p.json", *, api: str = "openssl",
                kinds: dict | None = None) -> None:
    packs_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "api": api,
        "kinds": kinds if kinds is not None else {
            "call": {"prefixes": ["EVP_Digest"], "names": ["HMAC"]},
        },
    }
    (packs_dir / name).write_text(json.dumps(payload), encoding="utf-8")


class TestPackDirContainment:
    def test_prefix_sharing_sibling_dir_rejected(self, tmp_path: Path):
        # rules-evil shares the string prefix of rules but is NOT
        # inside it — a bare startswith() containment test passed it.
        rules = tmp_path / "rules"
        rules.mkdir()
        _write_pack(tmp_path / "rules-evil", api="evilapi")
        rule = rules / "r.cocci"
        rule.write_text("// @api-packs: ../rules-evil crypto\n", encoding="utf-8")
        assert render_text(rule) is None

    def test_legitimate_subdir_still_renders(self, tmp_path: Path):
        rules = tmp_path / "rules"
        _write_pack(rules / "packs")
        rule = rules / "r.cocci"
        rule.write_text("// @api-packs: packs crypto\n", encoding="utf-8")
        text = render_text(rule)
        assert text is not None
        assert "crypto:call:openssl:" in text


class TestIdentsContainerGuard:
    def test_string_prefixes_dropped_not_per_char(self, tmp_path: Path):
        # 'prefixes': 'EVP' iterated per character pre-fix, compiling
        # an every-identifier-starting-E/P/V regex.
        _write_pack(
            tmp_path, api="openssl",
            kinds={"call": {"prefixes": "EVP", "names": ["HMAC"]}},
        )
        packs = load_packs(tmp_path)
        assert len(packs) == 1
        spec = packs[0].kinds["call"]
        assert spec.prefixes == ()
        assert spec.names == ("HMAC",)

    def test_non_iterable_prefixes_degrade_not_raise(self, tmp_path: Path):
        _write_pack(
            tmp_path, api="openssl",
            kinds={"call": {"prefixes": 7, "names": ["HMAC"]}},
        )
        packs = load_packs(tmp_path)  # must not raise TypeError
        assert len(packs) == 1
        assert packs[0].kinds["call"].names == ("HMAC",)

    def test_valid_list_still_loads(self, tmp_path: Path):
        _write_pack(tmp_path)
        packs = load_packs(tmp_path)
        assert packs[0].kinds["call"].prefixes == ("EVP_Digest",)


class TestFullmatchAnchoring:
    def test_trailing_newline_rejected(self):
        # re.match + '$' accepted a trailing newline, splicing a
        # literal line break into the rendered cocci.
        assert _API_RE.fullmatch("openssl\n") is None
        assert _IDENT_RE.fullmatch("HMAC\n") is None

    def test_valid_values_still_accepted(self):
        assert _API_RE.fullmatch("openssl")
        assert _IDENT_RE.fullmatch("HMAC")

    def test_newline_api_pack_skipped(self, tmp_path: Path):
        rules = tmp_path / "rules"
        _write_pack(rules / "packs", api="openssl\n")
        rule = rules / "r.cocci"
        rule.write_text("// @api-packs: packs crypto\n", encoding="utf-8")
        # Sole pack invalid -> nothing usable -> unrendered slot.
        assert render_text(rule) is None


class TestMarkerPredicate:
    def test_two_space_marker_detected_and_rendered(self, tmp_path: Path):
        # '//  @api-packs:' matches the authoritative regex but the old
        # substring pre-check silently never rendered it.
        rules = tmp_path / "rules"
        _write_pack(rules / "packs")
        rule = rules / "r.cocci"
        rule.write_text("//  @api-packs: packs crypto\n", encoding="utf-8")
        text = render_text(rule)
        assert text is not None
        assert "crypto:call:openssl:" in text

    def test_predicate_spellings(self):
        assert has_api_pack_marker("// @api-packs: packs crypto\n")
        assert has_api_pack_marker("//@api-packs: packs crypto\n")
        assert has_api_pack_marker("//   @api-packs: packs crypto\n")
        assert not has_api_pack_marker("plain cocci text\n")
        # Marker must be its own line, not embedded mid-line.
        assert not has_api_pack_marker("x // @api-packs: packs crypto\n")
