"""Tests for the ``core.binary.pe`` signing facts: the
WIN_CERTIFICATE table walk and the bounded PKCS#7 DER skim behind
``claimed_signer``.

Crafted-blob coverage (pure-python DER assembly, no toolchain):

  * a valid minimal PKCS#7 SignedData with a known CN — exact
    extraction pinned, through the whole-file extractor and the
    skim alike, for every string universe the field accepts
  * the skim's refusals: indefinite lengths, TLV length lies in
    both directions, depth/node budgets at their REAL values,
    unmatched certificates, absent / undecodable CNs
  * WIN_CERTIFICATE table rules: first-PKCS#7-wins, non-PKCS
    entries skipped marker-visibly, extra entries counted never
    consulted, dwLength lies, tables over-running EOF, zero-length
    shapes
  * hostile-CN egress through the repo render chokepoint
    (``core.security.log_sanitisation``)
  * seeded random mutation fuzz over the DER skim — 3 seeds x
    10,000 mutations (30,000 total), never-raises + per-parse
    wall-clock bound
  * the signing-facts FENCE census (see ``TestSigningFactsFence``)
"""

from __future__ import annotations

import random
import struct
import time
from pathlib import Path

from core.binary import pe as pe_mod
from core.binary.pe import (
    _skim_claimed_signer,
    extract_pe_facts,
)
from core.security.log_sanitisation import (
    escape_nonprintable,
    has_nonprintable,
)

from .test_pe_facts import PeSpec, Sec, build_pe

_OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")
_OID_PKCS7_DATA = bytes.fromhex("2a864886f70d010701")
_OID_CN = bytes.fromhex("550403")
_OID_ORG = bytes.fromhex("55040a")
_OID_SHA256_RSA = bytes.fromhex("2a864886f70d01010b")


# ---------------------------------------------------------------------------
# DER assembly helpers
# ---------------------------------------------------------------------------


def der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def x500_name(cn: bytes, *, string_tag: int = 0x13,
              extra_rdns: bytes = b"") -> bytes:
    """RDNSequence with one CN attribute (plus optional extra
    RDNs before it)."""
    atv = der(0x30, der(0x06, _OID_CN) + der(string_tag, cn))
    return der(0x30, extra_rdns + der(0x31, atv))


def certificate(serial: bytes, issuer: bytes,
                subject: bytes) -> bytes:
    tbs = der(0x30,
              der(0xA0, der(0x02, b"\x02"))       # [0] version v3
              + der(0x02, serial)
              + der(0x30, der(0x06, _OID_SHA256_RSA))
              + issuer
              + der(0x30, b"")                    # validity (skipped)
              + subject)
    return der(0x30, tbs + der(0x30, der(0x06, _OID_SHA256_RSA))
               + der(0x03, b"\x00"))


def signer_info(serial: bytes, issuer: bytes) -> bytes:
    return der(0x30, der(0x02, b"\x01")
               + der(0x30, issuer + der(0x02, serial)))


def pkcs7(certs: list[bytes] | None,
          signer_infos: list[bytes]) -> bytes:
    signed_data = der(
        0x30,
        der(0x02, b"\x01")                        # version
        + der(0x31, b"")                          # digestAlgorithms
        + der(0x30, der(0x06, _OID_PKCS7_DATA))   # contentInfo
        + (der(0xA0, b"".join(certs)) if certs is not None else b"")
        + der(0x31, b"".join(signer_infos)))
    return der(0x30, der(0x06, _OID_SIGNED_DATA)
               + der(0xA0, signed_data))


_ISSUER = x500_name(b"Contoso Root CA")
_SERIAL = b"\x05"


def simple_blob(cn: bytes = b"Contoso Signing", *,
                string_tag: int = 0x13) -> bytes:
    subject = x500_name(cn, string_tag=string_tag)
    return pkcs7([certificate(_SERIAL, _ISSUER, subject)],
                 [signer_info(_SERIAL, _ISSUER)])


def win_cert(blob: bytes, *, cert_type: int = 0x0002,
             dw_length: int | None = None) -> bytes:
    dw = 8 + len(blob) if dw_length is None else dw_length
    entry = struct.pack("<IHH", dw, 0x0200, cert_type) + blob
    return entry + b"\x00" * (-len(entry) % 8)


def image_with_table(table: bytes, *,
                     declared_size: int | None = None,
                     declared_offset: int | None = None) -> bytes:
    """A minimal image whose security directory points at ``table``
    appended as overlay (the conventional certificate-table home)."""
    secs = [Sec(name=b".text", va=0x1000, data=b"x" * 16)]
    base_len = len(build_pe(PeSpec(secs=list(secs))))
    off = base_len if declared_offset is None else declared_offset
    size = len(table) if declared_size is None else declared_size
    return build_pe(PeSpec(secs=list(secs),
                           data_dirs={4: (off, size)},
                           overlay=table))


def facts_for(tmp_path: Path, image: bytes, name: str = "s.exe"):
    p = tmp_path / name
    p.write_bytes(image)
    facts = extract_pe_facts(p)
    assert facts is not None
    return facts


# ---------------------------------------------------------------------------
# Happy-path extraction
# ---------------------------------------------------------------------------


class TestClaimedSignerExtraction:
    def test_known_cn_extracted_exactly(self, tmp_path):
        facts = facts_for(
            tmp_path, image_with_table(win_cert(simple_blob())))
        assert facts.authenticode_present is True
        assert facts.claimed_signer == "Contoso Signing"
        assert facts.caps_hit == []

    def test_every_accepted_string_universe(self, tmp_path):
        for tag, raw, expect in [
            (0x13, b"Printable Co", "Printable Co"),
            (0x0C, "UTF8 Signér".encode(), "UTF8 Signér"),
            (0x16, b"ia5@example", "ia5@example"),
            (0x14, b"teletex", "teletex"),
            (0x1E, "BMP 会社".encode("utf-16-be"),
             "BMP 会社"),
        ]:
            facts = facts_for(
                tmp_path,
                image_with_table(win_cert(
                    simple_blob(raw, string_tag=tag))),
                name=f"t{tag:02x}.exe")
            assert facts.claimed_signer == expect, hex(tag)

    def test_signer_matched_by_issuer_and_serial_not_order(
            self, tmp_path):
        """The leaf sits SECOND in the certificates list; a decoy
        with the wrong serial sits first — the recorded claim is
        the matched certificate's subject CN."""
        decoy = certificate(b"\x09", _ISSUER, x500_name(b"Decoy"))
        leaf = certificate(_SERIAL, _ISSUER,
                           x500_name(b"Real Signer"))
        blob = pkcs7([decoy, leaf], [signer_info(_SERIAL, _ISSUER)])
        facts = facts_for(tmp_path, image_with_table(win_cert(blob)))
        assert facts.claimed_signer == "Real Signer"

    def test_cn_found_behind_other_rdns(self, tmp_path):
        org = der(0x31, der(0x30, der(0x06, _OID_ORG)
                            + der(0x13, b"Contoso Org")))
        subject = x500_name(b"Behind Org", extra_rdns=org)
        blob = pkcs7([certificate(_SERIAL, _ISSUER, subject)],
                     [signer_info(_SERIAL, _ISSUER)])
        facts = facts_for(tmp_path, image_with_table(win_cert(blob)))
        assert facts.claimed_signer == "Behind Org"

    def test_serialization_carries_the_claim(self, tmp_path):
        facts = facts_for(
            tmp_path, image_with_table(win_cert(simple_blob())))
        assert facts.to_dict()["claimed_signer"] == "Contoso Signing"

    def test_unsigned_image_records_no_signing_markers(
            self, tmp_path):
        facts = facts_for(tmp_path, build_pe(PeSpec(
            secs=[Sec(name=b".text", va=0x1000, data=b"x" * 16)])))
        assert facts.authenticode_present is False
        assert facts.claimed_signer == ""
        assert not [c for c in facts.caps_hit
                    if c.startswith(("authenticode_", "signer_"))]


# ---------------------------------------------------------------------------
# WIN_CERTIFICATE table rules
# ---------------------------------------------------------------------------


class TestCertificateTableWalk:
    def test_first_pkcs7_entry_wins_extra_marked(self, tmp_path):
        first = win_cert(simple_blob(b"First"))
        second = win_cert(simple_blob(b"Second"))
        facts = facts_for(tmp_path,
                          image_with_table(first + second))
        assert facts.claimed_signer == "First"
        assert "authenticode_extra_certificates" in facts.caps_hit

    def test_non_pkcs_entry_skipped_with_marker(self, tmp_path):
        ts = win_cert(b"\x01\x02\x03\x04", cert_type=0x0001)
        good = win_cert(simple_blob(b"After X509"))
        facts = facts_for(tmp_path, image_with_table(ts + good))
        assert facts.claimed_signer == "After X509"
        assert "authenticode_non_pkcs_entry" in facts.caps_hit
        assert ("authenticode_extra_certificates"
                not in facts.caps_hit)

    def test_failed_first_entry_never_falls_back(self, tmp_path):
        """A doctored first PKCS#7 entry fails SAFE to no claim —
        it must not redirect the record to the second entry."""
        broken = win_cert(b"\x30\x03garbage")
        good = win_cert(simple_blob(b"Backup"))
        facts = facts_for(tmp_path, image_with_table(broken + good))
        assert facts.claimed_signer == ""
        assert "signer_skim_malformed" in facts.caps_hit
        assert "authenticode_extra_certificates" in facts.caps_hit

    def test_entry_flood_capped_at_real_value(self, tmp_path):
        cap = pe_mod._MAX_CERT_TABLE_ENTRIES
        entry = win_cert(b"", cert_type=0x0001, dw_length=8)
        table = entry * (cap + 8)
        start = time.perf_counter()
        facts = facts_for(tmp_path, image_with_table(table))
        elapsed = time.perf_counter() - start
        assert "authenticode_entries_capped" in facts.caps_hit
        assert facts.claimed_signer == ""
        assert elapsed < 1.0

    def test_entry_count_at_the_cap_is_clean(self, tmp_path):
        cap = pe_mod._MAX_CERT_TABLE_ENTRIES
        entry = win_cert(b"", cert_type=0x0001, dw_length=8)
        facts = facts_for(tmp_path, image_with_table(entry * cap))
        assert "authenticode_entries_capped" not in facts.caps_hit

    def test_dw_length_smaller_than_header_stops(self, tmp_path):
        table = struct.pack("<IHH", 4, 0x0200, 2) + b"\x00" * 8
        facts = facts_for(tmp_path, image_with_table(table))
        assert "authenticode_malformed" in facts.caps_hit
        assert facts.claimed_signer == ""

    def test_dw_length_over_running_table_still_skims_real_bytes(
            self, tmp_path):
        """dwLength = u32 max: the entry extent clamps to the table
        end (marker), and the skim still reads the bytes the file
        really has."""
        blob = simple_blob(b"Clamped")
        table = struct.pack("<IHH", 2**32 - 1, 0x0200, 2) + blob
        facts = facts_for(tmp_path, image_with_table(table))
        assert facts.claimed_signer == "Clamped"
        assert "authenticode_malformed" in facts.caps_hit

    def test_directory_pointing_past_eof(self, tmp_path):
        facts = facts_for(tmp_path, image_with_table(
            b"", declared_offset=0x900000, declared_size=0x100))
        assert facts.authenticode_present is True
        assert facts.claimed_signer == ""
        assert "authenticode_unreadable" in facts.caps_hit

    def test_directory_size_over_running_eof_degrades(
            self, tmp_path):
        table = win_cert(simple_blob(b"Short Table"))
        facts = facts_for(tmp_path, image_with_table(
            table, declared_size=len(table) + 0x4000))
        # The walk clamps to EOF; the one real entry still skims.
        assert facts.claimed_signer == "Short Table"

    def test_zero_length_blob_degrades(self, tmp_path):
        facts = facts_for(tmp_path, image_with_table(
            win_cert(b"", dw_length=8)))
        assert facts.claimed_signer == ""
        assert "signer_skim_malformed" in facts.caps_hit

    def test_blob_cap_engages_with_marker(self, tmp_path,
                                          monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_CERT_BLOB_BYTES", 64)
        facts = facts_for(
            tmp_path, image_with_table(win_cert(simple_blob())))
        assert "authenticode_blob_capped" in facts.caps_hit
        assert facts.claimed_signer == ""


# ---------------------------------------------------------------------------
# DER skim refusals
# ---------------------------------------------------------------------------


class TestDerSkimRefusals:
    def _skim(self, blob: bytes) -> tuple[str | None, set[str]]:
        caps: set[str] = set()
        return _skim_claimed_signer(blob, caps), caps

    def test_indefinite_length_refused(self):
        blob = simple_blob()
        # Rewrite the outer SEQUENCE's length octet to indefinite.
        name, caps = self._skim(blob[:1] + b"\x80" + blob[2:])
        assert name is None
        assert "signer_skim_indefinite_length" in caps

    def test_length_lie_past_enclosure_refused(self):
        blob = bytearray(simple_blob())
        idx = bytes(blob).find(b"Contoso Signing")
        blob[idx - 1] = 0x7F        # CN claims bytes past its ATV
        name, caps = self._skim(bytes(blob))
        assert name is None
        assert "signer_skim_malformed" in caps

    def test_length_understatement_degrades_honestly(self):
        blob = bytearray(simple_blob())
        idx = bytes(blob).find(b"Contoso Signing")
        blob[idx - 1] = 7           # CN claims FEWER bytes
        name, caps = self._skim(bytes(blob))
        # Either a shorter honest string or a structural degrade —
        # never invented bytes, never an exception.
        assert name is None or name == "Contoso"

    def test_wrong_content_type_oid_refused(self):
        blob = simple_blob().replace(_OID_SIGNED_DATA,
                                     _OID_PKCS7_DATA, 1)
        name, caps = self._skim(blob)
        assert name is None
        assert "signer_skim_malformed" in caps

    def test_truncated_blob_never_raises(self):
        blob = simple_blob()
        for cut in range(0, len(blob), 7):
            name, caps = self._skim(blob[:cut])
            assert name is None or isinstance(name, str)

    def test_serial_mismatch_is_unmatched(self):
        blob = pkcs7(
            [certificate(b"\x06", _ISSUER, x500_name(b"X"))],
            [signer_info(_SERIAL, _ISSUER)])
        name, caps = self._skim(blob)
        assert name is None
        assert "signer_cert_unmatched" in caps

    def test_issuer_mismatch_is_unmatched(self):
        other = x500_name(b"Other CA")
        blob = pkcs7(
            [certificate(_SERIAL, other, x500_name(b"X"))],
            [signer_info(_SERIAL, _ISSUER)])
        name, caps = self._skim(blob)
        assert name is None
        assert "signer_cert_unmatched" in caps

    def test_absent_certificates_field_is_unmatched(self):
        blob = pkcs7(None, [signer_info(_SERIAL, _ISSUER)])
        name, caps = self._skim(blob)
        assert name is None
        assert "signer_cert_unmatched" in caps

    def test_multiple_signers_first_wins_marked(self):
        second_issuer = x500_name(b"Second CA")
        blob = pkcs7(
            [certificate(_SERIAL, _ISSUER, x500_name(b"One")),
             certificate(_SERIAL, second_issuer,
                         x500_name(b"Two"))],
            [signer_info(_SERIAL, _ISSUER),
             signer_info(_SERIAL, second_issuer)])
        name, caps = self._skim(blob)
        assert name == "One"
        assert "signer_multiple_signers" in caps

    def test_subject_without_cn_is_marked(self):
        org_only = der(0x30, der(0x31, der(
            0x30, der(0x06, _OID_ORG) + der(0x13, b"Org"))))
        blob = pkcs7(
            [certificate(_SERIAL, _ISSUER, org_only)],
            [signer_info(_SERIAL, _ISSUER)])
        name, caps = self._skim(blob)
        assert name is None
        assert "signer_cn_absent" in caps

    def _steer_blob(self, first_rdns: bytes) -> bytes:
        """Subject = ``first_rdns`` then a well-formed decoy CN —
        the sibling a structural poison would steer the record to."""
        decoy = der(0x31, der(0x30, der(0x06, _OID_CN)
                              + der(0x13, b"ChooseMe")))
        subject = der(0x30, first_rdns + decoy)
        return pkcs7(
            [certificate(_SERIAL, _ISSUER, subject)],
            [signer_info(_SERIAL, _ISSUER)])

    def test_length_lie_first_cn_is_terminal(self):
        """Structural poison lane B1: the first CN's value TLV
        claims bytes past its ATV. Malformation in the CN walk is
        TERMINAL — no claim, never a fall-through to the later,
        attacker-chosen CN."""
        atv = der(0x30, der(0x06, _OID_CN) + b"\x13\x7fXX")
        name, caps = self._skim(self._steer_blob(der(0x31, atv)))
        assert name is None
        assert "signer_skim_malformed" in caps

    def test_indefinite_first_cn_is_terminal(self):
        """Structural poison lane B2: indefinite-length first CN
        value — refused, no fall-through."""
        atv = der(0x30, der(0x06, _OID_CN) + b"\x13\x80XX")
        name, caps = self._skim(self._steer_blob(der(0x31, atv)))
        assert name is None
        assert "signer_skim_indefinite_length" in caps

    def test_broken_first_rdn_member_is_terminal(self):
        """Structural poison lane B3: the first RDN's member
        carries a broken header — refused, no fall-through."""
        name, caps = self._skim(
            self._steer_blob(der(0x31, b"\x30\x7fjunk")))
        assert name is None
        assert "signer_skim_malformed" in caps

    def test_broken_pre_cn_sibling_atv_is_terminal(self):
        """Structural poison lane B4: a broken sibling INSIDE the
        CN's own RDN SET, ahead of a well-formed CN — refused, no
        fall-through to either CN."""
        rdn = der(0x31, b"\x30\x7fjunk"
                  + der(0x30, der(0x06, _OID_CN)
                        + der(0x13, b"Hidden")))
        name, caps = self._skim(self._steer_blob(rdn))
        assert name is None
        assert "signer_skim_malformed" in caps

    def test_wellformed_non_cn_siblings_still_walk(self):
        """The terminal rule targets MALFORMATION only: well-formed
        non-CN attributes and wrong-tag siblings ahead of the CN
        remain normal subject structure."""
        org = der(0x31, der(0x30, der(0x06, _OID_ORG)
                            + der(0x13, b"Org")))
        wrong_tag = der(0x02, b"\x01")     # INTEGER in RDNSequence
        name, caps = self._skim(self._steer_blob(wrong_tag + org))
        assert name == "ChooseMe"

    def test_unrecognised_cn_type_never_falls_through(self):
        """The first CN carries an OCTET STRING value; a second,
        decodable CN follows — the skim must degrade on the first,
        not let a hostile subject choose the recorded name."""
        bad_atv = der(0x30, der(0x06, _OID_CN)
                      + der(0x04, b"\xde\xad"))
        good_atv = der(0x30, der(0x06, _OID_CN)
                       + der(0x13, b"Choose Me"))
        subject = der(0x30, der(0x31, bad_atv)
                      + der(0x31, good_atv))
        blob = pkcs7(
            [certificate(_SERIAL, _ISSUER, subject)],
            [signer_info(_SERIAL, _ISSUER)])
        name, caps = self._skim(blob)
        assert name is None
        assert "signer_cn_unrecognised_type" in caps

    def test_cn_truncated_at_retention_cap(self):
        cap = pe_mod._MAX_SIGNER_NAME_BYTES
        name, caps = self._skim(simple_blob(b"n" * (cap + 100)))
        assert name == "n" * cap
        assert "signer_name_truncated" in caps

    def test_cn_at_the_cap_is_clean(self):
        cap = pe_mod._MAX_SIGNER_NAME_BYTES
        name, caps = self._skim(simple_blob(b"n" * cap))
        assert name == "n" * cap
        assert "signer_name_truncated" not in caps


# ---------------------------------------------------------------------------
# Budgets: depth, nodes, cost pins
# ---------------------------------------------------------------------------


class TestSkimBudgets:
    def test_depth_cap_fires_on_the_children_walk(self):
        """The targeted walk's deepest call sits at depth 9 by
        construction, so the depth budget is a tripwire for future
        edits — prove it actually fires."""
        caps: set[str] = set()
        skim = pe_mod._DerSkim(der(0x30, der(0x30, b"")), caps)
        node = skim.top()
        assert node is not None
        assert skim.children(node, pe_mod._MAX_DER_DEPTH) == []
        assert "signer_skim_depth_capped" in caps

    def test_nesting_bomb_degrades_in_bounded_time(self):
        bomb = b"x"
        for _ in range(5_000):
            bomb = der(0x30, bomb)
        caps: set[str] = set()
        start = time.perf_counter()
        assert _skim_claimed_signer(bomb, caps) is None
        assert time.perf_counter() - start < 0.5
        assert caps      # degraded marker-visibly, never raised

    def test_node_budget_fires_at_real_cap_on_tlv_flood(self):
        """The op-count regression pin: a flood of 2-byte TLVs in
        signerInfos must hit the NODE budget (a lifted or removed
        ``_MAX_DER_NODES`` fails this test), and the capped parse
        stays flat-time while the flood grows."""
        def flood_blob(n: int) -> bytes:
            signed = der(
                0x30,
                der(0x02, b"\x01") + der(0x31, b"")
                + der(0x30, der(0x06, _OID_PKCS7_DATA))
                + der(0x31, der(0x30, b"") * n))
            return der(0x30, der(0x06, _OID_SIGNED_DATA)
                       + der(0xA0, signed))

        small = flood_blob(100_000)
        large = flood_blob(400_000)
        caps: set[str] = set()
        start = time.perf_counter()
        assert _skim_claimed_signer(small, caps) is None
        t_small = time.perf_counter() - start
        assert "signer_skim_nodes_capped" in caps
        caps = set()
        start = time.perf_counter()
        assert _skim_claimed_signer(large, caps) is None
        t_large = time.perf_counter() - start
        assert "signer_skim_nodes_capped" in caps
        # Work is bounded by the node budget, not input size: the
        # 4x flood must not cost 4x (generous 2.5x + 20ms floor
        # absorbs timer noise; the UNCAPPED walk measures ~4.3x).
        assert t_large < max(t_small * 2.5, t_small + 0.02), (
            t_small, t_large)

    def test_oid_flood_in_the_subject_stays_bounded(self):
        """Thousands of non-CN attributes ahead of the CN: every
        skipped attribute costs bounded header parses and a
        fixed-width OID comparison (raw-byte equality, never arc
        decoding), so the walk either reaches the CN or spends the
        node budget — marker-visibly, in bounded time."""
        junk_atv = der(0x30, der(0x06, _OID_ORG)
                       + der(0x13, b"x"))
        flood_rdns = der(0x31, junk_atv) * 2_000
        subject = x500_name(b"Behind Flood", extra_rdns=flood_rdns)
        blob = pkcs7(
            [certificate(_SERIAL, _ISSUER, subject)],
            [signer_info(_SERIAL, _ISSUER)])
        caps: set[str] = set()
        start = time.perf_counter()
        name = _skim_claimed_signer(blob, caps)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5
        assert (name == "Behind Flood"
                or "signer_skim_nodes_capped" in caps)

    def test_worst_shape_wall_clock_through_the_extractor(
            self, tmp_path):
        """The priced adversarial product end-to-end: a max-entry
        table whose first PKCS#7 entry is a max-size TLV flood —
        every signing cap engages and the whole parse stays fast."""
        flood = der(0x30, b"") * 500_000       # ~1 MiB of TLVs
        signed = der(
            0x30,
            der(0x02, b"\x01") + der(0x31, b"")
            + der(0x30, der(0x06, _OID_PKCS7_DATA))
            + der(0x31, flood))
        blob = der(0x30, der(0x06, _OID_SIGNED_DATA)
                   + der(0xA0, signed))
        table = win_cert(blob) + win_cert(
            b"", cert_type=1, dw_length=8) * 32
        start = time.perf_counter()
        facts = facts_for(tmp_path, image_with_table(table))
        elapsed = time.perf_counter() - start
        assert facts.claimed_signer == ""
        assert "signer_skim_nodes_capped" in facts.caps_hit
        assert "authenticode_extra_certificates" in facts.caps_hit
        assert elapsed < 1.0


# ---------------------------------------------------------------------------
# Hostile-CN egress
# ---------------------------------------------------------------------------


class TestHostileClaimedSigner:
    def test_control_bytes_survive_as_data_and_render_inert(
            self, tmp_path):
        hostile = b"Evil\x1b]0;pwn\x07 \xe2\x80\xaeCorp\x00Inc"
        facts = facts_for(
            tmp_path,
            image_with_table(win_cert(simple_blob(
                hostile, string_tag=0x0C))))
        name = facts.claimed_signer
        # The bytes are DATA at rest: ESC, the bidi override and
        # the NUL all survive capture (nothing pre-escapes).
        assert "\x1b" in name
        assert "‮" in name
        assert "\x00" in name
        # And the repo render chokepoint neutralises every one.
        rendered = escape_nonprintable(name)
        assert not has_nonprintable(rendered)
        assert "\\x1b" in rendered
        assert "\\u202e" in rendered
        assert "\\x00" in rendered

    def test_invalid_utf8_degrades_to_replacement_never_raises(
            self, tmp_path):
        facts = facts_for(
            tmp_path,
            image_with_table(win_cert(simple_blob(
                b"\xff\xfe broken \x80", string_tag=0x0C))))
        assert "�" in facts.claimed_signer


# ---------------------------------------------------------------------------
# Mutation fuzz over the skim
# ---------------------------------------------------------------------------


class TestSkimMutationFuzz:
    def test_thirty_thousand_seeded_mutations_never_raise(self):
        """Never-raises + wall-clock contract for the DER skim
        under random damage, across THREE independent seeds
        (30,000 mutations total — every run replays the identical
        corpus). Truncations are mixed in every tenth round."""
        base = pkcs7(
            [certificate(b"\x09", _ISSUER, x500_name(b"Decoy")),
             certificate(_SERIAL, _ISSUER,
                         x500_name(b"Fuzz Target",
                                   string_tag=0x0C))],
            [signer_info(_SERIAL, _ISSUER),
             signer_info(b"\x07", _ISSUER)])
        worst = 0.0
        for seed in (0x51611ED, 0xDE_5EED2, 0x5EED0003):
            rng = random.Random(seed)
            for i in range(10_000):
                blob = bytearray(base)
                if i % 10 == 9:
                    blob = blob[:rng.randrange(1, len(blob))]
                for _ in range(rng.randint(1, 8)):
                    blob[rng.randrange(len(blob))] = rng.randrange(256)
                caps: set[str] = set()
                start = time.perf_counter()
                name = _skim_claimed_signer(bytes(blob), caps)
                elapsed = time.perf_counter() - start
                worst = max(worst, elapsed)
                assert elapsed < 0.5, (
                    f"seed {seed:#x} mutation {i} took "
                    f"{elapsed:.3f}s — pathological skim")
                assert name is None or isinstance(name, str)
                if name is not None:
                    assert len(name) <= 4 * pe_mod._MAX_SIGNER_NAME_BYTES
        assert worst < 0.5

    def test_mutated_whole_images_never_raise(self, tmp_path):
        """The same contract through the full extractor with the
        certificate table in play (2,000 mutations biased into the
        table region)."""
        base = image_with_table(win_cert(simple_blob()))
        table_start = len(base) - len(win_cert(simple_blob()))
        p = tmp_path / "mut.exe"
        rng = random.Random(0x516F00D)
        for _ in range(2_000):
            blob = bytearray(base)
            for _ in range(rng.randint(1, 6)):
                if rng.random() < 0.7:
                    pos = rng.randrange(table_start, len(blob))
                else:
                    pos = rng.randrange(len(blob))
                blob[pos] = rng.randrange(256)
            p.write_bytes(bytes(blob))
            facts = extract_pe_facts(p)   # must never raise
            assert facts is None or facts.claimed_signer is not None


# ---------------------------------------------------------------------------
# The signing-facts fence
# ---------------------------------------------------------------------------


class TestSigningFactsFence:
    def test_no_mechanical_consumer_gates_on_signing_facts(self):
        """FENCE PIN: ``authenticode_present`` / ``claimed_signer``
        are attacker-authored CLAIMS — display/correlation facts
        only. No runtime module may read them to gate, suppress,
        rank, or trust anything; the ONLY runtime references live
        in ``core/binary/pe.py`` itself (field declarations and
        the extraction that populates them — serialization rides
        ``to_dict``'s generic ``asdict``). This census pins that
        consumer set to exactly that one file. If a consumer is
        ever added deliberately, amend BOTH places together: this
        pin AND the FENCE note on the ``claimed_signer`` field."""
        repo = Path(__file__).resolve().parents[3]
        allowed = {Path("core/binary/pe.py")}
        offenders: set[Path] = set()
        candidates: list[Path] = [repo / "raptor.py"]
        for root in ("core", "packages", "libexec", "plugins"):
            base = repo / root
            if not base.is_dir():
                continue
            candidates.extend(base.rglob("*"))
        for path in candidates:
            if not path.is_file():
                continue
            if path.suffix not in ("", ".py"):
                continue
            rel = path.relative_to(repo)
            parts = rel.parts
            if "tests" in parts or "scripts" in parts:
                continue
            try:
                text = path.read_text(encoding="utf-8",
                                      errors="ignore")
            except OSError:
                continue
            if ("claimed_signer" in text
                    or "authenticode_present" in text):
                offenders.add(rel)
        assert offenders == allowed, (
            f"signing-facts fence breached: {sorted(offenders - allowed)} "
            "reference claimed_signer/authenticode_present — these are "
            "unverified attacker-authored claims; no mechanical consumer "
            "may gate on them (see the FENCE note in core/binary/pe.py)")
