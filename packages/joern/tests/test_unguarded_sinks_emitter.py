"""unguarded_sinks.sc emitter ordering: the genuine summary is LAST.

The scalar parser (core.analysis._joern_lines.extract_scalar_marker)
keeps the LAST mid-line occurrence of a marker, and jsonEsc preserves
marker TEXT inside a record's "code" field — target code like
``system("JOERN_GUARD_SUMMARY:0/5")`` rides the transcript verbatim
(escaped, but textually present). With the summary emitted FIRST on
the final-expression echo, a scanned-repo author could therefore flip
"unguarded" to "guarded" for any consumer reading the scalar off that
transcript. The emitter now puts the genuine summary after every
record on BOTH transports (println order already did).
"""

from __future__ import annotations

import re
from pathlib import Path

_SC = Path(__file__).resolve().parents[1] / "queries" / "unguarded_sinks.sc"


def _final_expression() -> str:
    lines = [ln for ln in _SC.read_text(encoding="utf-8").splitlines()
             if ln.strip() and not ln.lstrip().startswith("//")]
    return lines[-1]


def test_final_expression_emits_summary_after_records():
    final = _final_expression()
    assert "results.mkString" in final
    assert "JOERN_GUARD_SUMMARY" in final
    assert final.index("results.mkString") < final.index(
        "JOERN_GUARD_SUMMARY",
    ), "the genuine summary must be LAST on the value-echo transport"


def test_genuine_summary_beats_forged_record_payload():
    # Transcript shaped as the server's value echo of the final
    # expression, with one record whose target code embeds a forged
    # summary (jsonEsc keeps the marker text, quotes escaped).
    from core.analysis._joern_lines import extract_scalar_marker

    record = (
        'JOERN_UNGUARDED:{"sink":"system","line":10,'
        '"code":"system(\\"JOERN_GUARD_SUMMARY:0/5\\")","guarded":false}'
    )
    genuine = "JOERN_GUARD_SUMMARY:2/5"
    transcript = 'val res42: String = """' + record + "\n" + genuine + '"""'
    val = extract_scalar_marker(transcript, "JOERN_GUARD_SUMMARY:")
    assert val is not None
    assert re.fullmatch(r"(\d+)/(\d+)", val)
    assert val == "2/5", (
        "forged record payload beat the genuine summary — emitter "
        "ordering regressed"
    )
