"""build_flow_query routes JSON-embedded CPG text through jsonEsc.

The flow query interpolates ``.code``, method names, and filenames
from the SCANNED repo into JOERN_FLOW JSON records; unescaped, hostile
content forges or destroys records. The escape authority is the shared
Scala helper ``packages.joern.runner.SCALA_JSON_ESC_DEF`` — one
definition per submitted query, no hand-inlined chains.
"""

from __future__ import annotations

from core.audit.joern_verify import build_flow_query
from packages.joern.runner import SCALA_JSON_ESC_DEF, _validate_query

# The Scala-source shape of a hand-inlined backslash escape chain,
# built from a single-backslash char so the target bytes are explicit.
_BS = "\\"
_CHAIN = f'.replace("{_BS * 2}", "{_BS * 4}")'


class TestFlowQueryJsonEscaping:
    def test_embeds_canonical_json_esc_definition(self):
        q = build_flow_query("handler", "argv", "system")
        assert SCALA_JSON_ESC_DEF in q

    def test_every_json_field_routed_through_json_esc(self):
        q = build_flow_query("handler", "argv", "system")
        # .take(200) on the RAW code BEFORE jsonEsc — escape-then-
        # truncate can bisect an injected \" leaving a dangling
        # backslash.
        assert "val cd = jsonEsc(e.code.take(200))" in q
        assert "val fnEsc = jsonEsc(fnName)" in q
        assert "val flEsc = jsonEsc(fl)" in q

    def test_single_escape_authority(self):
        q = build_flow_query("handler", "argv", "system")
        # Exactly one chain — the one inside the jsonEsc definition.
        assert q.count(_CHAIN) == 1

    def test_still_passes_query_validation(self):
        q = build_flow_query("handler", "argv", "system")
        assert _validate_query(q, check_length=False) is None
