"""PHP probe synthesis and output parsing for the sanitizer witness.

The probe is generated from a FIXED template plus the grammar-
validated chain steps (re-emitted from their original lexemes, data
slot renamed to ``$x``). Payloads never appear in probe code — they
travel in a JSON data file read via ``argv`` — and the probe's JSON
output is authenticated by a per-execution token (the dark_verify
receipt discipline: unauthenticated output never yields a verdict).

Token trust story, stated honestly: the token authenticates that the
output came from THIS probe execution (against wrong-output, partial
runs, stale captures). It is NOT a defense against grammar escape —
the token lives in the probe's own source, so any code that escapes
the step grammar runs in the same process and can read it. The
grammar (`_extract`'s literal/allowlist rules, including the blanket
``$``-in-double-quotes refusal) is the one and only defense against
escape; the token and the grammar are one layered defense, not two
independent ones.

Failure honesty: a step returning ``null``/non-string or raising
(warnings are promoted to exceptions) marks that payload errored; a
silently-failed step must never read as "neutralized". Outputs are
base64-marshalled (arbitrary transform bytes survive json_encode)
and truncated outputs are marked — a hidden tail must not fake
sufficiency.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field

from ._extract import ChainStep

#: Per-output probe-side truncation bound. Payloads are <= 64 bytes,
#: so any legitimate chain output is far below this; the cap exists
#: so a pathological literal-replacement blowup cannot flood the
#: capture channel. A truncated output is INDETERMINATE for that
#: payload (never "sufficient"), so a tighter cap only costs
#: determinacy on degenerate chains and a looser one only buys
#: capture bytes.
MAX_OUTPUT_CHARS = 4096


def generate_probe(steps: tuple[ChainStep, ...], token: str) -> str:
    """Render the probe script for *steps* with authentication *token*.

    ``token`` is generated in-process per execution and is hex-only
    by contract (asserted here) so it composes inertly into the
    template.
    """
    if not token.isalnum():  # pragma: no cover — caller contract
        msg = "witness token must be alphanumeric"
        raise ValueError(msg)
    lines = [step.render("$x") + ";" for step in steps]
    chain_src = "\n        ".join(f"$x = {line}" for line in lines)
    return f"""<?php
error_reporting(E_ALL);
set_error_handler(function ($no, $str) {{
    throw new ErrorException($str);
}});
$__in = json_decode(file_get_contents($argv[1]), true);
if (!is_array($__in) || !isset($__in["payloads"])) {{
    fwrite(STDERR, "sanwit: bad payload file");
    exit(3);
}}
$__outputs = array();
$__errors = array();
$__truncated = array();
foreach ($__in["payloads"] as $__id => $__p) {{
    $x = $__p;
    try {{
        {chain_src}
    }} catch (Throwable $__e) {{
        $__errors[$__id] = substr($__e->getMessage(), 0, 200);
        continue;
    }}
    if (!is_string($x)) {{
        $__errors[$__id] = "chain produced " . gettype($x);
        continue;
    }}
    if (strlen($x) > {MAX_OUTPUT_CHARS}) {{
        $__truncated[$__id] = true;
        $x = substr($x, 0, {MAX_OUTPUT_CHARS});
    }}
    $__outputs[$__id] = base64_encode($x);
}}
echo json_encode(array(
    "sanwit_token" => "{token}",
    "php_version" => PHP_VERSION,
    "outputs" => $__outputs,
    "errors" => $__errors,
    "truncated" => $__truncated,
), JSON_FORCE_OBJECT);
"""


def payloads_document(corpus: tuple[tuple[str, str], ...]) -> str:
    """The JSON payload document for *corpus* (id → payload)."""
    return json.dumps({"payloads": dict(corpus)})


@dataclass
class ProbeRun:
    """Parsed, authenticated probe output."""

    php_version: str
    outputs: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    truncated: dict[str, bool] = field(default_factory=dict)


def parse_probe_output(stdout: str, token: str) -> ProbeRun | str:
    """Parse and authenticate probe stdout.

    Returns :class:`ProbeRun` or a refusal reason string. Only a JSON
    document carrying the per-execution token is accepted; outputs
    that fail base64 decoding mark their payload errored rather than
    contributing a (forgeable) verdict.
    """
    text = (stdout or "").strip()
    doc = None
    for candidate in (text, *reversed(text.splitlines())):
        candidate = candidate.strip()
        if not candidate.startswith("{"):
            continue
        try:
            doc = json.loads(candidate)
            break
        except (json.JSONDecodeError, ValueError):
            continue
    if not isinstance(doc, dict):
        return "no JSON document in probe output"
    if doc.get("sanwit_token") != token:
        return "probe output missing the execution token"
    def _as_map(value) -> dict:
        # Belt to JSON_FORCE_OBJECT: an empty PHP array would encode
        # as [] without the flag, and an authenticated all-errored
        # run must not be mislabeled unparseable.
        if isinstance(value, list) and not value:
            return {}
        return value if isinstance(value, dict) else {}

    outputs: dict[str, str] = {}
    errors: dict[str, str] = {
        str(k): str(v) for k, v in _as_map(doc.get("errors")).items()
    }
    truncated: dict[str, bool] = {
        str(k): bool(v) for k, v in _as_map(doc.get("truncated")).items()
    }
    raw_outputs = doc.get("outputs")
    if isinstance(raw_outputs, list) and not raw_outputs:
        raw_outputs = {}
    if not isinstance(raw_outputs, dict):
        return "probe output carries no outputs map"
    for pid, b64 in raw_outputs.items():
        try:
            outputs[str(pid)] = base64.b64decode(
                str(b64), validate=True,
            ).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            errors[str(pid)] = "output failed base64 decoding"
    return ProbeRun(
        php_version=str(doc.get("php_version") or ""),
        outputs=outputs,
        errors=errors,
        truncated=truncated,
    )
