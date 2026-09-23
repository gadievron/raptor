"""Mechanical verification oracle for /web heuristic findings.

The fuzzer's ``_analyze_response`` heuristics classify a single
response. This layer upgrades (or refutes) those hits with evidence a
regex on one response cannot provide:

* **Replay** — the confirming observation must reproduce on an
  immediate second request. A hit that vanishes on replay stays a
  heuristic finding (``inconclusive``), never a verified one.
* **Control differential** (sqli / command_injection /
  path_traversal) — a benign unique-token value for the same
  parameter must NOT produce the class marker. A page that shows the
  marker for benign input is page noise; the control legs are
  themselves replayed so one flaky response can't refute.
* **Canary attribution** (xss) — a fresh 16-hex token probe must
  reflect before payload reflection counts: a unique token cannot
  collide with page furniture, so its reflection is attributable to
  THIS probe. If the payload text already appears in the canary
  probe's response, the "reflection" was static page content.

All requests go through the scanner's existing :class:`WebClient`
(scope enforcement, rate limiting, redaction) — this layer adds no
new network paths. Request/transport errors degrade to
``inconclusive`` and are counted, never raised.

Verdicts (:class:`VerificationResult.status`):

* ``verified``   — replay reproduced and controls were clean.
* ``refuted``    — the control experiment showed the signal is page
                   noise (marker on both control legs, or payload
                   text present in the canary probe's response).
* ``inconclusive`` — flaky replay, mixed controls, or transport
                   errors. The finding keeps its heuristic tier.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.logging import get_logger
from packages.web.markers import marker_present

if TYPE_CHECKING:
    from packages.web.client import WebClient

logger = get_logger()

# Verdict vocabulary for VerificationResult.status.
VERIFIED = "verified"
REFUTED = "refuted"
INCONCLUSIVE = "inconclusive"

# Response excerpt cap for evidence records — enough to show the
# marker in context, small enough that records stay readable.
_EXCERPT_LEN = 400

# Marker-differential classes get 3 extra requests (payload replay,
# control, control replay); xss gets 2 (canary probe, payload replay).
_MARKER_CLASSES = frozenset({"sqli", "command_injection", "path_traversal", "ssti"})


def mint_canary() -> str:
    """A fresh benign token that cannot collide with page content."""
    return f"raptorcanary{secrets.token_hex(8)}"


def _strip_query_params(url: str, names: dict[str, str]) -> str:
    """Remove ``names``' keys from ``url``'s query string.

    The recorded hit URL is the PRE-injection URL and commonly already
    carries the fuzzed parameter (``page.php?id=1``). ``requests``
    APPENDS ``params=`` to the existing query, so a replay/control leg
    would send ``?id=1&id=<probe>`` — and first-occurrence-wins
    frameworks (Werkzeug ``request.args.get``, servlet
    ``getParameter``, Go ``FormValue``) would never see the probed
    value, systematically demoting real query-vector hits to
    inconclusive. Detection-time fuzzing REPLACES via
    ``_url_with_param``; this is the replay-side twin.
    """
    parsed = urlparse(url)
    if not parsed.query:
        return url
    query = [
        (name, existing_value)
        for name, existing_value in parse_qsl(
            parsed.query, keep_blank_values=True,
        )
        if name not in names
    ]
    return urlunparse(parsed._replace(query=urlencode(query)))


@dataclass
class VerificationResult:
    """Outcome of one finding's mechanical verification."""

    status: str                       # verified / refuted / inconclusive
    evidence_type: str                # e.g. "sqli_error", "xss_reflection"
    requests_used: int = 0
    # Per-leg observations, bounded excerpts only — feeds the
    # WebEvidence.response_evidence record.
    observations: dict[str, Any] = field(default_factory=dict)
    # True when the control experiment positively refuted the signal —
    # a mere failed replay never sets it. The verified-outcomes
    # projection gates REFUTED on ``verification_status`` (set from
    # ``status``, which is "refuted" exactly when this flag is true);
    # this flag rides the evidence record as the explicit control-
    # experiment marker.
    refuted_by_control: bool = False
    reason: str = ""


_EVIDENCE_TYPES = {
    "sqli": "sqli_error",
    "xss": "xss_reflection",
    "command_injection": "cmdi_output",
    "path_traversal": "path_traversal",
    # ssti's bare marker (evaluated 7*7) is meaningless without the
    # control legs this oracle runs — which is exactly why it belongs
    # in the marker-differential scheme rather than a naive grep.
    "ssti": "ssti_evaluated",
}


class VerificationOracle:
    """Replays and controls heuristic hits through the scan client."""

    def __init__(self, client: WebClient) -> None:
        self.client = client
        self.requests_used = 0
        self.errors = 0

    # -- transport ---------------------------------------------------------

    def _probe(self, url: str, param: str, value: str, method: str,
               base_data: dict[str, str] | None = None) -> Any | None:
        """One rate-limited request via the scan client; None on error.

        ``base_data`` carries the sibling form fields the fuzzer sent
        at detection time (required fields, CSRF tokens, captured
        defaults); the probed value replaces (never duplicates) its
        own entry. Without them, a multi-field form's server-side
        validation rejects every replay/control leg before the probed
        value reaches a sink — demoting real hits to inconclusive.
        """
        try:
            self.requests_used += 1
            values = {**(base_data or {}), param: value}
            if method.upper() == "POST":
                return self.client.post(url, data=values)
            # Strip every probed key from the recorded URL's query so
            # the probe value is the ONLY occurrence (POST bodies
            # cannot duplicate into the query, so only GET needs it).
            return self.client.get(
                _strip_query_params(url, values), params=values,
            )
        except Exception:
            # Transport errors (offline target, timeout, scope refusal)
            # degrade the verification, never the scan. URL/credential
            # material is kept out of the log by not interpolating the
            # exception text.
            self.errors += 1
            logger.debug("verification probe failed", exc_info=True)
            return None

    @staticmethod
    def _excerpt(text: str) -> str:
        return text[:_EXCERPT_LEN]

    # -- per-class verification --------------------------------------------

    def verify(self, url: str, param: str, payload: str, vuln_type: str,
               method: str = "GET",
               base_data: dict[str, str] | None = None) -> VerificationResult:
        """Verify one heuristic finding. Never raises."""
        evidence_type = _EVIDENCE_TYPES.get(vuln_type, vuln_type)
        if vuln_type == "xss":
            return self._verify_reflection(url, param, payload, method,
                                           evidence_type,
                                           base_data=base_data)
        if vuln_type in _MARKER_CLASSES:
            return self._verify_marker_differential(url, param, payload,
                                                    vuln_type, method,
                                                    evidence_type,
                                                    base_data=base_data)
        return VerificationResult(
            status=INCONCLUSIVE,
            evidence_type=evidence_type,
            reason=f"no verification scheme for {vuln_type}",
        )

    def _verify_reflection(self, url: str, param: str, payload: str,
                           method: str, evidence_type: str,
                           base_data: dict[str, str] | None = None,
                           ) -> VerificationResult:
        start = self.requests_used
        canary = mint_canary()
        obs: dict[str, Any] = {"canary": canary}

        canary_resp = self._probe(url, param, canary, method, base_data)
        if canary_resp is None:
            return VerificationResult(
                status=INCONCLUSIVE, evidence_type=evidence_type,
                requests_used=self.requests_used - start,
                observations=obs, reason="canary probe failed",
            )
        canary_reflects = canary in canary_resp.text
        payload_is_furniture = payload in canary_resp.text
        obs["canary_reflected"] = canary_reflects
        obs["payload_in_canary_response"] = payload_is_furniture

        if payload_is_furniture:
            # The payload text renders on a response we did NOT send it
            # to — the original "reflection" was static page content.
            return VerificationResult(
                status=REFUTED, evidence_type=evidence_type,
                requests_used=self.requests_used - start,
                observations=obs, refuted_by_control=True,
                reason="payload text is static page content",
            )

        replay_resp = self._probe(url, param, payload, method, base_data)
        if replay_resp is None:
            return VerificationResult(
                status=INCONCLUSIVE, evidence_type=evidence_type,
                requests_used=self.requests_used - start,
                observations=obs, reason="payload replay failed",
            )
        replay_reflects = payload in replay_resp.text
        obs["payload_reflected_on_replay"] = replay_reflects
        obs["replay_status_code"] = replay_resp.status_code
        obs["replay_excerpt"] = self._excerpt(replay_resp.text)

        if canary_reflects and replay_reflects:
            return VerificationResult(
                status=VERIFIED, evidence_type=evidence_type,
                requests_used=self.requests_used - start,
                observations=obs,
                reason="canary attributable and payload reproduced",
            )
        return VerificationResult(
            status=INCONCLUSIVE, evidence_type=evidence_type,
            requests_used=self.requests_used - start, observations=obs,
            reason="reflection did not reproduce"
            if not replay_reflects else "parameter does not reflect canary",
        )

    def _verify_marker_differential(self, url: str, param: str, payload: str,
                                    vuln_type: str, method: str,
                                    evidence_type: str,
                                    base_data: dict[str, str] | None = None,
                                    ) -> VerificationResult:
        start = self.requests_used
        obs: dict[str, Any] = {}

        replay_resp = self._probe(url, param, payload, method, base_data)
        if replay_resp is None:
            return VerificationResult(
                status=INCONCLUSIVE, evidence_type=evidence_type,
                requests_used=self.requests_used - start,
                observations=obs, reason="payload replay failed",
            )
        replay_marker = marker_present(vuln_type, replay_resp.text)
        obs["marker_on_replay"] = replay_marker
        obs["replay_status_code"] = replay_resp.status_code
        obs["replay_excerpt"] = self._excerpt(replay_resp.text)

        control = mint_canary()
        obs["control_value"] = control
        control_markers: list[bool] = []
        for leg in ("control", "control_replay"):
            resp = self._probe(url, param, control, method, base_data)
            if resp is None:
                return VerificationResult(
                    status=INCONCLUSIVE, evidence_type=evidence_type,
                    requests_used=self.requests_used - start,
                    observations=obs, reason=f"{leg} probe failed",
                )
            hit = marker_present(vuln_type, resp.text)
            control_markers.append(hit)
            obs[f"marker_on_{leg}"] = hit

        if all(control_markers):
            # Benign input shows the marker on two independent
            # responses — the marker is page noise, not injection.
            return VerificationResult(
                status=REFUTED, evidence_type=evidence_type,
                requests_used=self.requests_used - start,
                observations=obs, refuted_by_control=True,
                reason="class marker present for benign control input",
            )
        if replay_marker and not any(control_markers):
            return VerificationResult(
                status=VERIFIED, evidence_type=evidence_type,
                requests_used=self.requests_used - start,
                observations=obs,
                reason="marker reproduced on replay, controls clean",
            )
        return VerificationResult(
            status=INCONCLUSIVE, evidence_type=evidence_type,
            requests_used=self.requests_used - start, observations=obs,
            reason="marker did not reproduce on replay"
            if not replay_marker else "control legs disagree",
        )
