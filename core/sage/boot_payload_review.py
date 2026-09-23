"""Variant-aware compare/merge/deny for the SAGE boot-payload stamp.

Operator-review companion to the enforcement shim
(``libexec/raptor-sage-mcp-guard``). The guard strips any live
instruction surface that does not match the operator-authorized record
and tells the operator to review — this module is the review: it diffs
every live surface against the recorded variants (mirroring the
guard's own comparison semantics, which it imports rather than
re-implements) and records the operator's decision:

- APPROVE merges the newly reviewed variants into the stamp as a
  union. Union, not replacement: the payload is server-state-dependent
  (Auto-Inception vs Auto-Connect variants), so a fresh capture can
  legitimately observe a variant set disjoint from an earlier one —
  replacing the stamp would flap authorization between states forever.
- REJECT records the variants in a denied section of the same stamp.
  A denied variant stays stripped by the guard (with a calm "working
  as configured" note instead of the alarm), and review/status stop
  flagging it as pending — a rejection is a decision, not a deferral.

Modes (driven by ``libexec/raptor-sage-setup``):
  compare  --authorized <stamp> --live <capture>   human diff report
  summary  --authorized <stamp> --live <capture>   one line per surface
  merge    --authorized <stamp> --live <capture>   approved v2 BODY on stdout
  deny     --authorized <stamp> --live <capture>   rejected v2 BODY on stdout

``merge`` authorizes the live variants that are PENDING — the ones the
compare screen showed as "Not Authorized". Previously rejected
variants stay rejected: the compare display labels them "Rejected by
operator — nothing pending" and the approve prompt scopes itself to
the pending set, so an approve of an unrelated new variant must never
silently re-authorize a decided-and-denied one (a hostile server could
otherwise launder a rejected payload back into the stamp by re-serving
it beside any innocuous variant the operator will approve). Reversing
a rejection is its own explicit operator act: re-authorize the full
payload with ``raptor-sage-setup install --reauthorize``, which
replaces the stamp (denied records included) with the fresh capture.
``deny`` rejects the live variants that are not authorized, leaving
authorized records untouched.

Exit codes: 0 = nothing pending operator review (every live surface is
authorized or operator-rejected), 4 = new unreviewed variant(s)
present, 3 = usage / unreadable input.

Caveats the operator should know:

- The capture probe self-identifies (``clientInfo.name:
  "raptor-sage-setup"``), so a server that distinguishes probe from
  real sessions can serve this review clean text. The guard on the
  REAL session remains the enforcement; this module only decides what
  that guard treats as authorized or rejected.
- Legacy v1 stamps record the inception surface as message text only.
  Merging upgrades the stamp to v2 whole-content records, so a
  variant that was previously v1-authorized may need one more review
  the next time the server serves it — that single re-review upgrades
  it to the stronger whole-content authorization.
- Stamps recorded before the ``tools.list`` surface existed carry no
  tools baseline: every live tool definition shows as pending on the
  first review after upgrading. Approving them IS the migration — the
  merged stamp gains the baseline and the guard starts enforcing
  tools/list (until then it forwards the list with an unverified
  notice).
"""

from __future__ import annotations

import argparse
import difflib
import functools
import hashlib
import importlib.machinery
import importlib.util
import json
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GUARD_PATH = _REPO_ROOT / "libexec" / "raptor-sage-mcp-guard"

SURFACE_INIT = "initialize.instructions"
SURFACE_INIT_JSON = "initialize.instructions.json"
SURFACE_INCEPTION = "sage_inception.message"
SURFACE_INCEPTION_CONTENT = "sage_inception.content"
SURFACE_TOOLS = "tools.list"
SURFACE_INIT_DENIED = "initialize.instructions.denied.json"
SURFACE_INCEPTION_DENIED = "sage_inception.content.denied"
SURFACE_TOOLS_DENIED = "tools.list.denied"

AUTHORIZED = "authorized"
DENIED = "denied"
NEW = "new"
# The tools surface has no authorized baseline AND the live capture
# returned no tool definitions to decide on: the guard is forwarding
# real sessions' tools/list with only a notice, and there is nothing
# an approve could merge. Counted as pending (exit 4) — reporting this
# state as "nothing pending" would let a probe-evading server keep the
# surface permanently unverified while review/status say clean.
UNBASELINED = "unbaselined"

# Cap on the live-capture read. The capture is SERVER-EMITTED text —
# the hostile party in this module's own threat model — and the
# review runs on an operator consent surface; an uncapped read
# buffered a multi-hundred-MB capture whole. Real boot payloads are
# a few KB; 8 MiB is generous headroom, and an over-budget capture
# refuses loudly (exit 3) rather than reviewing a truncated payload.
_MAX_CAPTURE_CHARS = 8 * 1024 * 1024

# Cap on the text fed to difflib per variant. SequenceMatcher is
# quadratic on diverse-codepoint content that defeats its autojunk
# (measured minutes for single-MB hostile variants), and the closest-
# variant selection plus the rendered diff both walk server-emitted
# text. Prefixes are compared instead; a truncation marker joins the
# rendered diff so the operator knows the tail was not reviewed here.
_MAX_DIFF_CHARS = 100_000


def _load_guard():
    """Import the enforcement shim as a module.

    The guard's parsing and variant semantics are the single source of
    truth for what an agent session will actually accept; importing
    them here keeps review verdicts and enforcement verdicts from ever
    drifting apart. Import-time side effects (trust-marker check,
    process_init) are the same ones every libexec caller already has.
    """
    spec = importlib.util.spec_from_file_location(
        "raptor_sage_mcp_guard", _GUARD_PATH,
        loader=importlib.machinery.SourceFileLoader(
            "raptor_sage_mcp_guard", str(_GUARD_PATH)),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@functools.lru_cache(maxsize=1)
def _load_sanitiser():
    """Import ``core.security.log_sanitisation`` by file location.

    Same standalone-invocation constraint as :func:`_load_guard`: this
    module runs as ``python3 core/sage/boot_payload_review.py`` with no
    repo root on ``sys.path``, so a package import is unavailable. The
    sanitiser module is stdlib-only, so a file-location load is safe.
    """
    path = _REPO_ROOT / "core" / "security" / "log_sanitisation.py"
    spec = importlib.util.spec_from_file_location("log_sanitisation", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@functools.lru_cache(maxsize=1)
def _load_preflight():
    """Import ``core.security.prompt_input_preflight`` by file location.

    Same standalone-invocation constraint as :func:`_load_sanitiser`
    (stdlib-only module, no repo root on ``sys.path``). Lends the
    detection program's injection-pattern corpus to the tools-digest
    red-flag scan instead of re-inventing detectors here.
    """
    path = _REPO_ROOT / "core" / "security" / "prompt_input_preflight.py"
    name = "raptor_prompt_input_preflight"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    # dataclasses resolves the defining module through sys.modules at
    # class-creation time; a file-location load that skips the
    # registration breaks that lookup.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _line(s: str) -> str:
    r"""Terminal-render one line of server-derived text: non-printables
    escaped to ``\xHH`` and per-line length bounded (explicit elision
    marker, never silent).

    The compare display is an operator AUTHORIZATION surface — the diff
    it prints is exactly what the operator approves or rejects, and the
    variant text comes from the SAGE server, the hostile party in the
    threat model this review exists for. Raw ESC/CSI/OSC or bidi
    controls embedded in a variant could re-render the diff (cursor
    moves overwriting hostile lines with forged clean ones, colour
    flips, reordered text) at exactly the moment display integrity IS
    the control, so every diff line is escaped before it reaches the
    TTY. The generous per-line cap keeps prose payloads fully visible
    while bounding a single-line terminal flood.
    """
    return _load_sanitiser().sanitise_for_terminal(s, max_len=2000)


def _nl_lines(text: str) -> list[str]:
    """Split section/stamp text on ``\\n`` ONLY — mirror of the
    guard's ``_stamp_lines``.

    Never ``str.splitlines()``: it also breaks on ``\\r`` ``\\v``
    ``\\f`` ``\\x1c``-``\\x1e`` U+0085 U+2028 U+2029, which a hostile
    server can embed RAW in payload text (jq emits U+2028/U+2029
    unescaped), opening a forged ``### <surface>`` section mid-line —
    a forged ``.denied`` section would make review count a hostile
    variant as already decided. Raw-``\\n`` scanning keeps embedded
    text inside the section body.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        # Mirror splitlines() on \n-terminated text: no phantom last line.
        lines.pop()
    return lines


def parse_sections(text: str) -> dict:
    """Parse ``### <surface>`` sections from a capture or stamp body.

    Accepts both a bare ``capture_boot_payload`` output and a full
    stamp file (header + ``# ---`` marker); the guard's own parser
    requires the marker, this one tolerates its absence so live
    captures don't need a fake header.

    Raises ``ValueError`` on a duplicate section header — mirroring
    the guard's hard rejection. The capture pipeline neutralises
    header-shaped lines inside embedded payload text and every writer
    emits each section once, so a duplicate only ever means section
    injection or corruption; a last-wins (or first-wins-silent) parse
    would let the injected copy steer what review authorizes.

    Line scanning is raw-``\\n`` only (``_nl_lines``) so a
    splitlines-class separator embedded in payload text can never open
    a section.
    """
    marker = "\n# ---\n"
    if marker in text:
        text = text.split(marker, 1)[1]
    surfaces: dict = {}
    current = None
    acc: list = []
    for line in _nl_lines(text):
        if line.startswith("### "):
            if current is not None:
                surfaces[current] = "\n".join(acc)
            current = line[4:].strip()
            if current in surfaces:
                raise ValueError(
                    f"duplicate section header {current!r} — refusing to "
                    "parse (possible section injection); re-capture with "
                    "bin/raptor sage-setup install"
                )
            acc = []
        elif current is not None:
            acc.append(line)
    if current is not None:
        surfaces[current] = "\n".join(acc)
    return surfaces


def _json_lines(section_body: str | None) -> list:
    """One JSON value per non-empty line; garbage lines are skipped
    (mirrors the guard's ``_variant_objects`` fail direction: never
    authorize on unparseable input; raw-``\\n`` scanning so an embedded
    U+2028-class separator cannot split a variant line)."""
    out = []
    for line in _nl_lines(section_body or ""):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _inception_message(content) -> str:
    """The guard's legacy v1 extraction: ``message`` key of the JSON
    in ``content[0].text``."""
    if not (isinstance(content, list) and content
            and isinstance(content[0], dict)):
        return ""
    text = content[0].get("text")
    if not isinstance(text, str):
        return ""
    try:
        payload = json.loads(text)
    except ValueError:
        return ""
    if isinstance(payload, dict):
        return str(payload.get("message") or "")
    return ""


def _init_variants(guard, surfaces: dict | None) -> list[str]:
    """Authorized initialize.instructions texts (v2 ``.json`` records,
    or the v1 single text as fallback).

    Empty/whitespace-only variants are dropped on both the stamp and
    the live side: an absent-or-empty ``instructions`` field delivers
    no instruction text, the guard neither verifies nor strips it, and
    review flagging it as "pending" would demand a decision about
    nothing (and merging ``""`` as an authorized variant would record
    a meaningless wildcard-shaped entry)."""
    v2 = [
        v for v in guard._variant_objects(surfaces, SURFACE_INIT_JSON)
        if isinstance(v, str) and v.strip()
    ]
    if v2:
        return v2
    v1 = (surfaces or {}).get(SURFACE_INIT)
    return [v1] if v1 is not None and v1.strip() else []


def _init_denied(guard, surfaces: dict | None) -> list[str]:
    return [
        v for v in guard._variant_objects(surfaces, SURFACE_INIT_DENIED)
        if isinstance(v, str)
    ]


def compare(guard, auth: dict | None, live: dict) -> dict:
    """Classify every live variant of both surfaces.

    Returns ``{surface: [(variant, status), ...]}`` where ``status``
    is AUTHORIZED / DENIED / NEW and ``variant`` is the instruction
    text (init) or the content object (inception). The authorization
    rule for each surface is exactly the guard's: strip-equality
    against any recorded text variant for init; object equality
    against any recorded content variant for inception, with the
    guard's v1 message fallback (empty stamped message never
    authorizes). DENIED marks operator-rejected variants — decided,
    not pending.
    """
    report: dict = {}

    auth_init = _init_variants(guard, auth)
    denied_init = _init_denied(guard, auth)
    rows: list[tuple] = []
    for v in _init_variants(guard, live):
        if any(v.strip() == a.strip() for a in auth_init):
            rows.append((v, AUTHORIZED))
        elif any(v.strip() == d.strip() for d in denied_init):
            rows.append((v, DENIED))
        else:
            rows.append((v, NEW))
    report[SURFACE_INIT] = rows

    auth_content = list(
        guard._variant_objects(auth, SURFACE_INCEPTION_CONTENT))
    denied_content = list(
        guard._variant_objects(auth, SURFACE_INCEPTION_DENIED))
    auth_msg = (auth or {}).get(SURFACE_INCEPTION) or ""
    rows = []
    for v in _json_lines((live or {}).get(SURFACE_INCEPTION_CONTENT)):
        if auth_content:
            ok = any(v == a for a in auth_content)
        else:
            msg = _inception_message(v)
            ok = bool(auth_msg.strip()) and msg.strip() == auth_msg.strip()
        if ok:
            rows.append((v, AUTHORIZED))
        elif any(v == d for d in denied_content):
            rows.append((v, DENIED))
        else:
            rows.append((v, NEW))
    report[SURFACE_INCEPTION_CONTENT] = rows

    # tools/list baseline: one whole tool object per variant, matched
    # by object equality — exactly the guard's _check_tools_list rule
    # (dict variants only; a non-dict live entry can never authorize,
    # mirroring the guard's dropped-outright lane, so it stays NEW).
    auth_tools = [
        v for v in guard._variant_objects(auth, SURFACE_TOOLS)
        if isinstance(v, dict)
    ]
    denied_tools = [
        v for v in guard._variant_objects(auth, SURFACE_TOOLS_DENIED)
        if isinstance(v, dict)
    ]
    rows = []
    for v in _json_lines((live or {}).get(SURFACE_TOOLS)):
        if any(v == a for a in auth_tools):
            rows.append((v, AUTHORIZED))
        elif any(v == d for d in denied_tools):
            rows.append((v, DENIED))
        else:
            rows.append((v, NEW))
    if not rows and not auth_tools:
        # See UNBASELINED: no baseline and no live capture to decide
        # on — never report this surface as clean.
        rows = [(None, UNBASELINED)]
    report[SURFACE_TOOLS] = rows
    return report


def _closest(text: str, candidates: list[str]) -> str:
    if not candidates:
        return ""
    # Prefix compare (_MAX_DIFF_CHARS): SequenceMatcher over full
    # server-emitted variants is the quadratic lever — the prefix is
    # plenty to pick the closest recorded variant for display.
    probe = text[:_MAX_DIFF_CHARS]
    return max(
        candidates,
        key=lambda c: difflib.SequenceMatcher(
            None, c[:_MAX_DIFF_CHARS], probe).ratio(),
    )


def _tool_name(v) -> str | None:
    """The live tool's self-declared name, or None for a nameless /
    non-object entry (which the guard can never authorize)."""
    if isinstance(v, dict):
        name = v.get("name")
        if isinstance(name, str) and name:
            return name
    return None


def _name_disp(v, idx: int) -> str:
    """Escaped, length-bounded display label for one live tool entry.

    The name is server-controlled text on an authorization display —
    same escaping rationale as :func:`_line`, with a tighter cap so a
    flooding name cannot bury the digest table."""
    name = _tool_name(v)
    if name is None:
        return f"#{idx} (unnamed/non-object entry)"
    return _load_sanitiser().sanitise_for_terminal(name, max_len=48)


def _schema_summary(v: dict) -> str:
    """Byte-size + short hash of the tool's inputSchema.

    The guard compares schemas mechanically (whole-object equality);
    they are not human-reviewable content, so the digest shows only
    enough to notice drift and to correlate with a drill-down — never
    the schema body itself."""
    if "inputSchema" not in v:
        return "no inputSchema"
    blob = json.dumps(v["inputSchema"], sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(blob).hexdigest()[:12]
    return f"schema {len(blob)} B sha256:{digest}"


# Description red-flag heuristics local to this review surface —
# deliberately NOT added to the shared injection_patterns corpus:
# URLs and base64-shaped blobs are legitimate in most preflight
# consumers' inputs (scanned source code, findings, commit text), and
# agent-directed run/approve imperatives would false-positive on
# RAPTOR's own reports. None of them belong in a SAGE tool
# description, so HERE they are review leads. Advisory only: a hit is
# something to drill into, never a verdict.
_DESCRIPTION_FLAGS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("url", re.compile(r"(?:https?|ftps?|wss?)://\S+", re.IGNORECASE)),
    ("base64-blob", re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")),
    ("agent-imperative", re.compile(
        r"(?:approve|authorize|baseline)[^\S\n]+(?:this|the|it)\b"
        r"|\brun[^\S\n]+(?:this|the)[^\S\n]+(?:command|tool|script)"
        r"|without[^\S\n]+(?:asking|review|confirmation|telling)"
        r"|do[^\S\n]+not[^\S\n]+(?:tell|inform|ask|mention)",
        re.IGNORECASE)),
)

_EXCERPT_CONTEXT = 24


def _description_red_flags(desc: str) -> list[tuple[str, str]]:
    """(label, raw excerpt) red-flag hits for one tool description.

    Reuses the framework's existing detection surfaces: the
    injection-pattern corpus (``core/security/prompt_input_preflight``)
    and the non-printable classifier
    (``core/security/log_sanitisation``), plus the review-local
    heuristics above. Raises on scanner malfunction (including an
    empty pattern corpus) — the CALLER renders that as "scan
    unavailable", so a broken scanner can never present as a clean
    result. Excerpts are raw; display goes through :func:`_line`.
    """
    hits: list[tuple[str, str]] = []
    san = _load_sanitiser()
    if san.has_nonprintable(desc):
        first = next(
            i for i, c in enumerate(desc) if not c.isprintable())
        lo = max(0, first - _EXCERPT_CONTEXT)
        hi = min(len(desc), first + _EXCERPT_CONTEXT)
        hits.append(("control/invisible-chars", desc[lo:hi]))
    preflight = _load_preflight()
    if not preflight.loaded_corpora():
        raise RuntimeError("injection-pattern corpus failed to load")
    hits.extend(
        (f"injection-pattern:{stem}", excerpt)
        for stem, excerpt in preflight.preflight_excerpts(
            desc, context=_EXCERPT_CONTEXT)
    )
    for label, pattern in _DESCRIPTION_FLAGS:
        match = pattern.search(desc)
        if match:
            lo = max(0, match.start() - _EXCERPT_CONTEXT)
            hi = min(len(desc), match.end() + _EXCERPT_CONTEXT)
            hits.append((label, desc[lo:hi]))
    return hits


def _print_red_flag_scan(entries: list[tuple[int, dict]]) -> None:
    """Description red-flag section for the digest.

    Fail direction is LOUD toward showing more: any scanner error
    renders as "scan unavailable — drill down manually", never as a
    silently clean section (a broken scanner presenting as green would
    weaken the one aggregate consent signal bulk mode offers).
    """
    print("  Description red-flag scan (injection-pattern corpus + review")
    print("  heuristics — a hit is a lead to drill into; a clean result is")
    print("  NOT proof of safety):")
    try:
        flagged = 0
        for idx, v in entries:
            desc = v.get("description") if isinstance(v, dict) else None
            if isinstance(v, dict) and not isinstance(desc, str):
                flagged += 1
                kind = ("missing" if "description" not in v
                        else "non-string")
                print(f"    {_name_disp(v, idx)}: [malformed-description] "
                      f"{kind} — drill down before deciding")
                continue
            if not isinstance(v, dict):
                flagged += 1
                print(f"    {_name_disp(v, idx)}: [non-object-entry] "
                      f"cannot be authorized; drill down (`d #{idx}`)")
                continue
            for label, excerpt in _description_red_flags(desc):
                flagged += 1
                print(f"    {_name_disp(v, idx)}: [{_line(label)}] "
                      f'"{_line(excerpt)}"')
        if not flagged:
            print("    no red flags in any description")
    except Exception as exc:  # loud, never silently green
        print(f"    ⚠ scan unavailable ({type(exc).__name__}: "
              f"{_line(str(exc))}) — treat every description as")
        print("    unreviewed and drill down on each tool before approving")


def _print_tools_digest(rows: list, *, decision_hint: str) -> None:
    """First-baseline bulk lane: ONE digest screen for the whole live
    tool surface instead of one full-JSON wall per tool.

    There is no recorded variant to diff against on a first capture —
    a per-item "diff against closest recorded variant" degenerates
    into N walls of pure additions, which nobody can meaningfully
    review item by item (serial consent theater). The digest gives the
    operator aggregate evidence that IS reviewable: the full sorted
    name list, per-tool description length, schema size+hash (schema
    mechanics are guard-compared, not human-readable — never printed
    in bulk), and a red-flag scan over ALL description text (the
    descriptions are the instruction/injection surface). Full
    definitions stay one drill-down away; the approve/reject act is a
    single decision over the digest.
    """
    pending = [(i, v) for i, (v, s) in enumerate(rows, 1) if s == NEW]
    denied = sum(1 for _, s in rows if s == DENIED)
    print(f"  {len(pending)} live tool definition(s): ⚠ Not Authorized — "
          "no operator tools")
    print("  baseline exists yet (first capture). Approving baselines the "
          "CURRENT live")
    print("  surface: trust-on-first-use, with this digest as the evidence "
          "reviewed.")
    if denied:
        print(f"  {denied} further live definition(s): ✗ Rejected by "
              "operator — the guard")
        print("  strips them; nothing pending for those.")
    if not pending:
        return
    print()
    ordered = sorted(
        pending,
        key=lambda iv: (_tool_name(iv[1]) is None,
                        _tool_name(iv[1]) or "", iv[0]),
    )
    labels = [_name_disp(v, i) for i, v in ordered]
    width = max(len(lbl) for lbl in labels)
    for lbl, (idx, v) in zip(labels, ordered):
        # The capture position drives `d #<n>` drill-down — the only
        # reliable handle when a hostile name is elided or duplicated.
        pos = f"#{idx}"
        if isinstance(v, dict):
            desc = v.get("description")
            if isinstance(desc, str):
                desc_part = f"descr {len(desc)} ch"
            else:
                desc_part = ("no description" if "description" not in v
                             else "malformed description")
            schema_part = _schema_summary(v)
        else:
            desc_part = "non-object entry"
            schema_part = "cannot be authorized"
        print(f"    {pos:<4} {lbl:<{width}}  {desc_part:<16}  "
              f"{schema_part}")
    print()
    _print_red_flag_scan(ordered)
    print()
    print("  Full definition drill-down: " + decision_hint)


# Drill-down hints: the interactive review/install prompts accept
# `d <name>` / `d #<n>`; a non-interactive run has no prompt, so its
# hint routes the operator to the review at their own terminal
# instead of describing a prompt that is not there.
_HINT_PROMPT = ("enter `d <tool-name>` (or `d #<n>`) at the\n"
                "  prompt below to see one full definition before "
                "deciding.")
_HINT_STANDALONE = ("run libexec/raptor-sage-setup review at your\n"
                    "  own terminal, then `d <tool-name>` (or `d #<n>`) "
                    "at its prompt.")


def _drilldown_hint() -> str:
    """Prompt-shaped hint only when a prompt can actually follow —
    stdin is the same fd the caller's prompt would read."""
    return _HINT_PROMPT if sys.stdin.isatty() else _HINT_STANDALONE


def show_tool(live: dict, name: str) -> int:
    """Print the full (escaped) definition of one live tool.

    Matches by declared tool name or by ``#<n>`` digest position. ALL
    matches print — a hostile duplicate name cannot hide one variant
    behind another during drill-down. Unknown name is a loud error
    (exit 3), never an empty success.
    """
    tools = _json_lines((live or {}).get(SURFACE_TOOLS))
    matches = [
        (i, v) for i, v in enumerate(tools, 1)
        if _tool_name(v) == name or name == f"#{i}"
    ]
    if not matches:
        print("show-tool: no live tool definition named "
              f"{_line(name)!r}", file=sys.stderr)
        return 3
    for n, (i, v) in enumerate(matches):
        if n:
            print()
        label = f"live tool #{i}"
        bar = "─" * max(4, 58 - len(label))
        print(f"── {label} {bar}")
        for line in json.dumps(v, indent=2).splitlines():
            print(f"  {_line(line)}")
    return 0


def _print_compare(guard, auth: dict | None, report: dict) -> None:
    auth_init = _init_variants(guard, auth)
    for n, (surface, rows) in enumerate(report.items()):
        if n:
            print()
        bar = "─" * max(4, 58 - len(surface))
        print(f"── {surface} {bar}")
        if not rows:
            print("  no live variant captured")
            continue
        if (surface == SURFACE_TOOLS
                and not any(s == UNBASELINED for _, s in rows)
                and not [
                    v for v in guard._variant_objects(auth, SURFACE_TOOLS)
                    if isinstance(v, dict)
                ]):
            # First-baseline bulk lane: no authorized tools baseline
            # exists, so every live definition is a first capture —
            # render ONE digest, not a full-JSON wall per tool. The
            # drift lane (baseline exists) keeps the per-item diff
            # below, where a diff against a recorded variant is real
            # evidence. The boot surfaces are untouched either way.
            _print_tools_digest(rows, decision_hint=_drilldown_hint())
            continue
        for i, (variant, status) in enumerate(rows):
            if i:
                print()
            label = f"variant {i + 1}/{len(rows)}"
            if status == AUTHORIZED:
                print(f"  {label}: ✓ Authorized")
                continue
            if status == DENIED:
                print(f"  {label}: ✗ Rejected by operator — the guard "
                      "strips it; nothing pending")
                continue
            if status == UNBASELINED:
                print("  ⚠ Unbaselined: no operator-authorized tools "
                      "baseline exists and the live capture returned "
                      "no tool definitions. The guard forwards real "
                      "sessions' tools/list with only an unverified "
                      "notice. Investigate why the capture saw no "
                      "tools, then re-run review to approve a baseline.")
                continue
            print(f"  {label}: ⚠ Not Authorized — diff against closest "
                  "recorded variant:")
            print()
            if surface == SURFACE_INIT:
                live_txt, auth_txt = variant, _closest(variant, auth_init)
            else:
                json_surface = (SURFACE_TOOLS if surface == SURFACE_TOOLS
                                else SURFACE_INCEPTION_CONTENT)
                live_txt = json.dumps(variant, indent=2)
                recorded = [
                    json.dumps(v, indent=2) for v in
                    guard._variant_objects(auth, json_surface)
                ]
                auth_txt = _closest(live_txt, recorded)
            truncated = (len(live_txt) > _MAX_DIFF_CHARS
                         or len(auth_txt) > _MAX_DIFF_CHARS)
            diff = difflib.unified_diff(
                auth_txt[:_MAX_DIFF_CHARS].splitlines(),
                live_txt[:_MAX_DIFF_CHARS].splitlines(),
                "authorized", "live", lineterm="",
            )
            for line in diff:
                print(f"    {_line(line)}")
            if truncated:
                print(f"    [diff truncated at {_MAX_DIFF_CHARS} "
                      "characters — oversized variant; the full text "
                      "was NOT reviewed here]")


def _print_summary(report: dict) -> None:
    for surface, rows in report.items():
        if not rows:
            print(f"  {surface}: no live variant captured")
            continue
        new = sum(1 for _, s in rows if s == NEW)
        denied = sum(1 for _, s in rows if s == DENIED)
        unbaselined = any(s == UNBASELINED for _, s in rows)
        parts = []
        if new:
            parts.append(f"{new} not authorized (pending review)")
        if denied:
            parts.append(f"{denied} rejected by operator")
        if unbaselined:
            parts.append("UNBASELINED — no authorized baseline and no "
                         "live capture; the guard forwards this surface "
                         "with an unverified notice")
        if not parts:
            parts.append(f"{len(rows)} live variant(s) authorized")
        print(f"  {surface}: " + ", ".join(parts))


def _neutralize_headers(text: str) -> str:
    """Quote-prefix header-shaped lines in embedded payload text —
    same neutralisation ``capture_boot_payload`` applies at capture
    time, kept here so a merge/deny rewrite can never reintroduce a
    parseable ``### `` line from older (pre-neutralisation) text.

    splitlines() here is DELIBERATE (unlike the parsers): it flattens
    the splitlines-class separators (\\r \\v \\f U+2028 ...) in legacy
    text into ``\\n`` while quoting any header-shaped line they hid,
    so the re-rendered stamp is inert under both old (splitlines) and
    new (raw-``\\n``) parsers."""
    return "\n".join(
        ("> " + line) if line.startswith("### ") else line
        for line in text.splitlines()
    )


def _render_body(init_text: str, msg_text: str,
                 init_variants: list, content_variants: list,
                 tools_variants: list,
                 init_denied: list, content_denied: list,
                 tools_denied: list) -> str:
    init_text = _neutralize_headers(init_text)
    msg_text = _neutralize_headers(msg_text)
    lines = [f"### {SURFACE_INIT}", init_text, f"### {SURFACE_INIT_JSON}"]
    lines += [json.dumps(v) for v in init_variants]
    lines += [f"### {SURFACE_INCEPTION}", msg_text,
              f"### {SURFACE_INCEPTION_CONTENT}"]
    lines += [json.dumps(v) for v in content_variants]
    # Emitted only when populated (like the denied sections below): an
    # absent tools.list section means "no tools baseline" to the guard
    # — the honest state, never an empty section that looks recorded.
    if tools_variants:
        lines.append(f"### {SURFACE_TOOLS}")
        lines += [json.dumps(v) for v in tools_variants]
    if init_denied:
        lines.append(f"### {SURFACE_INIT_DENIED}")
        lines += [json.dumps(v) for v in init_denied]
    if content_denied:
        lines.append(f"### {SURFACE_INCEPTION_DENIED}")
        lines += [json.dumps(v) for v in content_denied]
    if tools_denied:
        lines.append(f"### {SURFACE_TOOLS_DENIED}")
        lines += [json.dumps(v) for v in tools_denied]
    return "\n".join(lines) + "\n"


def _stamp_parts(guard, auth: dict | None, live: dict):
    """Shared decomposition for merge/deny."""
    auth_init = _init_variants(guard, auth)
    live_init = _init_variants(guard, live)
    denied_init = _init_denied(guard, auth)
    auth_content = list(
        guard._variant_objects(auth, SURFACE_INCEPTION_CONTENT))
    live_content = _json_lines((live or {}).get(SURFACE_INCEPTION_CONTENT))
    denied_content = list(
        guard._variant_objects(auth, SURFACE_INCEPTION_DENIED))
    # dict-only on the recorded side, mirroring the guard (a non-dict
    # record can never authorize a live tool).
    auth_tools = [
        v for v in guard._variant_objects(auth, SURFACE_TOOLS)
        if isinstance(v, dict)
    ]
    live_tools = _json_lines((live or {}).get(SURFACE_TOOLS))
    denied_tools = [
        v for v in guard._variant_objects(auth, SURFACE_TOOLS_DENIED)
        if isinstance(v, dict)
    ]
    init_text = (auth or {}).get(SURFACE_INIT)
    if init_text is None:
        init_text = live_init[0] if live_init else ""
    msg_text = (auth or {}).get(SURFACE_INCEPTION)
    if msg_text is None:
        msg_text = (live or {}).get(SURFACE_INCEPTION) or ""
    return (auth_init, live_init, denied_init,
            auth_content, live_content, denied_content,
            auth_tools, live_tools, denied_tools,
            init_text, msg_text)


def merge(guard, auth: dict | None, live: dict) -> str:
    """Approve: union the PENDING live variants into the authorized
    records.

    Previously authorized variants are always kept; live variants are
    appended when unseen. Previously REJECTED variants stay rejected —
    they are neither authorized nor removed from the denied records.
    The consent surface (compare display + approve prompt) presents
    rejected-but-live variants as decided ("Rejected by operator —
    nothing pending") and scopes the question to the variants marked
    "Not Authorized"; an approve that also un-rejected would let a
    hostile server launder a denied payload back into the stamp by
    re-serving it beside any innocuous new variant the operator
    approves. Un-rejecting is an explicit operator act via
    ``raptor-sage-setup install --reauthorize`` (full-payload
    re-authorization; replaces the stamp, denied records included).
    A v1 stamp is upgraded: its single init text becomes the first
    ``.json`` variant, and its message section is carried through for
    readability (the guard ignores it once ``.content`` records
    exist — see module docstring).
    """
    (auth_init, live_init, denied_init,
     auth_content, live_content, denied_content,
     auth_tools, live_tools, denied_tools,
     init_text, msg_text) = _stamp_parts(guard, auth, live)

    init_variants = list(auth_init)
    for v in live_init:
        if any(v.strip() == d.strip() for d in denied_init):
            continue  # rejected stays rejected — decided, not pending
        if not any(v.strip() == a.strip() for a in init_variants):
            init_variants.append(v)

    content_variants = list(auth_content)
    for v in live_content:
        if any(v == d for d in denied_content):
            continue  # rejected stays rejected — decided, not pending
        if not any(v == a for a in content_variants):
            content_variants.append(v)

    tools_variants = list(auth_tools)
    for v in live_tools:
        if any(v == d for d in denied_tools):
            continue  # rejected stays rejected — decided, not pending
        if not any(v == a for a in tools_variants):
            tools_variants.append(v)

    return _render_body(init_text, msg_text, init_variants,
                        content_variants, tools_variants,
                        denied_init, denied_content, denied_tools)


def deny(guard, auth: dict | None, live: dict) -> str:
    """Reject: record the unauthorized live variants as denied.

    Authorized records are untouched; the guard keeps stripping the
    denied variants (with a calm note instead of the alarm) and
    compare/summary stop counting them as pending review.
    """
    (auth_init, live_init, denied_init,
     auth_content, live_content, denied_content,
     auth_tools, live_tools, denied_tools,
     init_text, msg_text) = _stamp_parts(guard, auth, live)
    auth_msg = (auth or {}).get(SURFACE_INCEPTION) or ""

    new_denied_init = list(denied_init)
    for v in live_init:
        if any(v.strip() == a.strip() for a in auth_init):
            continue
        if not any(v.strip() == d.strip() for d in new_denied_init):
            new_denied_init.append(v)

    new_denied_content = list(denied_content)
    for v in live_content:
        if auth_content:
            if any(v == a for a in auth_content):
                continue
        elif (auth_msg.strip()
                and _inception_message(v).strip() == auth_msg.strip()):
            continue
        if not any(v == d for d in new_denied_content):
            new_denied_content.append(v)

    new_denied_tools = list(denied_tools)
    for v in live_tools:
        if any(v == a for a in auth_tools):
            continue
        if not any(v == d for d in new_denied_tools):
            new_denied_tools.append(v)

    return _render_body(init_text, msg_text, auth_init, auth_content,
                        auth_tools, new_denied_init, new_denied_content,
                        new_denied_tools)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="boot_payload_review")
    parser.add_argument("mode",
                        choices=("compare", "summary", "merge", "deny",
                                 "show-tool"))
    # Required for the stamp-comparing modes only: show-tool renders
    # one LIVE definition (a drill-down, no comparison), so demanding
    # a stamp path there would be a lie about what it reads.
    parser.add_argument("--authorized")
    parser.add_argument("--live", required=True)
    parser.add_argument("--name",
                        help="tool name (or #<n>) for show-tool")
    args = parser.parse_args(argv)
    if args.mode != "show-tool" and not args.authorized:
        parser.error(f"--authorized is required for {args.mode}")
    if args.mode == "show-tool" and not args.name:
        parser.error("show-tool requires --name")

    try:
        # newline="" — no universal-newline translation (a raw \r in
        # the capture must not become a line break before the \n-only
        # section scanner runs; see _nl_lines).
        with open(args.live, encoding="utf-8", newline="") as fh:
            raw = fh.read(_MAX_CAPTURE_CHARS + 1)
            if len(raw) > _MAX_CAPTURE_CHARS:
                # Server-emitted capture past any legitimate payload
                # size: refuse loudly rather than review a truncated
                # (or memory-detonating) capture.
                print(
                    "boot_payload_review: live capture exceeds "
                    f"{_MAX_CAPTURE_CHARS} characters — refusing to "
                    "review it", file=sys.stderr)
                return 3
            live = parse_sections(raw)
    except OSError as exc:
        print(f"boot_payload_review: cannot read live capture: {exc}",
              file=sys.stderr)
        return 3
    except ValueError as exc:
        print(f"boot_payload_review: {exc}", file=sys.stderr)
        return 3
    if not live:
        print("boot_payload_review: live capture has no surfaces",
              file=sys.stderr)
        return 3

    if args.mode == "show-tool":
        return show_tool(live, args.name)

    # The comparing modes import the guard (its semantics are the
    # single source of truth); the drill-down above stays guard-free —
    # it renders live text only, and the guard's import-time trust
    # gate must not block a pure display helper.
    guard = _load_guard()
    auth = guard._parse_authorized(args.authorized)

    if args.mode == "merge":
        sys.stdout.write(merge(guard, auth, live))
        return 0
    if args.mode == "deny":
        sys.stdout.write(deny(guard, auth, live))
        return 0

    report = compare(guard, auth, live)
    if args.mode == "compare":
        _print_compare(guard, auth, report)
    else:
        _print_summary(report)
    pending = any(
        s in (NEW, UNBASELINED)
        for rows in report.values() for _, s in rows
    )
    return 4 if pending else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
