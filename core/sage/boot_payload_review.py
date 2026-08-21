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

``merge`` authorizes EVERY live variant, including previously rejected
ones (that is the un-reject path); ``deny`` rejects the live variants
that are not authorized, leaving authorized records untouched.

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
"""

from __future__ import annotations

import argparse
import difflib
import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GUARD_PATH = _REPO_ROOT / "libexec" / "raptor-sage-mcp-guard"

SURFACE_INIT = "initialize.instructions"
SURFACE_INIT_JSON = "initialize.instructions.json"
SURFACE_INCEPTION = "sage_inception.message"
SURFACE_INCEPTION_CONTENT = "sage_inception.content"
SURFACE_INIT_DENIED = "initialize.instructions.denied.json"
SURFACE_INCEPTION_DENIED = "sage_inception.content.denied"

AUTHORIZED = "authorized"
DENIED = "denied"
NEW = "new"


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


def parse_sections(text: str) -> dict:
    """Parse ``### <surface>`` sections from a capture or stamp body.

    Accepts both a bare ``capture_boot_payload`` output and a full
    stamp file (header + ``# ---`` marker); the guard's own parser
    requires the marker, this one tolerates its absence so live
    captures don't need a fake header.
    """
    marker = "\n# ---\n"
    if marker in text:
        text = text.split(marker, 1)[1]
    surfaces: dict = {}
    current = None
    acc: list = []
    for line in text.splitlines():
        if line.startswith("### "):
            if current is not None:
                surfaces[current] = "\n".join(acc)
            current = line[4:].strip()
            acc = []
        elif current is not None:
            acc.append(line)
    if current is not None:
        surfaces[current] = "\n".join(acc)
    return surfaces


def _json_lines(section_body: str | None) -> list:
    """One JSON value per non-empty line; garbage lines are skipped
    (mirrors the guard's ``_variant_objects`` fail direction: never
    authorize on unparseable input)."""
    out = []
    for line in (section_body or "").splitlines():
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
    or the v1 single text as fallback)."""
    v2 = [
        v for v in guard._variant_objects(surfaces, SURFACE_INIT_JSON)
        if isinstance(v, str)
    ]
    if v2:
        return v2
    v1 = (surfaces or {}).get(SURFACE_INIT)
    return [v1] if v1 is not None else []


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
    rows = []
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
    return report


def _closest(text: str, candidates: list[str]) -> str:
    if not candidates:
        return ""
    return max(
        candidates,
        key=lambda c: difflib.SequenceMatcher(None, c, text).ratio(),
    )


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
            print(f"  {label}: ⚠ Not Authorized — diff against closest "
                  "recorded variant:")
            print()
            if surface == SURFACE_INIT:
                live_txt, auth_txt = variant, _closest(variant, auth_init)
            else:
                live_txt = json.dumps(variant, indent=2)
                recorded = [
                    json.dumps(v, indent=2) for v in
                    guard._variant_objects(auth, SURFACE_INCEPTION_CONTENT)
                ]
                auth_txt = _closest(live_txt, recorded)
            diff = difflib.unified_diff(
                auth_txt.splitlines(), live_txt.splitlines(),
                "authorized", "live", lineterm="",
            )
            for line in diff:
                print(f"    {line}")


def _print_summary(report: dict) -> None:
    for surface, rows in report.items():
        if not rows:
            print(f"  {surface}: no live variant captured")
            continue
        new = sum(1 for _, s in rows if s == NEW)
        denied = sum(1 for _, s in rows if s == DENIED)
        parts = []
        if new:
            parts.append(f"{new} not authorized (pending review)")
        if denied:
            parts.append(f"{denied} rejected by operator")
        if not parts:
            parts.append(f"{len(rows)} live variant(s) authorized")
        print(f"  {surface}: " + ", ".join(parts))


def _render_body(init_text: str, msg_text: str,
                 init_variants: list, content_variants: list,
                 init_denied: list, content_denied: list) -> str:
    lines = [f"### {SURFACE_INIT}", init_text, f"### {SURFACE_INIT_JSON}"]
    lines += [json.dumps(v) for v in init_variants]
    lines += [f"### {SURFACE_INCEPTION}", msg_text,
              f"### {SURFACE_INCEPTION_CONTENT}"]
    lines += [json.dumps(v) for v in content_variants]
    if init_denied:
        lines.append(f"### {SURFACE_INIT_DENIED}")
        lines += [json.dumps(v) for v in init_denied]
    if content_denied:
        lines.append(f"### {SURFACE_INCEPTION_DENIED}")
        lines += [json.dumps(v) for v in content_denied]
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
    init_text = (auth or {}).get(SURFACE_INIT)
    if init_text is None:
        init_text = live_init[0] if live_init else ""
    msg_text = (auth or {}).get(SURFACE_INCEPTION)
    if msg_text is None:
        msg_text = (live or {}).get(SURFACE_INCEPTION) or ""
    return (auth_init, live_init, denied_init,
            auth_content, live_content, denied_content,
            init_text, msg_text)


def merge(guard, auth: dict | None, live: dict) -> str:
    """Approve: union EVERY live variant into the authorized records.

    Previously authorized variants are always kept; live variants are
    appended when unseen — including previously rejected ones (an
    explicit approve is the un-reject path), which are removed from
    the denied records. A v1 stamp is upgraded: its single init text
    becomes the first ``.json`` variant, and its message section is
    carried through for readability (the guard ignores it once
    ``.content`` records exist — see module docstring).
    """
    (auth_init, live_init, denied_init,
     auth_content, live_content, denied_content,
     init_text, msg_text) = _stamp_parts(guard, auth, live)

    init_variants = list(auth_init)
    for v in live_init:
        if not any(v.strip() == a.strip() for a in init_variants):
            init_variants.append(v)
    denied_init = [
        d for d in denied_init
        if not any(d.strip() == v.strip() for v in live_init)
    ]

    content_variants = list(auth_content)
    for v in live_content:
        if not any(v == a for a in content_variants):
            content_variants.append(v)
    denied_content = [d for d in denied_content if d not in live_content]

    return _render_body(init_text, msg_text, init_variants,
                        content_variants, denied_init, denied_content)


def deny(guard, auth: dict | None, live: dict) -> str:
    """Reject: record the unauthorized live variants as denied.

    Authorized records are untouched; the guard keeps stripping the
    denied variants (with a calm note instead of the alarm) and
    compare/summary stop counting them as pending review.
    """
    (auth_init, live_init, denied_init,
     auth_content, live_content, denied_content,
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

    return _render_body(init_text, msg_text, auth_init, auth_content,
                        new_denied_init, new_denied_content)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="boot_payload_review")
    parser.add_argument("mode",
                        choices=("compare", "summary", "merge", "deny"))
    parser.add_argument("--authorized", required=True)
    parser.add_argument("--live", required=True)
    args = parser.parse_args(argv)

    guard = _load_guard()
    auth = guard._parse_authorized(args.authorized)
    try:
        live = parse_sections(
            Path(args.live).read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"boot_payload_review: cannot read live capture: {exc}",
              file=sys.stderr)
        return 3
    if not live:
        print("boot_payload_review: live capture has no surfaces",
              file=sys.stderr)
        return 3

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
    pending = any(s == NEW for rows in report.values() for _, s in rows)
    return 4 if pending else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
