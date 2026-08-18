#!/usr/bin/env python3
"""PreToolUse hook: enforce a per-agent WebFetch domain allowlist.

Wired via the ``hooks:`` frontmatter of individual agent definitions
(.claude/agents/*.md) so the restriction is scoped to one agent, not
the whole session. The harness's declarative ``WebFetch(domain:...)``
permission rules are settings-scope (session-wide) only; per-agent
``PreToolUse`` hooks are the documented mechanism for per-agent tool
narrowing.

Usage (in agent frontmatter):

    hooks:
      PreToolUse:
        - matcher: WebFetch
          hooks:
            - type: command
              command: "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/webfetch-domain-allowlist.py github.com api.github.com"

Arguments are the allowed hostnames (case-insensitive exact match).
With ``--https-any`` instead of a hostname list, any host is allowed
but the scheme must be https (used by agents that fetch
operator-supplied URLs on arbitrary vendor domains).

With ``--anchor-file <path>`` the allowlist is derived at run time
from an operator-provenance anchor file the dispatching orchestrator
writes BEFORE the agent sees any fetched content:

  - line 1 (first non-empty, non-``#`` line): the operator-supplied
    URL (or bare hostname) — the anchor;
  - later lines: extra allowed hostnames (exact match), one per line
    — operator-visible additions for attachment hosts outside the
    anchor's domain.

A fetch is allowed when its host shares the anchor's registrable
domain (eTLD+1, conservative built-in heuristic — not a full public
suffix list) or exactly matches an extra-host line. Every decision is
appended to ``<path>.log`` (timestamp, verdict, host, URL) so hosts
the fetched page pulled in — attachment CDNs and the like — are
operator-auditable. Scheme must be https in every mode.

Contract (Claude Code PreToolUse hooks):
  stdin  — JSON with ``tool_name`` and ``tool_input`` (``url`` key).
  exit 0 — allow the call.
  exit 2 — block the call; stderr is fed back to the agent.

Fail-closed: unparseable input, a missing/relative URL, an unknown
flag, or a missing/empty/non-https anchor file is blocked.
"""

import datetime
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

# Common multi-label public suffixes for the registrable-domain
# heuristic. Deliberately small: a miss here makes the check STRICTER
# (two sibling hosts under an unlisted suffix compare as different
# registrable domains and the fetch is denied), never looser.
_MULTI_LABEL_SUFFIXES = frozenset({
    "ac.jp", "ac.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.uk",
    "co.za", "com.ar", "com.au", "com.br", "com.cn", "com.mx",
    "com.tr", "go.jp", "gov.uk", "ne.jp", "net.au", "net.uk",
    "or.jp", "org.au", "org.uk",
})


def _registrable_domain(host: str) -> str:
    """eTLD+1 approximation for a lowercased hostname."""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _log_decision(anchor_file: str, verdict: str, host: str, url: str) -> None:
    """Best-effort audit trail next to the anchor file."""
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        with open(f"{anchor_file}.log", "a", encoding="utf-8") as fh:
            fh.write(f"{stamp}\t{verdict}\t{host}\t{url}\n")
    except OSError:
        # Logging never changes the verdict; an unwritable log
        # directory must not turn a deny into a crash or an allow
        # into a deny.
        pass


def _check_anchor(anchor_file: str, host: str, url: str) -> int:
    """Anchor-file mode decision for an https URL's ``host``."""
    try:
        lines = Path(anchor_file).read_text(encoding="utf-8").splitlines()
    except OSError:
        sys.stderr.write(
            f"webfetch-domain-allowlist: anchor file {anchor_file!r} is "
            "missing or unreadable; blocking the WebFetch call "
            "(fail-closed). The orchestrator must write the "
            "operator-supplied URL there before dispatching this agent.\n"
        )
        return 2

    entries = [ln.strip() for ln in lines
               if ln.strip() and not ln.strip().startswith("#")]
    if not entries:
        sys.stderr.write(
            f"webfetch-domain-allowlist: anchor file {anchor_file!r} has "
            "no anchor URL; blocking the WebFetch call (fail-closed).\n"
        )
        return 2

    anchor = entries[0]
    if "://" not in anchor:
        anchor = f"https://{anchor}"
    try:
        anchor_parts = urlsplit(anchor)
    except ValueError:
        anchor_parts = None
    anchor_host = ""
    if anchor_parts is not None and anchor_parts.scheme.lower() == "https":
        anchor_host = (anchor_parts.hostname or "").lower().rstrip(".")
    if not anchor_host:
        sys.stderr.write(
            f"webfetch-domain-allowlist: anchor file {anchor_file!r} does "
            "not start with a valid https URL; blocking the WebFetch "
            "call (fail-closed).\n"
        )
        return 2

    extra_hosts = {e.lower().rstrip(".") for e in entries[1:]}
    allowed = (
        host == anchor_host
        or host in extra_hosts
        or _registrable_domain(host) == _registrable_domain(anchor_host)
    )
    _log_decision(anchor_file, "allow" if allowed else "deny", host, url)
    if allowed:
        return 0

    sys.stderr.write(
        f"webfetch-domain-allowlist: host {host!r} is outside the "
        f"registrable domain of the operator-supplied URL "
        f"({_registrable_domain(anchor_host)!r}) and not an "
        "operator-listed extra host. The fetch was blocked and logged. "
        "If the bug report genuinely links an attachment on this host, "
        "report that to the orchestrator/operator instead of retrying.\n"
    )
    return 2


def main(argv: list[str]) -> int:
    https_any = False
    anchor_file = None
    allowed = set()
    it = iter(argv)
    for arg in it:
        if arg == "--https-any":
            https_any = True
        elif arg == "--anchor-file":
            anchor_file = next(it, None)
            if anchor_file is None:
                sys.stderr.write(
                    "webfetch-domain-allowlist: --anchor-file requires a "
                    "path; blocking the WebFetch call (fail-closed).\n"
                )
                return 2
        elif arg.startswith("--"):
            sys.stderr.write(
                f"webfetch-domain-allowlist: unknown flag {arg!r}; "
                "blocking the WebFetch call (fail-closed).\n"
            )
            return 2
        else:
            allowed.add(arg.lower())

    try:
        payload = json.load(sys.stdin)
    except ValueError:
        sys.stderr.write(
            "webfetch-domain-allowlist: unparseable hook input; "
            "blocking the WebFetch call (fail-closed).\n"
        )
        return 2

    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    url = tool_input.get("url") if isinstance(tool_input, dict) else None
    if not isinstance(url, str) or not url.strip():
        sys.stderr.write(
            "webfetch-domain-allowlist: no url in tool input; "
            "blocking the WebFetch call (fail-closed).\n"
        )
        return 2

    try:
        parts = urlsplit(url.strip())
    except ValueError:
        sys.stderr.write(
            f"webfetch-domain-allowlist: unparseable url {url!r}; "
            "blocking the WebFetch call (fail-closed).\n"
        )
        return 2

    if parts.scheme.lower() != "https":
        sys.stderr.write(
            f"webfetch-domain-allowlist: scheme {parts.scheme!r} denied — "
            "this agent may only fetch https:// URLs.\n"
        )
        return 2

    if https_any:
        return 0

    host = (parts.hostname or "").lower().rstrip(".")
    if host in allowed:
        return 0

    if anchor_file is not None:
        return _check_anchor(anchor_file, host, url.strip())

    sys.stderr.write(
        f"webfetch-domain-allowlist: host {host!r} is not in this agent's "
        f"allowlist ({', '.join(sorted(allowed))}). The fetch was blocked. "
        "If the investigation genuinely requires this host, report that to "
        "the orchestrator/operator instead of retrying.\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
