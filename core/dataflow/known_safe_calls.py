"""Curated table of known-safe library calls per sink class + language.

The Tier 1B trust surface.  Every entry is a human-verified soundness
claim: "calling this function with user-controlled input produces a
value that is safe for the named sink class."

Adding entries is a soundness-critical operation — each ``soundness_note``
documents WHY the call is safe (per library docs / known semantics) so
reviewers can sanity-check the claim.  Keep the table small and well-
justified; growth should be driven by concrete corpus cases.

Lookup contract:
  ``find(library_call: str, sink_class: str, language: str)`` returns
  the matching :class:`KnownSafeCall` entry or ``None``.  Matching is by
  full dotted name and language, both case-sensitive.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class KnownSafeCall:
    """One curated entry — a soundness claim for a single library call.

    ``library_call`` is the fully-qualified dotted name as it would appear
    in the source (after any standard ``from X import Y`` flattening:
    ``html.escape``, ``django.utils.html.escape``, etc).

    ``input_arg_kind`` distinguishes:

      * ``"transform"`` — the call takes user input and returns the
        sanitized value (e.g. ``html.escape(x)``).  The CHAIN must show
        the return value (or a name assigned from it) reaching the sink.
      * ``"validate"`` — the call validates user input and raises /
        returns sentinel on bad input (e.g. ``werkzeug.security.safe_join``
        raises ``NotFound`` on traversal).  Same chain requirement
        applies to the return value.

    Both kinds are treated identically for chain checking — the
    distinction is documented so reviewers can verify the semantic
    claim matches the library's actual behaviour.
    """
    library_call: str
    sink_class: str
    languages: Tuple[str, ...]
    input_arg_kind: str            # "transform" | "validate"
    soundness_note: str


_TABLE: Tuple[KnownSafeCall, ...] = (
    # ------------------------------------------------------------------
    # pathtrav — path-traversal safe joiners / validators
    # ------------------------------------------------------------------
    KnownSafeCall(
        library_call="werkzeug.security.safe_join",
        sink_class="pathtrav",
        languages=("python",),
        input_arg_kind="validate",
        soundness_note=(
            "werkzeug.security.safe_join (since werkzeug 0.5) raises "
            "NotFound if the joined path escapes the base directory or "
            "contains traversal sequences.  Return value, when not None, "
            "is provably inside the base directory."
        ),
    ),
    KnownSafeCall(
        library_call="werkzeug.utils.secure_filename",
        sink_class="pathtrav",
        languages=("python",),
        input_arg_kind="transform",
        soundness_note=(
            "werkzeug.utils.secure_filename strips path separators and "
            "control chars; the return value contains only "
            "[A-Za-z0-9._-] and never a path separator (verified vs "
            "werkzeug source)."
        ),
    ),
    # ------------------------------------------------------------------
    # xss — HTML-context escapers
    # ------------------------------------------------------------------
    KnownSafeCall(
        library_call="html.escape",
        sink_class="xss",
        languages=("python",),
        input_arg_kind="transform",
        soundness_note=(
            "stdlib html.escape converts &, <, >, and (with default "
            "quote=True) \", ' to HTML entities.  Output cannot break "
            "out of an HTML attribute or tag context."
        ),
    ),
    KnownSafeCall(
        library_call="django.utils.html.escape",
        sink_class="xss",
        languages=("python",),
        input_arg_kind="transform",
        soundness_note=(
            "Django's escape (wraps stdlib html.escape; same semantics) "
            "+ marks result as SafeString.  Output is HTML-safe."
        ),
    ),
    KnownSafeCall(
        library_call="markupsafe.escape",
        sink_class="xss",
        languages=("python",),
        input_arg_kind="transform",
        soundness_note=(
            "markupsafe.escape escapes &, <, >, \", ' and returns Markup "
            "(SafeString equivalent).  Standard XSS-safe escaper used "
            "across Jinja2 / Flask."
        ),
    ),
    KnownSafeCall(
        library_call="bleach.clean",
        sink_class="xss",
        languages=("python",),
        input_arg_kind="transform",
        soundness_note=(
            "bleach.clean sanitises HTML against an allowlist of tags "
            "and attributes.  Default allowlist is XSS-safe; custom "
            "allowlists are caller's responsibility (we only claim "
            "safety for the default call form, no args beyond the "
            "input string)."
        ),
    ),
    # ------------------------------------------------------------------
    # cmdi — shell-quoting / arg-list safe constructors
    # ------------------------------------------------------------------
    KnownSafeCall(
        library_call="shlex.quote",
        sink_class="cmdi",
        languages=("python",),
        input_arg_kind="transform",
        soundness_note=(
            "shlex.quote returns a shell-escaped string safe to "
            "interpolate into a shell command (single-quoted, with "
            "embedded single quotes escaped).  Sound for shell=True "
            "subprocess invocations."
        ),
    ),
    # ------------------------------------------------------------------
    # JS / TS — mostly transforms via popular libraries
    # ------------------------------------------------------------------
    KnownSafeCall(
        library_call="validator.escape",
        sink_class="xss",
        languages=("javascript", "typescript"),
        input_arg_kind="transform",
        soundness_note=(
            "validator.js escape() replaces &, <, >, \", ', / with their "
            "HTML entity equivalents.  Output is XSS-safe in HTML "
            "context (verified vs validator.js source 13.x)."
        ),
    ),
    KnownSafeCall(
        library_call="DOMPurify.sanitize",
        sink_class="xss",
        languages=("javascript", "typescript"),
        input_arg_kind="transform",
        soundness_note=(
            "DOMPurify.sanitize is the canonical XSS sanitiser for "
            "user-supplied HTML; output is safe to assign to innerHTML.  "
            "Default config; custom configs are caller's responsibility."
        ),
    ),
    # ------------------------------------------------------------------
    # JS / TS — SQL escaping (mysql / mysql2 / mariadb packages)
    # ------------------------------------------------------------------
    KnownSafeCall(
        library_call="connection.escape",
        sink_class="sqli",
        languages=("javascript", "typescript"),
        input_arg_kind="transform",
        soundness_note=(
            "Node mysql / mysql2 connection.escape() escapes characters "
            "with special SQL-string meaning: single/double quotes "
            "(escaped as \\' / \\\"), backslashes, NUL, newlines, CR, "
            "Ctrl-Z, and zero-byte.  Output is wrapped in single quotes "
            "and safe to concatenate into a SQL string literal context.  "
            "Verified against mysql 2.x / mysql2 3.x sqlstring.escape "
            "implementation.  NB: only sound in SQL STRING-LITERAL "
            "context — not safe for identifier interpolation; that "
            "requires connection.escapeId."
        ),
    ),
    KnownSafeCall(
        library_call="conn.escape",
        sink_class="sqli",
        languages=("javascript", "typescript"),
        input_arg_kind="transform",
        soundness_note=(
            "Alias for connection.escape — same library, same "
            "semantics, common idiomatic variable name.  See "
            "connection.escape entry."
        ),
    ),
    # ------------------------------------------------------------------
    # Java — escaping + parameterised queries
    # ------------------------------------------------------------------
    KnownSafeCall(
        library_call="org.apache.commons.lang3.StringEscapeUtils.escapeHtml4",
        sink_class="xss",
        languages=("java",),
        input_arg_kind="transform",
        soundness_note=(
            "Apache Commons Lang escapeHtml4 escapes per HTML 4.0 spec; "
            "output is HTML-safe.  Note: escapeHtml3 is also safe but "
            "less common — add separately if needed."
        ),
    ),
    # NB: Java PreparedStatement.setString is a structurally different
    # pattern (a method call on a previously-allocated PreparedStatement
    # object that's then executed).  Not a single-call transform —
    # leaving for a future entry-kind that models multi-step
    # parameterised-query patterns.

    # ------------------------------------------------------------------
    # C / C++ — Phase 11 entries
    # ------------------------------------------------------------------
    #
    # Selection rule for C / C++: only "transform" sanitizers that
    # return a newly-allocated value qualify. Destination-buffer
    # writers (``mysql_real_escape_string(conn, dst, src, len)``,
    # ``realpath(in, dst)``) are excluded because Phase 10's
    # may_escape policy would downgrade them to candidate_only anyway
    # — wiring them through the catalog would only generate audit
    # noise. Such patterns will become value-bound under Phase 12-14's
    # inter-procedural taint or a future alias-tracking refinement.
    #
    # All four entries below are GLib / SQLite library calls because
    # those libraries publish soundness contracts in their API docs.
    # Adding entries from other libraries should follow the same
    # bar: a documented "returns sanitized output" contract.
    KnownSafeCall(
        library_call="g_markup_escape_text",
        sink_class="xss",
        languages=("c", "cpp"),
        input_arg_kind="transform",
        soundness_note=(
            "GLib g_markup_escape_text (since GLib 2.0) escapes the XML "
            "metacharacters &, <, >, \", ' to their entity references. "
            "Returns a newly-allocated gchar* that is XML-safe and "
            "(by extension) HTML-safe for text content."
        ),
    ),
    KnownSafeCall(
        library_call="g_uri_escape_string",
        sink_class="pathtrav",
        languages=("c", "cpp"),
        input_arg_kind="transform",
        soundness_note=(
            "GLib g_uri_escape_string (since GLib 2.16) percent-encodes "
            "every byte that isn't in the user-supplied reserved set, "
            "by default escaping path separators and traversal sequences. "
            "Returns a newly-allocated URI-safe string."
        ),
    ),
    KnownSafeCall(
        library_call="g_shell_quote",
        sink_class="cmdi",
        languages=("c", "cpp"),
        input_arg_kind="transform",
        soundness_note=(
            "GLib g_shell_quote (since GLib 2.0) returns a newly-allocated "
            "string wrapped in single quotes with any embedded single "
            "quotes properly escaped. The output is safe for inclusion "
            "in a shell command line per POSIX sh(1) quoting rules."
        ),
    ),
    # NOTE: sqlite3_mprintf is deliberately NOT in this catalog. Only its
    # %q/%Q format specifiers escape; a generic %s does not, so keying
    # suppression on the call name alone would falsely clear
    # sqlite3_mprintf("... = %s", tainted) — the exact wrong-format-
    # specifier FN this arc exists to prevent (review #1 on PR #794).
    # Re-add only behind per-format-specifier discrimination.
)


def find(library_call: str, sink_class: str, language: str) -> Optional[KnownSafeCall]:
    """Look up a known-safe call entry.  Returns the matching entry or
    None.  Exact match on ``library_call`` and ``sink_class``; language
    must be in the entry's ``languages`` tuple."""
    for entry in _TABLE:
        if (entry.library_call == library_call
                and entry.sink_class == sink_class
                and language in entry.languages):
            return entry
    return None


def all_entries() -> Tuple[KnownSafeCall, ...]:
    """Diagnostic accessor — returns the full table for testing /
    audit-rendering."""
    return _TABLE
