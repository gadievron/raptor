"""Render Coccinelle rules from per-library API pack data files.

A rule opts in with a marker line:

    // @api-packs: <subdir> <message-domain>

``<subdir>`` names a directory (relative to the rule file) of ``*.json``
API packs; ``<message-domain>`` is the first segment of the emitted
COCCIRESULT message (e.g. ``crypto`` →
``crypto:<kind>:<api>:<fn>``). At render time the marker line is
replaced with one generated rule pair (position match + Python report)
per ``(api, kind)`` found in the packs, so family membership lives in
data — a new library is a new pack file, never a cocci edit.

Pack schema (see the pack directory README for the full contract)::

    {
      "api": "openssl",
      "kinds": {
        "primitive_call": {"prefixes": ["EVP_Digest"], "names": ["HMAC"]},
        "rng_source":     {"prefixes": ["RAND_"],      "names": []}
      }
    }

``prefixes`` become anchored identifier-prefix matches; ``names`` become
exact matches. Both are compiled into a single OCaml-Str-syntax regex
constraint (``identifier fn =~ "^\\(a\\|b$\\)";`` — this spatch regex
dialect supports ``\\(``/``\\|`` grouping and ``^``/``$`` anchors; an
unanchored pattern is a substring search, so everything here is
``^``-anchored).

Failure posture mirrors :mod:`engine.coccinelle.vocab_renderer`: a
missing pack dir, malformed JSON, or invalid entry degrades (warning +
skip) — the unrendered rule still parses because the marker is a
comment.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_MARKER_RE = re.compile(r"^//\s*@api-packs:\s*(\S+)\s+([a-z][a-z0-9_]*)\s*$")

# Spliced into generated rule names and COCCIRESULT messages — keep tight.
_API_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_KIND_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
# C identifier (prefixes are identifier *prefixes*, same alphabet).
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


@dataclass(frozen=True)
class KindSpec:
    """Match spec for one (api, kind): prefix families + exact names."""

    prefixes: tuple[str, ...] = ()
    names: tuple[str, ...] = ()

    def str_regex(self) -> str:
        """OCaml-Str-syntax regex for a cocci identifier constraint."""
        alts = list(self.prefixes) + [f"{n}$" for n in self.names]
        return "^\\(" + "\\|".join(alts) + "\\)"

    def python_regex(self) -> re.Pattern[str]:
        """Python-re equivalent of :meth:`str_regex` (for hermetic tests
        and non-spatch consumers). Entries are identifier-alphabet only
        (validated at load), so the dialects agree."""
        alts = [re.escape(p) for p in self.prefixes] + [
            re.escape(n) + "$" for n in self.names
        ]
        return re.compile("^(?:" + "|".join(alts) + ")")


@dataclass(frozen=True)
class ApiPack:
    """One per-library API pack."""

    api: str
    kinds: dict[str, KindSpec] = field(default_factory=dict)
    source: str = ""


def _load_pack(path: Path) -> ApiPack | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.warning("api pack %s unreadable (%s); skipping", path, e)
        return None
    if not isinstance(raw, dict):
        logger.warning("api pack %s is not a JSON object; skipping", path)
        return None
    api = raw.get("api")
    if not isinstance(api, str) or not _API_RE.match(api):
        logger.warning("api pack %s has invalid 'api' tag; skipping", path)
        return None
    kinds_raw = raw.get("kinds")
    if not isinstance(kinds_raw, dict):
        logger.warning("api pack %s has no 'kinds' object; skipping", path)
        return None

    def _idents(spec: dict, key: str) -> tuple[str, ...]:
        out = []
        for entry in spec.get(key, []):
            if isinstance(entry, str) and _IDENT_RE.match(entry):
                out.append(entry)
            else:
                logger.warning(
                    "api pack %s: invalid %s entry %r dropped",
                    path, key, entry,
                )
        return tuple(sorted(set(out)))

    kinds: dict[str, KindSpec] = {}
    for kind, spec in kinds_raw.items():
        if not isinstance(kind, str) or not _KIND_RE.match(kind):
            logger.warning("api pack %s: invalid kind %r dropped", path, kind)
            continue
        if not isinstance(spec, dict):
            logger.warning("api pack %s: kind %r not an object", path, kind)
            continue
        prefixes = _idents(spec, "prefixes")
        names = _idents(spec, "names")
        if prefixes or names:
            kinds[kind] = KindSpec(prefixes=prefixes, names=names)
    if not kinds:
        logger.warning("api pack %s carries no usable entries; skipping", path)
        return None
    return ApiPack(api=api, kinds=kinds, source=str(path))


def load_packs(packs_dir: Path) -> list[ApiPack]:
    """Load every ``*.json`` pack in ``packs_dir`` (sorted by filename).

    Malformed packs are skipped with a warning. Two packs declaring the
    same ``api`` tag are both kept — rule names are derived from the
    filename so they cannot collide.
    """
    if not packs_dir.is_dir():
        return []
    packs = []
    for path in sorted(packs_dir.glob("*.json")):
        pack = _load_pack(path)
        if pack is not None:
            packs.append(pack)
    return packs


def pack_apis(packs_dir: Path) -> frozenset[str]:
    """The set of ``api`` tags declared by the packs in ``packs_dir``."""
    return frozenset(p.api for p in load_packs(packs_dir))


_RULE_TEMPLATE = """\
@{rule_name}@
position p;
identifier fn =~ "{regex}";
@@
fn@p(...)

@script:python depends on {rule_name}@
p << {rule_name}.p;
fn << {rule_name}.fn;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({{
        "file": _p.file, "line": int(_p.line),
        "rule": "{rule_stem}",
        "message": "{domain}:{kind}:{api}:" + str(fn),
    }}) + "\\n")
"""


def _generate_blocks(
    packs: list[ApiPack], domain: str, rule_stem: str,
) -> str:
    blocks: list[str] = []
    for idx, pack in enumerate(packs):
        for kind, spec in sorted(pack.kinds.items()):
            rule_name = f"pk{idx}_{pack.api}_{kind}"
            blocks.append(_RULE_TEMPLATE.format(
                rule_name=rule_name,
                regex=spec.str_regex(),
                rule_stem=rule_stem,
                domain=domain,
                kind=kind,
                api=pack.api,
            ))
    return "\n\n".join(blocks)


def render_text(rule_path: Path) -> str | None:
    """Render a ``.cocci`` rule's ``@api-packs`` slot from its packs.

    Returns the rendered rule text, or None when the rule has no marker
    or its pack directory yields nothing (caller then runs the rule
    unrendered — still-valid cocci, minus the generated coverage).
    """
    try:
        text = rule_path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("cannot read rule %s (%s)", rule_path, e)
        return None
    if "// @api-packs:" not in text and "//@api-packs:" not in text:
        return None

    out: list[str] = []
    rendered = False
    for line in text.splitlines(keepends=True):
        marker = _MARKER_RE.match(line.rstrip())
        if not marker:
            out.append(line)
            continue
        subdir, domain = marker.group(1), marker.group(2)
        packs_dir = (rule_path.parent / subdir).resolve()
        # Packs must live beside the rule — a marker cannot escape the
        # rule tree and load JSON from elsewhere.
        if not str(packs_dir).startswith(str(rule_path.parent.resolve())):
            logger.warning(
                "rule %s: pack dir %r escapes the rule directory; ignored",
                rule_path, subdir,
            )
            out.append(line)
            continue
        packs = load_packs(packs_dir)
        if not packs:
            logger.warning(
                "rule %s: no usable packs under %s; slot left unrendered",
                rule_path, packs_dir,
            )
            out.append(line)
            continue
        out.append(line)  # keep the marker as provenance in rendered text
        out.append("\n")
        out.append(_generate_blocks(packs, domain, rule_path.stem))
        out.append("\n")
        rendered = True

    if not rendered:
        return None
    return "".join(out)


def render(rule_path: Path) -> Path | None:
    """Tempfile variant of :func:`render_text` (mirrors
    ``vocab_renderer.render``'s contract). Caller unlinks."""
    text = render_text(rule_path)
    if text is None:
        return None
    fd, name = tempfile.mkstemp(
        suffix=".cocci", prefix=rule_path.stem + "_packs_",
    )
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return Path(name)
