"""Audit → /fuzz handoff: dictionaries and seed hints from audit knowledge.

/audit already extracts exactly the artefacts a coverage-guided fuzzer
wants in a dictionary — unique magic constants (constant_resolution),
protocol keywords and format strings (ts_extract string literals),
dispatch/switch keys (ts_extract dispatch tables) — and IRIS taint
specs name the parse-adjacent sinks a harness should aim at. Until
now none of it reached ``-x``: only an operator-supplied file ever
became an AFL dictionary.

This module mines those sources at the end of an audit run and writes:

* ``<out_dir>/fuzz-dict.json`` — structured tokens, each with a
  provenance string, plus IRIS-derived seed hints;
* ``<out_dir>/fuzz.dict`` — the same tokens in AFL ``name="value"``
  dictionary format, ready for ``afl-fuzz -x`` / libFuzzer ``-dict``.

/fuzz auto-discovers ``fuzz.dict`` (own run dir first, then newest
sibling run dir — see ``packages.fuzzing.audit_dict``), mirroring the
fuzz→audit ``coverage-fuzz.json`` convention in the other direction.

Bounded and best-effort: token count and length are capped, and any
failure must never affect the audit run.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DICT_JSON_FILENAME = "fuzz-dict.json"
DICT_AFL_FILENAME = "fuzz.dict"

MAX_TOKENS = 256
MAX_TOKEN_LEN = 64
MAX_SEED_HINTS = 32
# Source-scan bounds for the string/dispatch extractors.
MAX_FILES = 200
MAX_FILE_BYTES = 512 * 1024
# Constants at or below this are byte noise, not magic values.
MIN_CONSTANT_MAGNITUDE = 255

# String-literal contexts that describe parse shapes (worth fuzzing);
# "return"/"assignment"/"argument" literals are mostly log messages.
_PARSE_CONTEXTS = frozenset({"dict_key", "comparison", "switch_case"})


def _afl_escape(data: bytes) -> str:
    """Escape a token value for the AFL dictionary format."""
    out = []
    for b in data:
        if 32 <= b <= 126 and b not in (0x22, 0x5C):  # printable, not " or \
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def _pack_constant(value: int) -> bytes | None:
    """Pack an integer constant into its minimal LE byte width."""
    for width in (1, 2, 4, 8):
        try:
            return value.to_bytes(width, "little", signed=value < 0)
        except OverflowError:
            continue
    return None


def _sanitise_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "_-." else "_" for c in name)[:48]


def _checklist_sources(
    target_path: Path, out_dir: Path,
) -> dict[str, str]:
    """Read the checklist's source files (bounded) for the extractors."""
    from core.audit.gaps import load_checklist

    checklist = load_checklist(Path(out_dir))
    sources: dict[str, str] = {}
    for file_info in checklist.get("files", [])[:MAX_FILES]:
        rel = file_info.get("path", "")
        if not rel:
            continue
        full = Path(target_path) / rel
        try:
            if not full.is_file() or full.stat().st_size > MAX_FILE_BYTES:
                continue
            sources[rel] = full.read_text(errors="replace")
        except OSError:
            continue
    return sources


def _constant_tokens(target_path: Path) -> list[dict[str, Any]]:
    try:
        from core.audit.constant_resolution import build_unique_constants
    except ImportError:
        return []
    tokens: list[dict[str, Any]] = []
    try:
        table = build_unique_constants(Path(target_path))
    except Exception:
        logger.debug("fuzz handoff: constant table failed", exc_info=True)
        return []
    for name, const in table.unique.items():
        value = const.value
        if abs(value) <= MIN_CONSTANT_MAGNITUDE:
            continue
        packed = _pack_constant(value)
        if not packed:
            continue
        tokens.append({
            "name": f"const_{_sanitise_name(name)}",
            "value": _afl_escape(packed),
            "provenance": f"constant:{name}={value:#x} ({const.file})",
        })
    return tokens


def _string_tokens(sources: dict[str, str]) -> list[dict[str, Any]]:
    try:
        from core.audit.ts_extract import (
            extract_all_dispatch_tables,
            extract_all_string_literals,
        )
    except ImportError:
        return []
    tokens: list[dict[str, Any]] = []

    try:
        literal_map = extract_all_string_literals(sources)
    except Exception:
        logger.debug("fuzz handoff: literal extraction failed", exc_info=True)
        literal_map = {}
    for fp, sites in literal_map.items():
        for site in sites:
            value = site.value
            if not value or len(value) > MAX_TOKEN_LEN:
                continue
            if site.is_template:
                kind = "format_string"
            elif site.context in _PARSE_CONTEXTS:
                kind = f"string:{site.context}"
            else:
                continue
            tokens.append({
                "name": f"str_{_sanitise_name(value)}",
                "value": _afl_escape(value.encode("utf-8", "replace")),
                "provenance": f"{kind} ({fp}:{site.line})",
            })

    try:
        dispatch_map = extract_all_dispatch_tables(sources)
    except Exception:
        logger.debug("fuzz handoff: dispatch extraction failed", exc_info=True)
        dispatch_map = {}
    for fp, tables in dispatch_map.items():
        for table in tables:
            for key in table.keys:
                if not key or len(str(key)) > MAX_TOKEN_LEN:
                    continue
                tokens.append({
                    "name": f"dispatch_{_sanitise_name(str(key))}",
                    "value": _afl_escape(str(key).encode("utf-8", "replace")),
                    "provenance": f"dispatch:{table.table_type} ({fp})",
                })
    return tokens


def _iris_seed_hints(out_dir: Path) -> list[dict[str, Any]]:
    """Seed hints from persisted IRIS taint specs (sinks + sources)."""
    hints: list[dict[str, Any]] = []
    path = Path(out_dir) / "iris-taint-specs.json"
    if not path.is_file():
        return hints
    try:
        specs = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return hints
    for spec in specs:
        role = spec.get("role", "")
        if role not in ("sink", "source"):
            continue
        hints.append({
            "function": spec.get("function", ""),
            "file": spec.get("file", ""),
            "role": role,
            "provenance": "iris:taint-spec",
            "note": (
                f"project {role} '{spec.get('function', '')}' — inputs "
                f"reaching it are high-value fuzz targets"
            ),
        })
        if len(hints) >= MAX_SEED_HINTS:
            break
    return hints


def emit_fuzz_dict(target_path: Path, out_dir: Path) -> Path | None:
    """Mine audit knowledge and write the fuzz dictionary artefacts.

    Returns the AFL dictionary path, or None when nothing was mined.
    Never raises.
    """
    try:
        sources = _checklist_sources(target_path, out_dir)

        tokens = _constant_tokens(target_path)
        tokens.extend(_string_tokens(sources))

        # Dedupe by escaped value, keep first provenance, cap.
        seen: set[str] = set()
        unique_tokens: list[dict[str, Any]] = []
        for tok in tokens:
            if not tok["value"] or tok["value"] in seen:
                continue
            seen.add(tok["value"])
            unique_tokens.append(tok)
            if len(unique_tokens) >= MAX_TOKENS:
                break

        seed_hints = _iris_seed_hints(out_dir)

        if not unique_tokens and not seed_hints:
            return None

        doc = {
            "meta": {
                "producer": "raptor-audit",
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "target": str(target_path),
                "token_count": len(unique_tokens),
            },
            "tokens": unique_tokens,
            "seed_hints": seed_hints,
        }
        json_path = Path(out_dir) / DICT_JSON_FILENAME
        json_path.write_text(
            json.dumps(doc, indent=2) + "\n", encoding="utf-8",
        )

        if not unique_tokens:
            return None

        lines = ["# AFL dictionary generated by raptor-audit (P39)"]
        used_names: set[str] = set()
        for tok in unique_tokens:
            name = tok["name"]
            n = 1
            while name in used_names:
                n += 1
                name = f"{tok['name']}_{n}"
            used_names.add(name)
            lines.append(f'{name}="{tok["value"]}"')
        afl_path = Path(out_dir) / DICT_AFL_FILENAME
        afl_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        logger.info(
            "fuzz handoff: %d dictionary token(s), %d seed hint(s) → %s",
            len(unique_tokens), len(seed_hints), afl_path.name,
        )
        return afl_path
    except Exception:
        logger.debug("fuzz dict handoff failed", exc_info=True)
        return None
