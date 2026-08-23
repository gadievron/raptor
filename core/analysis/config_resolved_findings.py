"""Additive config-resolved findings (detection, never suppression).

A security-sensitive algorithm selector whose argument is read from a
bundled ``.properties`` file is invisible to pattern detectors: the
weak name ("MD5") lives in the config file, not at the call site.
This stage walks Java sources for the ``getInstance`` selector family,
resolves identifier arguments through the strict config resolver
(:mod:`core.analysis.config_resolve_java`), and emits a NEW finding
when — and only when — the file-recorded value is a known-weak
algorithm. Emission requires the full resolver proof; any resolution
failure emits nothing (the honest asymmetry: detection may consume the
two-arg ``getProperty(key, default)`` form because the FILE value is
the runtime value whenever the named resource loads, but it never
guesses past a refusal).

Literal arguments are deliberately out of scope — literal weak names
are the pattern detectors' job; duplicating them here would double
findings.

The output is a separate SARIF run (``raptor-config-resolved``) that
joins combined.sarif exactly like the graduated-rules stage; rule
metadata carries ``external/cwe/cwe-N`` tags for the shared parser.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path

from core.analysis.config_resolve_java import (
    ConfigResolver,
    _call_arguments,
    _enclosing_method,
    _parser,
    _string_literal_value,
    _text,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node

logger = logging.getLogger(__name__)

_FILE_CAP = 5000

# Selector APIs whose string argument names an algorithm. Seed set —
# growth must come from learned vocabulary, never by editing this
# table (repo doctrine: learn vocab, don't hardcode project APIs;
# these are JDK platform names, the sanctioned hardcoding class).
_API_CLASSES: dict[str, str] = {
    "MessageDigest": "hash",
    "Cipher": "cipher",
    "SecureRandom": "prng",
}

# Known-weak algorithm names per selector family (seed sets <= 9,
# same growth rule as above). Cipher transformations match on the
# leading algorithm segment ("DES/ECB/..." -> DES).
_WEAK: dict[str, frozenset] = {
    "hash": frozenset({"MD2", "MD4", "MD5", "SHA1", "SHA-1"}),
    "cipher": frozenset({"DES", "DESEDE", "RC2", "RC4"}),
    "prng": frozenset({"SHA1PRNG"}),
}

_RULES: dict[str, tuple[str, str]] = {
    "hash": ("raptor.config-resolved.weak-hash", "cwe-328"),
    "cipher": ("raptor.config-resolved.weak-cipher", "cwe-327"),
    "prng": ("raptor.config-resolved.weak-prng", "cwe-338"),
}


def _selector_family(node: Node) -> str | None:
    """Family name when this method_invocation is a getInstance call
    on a seed selector class (bare or fully-qualified receiver)."""
    meth = node.child_by_field_name("name")
    if meth is None or _text(meth) != "getInstance":
        return None
    obj = node.child_by_field_name("object")
    if obj is None:
        return None
    receiver = _text(obj).rsplit(".", 1)[-1]
    return _API_CLASSES.get(receiver)


def _single_method_def(method_node, name: str):
    """The RHS node of ``name``'s single definition inside the method,
    or None when zero, several, or compound-written — multiple
    definitions would need reaching-defs to pick, and detection never
    guesses."""
    rhs = None
    count = 0
    stack = [method_node]
    while stack:
        n = stack.pop()
        if n.type == "variable_declarator":
            nm = n.child_by_field_name("name")
            if nm is not None and _text(nm) == name:
                count += 1
                rhs = n.child_by_field_name("value")
        elif n.type == "assignment_expression":
            left = n.child_by_field_name("left")
            if left is not None and left.type == "identifier" \
                    and _text(left) == name:
                count += 1
                rhs = n.child_by_field_name("right")
        elif n.type == "update_expression":
            for ch in n.children:
                if ch.type == "identifier" and _text(ch) == name:
                    count += 2  # forces the multi-def skip
        stack.extend(n.children)
    if count != 1:
        return None
    return rhs


def _weak_class(family: str, value: str) -> bool:
    head = value.split("/", 1)[0].strip().upper()
    return head in _WEAK[family]


def scan_java_source(source_text: str, file_path: str,
                     repo_root: str, stats: Counter) -> list[dict]:
    """Config-resolved weak-selector findings for one Java file."""
    parser = _parser()
    if parser is None:
        stats["parser_unavailable"] += 1
        return []
    try:
        tree = parser.parse(source_text.encode("utf-8"))
    except Exception:  # noqa: BLE001
        stats["parse_failed"] += 1
        return []
    resolver = ConfigResolver(source_text, file_path, repo_root)
    findings: list[dict] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "method_invocation":
            continue
        family = _selector_family(node)
        if family is None:
            continue
        stats["calls_examined"] += 1
        args = _call_arguments(node)
        if not args:
            continue
        arg = args[0]
        if _string_literal_value(arg) is not None:
            stats["skipped_literal_arg"] += 1
            continue
        if arg.type != "identifier":
            stats["skipped_nonidentifier_arg"] += 1
            continue
        method_node = _enclosing_method(arg)
        if method_node is None:
            stats["skipped_no_method"] += 1
            continue
        rhs = _single_method_def(method_node, _text(arg))
        if rhs is None:
            stats["skipped_multi_def"] += 1
            continue
        if rhs.type != "method_invocation":
            stats["skipped_nonconfig_def"] += 1
            continue
        res = resolver.resolve_call(rhs, allow_default=True)
        if not res.resolved:
            continue  # refusal accounting lives on resolver.stats
        if not _weak_class(family, res.value):
            stats["resolved_safe"] += 1
            continue
        rule_id, cwe = _RULES[family]
        try:
            rel_cfg = str(
                Path(res.config_file).resolve().relative_to(
                    Path(repo_root).resolve()))
        except ValueError:
            rel_cfg = Path(res.config_file).name
        stats["emitted"] += 1
        findings.append({
            "rule_id": rule_id,
            "cwe": cwe,
            "file": file_path,
            "line": node.start_point[0] + 1,
            "message": (
                f"weak algorithm selected via configuration: "
                f"key {res.key!r} in {rel_cfg} resolves to a "
                f"known-weak {family} algorithm"
                + (" (a call-site default exists but the bundled file"
                   " value is the loaded value)" if res.default else "")
            ),
        })
    for reason, n in resolver.stats.items():
        stats[f"resolver:{reason}"] += n
    return findings


def to_sarif(findings: list[dict], repo_root: str) -> dict:
    """SARIF 2.1.0 document; distinct tool.driver.name keeps this a
    separate run in combined.sarif (graduated-stage precedent)."""
    rule_defs: list[dict] = []
    seen: set = set()
    results: list[dict] = []
    for f in findings:
        if f["rule_id"] not in seen:
            rule_defs.append({
                "id": f["rule_id"],
                "name": f["rule_id"],
                "shortDescription": {"text": f["rule_id"]},
                "defaultConfiguration": {"level": "warning"},
                "properties": {
                    "tags": ["security", f"external/cwe/{f['cwe']}"],
                    "provenance": "config-resolved",
                },
            })
            seen.add(f["rule_id"])
        try:
            rel = str(Path(f["file"]).resolve().relative_to(
                Path(repo_root).resolve()))
        except ValueError:
            rel = f["file"]
        results.append({
            "ruleId": f["rule_id"],
            "level": "warning",
            "message": {"text": f["message"]},
            "properties": {"provenance": "config-resolved"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel},
                    "region": {"startLine": f["line"]},
                },
            }],
        })
    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "raptor-config-resolved",
                "rules": rule_defs,
            }},
            "results": results,
        }],
    }


def run_config_resolved_stage(
        repo_path: Path, out_dir: Path) -> tuple[Path | None, dict]:
    """Scan the repo, write ``config-resolved.sarif`` into ``out_dir``.

    Returns (sarif_path_or_None, stats). Never raises — the stage can
    never fail a scan; a SARIF is written even for zero findings so
    the run records that the stage executed.
    """
    stats: Counter = Counter()
    findings: list[dict] = []
    try:
        java_files: list[Path] = []
        for p in repo_path.rglob("*.java"):
            if any(part in (".git", "node_modules", "target", "build")
                   for part in p.parts):
                continue
            java_files.append(p)
            if len(java_files) >= _FILE_CAP:
                stats["file_cap_hit"] += 1
                logger.warning(
                    "config-resolved stage: file cap (%d) reached — "
                    "remaining Java files not scanned", _FILE_CAP)
                break
        for p in java_files:
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "getInstance" not in text:
                continue
            stats["files_scanned"] += 1
            findings.extend(
                scan_java_source(text, str(p), str(repo_path), stats))
    except Exception as e:  # noqa: BLE001 — stage must never fail a scan
        logger.warning("config-resolved stage failed: %s", e)
        stats["stage_error"] += 1
        return None, dict(stats)
    sarif_path = out_dir / "config-resolved.sarif"
    try:
        sarif_path.write_text(
            json.dumps(to_sarif(findings, str(repo_path)), indent=2),
            encoding="utf-8")
    except OSError as e:
        logger.warning("config-resolved stage: SARIF write failed: %s", e)
        return None, dict(stats)
    logger.info(
        "config-resolved stage: %d Java file(s) scanned, %d finding(s) "
        "emitted", stats.get("files_scanned", 0), stats.get("emitted", 0))
    return sarif_path, dict(stats)
