"""Tests for the Java (Maven) function-level reachability tier."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from packages.sca.models import Confidence, Dependency, PinStyle, Reachability
from packages.sca.reachability.java_function_level import (
    build_maven_symbol_map,
    refine_maven_verdicts,
)


@dataclass
class _Adv:
    ecosystem_specific: Optional[Dict[str, Any]] = None
    database_specific: Optional[Dict[str, Any]] = None


@dataclass
class _OsvResult:
    dep_key: str
    advisories: List[_Adv] = field(default_factory=list)


def _dep(
    name: str = "com.fasterxml.jackson.core:jackson-databind",
    version: str = "2.9.0",
    ecosystem: str = "Maven",
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("pom.xml"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:maven/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _not_evaluated() -> Reachability:
    return Reachability(
        verdict="not_evaluated",
        confidence=Confidence("low", reason="no maven module scanner"),
        evidence=[],
    )


def _imported() -> Reachability:
    return Reachability(
        verdict="imported",
        confidence=Confidence("high", reason="hypothetical module-level"),
        evidence=["src/Main.java:1"],
    )


# ---------------------------------------------------------------------------
# build_maven_symbol_map
# ---------------------------------------------------------------------------


def test_extract_symbols_with_path():
    """``imports[].path + .symbols`` form qualified names."""
    adv = _Adv(ecosystem_specific={
        "imports": [{
            "path": "com.fasterxml.jackson.databind",
            "symbols": ["ObjectMapper.readValue", "ObjectMapper.readTree"],
        }],
    })
    out = build_maven_symbol_map([
        _OsvResult(
            dep_key="Maven:com.fasterxml.jackson.core:jackson-databind@2.9.0",
            advisories=[adv],
        ),
    ])
    assert out == {
        "Maven:com.fasterxml.jackson.core:jackson-databind@2.9.0": [
            "com.fasterxml.jackson.databind.ObjectMapper.readValue",
            "com.fasterxml.jackson.databind.ObjectMapper.readTree",
        ],
    }


def test_extract_skips_entries_without_path():
    """Maven flat fallback (``affected_functions`` without path) is
    skipped — the dep name (``groupId:artifactId``) is not a Java
    package, so we can't build a valid qualified name."""
    adv = _Adv(database_specific={"affected_functions": ["readValue"]})
    out = build_maven_symbol_map([
        _OsvResult(
            dep_key="Maven:com.example:foo@1.0",
            advisories=[adv],
        ),
    ])
    assert out == {}


def test_extract_database_specific_path():
    """``database_specific.imports[]`` shape (alt source)."""
    adv = _Adv(database_specific={
        "imports": [{"path": "org.apache.log4j", "symbols": ["Logger.info"]}],
    })
    out = build_maven_symbol_map([
        _OsvResult(
            dep_key="Maven:org.apache.logging.log4j:log4j-core@2.14.0",
            advisories=[adv],
        ),
    ])
    assert out == {
        "Maven:org.apache.logging.log4j:log4j-core@2.14.0": [
            "org.apache.log4j.Logger.info",
        ],
    }


def test_dedup_across_advisories():
    adv1 = _Adv(ecosystem_specific={
        "imports": [{"path": "com.x", "symbols": ["A.m", "B.m"]}],
    })
    adv2 = _Adv(ecosystem_specific={
        "imports": [{"path": "com.x", "symbols": ["B.m", "C.m"]}],
    })
    out = build_maven_symbol_map([
        _OsvResult(
            dep_key="Maven:com.x:lib@1.0",
            advisories=[adv1, adv2],
        ),
    ])
    assert out == {"Maven:com.x:lib@1.0": [
        "com.x.A.m", "com.x.B.m", "com.x.C.m",
    ]}


def test_skips_non_maven_dep_keys():
    adv = _Adv(ecosystem_specific={
        "imports": [{"path": "x", "symbols": ["Y.z"]}],
    })
    out = build_maven_symbol_map([
        _OsvResult(dep_key="Go:foo@1.0", advisories=[adv]),
        _OsvResult(dep_key="PyPI:requests@1.0", advisories=[adv]),
        _OsvResult(dep_key="npm:lodash@1.0", advisories=[adv]),
    ])
    assert out == {}


def test_empty_or_missing_returns_empty():
    assert build_maven_symbol_map(None) == {}
    assert build_maven_symbol_map([]) == {}
    assert build_maven_symbol_map([
        _OsvResult(dep_key="Maven:x:y@1.0", advisories=[]),
    ]) == {}


def test_skips_malformed_imports():
    """Imports with no path field (or non-string path) are skipped
    silently; entry-by-entry, not whole-advisory."""
    adv = _Adv(ecosystem_specific={
        "imports": [
            {"symbols": ["NoPath.m"]},        # no path
            {"path": None, "symbols": ["X.m"]},
            {"path": "com.good", "symbols": ["Good.m"]},
        ],
    })
    out = build_maven_symbol_map([
        _OsvResult(dep_key="Maven:x:y@1.0", advisories=[adv]),
    ])
    assert out == {"Maven:x:y@1.0": ["com.good.Good.m"]}


# ---------------------------------------------------------------------------
# refine_maven_verdicts
# ---------------------------------------------------------------------------


pytest.importorskip("tree_sitter_java")


def _project(tmp_path: Path, source: str, filename: str = "Main.java") -> Path:
    (tmp_path / filename).write_text(source)
    return tmp_path


def test_called_static_method_upgrades_to_likely_called(tmp_path):
    """Static-class call from project source → ``likely_called``."""
    target = _project(
        tmp_path,
        'package x;\n'
        'import com.fasterxml.jackson.databind.ObjectMapper;\n'
        'class Main { void m() { ObjectMapper.readValue("x"); } }\n',
    )
    deps = [_dep()]
    out: Dict[str, Reachability] = {deps[0].key(): _not_evaluated()}
    refine_maven_verdicts(
        deps, out,
        target=target,
        maven_symbol_map={
            deps[0].key(): [
                "com.fasterxml.jackson.databind.ObjectMapper.readValue",
            ],
        },
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_uncalled_method_downgrades(tmp_path):
    """Affected method not called from project Java source —
    downgrade to ``not_function_reachable``."""
    target = _project(
        tmp_path,
        'package x;\n'
        'import com.fasterxml.jackson.databind.ObjectMapper;\n'
        'class Main { void m() { ObjectMapper.readTree("x"); } }\n',
    )
    deps = [_dep()]
    out: Dict[str, Reachability] = {deps[0].key(): _not_evaluated()}
    refine_maven_verdicts(
        deps, out,
        target=target,
        maven_symbol_map={
            deps[0].key(): [
                "com.fasterxml.jackson.databind.ObjectMapper.readValue",
            ],
        },
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_imported_starting_verdict_also_promoted(tmp_path):
    """If a future Maven module-level scanner sets ``imported``, the
    function-level tier still fires from that gate."""
    target = _project(
        tmp_path,
        'package x;\n'
        'import com.fasterxml.jackson.databind.ObjectMapper;\n'
        'class Main { void m() { ObjectMapper.readValue("x"); } }\n',
    )
    deps = [_dep()]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_maven_verdicts(
        deps, out,
        target=target,
        maven_symbol_map={
            deps[0].key(): [
                "com.fasterxml.jackson.databind.ObjectMapper.readValue",
            ],
        },
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_uncertain_on_class_forname(tmp_path):
    """Reflective dispatch via ``Class.forName`` — UNCERTAIN, leave
    verdict alone (don't fabricate confidence)."""
    target = _project(
        tmp_path,
        'package x;\n'
        'class Main {\n'
        '    void m() {\n'
        '        Class.forName("y");\n'
        '        someInstance.readValue();\n'
        '    }\n'
        '}\n',
    )
    deps = [_dep()]
    out: Dict[str, Reachability] = {deps[0].key(): _not_evaluated()}
    refine_maven_verdicts(
        deps, out,
        target=target,
        maven_symbol_map={
            deps[0].key(): [
                "com.fasterxml.jackson.databind.ObjectMapper.readValue",
            ],
        },
    )
    assert out[deps[0].key()].verdict == "not_evaluated"


def test_partial_called_promotes(tmp_path):
    """Only one of multiple affected methods is called →
    ``likely_called`` (matches Go / npm / PyPI)."""
    target = _project(
        tmp_path,
        'package x;\n'
        'import com.fasterxml.jackson.databind.ObjectMapper;\n'
        'class Main { void m() { ObjectMapper.readValue("x"); } }\n',
    )
    deps = [_dep()]
    out: Dict[str, Reachability] = {deps[0].key(): _not_evaluated()}
    refine_maven_verdicts(
        deps, out,
        target=target,
        maven_symbol_map={
            deps[0].key(): [
                "com.fasterxml.jackson.databind.ObjectMapper.readValue",
                "com.fasterxml.jackson.databind.ObjectMapper.readTree",
            ],
        },
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_skips_non_maven_deps(tmp_path):
    target = _project(tmp_path, "package x;\nclass C {}\n")
    deps = [_dep(name="requests", ecosystem="PyPI", version="2.0")]
    out: Dict[str, Reachability] = {deps[0].key(): _not_evaluated()}
    refine_maven_verdicts(
        deps, out,
        target=target,
        maven_symbol_map={deps[0].key(): ["requests.get"]},
    )
    assert out[deps[0].key()].verdict == "not_evaluated"


def test_skips_likely_called_starting_verdict(tmp_path):
    """If a higher-priority tier already produced ``likely_called``,
    the function-level tier doesn't second-guess it."""
    target = _project(
        tmp_path,
        'package x;\nclass Main {}\n',
    )
    deps = [_dep()]
    out = {
        deps[0].key(): Reachability(
            verdict="likely_called",
            confidence=Confidence("high", reason="prior tier"),
        ),
    }
    refine_maven_verdicts(
        deps, out,
        target=target,
        maven_symbol_map={
            deps[0].key(): [
                "com.fasterxml.jackson.databind.ObjectMapper.readValue",
            ],
        },
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_no_symbols_no_op(tmp_path):
    target = _project(tmp_path, 'package x;\nclass C {}\n')
    deps = [_dep()]
    out: Dict[str, Reachability] = {deps[0].key(): _not_evaluated()}
    refine_maven_verdicts(
        deps, out,
        target=target,
        maven_symbol_map={},
    )
    assert out[deps[0].key()].verdict == "not_evaluated"


def test_evidence_lines_truncated_to_five(tmp_path):
    """Even if many call sites match, the verdict carries at most
    five evidence lines (matches Go / npm tier behaviour)."""
    body = "\n".join(
        "        ObjectMapper.readValue(\"x\");" for _ in range(8)
    )
    target = _project(
        tmp_path,
        'package x;\n'
        'import com.fasterxml.jackson.databind.ObjectMapper;\n'
        f'class Main {{ void m() {{\n{body}\n    }} }}\n',
    )
    deps = [_dep()]
    out: Dict[str, Reachability] = {deps[0].key(): _not_evaluated()}
    refine_maven_verdicts(
        deps, out,
        target=target,
        maven_symbol_map={
            deps[0].key(): [
                "com.fasterxml.jackson.databind.ObjectMapper.readValue",
            ],
        },
    )
    assert out[deps[0].key()].verdict == "likely_called"
    assert len(out[deps[0].key()].evidence) <= 5


def test_inventory_passed_in_is_reused(tmp_path):
    """Caller-supplied inventory short-circuits the local build."""
    target = _project(
        tmp_path,
        'package x;\n'
        'import com.fasterxml.jackson.databind.ObjectMapper;\n'
        'class Main { void m() { ObjectMapper.readValue("x"); } }\n',
    )
    from core.inventory.builder import build_inventory
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        inv = build_inventory(str(target), td)

    deps = [_dep()]
    out: Dict[str, Reachability] = {deps[0].key(): _not_evaluated()}
    refine_maven_verdicts(
        deps, out,
        target=target,
        maven_symbol_map={
            deps[0].key(): [
                "com.fasterxml.jackson.databind.ObjectMapper.readValue",
            ],
        },
        inventory=inv,
    )
    assert out[deps[0].key()].verdict == "likely_called"
