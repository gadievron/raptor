"""Tests for the Go function-level reachability tier."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from packages.sca.models import Confidence, Dependency, PinStyle, Reachability
from packages.sca.reachability.go_function_level import (
    build_go_symbol_map,
    refine_go_verdicts,
)


@dataclass
class _Adv:
    ecosystem_specific: Optional[Dict[str, Any]] = None
    database_specific: Optional[Dict[str, Any]] = None


@dataclass
class _OsvResult:
    dep_key: str
    advisories: List[_Adv] = field(default_factory=list)


def _dep(name: str, version: str = "v1.0.0", ecosystem: str = "Go") -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("go.mod"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:golang/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _imported(reason: str = "tier-1 imported") -> Reachability:
    return Reachability(
        verdict="imported",
        confidence=Confidence("high", reason=reason),
        evidence=["src/main.go:1"],
    )


# ---------------------------------------------------------------------------
# build_go_symbol_map
# ---------------------------------------------------------------------------


def test_extract_symbols_with_path():
    """OSV records pair each symbol with its sub-package ``path``;
    the symbol map carries fully-qualified names ready for the
    resolver."""
    adv = _Adv(ecosystem_specific={
        "imports": [{
            "path": "net/http",
            "symbols": ["HandlerFunc", "Server.ServeHTTP"],
        }],
    })
    out = build_go_symbol_map([
        _OsvResult(dep_key="Go:net/http@1.0", advisories=[adv]),
    ])
    assert out == {"Go:net/http@1.0": [
        "net/http.HandlerFunc",
        "net/http.Server.ServeHTTP",
    ]}


def test_extract_symbols_subpackage_path():
    """Common shape: dep is the module root, advisory points at a
    sub-package. The qualified name uses the SUB-PACKAGE path so
    the resolver matches against actual import paths in code."""
    adv = _Adv(ecosystem_specific={
        "imports": [{
            "path": "golang.org/x/crypto/ssh",
            "symbols": ["ParsePrivateKey"],
        }],
    })
    out = build_go_symbol_map([
        _OsvResult(
            dep_key="Go:golang.org/x/crypto@0.10.0",
            advisories=[adv],
        ),
    ])
    assert out == {
        "Go:golang.org/x/crypto@0.10.0": [
            "golang.org/x/crypto/ssh.ParsePrivateKey",
        ],
    }


def test_extract_symbols_flat_fallback_uses_dep_name():
    """The flat ``affected_functions`` shape lacks a per-symbol
    path — fall back to the dep name."""
    adv = _Adv(database_specific={"affected_functions": ["Vuln"]})
    out = build_go_symbol_map([
        _OsvResult(dep_key="Go:foo@1.0", advisories=[adv]),
    ])
    assert out == {"Go:foo@1.0": ["foo.Vuln"]}


def test_dedup_across_advisories():
    adv1 = _Adv(ecosystem_specific={
        "imports": [{"path": "foo", "symbols": ["A", "B"]}],
    })
    adv2 = _Adv(ecosystem_specific={
        "imports": [{"path": "foo", "symbols": ["B", "C"]}],
    })
    out = build_go_symbol_map([
        _OsvResult(dep_key="Go:foo@1.0", advisories=[adv1, adv2]),
    ])
    assert out == {"Go:foo@1.0": ["foo.A", "foo.B", "foo.C"]}


def test_skips_non_go_dep_keys():
    adv = _Adv(ecosystem_specific={
        "imports": [{"path": "x", "symbols": ["X"]}],
    })
    out = build_go_symbol_map([
        _OsvResult(dep_key="PyPI:requests@1.0", advisories=[adv]),
        _OsvResult(dep_key="npm:lodash@1.0", advisories=[adv]),
    ])
    assert out == {}


def test_empty_or_missing_returns_empty():
    assert build_go_symbol_map(None) == {}
    assert build_go_symbol_map([]) == {}
    assert build_go_symbol_map([
        _OsvResult(dep_key="Go:x@1.0", advisories=[]),
    ]) == {}


# ---------------------------------------------------------------------------
# refine_go_verdicts
# ---------------------------------------------------------------------------


pytest.importorskip("tree_sitter_go")


def _project(tmp_path: Path, source: str, filename: str = "main.go") -> Path:
    (tmp_path / filename).write_text(source)
    return tmp_path


def test_called_function_upgrades_to_likely_called(tmp_path):
    target = _project(
        tmp_path,
        'package main\n'
        'import "net/http"\n'
        'func main() { http.Get("/x") }\n',
    )
    deps = [_dep("net/http")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_go_verdicts(
        deps, out,
        target=target,
        go_symbol_map={deps[0].key(): ["net/http.Get"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_uncalled_function_downgrades(tmp_path):
    target = _project(
        tmp_path,
        'package main\n'
        'import "net/http"\n'
        'func main() { http.Post("/x", nil, nil) }\n',
    )
    deps = [_dep("net/http")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_go_verdicts(
        deps, out,
        target=target,
        go_symbol_map={deps[0].key(): ["net/http.Get"]},
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_subpackage_resolves_correctly(tmp_path):
    """The advisory pointed at a sub-package
    (``golang.org/x/crypto/ssh``) and the project's source uses
    that exact import — function-level matches."""
    target = _project(
        tmp_path,
        'package main\n'
        'import "golang.org/x/crypto/ssh"\n'
        'func main() { ssh.ParsePrivateKey(nil) }\n',
    )
    deps = [_dep("golang.org/x/crypto", version="0.10.0")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_go_verdicts(
        deps, out,
        target=target,
        go_symbol_map={
            deps[0].key(): ["golang.org/x/crypto/ssh.ParsePrivateKey"],
        },
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_subpackage_unreachable_function_downgrades(tmp_path):
    """Sub-package imported but the affected function isn't called
    — downgrade. This is the test_orchestrator scenario that used
    to stay at ``imported``; with the function-level tier we now
    have positive evidence the affected function isn't reached."""
    target = _project(
        tmp_path,
        'package main\n'
        'import "golang.org/x/crypto/ssh"\n'
        'func main() { ssh.Dial("tcp", "host:22", nil) }\n',
    )
    deps = [_dep("golang.org/x/crypto", version="0.10.0")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_go_verdicts(
        deps, out,
        target=target,
        go_symbol_map={
            deps[0].key(): ["golang.org/x/crypto/ssh.ParsePrivateKey"],
        },
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_uncertain_on_dot_import(tmp_path):
    """Dot import ``. "errors"`` is the Go wildcard analog;
    plus a bare-name call matching the target tail → UNCERTAIN."""
    target = _project(
        tmp_path,
        'package main\n'
        'import "net/http"\n'
        'import . "errors"\n'
        'func main() { Get("/x") }\n',
    )
    deps = [_dep("net/http")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_go_verdicts(
        deps, out,
        target=target,
        go_symbol_map={deps[0].key(): ["net/http.Get"]},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_partial_called_promotes(tmp_path):
    target = _project(
        tmp_path,
        'package main\n'
        'import "net/http"\n'
        'func main() { http.Get("/x") }\n',
    )
    deps = [_dep("net/http")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_go_verdicts(
        deps, out,
        target=target,
        go_symbol_map={
            deps[0].key(): ["net/http.Get", "net/http.Post"],
        },
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_skips_non_go_deps(tmp_path):
    target = _project(tmp_path, "package main\n", filename="main.go")
    deps = [_dep("requests", ecosystem="PyPI")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_go_verdicts(
        deps, out,
        target=target,
        go_symbol_map={deps[0].key(): ["requests.get"]},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_skips_non_imported_verdicts(tmp_path):
    """Tier only fires on ``imported``; ``likely_called`` from the
    module-level path is left alone."""
    target = _project(
        tmp_path,
        'package main\nimport "net/http"\nfunc main() { http.Get("/x") }\n',
    )
    deps = [_dep("net/http")]
    out = {
        deps[0].key(): Reachability(
            verdict="likely_called",
            confidence=Confidence("high", reason="module-level"),
        ),
    }
    refine_go_verdicts(
        deps, out,
        target=target,
        go_symbol_map={deps[0].key(): ["net/http.Get"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_no_symbols_no_op(tmp_path):
    target = _project(tmp_path, "package main\n", filename="main.go")
    deps = [_dep("net/http")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_go_verdicts(
        deps, out,
        target=target,
        go_symbol_map={},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_aliased_import_resolves(tmp_path):
    """``import nh "net/http"`` then ``nh.Get(...)`` — the chain
    head is the alias, but the import-map value retains the full
    path so the resolver matches."""
    target = _project(
        tmp_path,
        'package main\n'
        'import nh "net/http"\n'
        'func main() { nh.Get("/x") }\n',
    )
    deps = [_dep("net/http")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_go_verdicts(
        deps, out,
        target=target,
        go_symbol_map={deps[0].key(): ["net/http.Get"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"
