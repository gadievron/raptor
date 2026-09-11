"""Tests for core.audit.goconc — the Go internal-concurrency witness.

Every fixture is synthetic Go written for these tests.  The witness's
contract under test: ``isolated=True`` only when the package provably
has no goroutine spawn that reaches the claimed state; every parse
failure, unresolvable construct, or ambiguity refuses (``isolated=
False``) — the conservative direction is always "no witness".
"""

from __future__ import annotations

import pytest

from core.audit.goconc import (
    GoroutineIsolationResult,
    _go_parser,
    check_goroutine_isolation,
    load_go_package,
)

_HAS_TS_GO = _go_parser() is not None

needs_ts_go = pytest.mark.skipif(
    not _HAS_TS_GO, reason="tree-sitter Go grammar not installed",
)


# ---------------------------------------------------------------------------
# Fixtures (synthetic)
# ---------------------------------------------------------------------------

# A record type touched only by its own methods, plus pool/cursor
# machinery that spawns goroutines which never reach it.
_STORE_PKG = {
    "record.go": """package store

type Record struct {
\tVal   string
\tValid bool
}

func (r *Record) Scan(v string) error {
\tr.Valid = true
\tr.Val = v
\treturn nil
}

func (r Record) Get() string {
\treturn r.Val
}
""",
    "pool.go": """package store

type Pool struct {
\tch chan int
}

func (p *Pool) opener() {
\tfor range p.ch {
\t}
}

func NewPool() *Pool {
\tp := &Pool{ch: make(chan int)}
\tgo p.opener()
\treturn p
}

type Cursor struct {
\tdone chan struct{}
}

func (c *Cursor) awaitDone() {
\t<-c.done
}

func (c *Cursor) init() {
\tgo c.awaitDone()
}
""",
}

_RECORD_SCAN = """func (r *Record) Scan(v string) error {
\tr.Valid = true
\tr.Val = v
\treturn nil
}
"""

_CURSOR_NEXT = """func (c *Cursor) Next() bool {
\t<-c.done
\treturn false
}
"""

# A package with no goroutine spawns at all: option-application shape.
_OPTS_PKG = {
    "opts.go": """package opts

type Manifest struct {
\tLinux *Linux
\tGids  []uint32
}

type Linux struct{}

func setPlatform(m *Manifest) {
\tif m.Linux == nil {
\t\tm.Linux = &Linux{}
\t}
}

func ensureGids(m *Manifest, gid uint32) {
\tfor _, g := range m.Gids {
\t\tif g == gid {
\t\t\treturn
\t\t}
\t}
\tm.Gids = append([]uint32{gid}, m.Gids...)
}
""",
}

_SET_PLATFORM = """func setPlatform(m *Manifest) {
\tif m.Linux == nil {
\t\tm.Linux = &Linux{}
\t}
}
"""


def _pkg(extra: dict[str, str] | None = None) -> dict[str, str]:
    files = dict(_STORE_PKG)
    if extra:
        files.update(extra)
    return files


# ---------------------------------------------------------------------------
# Witness holds
# ---------------------------------------------------------------------------


@needs_ts_go
class TestWitnessHolds:
    def test_spawns_never_reach_claimed_type(self):
        r = check_goroutine_isolation(_RECORD_SCAN, _STORE_PKG)
        assert r.isolated is True
        assert r.spawn_count == 2
        assert r.claimed_types == ("Record",)

    def test_zero_spawn_package_discharges_any_state(self):
        r = check_goroutine_isolation(_SET_PLATFORM, _OPTS_PKG)
        assert r.isolated is True
        assert r.spawn_count == 0

    def test_zero_spawn_package_discharges_underivable_claim(self):
        # Value-parameter function: claimed state underivable, but the
        # zero-spawn arm needs no claimed types.
        src = "func format(id string) string {\n\treturn id\n}\n"
        r = check_goroutine_isolation(src, _OPTS_PKG)
        assert r.isolated is True
        assert r.spawn_count == 0


# ---------------------------------------------------------------------------
# Witness refuses: internal concurrency reaches the claimed state
# ---------------------------------------------------------------------------


@needs_ts_go
class TestWitnessRefusesReach:
    def test_spawn_inside_claimed_types_own_method(self):
        # go c.awaitDone() lives inside a Cursor method: a goroutine
        # born holding the receiver.
        r = check_goroutine_isolation(_CURSOR_NEXT, _STORE_PKG)
        assert r.isolated is False
        assert "Cursor" in r.reasoning

    def test_spawned_method_on_claimed_type(self):
        files = _pkg({
            "kick.go": """package store

func kick(r *Record) {
\tgo r.Scan("x")
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_claimed_type_named_in_spawn_subtree(self):
        files = _pkg({
            "lit.go": """package store

func launch() {
\tgo func() {
\t\tvar r Record
\t\tr.Valid = true
\t}()
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_occupancy_violation_helper_mentions_type(self):
        # A plain helper naming Record: a spawn could reach the state
        # through it without naming the type at the spawn site.
        files = _pkg({
            "helper.go": """package store

func snapshot(r *Record) string {
\treturn r.Val
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False
        assert "outside its own declaration" in r.reasoning

    def test_occupancy_violation_struct_field_of_claimed_type(self):
        files = _pkg({
            "holder.go": """package store

type Holder struct {
\trec Record
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_alias_base_joins_the_claimed_set(self):
        # `type Record = RealRecord` makes them THE SAME type: state
        # circulating under the base name is claimed state.
        files = {
            "record.go": """package store

type RealRecord struct {
\tVal   string
\tValid bool
}

type Record = RealRecord

var shared = &RealRecord{}

func (r *Record) Scan(v string) error {
\tr.Valid = true
\tr.Val = v
\treturn nil
}

func worker() {
\tshared.Valid = false
}

func launch() {
\tgo worker()
}
""",
        }
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False
        assert "RealRecord" in r.reasoning

    def test_receiver_escape_assignment_rhs(self):
        # The receiver stored into a package-local interface variable
        # inside its own method: a goroutine can then dispatch onto
        # the receiver without ever naming the type.
        files = _pkg({
            "reg.go": """package store

type sink interface {
\tGet() string
}

var box sink

func (r *Record) Register() {
\tbox = r
}

func flusher() {
\tgo box.Get()
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False
        assert "escape" in r.reasoning

    def test_receiver_escape_call_argument(self):
        files = _pkg({
            "reg.go": """package store

func keep(v interface{ Get() string }) {
\t_ = v
}

func (r *Record) Register() {
\tkeep(r)
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_receiver_escape_channel_send(self):
        files = _pkg({
            "reg.go": """package store

var events = make(chan interface{ Get() string }, 1)

func (r *Record) Register() {
\tevents <- r
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_receiver_field_access_is_not_an_escape(self):
        # r.Valid = true / convertAssign(&r.Val, v) shapes: the
        # receiver as a selector base or field-address argument stays
        # allowed — that is the class the witness exists for.
        files = _pkg({
            "conv.go": """package store

func convertAssign(dest *string, v string) error {
\t*dest = v
\treturn nil
}
""",
        })
        src = (
            "func (r *Record) Scan(v string) error {\n"
            "\tif v == \"\" {\n"
            "\t\treturn nil\n"
            "\t}\n"
            "\tr.Valid = true\n"
            "\treturn convertAssign(&r.Val, v)\n"
            "}\n"
        )
        files["record.go"] = (
            "package store\n\n"
            "type Record struct {\n\tVal   string\n\tValid bool\n}\n\n"
            + src
        )
        r = check_goroutine_isolation(src, files)
        assert r.isolated is True


# ---------------------------------------------------------------------------
# Witness refuses: undecidable constructs (conservative direction)
# ---------------------------------------------------------------------------


class TestConservativeRefusals:
    def test_function_value_spawn(self):
        files = _pkg({
            "hook.go": """package store

var hook func()

func kick() {
\tgo hook()
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_unresolvable_spawn_operand(self):
        files = _pkg({
            "dyn.go": """package store

type Worker struct{}

func (w *Worker) run() {}

func kick(m map[string]*Worker) {
\tgo m["x"].run()
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_opaque_any_value_in_spawn(self):
        files = _pkg({
            "carry.go": """package store

func carry(v any) {
\tgo func() {
\t\t_ = v
\t}()
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_parse_error_refuses(self):
        files = _pkg({"broken.go": "package store\n\nfunc ( {\n"})
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_cgo_refuses(self):
        files = _pkg({
            "cgo.go": 'package store\n\nimport "C"\n\nfunc native() {\n\tC.run()\n}\n',
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_unsafe_import_refuses(self):
        files = _pkg({
            "raw.go": (
                'package store\n\nimport "unsafe"\n\n'
                "func addr(p *int) uintptr {\n"
                "\treturn uintptr(unsafe.Pointer(p))\n}\n"
            ),
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_implicit_spawner_refuses(self):
        # time.AfterFunc runs its callback on a timer goroutine no go
        # statement shows.
        files = _pkg({
            "timer.go": (
                'package store\n\nimport "time"\n\n'
                "func later(f func()) {\n"
                "\ttime.AfterFunc(time.Second, f)\n}\n"
            ),
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_waitgroup_go_refuses(self):
        # sync.WaitGroup.Go (and the errgroup convention) spawns with
        # no go statement — the zero-spawn arm must never fire past it.
        files = {
            "record.go": _STORE_PKG["record.go"],
            "wg.go": (
                'package store\n\nimport "sync"\n\n'
                "func run(f func()) {\n"
                "\tvar wg sync.WaitGroup\n"
                "\twg.Go(f)\n"
                "\twg.Wait()\n}\n"
            ),
        }
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False
        assert "Go" in r.reasoning

    def test_http_serving_refuses(self):
        files = {
            "record.go": _STORE_PKG["record.go"],
            "srv.go": (
                'package store\n\nimport "net/http"\n\n'
                "func serve() {\n"
                "\thttp.ListenAndServe(\":0\", nil)\n}\n"
            ),
        }
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_opaque_package_var_in_spawn_refuses(self):
        files = _pkg({
            "box.go": (
                "package store\n\nvar box any\n\n"
                "func consume(v any) {\n\t_ = v\n}\n\n"
                "func launch() {\n\tgo consume(box)\n}\n"
            ),
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_opaque_struct_field_in_spawn_refuses(self):
        files = _pkg({
            "box.go": (
                "package store\n\n"
                "type Box struct{ f any }\n\n"
                "var box Box\n\n"
                "func launch() {\n"
                "\tgo func() {\n\t\t_ = box.f\n\t}()\n}\n"
            ),
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    @needs_ts_go
    def test_zero_spawn_callback_escape_func_literal_refuses(self):
        # A spawn-free package handing a closure to an imported worker
        # pool: the callee runs it on a goroutine no go statement
        # shows, so the zero-spawn arm must not fire past it.
        files = {
            "record.go": _STORE_PKG["record.go"],
            "pool.go": (
                'package store\n\nimport "workers"\n\n'
                "var shared = &Record{}\n\n"
                "func start() {\n"
                "\tworkers.Submit(func() {\n"
                "\t\tshared.Valid = true\n"
                "\t})\n}\n"
            ),
        }
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False
        assert "function value" in r.reasoning
        assert r.spawn_count == 0

    @needs_ts_go
    def test_zero_spawn_callback_escape_func_name_refuses(self):
        files = {
            "record.go": _STORE_PKG["record.go"],
            "pool.go": (
                'package store\n\nimport "workers"\n\n'
                "func job() {\n}\n\n"
                "func start() {\n"
                "\tworkers.Submit(job)\n}\n"
            ),
        }
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False
        assert "function value" in r.reasoning

    @needs_ts_go
    def test_zero_spawn_locally_bound_closure_to_import_refuses(self):
        # One level of local indirection must not hide the closure
        # from the escape probe: f := func(){...}; ext.Schedule(f).
        files = {
            "record.go": _STORE_PKG["record.go"],
            "pool.go": (
                'package store\n\nimport "workers"\n\n'
                "var shared = &Record{}\n\n"
                "func start() {\n"
                "\tf := func() {\n"
                "\t\tshared.Valid = true\n"
                "\t}\n"
                "\tworkers.Schedule(f)\n}\n"
            ),
        }
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False
        assert "function value" in r.reasoning

    @needs_ts_go
    def test_func_typed_parameter_forward_to_import_refuses(self):
        # A package-owned wrapper forwarding its func-typed FORMAL to
        # an import is the same escape one hop later.
        files = {
            "record.go": _STORE_PKG["record.go"],
            "pool.go": (
                'package store\n\nimport "workers"\n\n'
                "func run(f func()) {\n"
                "\tworkers.Schedule(f)\n}\n\n"
                "func start() {\n"
                "\trun(func() {\n\t})\n}\n"
            ),
        }
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False
        assert "function value" in r.reasoning

    @needs_ts_go
    def test_package_level_func_var_to_import_refuses(self):
        for decl in (
            "var hook = func() {\n}\n",   # func-literal initialized
            "var hook func()\n",           # func-typed
        ):
            files = {
                "record.go": _STORE_PKG["record.go"],
                "pool.go": (
                    'package store\n\nimport "workers"\n\n'
                    + decl +
                    "\nfunc start() {\n"
                    "\tworkers.Schedule(hook)\n}\n"
                ),
            }
            r = check_goroutine_isolation(_RECORD_SCAN, files)
            assert r.isolated is False, decl
            assert "function value" in r.reasoning

    @needs_ts_go
    def test_zero_spawn_local_callbacks_still_witness(self):
        # Control: a spawn-free package whose function values only go
        # to package-local callees keeps the witness.
        files = {
            "record.go": _STORE_PKG["record.go"],
            "helpers.go": (
                "package store\n\n"
                "func withHold(fn func()) {\n\tfn()\n}\n\n"
                "func use() {\n"
                "\twithHold(func() {\n\t})\n}\n"
            ),
        }
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is True
        assert r.spawn_count == 0

    @needs_ts_go
    def test_callback_to_external_callee_refuses(self):
        files = _pkg({
            "cb.go": (
                'package store\n\nimport "outside"\n\n'
                "func hook() {\n"
                "\toutside.Register(func() {\n\t})\n}\n"
            ),
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False
        assert "function value" in r.reasoning

    @needs_ts_go
    def test_method_value_to_import_refuses(self):
        # A METHOD VALUE (p.opener) is a function value: it slipped
        # past the identifier/literal checks and left isolated=True
        # standing while the import could run the method on a
        # goroutine no go statement shows.
        files = _pkg({
            "cb.go": (
                'package store\n\nimport "workers"\n\n'
                "func start(p *Pool) {\n"
                "\tworkers.OnEvent(p.opener)\n}\n"
            ),
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False
        assert "function value" in r.reasoning

    @needs_ts_go
    def test_method_value_to_package_callee_keeps_witness(self):
        # Control: a method value handed to a package-local callee
        # stays inside the analysis.
        files = _pkg({
            "cb.go": (
                "package store\n\n"
                "func withHold(fn func()) {\n\tfn()\n}\n\n"
                "func hook(p *Pool) {\n"
                "\twithHold(p.opener)\n}\n"
            ),
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is True

    @needs_ts_go
    def test_nested_closure_in_composite_refuses(self):
        # A closure buried in a composite-literal argument
        # (cfg{Handler: func(){…}}) is the same escape the top-level
        # literal check caught — nesting must not hide it.
        files = _pkg({
            "cb.go": (
                'package store\n\nimport "workers"\n\n'
                "type cfg struct {\n\tHandler func()\n}\n\n"
                "func start() {\n"
                "\tworkers.Run(cfg{Handler: func() {\n\t}})\n}\n"
            ),
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False
        assert "function value" in r.reasoning

    @needs_ts_go
    def test_callback_to_package_rooted_chain_allowed(self):
        # withLock-style helpers and sync primitives reached through
        # package-owned state keep the witness (their spawning
        # variants are the implicit-spawner name fence's job).
        files = _pkg({
            "cb.go": (
                "package store\n\n"
                "func withHold(fn func()) {\n\tfn()\n}\n\n"
                "func hook(p *Pool) {\n"
                "\twithHold(func() {\n\t})\n"
                "\tp.each(func() {\n\t})\n}\n"
            ),
            "each.go": (
                "package store\n\n"
                "func (p *Pool) each(fn func()) {\n\tfn()\n}\n"
            ),
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is True

    def test_comment_package_clause_cannot_hide_a_file(self):
        # A block comment containing a "package other" line must not
        # detach the file (and its spawn) from the package.
        files = _pkg({
            "hidden.go": (
                "/*\npackage helpers\n*/\npackage store\n\n"
                "var g = &Record{}\n\n"
                "func init() {\n"
                "\tgo func() {\n\t\tg.Valid = true\n\t}()\n}\n"
            ),
        })
        r = check_goroutine_isolation(
            _RECORD_SCAN, files, anchor_file="record.go",
        )
        assert r.isolated is False

    def test_bom_file_cannot_hide_a_spawn(self):
        files = _pkg({
            "bommed.go": (
                "﻿package store\n\n"
                "var g = &Record{}\n\n"
                "func init() {\n"
                "\tgo func() {\n\t\tg.Valid = true\n\t}()\n}\n"
            ),
        })
        r = check_goroutine_isolation(
            _RECORD_SCAN, files, anchor_file="record.go",
        )
        assert r.isolated is False

    @needs_ts_go
    def test_other_package_file_excluded_by_parsed_clause(self):
        files = _pkg({
            "main.go": (
                "package main\n\n"
                "func main() {\n"
                "\tgo func() {\n\t}()\n}\n"
            ),
        })
        r = check_goroutine_isolation(
            _RECORD_SCAN, files, anchor_file="record.go",
        )
        # The main-package file's spawn belongs to another package —
        # analysis proceeds on the store files alone.
        assert r.isolated is True

    def test_dot_import_refuses(self):
        files = _pkg({
            "dot.go": """package store

import . "fmt"

func hello() {
\tPrintln("x")
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is False

    def test_claim_underivable_with_spawns_refuses(self):
        # Value-parameter function in a package WITH spawns: no
        # claimed types → no witness.
        src = "func format(id string) string {\n\treturn id\n}\n"
        r = check_goroutine_isolation(src, _STORE_PKG)
        assert r.isolated is False

    def test_interface_pointer_param_refuses(self):
        src = "func poke(v *any) {\n\t_ = v\n}\n"
        r = check_goroutine_isolation(src, _STORE_PKG)
        assert r.isolated is False

    def test_claimed_type_not_declared_in_package(self):
        src = "func (a *Alien) M() {\n}\n"
        r = check_goroutine_isolation(src, _STORE_PKG)
        assert r.isolated is False

    def test_c_source_refuses(self):
        c_src = "static int handle(struct sk_buff *skb)\n{\n\treturn 0;\n}\n"
        r = check_goroutine_isolation(c_src, _STORE_PKG)
        assert r.isolated is False

    def test_empty_source_refuses(self):
        r = check_goroutine_isolation("", _STORE_PKG)
        assert r.isolated is False

    def test_no_package_files_refuses(self):
        r = check_goroutine_isolation(_RECORD_SCAN, {})
        assert r.isolated is False

    def test_result_default_is_refusal(self):
        assert GoroutineIsolationResult().isolated is False

    def test_missing_grammar_refuses(self, monkeypatch):
        # Runs everywhere (grammar installed or not): without the Go
        # grammar the witness must refuse with the exact conservative
        # result — never guess from unparsed source.
        import core.audit.goconc as goconc_mod

        monkeypatch.setattr(goconc_mod, "_go_parser", lambda: None)
        r = check_goroutine_isolation(_RECORD_SCAN, _pkg())
        assert r.isolated is False
        assert r.spawn_count == -1
        assert r.claimed_types == ()
        assert r.reasoning == "tree-sitter Go grammar unavailable"


# ---------------------------------------------------------------------------
# External-boundary spawns stay decidable
# ---------------------------------------------------------------------------


@needs_ts_go
class TestExternalBoundary:
    def test_spawned_imported_package_call_ok(self):
        files = _pkg({
            "log.go": """package store

import "log"

func note(msg string) {
\tgo log.Println(msg)
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is True

    def test_spawned_external_typed_method_ok(self):
        files = _pkg({
            "wg.go": """package store

import "sync"

func wait(wg *sync.WaitGroup) {
\tgo wg.Wait()
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is True

    def test_blank_unsafe_import_allowed(self):
        # A blank unsafe import only enables //go:linkname pragmas —
        # it grants the package no unsafe.Pointer capability.
        files = _pkg({
            "link.go": (
                'package store\n\nimport (\n\t_ "unsafe"\n)\n\nvar tick int\n'
            ),
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is True

    def test_named_result_binding_resolves(self):
        files = _pkg({
            "tx.go": """package store

type Tx struct {
\tdone chan struct{}
}

func (t *Tx) awaitDone() {
\t<-t.done
}

func begin() (t *Tx, err error) {
\tt = &Tx{done: make(chan struct{})}
\tgo t.awaitDone()
\treturn t, nil
}
""",
        })
        r = check_goroutine_isolation(_RECORD_SCAN, files)
        assert r.isolated is True


# ---------------------------------------------------------------------------
# Package loader
# ---------------------------------------------------------------------------


class TestLoadGoPackage:
    def _write(self, root, files):
        pkg = root / "pkg" / "store"
        pkg.mkdir(parents=True)
        for name, text in files.items():
            (pkg / name).write_text(text)
        return root

    def test_loads_same_package_siblings(self, tmp_path):
        self._write(tmp_path, _STORE_PKG)
        got = load_go_package(tmp_path, "pkg/store/record.go")
        assert got is not None
        assert sorted(got) == ["pool.go", "record.go"]

    def test_excludes_test_files(self, tmp_path):
        files = dict(_STORE_PKG)
        files["record_test.go"] = "package store\n\nfunc helper() {\n\tgo helper()\n}\n"
        self._write(tmp_path, files)
        got = load_go_package(tmp_path, "pkg/store/record.go")
        assert got is not None
        assert "record_test.go" not in got

    def test_loader_keeps_other_package_clause_for_witness(self, tmp_path):
        # Attribution is the WITNESS's job (parsed clause): the loader
        # returns every non-test sibling so a spawn cannot hide behind
        # a clause the loader's old regex mis-keyed.
        files = dict(_STORE_PKG)
        files["main.go"] = "package main\n\nfunc main() {\n}\n"
        self._write(tmp_path, files)
        got = load_go_package(tmp_path, "pkg/store/record.go")
        assert got is not None
        assert "main.go" in got

    def test_loader_strips_bom(self, tmp_path):
        files = dict(_STORE_PKG)
        files["bommed.go"] = "\ufeffpackage store\n\nvar bommed int\n"
        self._write(tmp_path, files)
        got = load_go_package(tmp_path, "pkg/store/record.go")
        assert got is not None
        assert got["bommed.go"].startswith("package store")

    def test_missing_anchor_returns_none(self, tmp_path):
        assert load_go_package(tmp_path, "pkg/store/nope.go") is None

    def test_non_go_anchor_returns_none(self, tmp_path):
        (tmp_path / "a.c").write_text("int x;\n")
        assert load_go_package(tmp_path, "a.c") is None

    def test_file_cap_returns_none(self, tmp_path):
        files = dict(_STORE_PKG)
        for i in range(70):
            files[f"gen_{i:03d}.go"] = f"package store\n\nvar g{i} int\n"
        self._write(tmp_path, files)
        assert load_go_package(tmp_path, "pkg/store/record.go") is None
