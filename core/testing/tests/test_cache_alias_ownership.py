"""Exercise native cache fixtures with private cache owners and aliases."""

from builtins import __import__ as real_import
from inspect import isgenerator, signature
from types import FunctionType, SimpleNamespace
import importlib

import pytest


JOURNAL_CASES = [
    ("core.coverage.tests.test_journal_load_cache", "_clean_cache"),
    ("core.coverage.tests.test_journal_latest_view", "_clean_cache"),
    ("core.coverage.tests.test_journal_prune_warn", "_clean_cache"),
]
CONTROL_CASES = [
    ("core.audit.tests.test_negative_controls", "_clear_negative_control_cache"),
    ("core.audit.tests.test_semgrep_control_batching", "_clear_negative_control_cache"),
    (
        "core.audit.tests.test_sweep_memo",
        "TestControlErrorNotPinned._clear_control_cache",
    ),
]
ALIAS_CASES = CONTROL_CASES[1:2]
CASES = JOURNAL_CASES + CONTROL_CASES


class _Lock:
    def __init__(self):
        self.held = False

    def __enter__(self):
        assert not self.held
        self.held = True

    def __exit__(self, *exc):
        self.held = False


class _Journal:
    def __init__(self, cache):
        self._load_cache_lock = _Lock()
        self.writes = []
        self.__dict__["_load_cache"] = cache

    def __setattr__(self, name, value):
        if name == "_load_cache":
            assert self._load_cache_lock.held, "cache publication must hold its lock"
            self.writes.append(value)
        super().__setattr__(name, value)


def _native_fixture(module_name, fixture_name, *, fail_at=None, separate_alias=False):
    module = importlib.import_module(module_name)
    fixture = module
    for part in fixture_name.split("."):
        fixture = getattr(fixture, part)
    original = fixture.__wrapped__
    borrowed = {"borrowed": object()}
    alias = {"alias": object()} if separate_alias else borrowed
    journal = _Journal(borrowed)
    sweep = SimpleNamespace(_negative_control_cache=borrowed)
    namespace = dict(original.__globals__)
    namespace.update(journal_mod=journal, _negative_control_cache=alias)
    steps = []

    class Patch(pytest.MonkeyPatch):
        def setattr(self, owner, name, value, *args, **kwargs):
            super().setattr(owner, name, value, *args, **kwargs)
            if name in {"_load_cache", "_negative_control_cache"}:
                steps.append(name)
                if len(steps) == fail_at:
                    raise RuntimeError("injected setup failure")

        def setitem(self, owner, name, value):
            super().setitem(owner, name, value)
            if name == "_negative_control_cache":
                steps.append(name)
                if len(steps) == fail_at:
                    raise RuntimeError("injected setup failure")

    def fixture_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.audit.sweep":
            return sweep
        if name == "core.audit" and "sweep" in fromlist:
            return SimpleNamespace(sweep=sweep)
        return real_import(name, globals, locals, fromlist, level)

    namespace["__builtins__"] = dict(
        vars(__import__("builtins")), __import__=fixture_import
    )
    namespace["pytest"] = SimpleNamespace(MonkeyPatch=Patch)
    function = FunctionType(
        original.__code__,
        namespace,
        original.__name__,
        original.__defaults__,
        original.__closure__,
    )
    return function, namespace, journal, sweep, borrowed, alias, Patch


def _start(function, patch):
    available = {"self": object(), "monkeypatch": patch}
    result = function(**{key: available[key] for key in signature(function).parameters})
    if isgenerator(result):
        next(result)
        return result
    return None


def _finish(generator, mode):
    if generator is None:
        return
    try:
        if mode == "close":
            generator.close()
        elif mode == "throw":
            with pytest.raises(KeyboardInterrupt):
                generator.throw(KeyboardInterrupt)
        else:
            with pytest.raises(StopIteration):
                next(generator)
    finally:
        generator.close()


@pytest.mark.parametrize("module_name,fixture_name", CASES)
@pytest.mark.parametrize("mode", ["normal", "body_error", "close", "throw"])
def test_native_cache_fixture_owns_only_fresh_state(module_name, fixture_name, mode):
    function, namespace, journal, sweep, borrowed, alias, patch_type = _native_fixture(
        module_name,
        fixture_name,
    )
    contents = borrowed.copy()
    patch = patch_type()
    generator = None
    try:
        generator = _start(function, patch)
        active = (
            journal._load_cache
            if (module_name, fixture_name) in JOURNAL_CASES
            else sweep._negative_control_cache
        )
        assert active is not borrowed
        assert active == {}
        assert borrowed == contents
        if (module_name, fixture_name) in ALIAS_CASES:
            assert namespace["_negative_control_cache"] is active
        active["local"] = object()
        if mode == "body_error":
            with pytest.raises(KeyboardInterrupt):
                raise KeyboardInterrupt
    finally:
        try:
            _finish(generator, mode)
        finally:
            patch.undo()
    assert borrowed == contents
    if (module_name, fixture_name) in JOURNAL_CASES:
        assert journal._load_cache is borrowed
        assert len(journal.writes) == 2
        assert not journal._load_cache_lock.held
    else:
        assert sweep._negative_control_cache is borrowed
        assert namespace["_negative_control_cache"] is alias


@pytest.mark.parametrize("module_name,fixture_name", ALIAS_CASES)
def test_imported_cache_alias_is_pinned_and_restored_independently(
    module_name, fixture_name
):
    function, namespace, _, sweep, borrowed, alias, patch_type = _native_fixture(
        module_name,
        fixture_name,
        separate_alias=True,
    )
    borrowed_contents, alias_contents = borrowed.copy(), alias.copy()
    patch = patch_type()
    generator = None
    try:
        generator = _start(function, patch)
        assert namespace["_negative_control_cache"] is sweep._negative_control_cache
        assert sweep._negative_control_cache is not borrowed
        assert namespace["_negative_control_cache"] is not alias
    finally:
        try:
            _finish(generator, "normal")
        finally:
            patch.undo()
    assert sweep._negative_control_cache is borrowed
    assert namespace["_negative_control_cache"] is alias
    assert borrowed == borrowed_contents
    assert alias == alias_contents


@pytest.mark.parametrize(
    "module_name,fixture_name,fail_at",
    [
        *(case + (1,) for case in CASES),
        *(case + (2,) for case in ALIAS_CASES),
    ],
)
def test_cache_setup_failure_restores_completed_publications(
    module_name, fixture_name, fail_at
):
    function, namespace, journal, sweep, borrowed, alias, patch_type = _native_fixture(
        module_name,
        fixture_name,
        fail_at=fail_at,
        separate_alias=True,
    )
    borrowed_contents, alias_contents = borrowed.copy(), alias.copy()
    patch = patch_type()
    try:
        with pytest.raises(RuntimeError, match="injected setup failure"):
            _start(function, patch)
    finally:
        patch.undo()
    assert borrowed == borrowed_contents
    assert alias == alias_contents
    assert sweep._negative_control_cache is borrowed
    assert namespace["_negative_control_cache"] is alias
    assert journal._load_cache is borrowed
    assert not journal._load_cache_lock.held
