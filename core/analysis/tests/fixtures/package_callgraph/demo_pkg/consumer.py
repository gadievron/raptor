"""Caller-side fixture module: one call site per resolution class."""
import demo_pkg.helpers
from demo_pkg import deep_fn as deep_alias
from demo_pkg.helpers import top_helper as th

from . import helpers
from .helpers import HANDLERS, Base
from .sub import deep_fn


def my_deco(fn):
    return fn


@my_deco
def decorated():
    return None


def use_plain_import():
    return demo_pkg.helpers.top_helper(1)


def use_aliased_import():
    return th(2)


def use_relative_module():
    return helpers.handle_a()


def use_reexport():
    return deep_fn()


def use_package_reexport():
    return deep_alias()


class User(Base):
    def local_method(self):
        return 3

    def run(self):
        self.local_method()
        self.greet()
        return Base.greet(self)


def make_user():
    return User()


def use_dispatch(key):
    return HANDLERS[key]()


def use_getattr(obj):
    return getattr(obj, "handle_b")()


def unresolvable(callback, obj):
    callback()
    obj.mystery()
    import os
    return os.path.join("a", "b")


BOOT = use_plain_import()
