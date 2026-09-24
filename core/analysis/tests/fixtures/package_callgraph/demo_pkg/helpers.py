"""Callee-side fixture module: plain functions, a nested def, a base
class with an inherited constructor, and a literal dispatch table."""


def top_helper(x):
    return leaf(x)


def leaf(x):
    return x


def outer():
    def inner():
        return 0
    return inner()


def handle_a():
    return "a"


def handle_b():
    return "b"


HANDLERS = {"a": handle_a, "b": handle_b}


class Base:
    def __init__(self):
        self.tag = "base"

    def greet(self):
        return "hi " + self.tag

    def helper_method(self):
        return self.greet()
