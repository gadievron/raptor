"""Unit tests for core.security.env_sanitisation."""

import unittest

from core.security.env_sanitisation import strip_env_vars, intersect_env_vars


class TestStripEnvVars(unittest.TestCase):
    def test_removes_named_keys(self):
        env = {"PATH": "/usr/bin", "LD_PRELOAD": "/evil.so", "HOME": "/home/u"}
        result = strip_env_vars(env, ["LD_PRELOAD"])
        self.assertEqual(result, {"PATH": "/usr/bin", "HOME": "/home/u"})

    def test_leaves_unrelated_keys(self):
        env = {"PATH": "/usr/bin", "HOME": "/home/u"}
        result = strip_env_vars(env, ["LD_PRELOAD", "BASH_ENV"])
        self.assertEqual(result, env)

    def test_does_not_mutate_input(self):
        env = {"PATH": "/usr/bin", "LD_PRELOAD": "/evil"}
        _ = strip_env_vars(env, ["LD_PRELOAD"])
        self.assertIn("LD_PRELOAD", env)

    def test_empty_env(self):
        self.assertEqual(strip_env_vars({}, ["LD_PRELOAD"]), {})

    def test_empty_names(self):
        env = {"PATH": "/usr/bin"}
        self.assertEqual(strip_env_vars(env, []), env)

    def test_accepts_iterable_types(self):
        env = {"PATH": "/usr/bin", "LD_PRELOAD": "/evil"}
        # frozenset / set / tuple / generator should all work
        self.assertEqual(
            strip_env_vars(env, frozenset(["LD_PRELOAD"])),
            {"PATH": "/usr/bin"},
        )
        self.assertEqual(
            strip_env_vars(env, (n for n in ["LD_PRELOAD"])),
            {"PATH": "/usr/bin"},
        )

    def test_preserves_insertion_order(self):
        env = {"A": 1, "B": 2, "LD_PRELOAD": "/evil", "C": 3}
        result = strip_env_vars(env, ["LD_PRELOAD"])
        self.assertEqual(list(result.keys()), ["A", "B", "C"])


class TestIntersectEnvVars(unittest.TestCase):
    def test_returns_sorted_intersection(self):
        env = {"LD_PRELOAD": "x", "BASH_ENV": "y", "HOME": "/home/u"}
        result = intersect_env_vars(env, ["LD_PRELOAD", "BASH_ENV", "OTHER"])
        self.assertEqual(result, ["BASH_ENV", "LD_PRELOAD"])

    def test_empty_when_none_match(self):
        env = {"PATH": "/usr/bin"}
        self.assertEqual(intersect_env_vars(env, ["LD_PRELOAD"]), [])

    def test_empty_when_env_empty(self):
        self.assertEqual(intersect_env_vars({}, ["LD_PRELOAD"]), [])


if __name__ == "__main__":
    unittest.main()
