"""Compatibility tests for the moved binary-understand module."""

import unittest

from packages.binary_analysis import BinaryContextMap, BinaryUnderstand, FunctionInfo
from packages.fuzzing import binary_understand


class TestFuzzingBinaryUnderstandCompatibility(unittest.TestCase):

    def test_fuzzing_module_reexports_shared_binary_analysis_api(self):
        self.assertIs(binary_understand.BinaryUnderstand, BinaryUnderstand)
        self.assertIs(binary_understand.BinaryContextMap, BinaryContextMap)
        self.assertIs(binary_understand.FunctionInfo, FunctionInfo)
        self.assertTrue(callable(binary_understand.analyse_binary_context))


if __name__ == "__main__":
    unittest.main()
