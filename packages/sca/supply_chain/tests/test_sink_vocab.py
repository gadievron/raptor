"""Drift guards for the shared supply-chain sink vocabulary.

``version_diff_sinks._DIFF_SINKS`` and ``hook_guard_analysis._HOOK_SINKS``
used to be two hand-edited copies of one core list; they now compose
from ``sink_vocab``. These pins prove the composition reproduces the
exact pre-split sets, so the refactor is behaviour-preserving and any
future divergence must be made in the shared module deliberately.
"""

from packages.sca.supply_chain.hook_guard_analysis import _HOOK_SINKS
from packages.sca.supply_chain.sink_vocab import (
    HOOK_PAYLOAD_EXTRA_SINKS,
    SHARED_SUPPLY_CHAIN_SINKS,
    VERSION_DIFF_EXTRA_SINKS,
)
from packages.sca.supply_chain.version_diff_sinks import _DIFF_SINKS

_PRE_SPLIT_DIFF_SINKS = frozenset({
    "os.system", "os.popen",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "system", "popen", "exec", "eval", "compile",
    "pickle.loads", "pickle.load", "marshal.loads", "yaml.load",
    "__import__",
    "requests.get", "requests.post", "urllib.request.urlopen",
    "socket.connect",
    "os.remove", "os.unlink", "shutil.rmtree",
    "open", "io.open", "os.open",
    "Command::new",
    "child_process.exec", "child_process.spawn",
    "child_process.execSync",
    "Runtime.exec", "ProcessBuilder",
    "passthru", "shell_exec",
    "Kernel.system", "Kernel.exec", "Kernel.eval",
    "Marshal.load",
    "exec.Command",
    "loadstring", "dofile",
    "cursor.execute", "cursor.executemany",
    "memcpy", "strcpy", "strcat", "sprintf", "gets",
})

_PRE_SPLIT_HOOK_SINKS = frozenset({
    "os.system", "os.popen", "subprocess.call", "subprocess.run",
    "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
    "system", "popen", "exec", "eval",
    "pickle.loads", "pickle.load", "marshal.loads",
    "yaml.load", "compile", "__import__",
    "requests.get", "requests.post", "urllib.request.urlopen",
    "http.client.HTTPSConnection", "socket.connect",
    "fetch", "XMLHttpRequest",
    "os.remove", "os.unlink", "shutil.rmtree",
    "Command::new", "std::process::Command",
    "child_process.exec", "child_process.spawn",
    "child_process.execSync", "child_process.execFile",
    "fs.readFileSync", "open",
})


class TestSinkVocabComposition:
    def test_diff_sinks_equal_pre_split_set(self):
        assert _DIFF_SINKS == _PRE_SPLIT_DIFF_SINKS

    def test_hook_sinks_equal_pre_split_set(self):
        assert _HOOK_SINKS == _PRE_SPLIT_HOOK_SINKS

    def test_shared_core_is_the_intersection(self):
        assert SHARED_SUPPLY_CHAIN_SINKS == (
            _PRE_SPLIT_DIFF_SINKS & _PRE_SPLIT_HOOK_SINKS
        )

    def test_extras_are_disjoint_from_shared(self):
        assert not SHARED_SUPPLY_CHAIN_SINKS & VERSION_DIFF_EXTRA_SINKS
        assert not SHARED_SUPPLY_CHAIN_SINKS & HOOK_PAYLOAD_EXTRA_SINKS
